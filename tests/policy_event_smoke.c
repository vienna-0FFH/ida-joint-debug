#include "joint_debug_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int wait_shared_events(int fd, struct ida_vtdbg_shared_ring *ring,
                              pid_t parent, pid_t child0, pid_t child1,
                              unsigned int expected_forks,
                              unsigned int expected_stops,
                              unsigned int *forks, unsigned int *stops)
{
    for (unsigned int pass = 0;
         pass < 200 && (*forks < expected_forks ||
                        *stops < expected_stops);
         ++pass) {
        uint64_t producer = __atomic_load_n(&ring->producer,
                                            __ATOMIC_ACQUIRE);
        uint64_t consumer = __atomic_load_n(&ring->consumer,
                                            __ATOMIC_RELAXED);

        while (consumer < producer) {
            struct ida_vtdbg_policy_event event;
            struct ida_vtdbg_shared_slot *slot =
                &ring->slots[consumer % ring->slot_count];

            memcpy(&event, &slot->event, sizeof(event));
            if (event.parent_tgid == (uint32_t)parent) {
                if (event.type == IDA_VTDBG_EVENT_FORK &&
                    (event.pid == (uint32_t)child0 ||
                     event.pid == (uint32_t)child1))
                    ++*forks;
                if (event.type == IDA_VTDBG_EVENT_STOP &&
                    event.pid == (uint32_t)child0 &&
                    (event.flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) != 0)
                    ++*stops;
            }
            ++consumer;
        }
        __atomic_store_n(&ring->consumer, consumer, __ATOMIC_RELEASE);
        if (*forks >= expected_forks && *stops >= expected_stops)
            return 0;

        {
            struct pollfd descriptor = {.fd = fd, .events = POLLIN};
            int poll_result = poll(&descriptor, 1, 10);
            if (poll_result < 0 && errno != EINTR)
                return -1;
        }
    }
    errno = ETIMEDOUT;
    return -1;
}

int main(void)
{
    int fd;
    int reader_fd;
    struct ida_vtdbg_shared_ring *reader_ring;
    pid_t parent = getpid();
    pid_t tree_root = getppid();
    pid_t children[2];
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (unsigned int)parent,
        .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
    };
    unsigned int events = 0;
    unsigned int shared_forks = 0;
    unsigned int shared_stops = 0;

    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open policy device");
        return 1;
    }
    if (ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session) < 0) {
        perror("register");
        close(fd);
        return 2;
    }
    reader_fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (reader_fd < 0) {
        perror("open event reader");
        (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
        close(fd);
        return 9;
    }
    reader_ring = mmap(NULL, IDA_VTDBG_SHARED_BYTES,
                       PROT_READ | PROT_WRITE, MAP_SHARED, reader_fd, 0);
    if (reader_ring == MAP_FAILED) {
        perror("mmap event reader");
        close(reader_fd);
        (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
        close(fd);
        return 10;
    }
    {
        struct ida_vtdbg_policy_session tree_subscription = session;
        tree_subscription.target_pid = (uint32_t)tree_root;
        if (ioctl(reader_fd, IDA_VTDBG_IOC_SUBSCRIBE_EVENTS,
                  &tree_subscription) < 0) {
            perror("subscribe event reader");
            munmap(reader_ring, IDA_VTDBG_SHARED_BYTES);
            close(reader_fd);
            (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
            close(fd);
            return 11;
        }
    }
    for (size_t index = 0; index < 2; ++index) {
        children[index] = fork();
        if (children[index] < 0) {
            perror("fork");
            return 3;
        }
        if (children[index] == 0)
            _exit(0);
    }
    for (size_t index = 0; index < 2; ++index)
        (void)waitpid(children[index], NULL, 0);

    for (unsigned int pass = 0; pass < 200 && events < 2; ++pass) {
        struct ida_vtdbg_policy_event event = {
            .abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (unsigned int)parent,
            .flags = IDA_VTDBG_EVENT_F_NONBLOCK,
        };
        if (ioctl(fd, IDA_VTDBG_IOC_NEXT_EVENT, &event) == 0) {
            if (event.type == IDA_VTDBG_EVENT_FORK &&
                event.parent_tgid == (unsigned int)parent) {
                printf("event=fork child=%u parent=%u seq=%llu\n",
                       event.pid, event.parent_tgid,
                       (unsigned long long)event.sequence);
                ++events;
            }
        } else if (errno != EAGAIN && errno != ENOENT) {
            perror("next_event");
            return 4;
        } else {
            usleep(1000);
        }
    }
    if (events != 2) {
        fprintf(stderr, "policy-event-smoke: expected 2 events, got %u\n",
                events);
        return 5;
    }
    if (wait_shared_events(reader_fd, reader_ring, parent,
                           children[0], children[1], 2, 0,
                           &shared_forks, &shared_stops) < 0) {
        perror("shared fork subscription");
        return 12;
    }
    {
        struct ida_vtdbg_policy_event report = {
            .abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (unsigned int)parent,
            .type = IDA_VTDBG_EVENT_STOP,
            .flags = IDA_VTDBG_EVENT_F_INITIAL_STOP,
            .pid = (unsigned int)children[0],
            .tgid = (unsigned int)children[0],
            .parent_pid = (unsigned int)parent,
            .parent_tgid = (unsigned int)parent,
            .status = (SIGSTOP << 8) | 0x7f,
        };
        struct ida_vtdbg_policy_event event = {
            .abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (unsigned int)parent,
            .flags = IDA_VTDBG_EVENT_F_NONBLOCK,
        };
        int saw_initial_stop = 0;

        if (ioctl(fd, IDA_VTDBG_IOC_REPORT_EVENT, &report) < 0) {
            perror("report initial stop");
            return 6;
        }
        for (unsigned int pass = 0; pass < 200 && !saw_initial_stop; ++pass) {
            if (ioctl(fd, IDA_VTDBG_IOC_NEXT_EVENT, &event) == 0) {
                saw_initial_stop =
                    event.type == IDA_VTDBG_EVENT_STOP &&
                    (event.flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) != 0 &&
                    event.pid == (unsigned int)children[0];
            } else if (errno == EAGAIN || errno == ENOENT) {
                usleep(1000);
            } else {
                perror("read initial stop event");
                return 7;
            }
        }
        if (!saw_initial_stop) {
            fprintf(stderr,
                    "policy-event-smoke: initial stop flag/type/pid lost "
                    "type=%u flags=0x%x pid=%u\n",
                    event.type, event.flags, event.pid);
            return 8;
        }
    }
    if (wait_shared_events(reader_fd, reader_ring, parent,
                           children[0], children[1], 2, 1,
                           &shared_forks, &shared_stops) < 0) {
        perror("shared stop subscription");
        return 13;
    }
    munmap(reader_ring, IDA_VTDBG_SHARED_BYTES);
    close(reader_fd);
    (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
    close(fd);
    puts("policy-event-smoke: fork/stop queue and independent shared subscribers PASS");
    return 0;
}
