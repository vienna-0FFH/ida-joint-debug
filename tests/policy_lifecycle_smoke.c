#include "joint_debug_abi.h"
#include "shared_event_reader.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Confirm the actual kernel exit status survives closure of the session
 * owner's fd. Pipe acknowledgements are causal barriers, never sleeps. */
int main(void)
{
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (unsigned int)getpid(),
        .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
    };
    int owner = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    int reader = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    int gate[2];
    int result = 1;
    pid_t child = -1;
    struct ida_vtdbg_shared_ring *ring = MAP_FAILED;
    if (owner < 0 || reader < 0 || pipe(gate) < 0) {
        perror("open/pipe");
        goto done;
    }
    if (ioctl(owner, IDA_VTDBG_IOC_REGISTER, &session) < 0) {
        perror("register");
        goto done;
    }
    session.flags |= IDA_VTDBG_SUBSCRIBE_F_PERSISTENT_TREE;
    if (ioctl(reader, IDA_VTDBG_IOC_SUBSCRIBE_EVENTS, &session) < 0) {
        perror("subscribe");
        goto done;
    }
    ring = mmap(NULL, IDA_VTDBG_SHARED_BYTES, PROT_READ | PROT_WRITE,
                MAP_SHARED, reader, 0);
    if (ring == MAP_FAILED) {
        perror("mmap");
        goto done;
    }
    child = fork();
    if (child == 0) {
        char byte;
        close(owner);
        close(reader);
        close(gate[1]);
        _exit(read(gate[0], &byte, 1) == 1 ? 37 : 99);
    }
    if (child < 0) {
        perror("fork");
        goto done;
    }
    close(gate[0]);
    bool saw_fork = false;
    bool saw_exit = false;
    for (unsigned int pass = 0; pass < 10 && !saw_exit; ++pass) {
        struct ida_vtdbg_policy_event event;
        while (ida_vtdbg_shared_ring_next(ring, &event)) {
            if (event.pid != (unsigned int)child)
                continue;
            if (event.type == IDA_VTDBG_EVENT_FORK && !saw_fork) {
                saw_fork = true;
                close(owner);
                owner = -1;
                if (write(gate[1], "x", 1) != 1)
                    goto done;
            }
            if (event.type == IDA_VTDBG_EVENT_EXIT) {
                printf("child=%u actual_status=0x%x flags=0x%x\n",
                       event.pid, event.status, event.flags);
                saw_exit = event.status == (37u << 8) &&
                    (event.flags & IDA_VTDBG_EVENT_F_KERNEL_LIFECYCLE) != 0;
                if (!saw_exit)
                    goto done;
            }
        }
        if (!saw_exit) {
            struct pollfd descriptor = {.fd = reader, .events = POLLIN};
            int rc = poll(&descriptor, 1, 1000);
            if (rc < 0 && errno != EINTR) {
                perror("poll");
                goto done;
            }
        }
    }
    if (saw_fork && saw_exit) {
        puts("policy-lifecycle-smoke: pinned identity + real exit status + closed owner PASS");
        result = 0;
    }
done:
    if (child > 0) {
        if (result != 0)
            kill(child, SIGKILL);
        waitpid(child, NULL, 0);
    }
    if (ring != MAP_FAILED)
        munmap(ring, IDA_VTDBG_SHARED_BYTES);
    if (owner >= 0)
        close(owner);
    if (reader >= 0)
        close(reader);
    return result;
}
