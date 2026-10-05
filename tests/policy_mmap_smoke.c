#include "joint_debug_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static uint64_t load_u64(const __u64 *value)
{
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static void store_u64(__u64 *value, uint64_t next)
{
    __atomic_store_n(value, next, __ATOMIC_RELEASE);
}

int main(void)
{
    int fd = -1;
    struct ida_vtdbg_shared_ring *ring = MAP_FAILED;
    struct ida_vtdbg_policy_session session;
    pid_t parent = getpid();
    pid_t child;
    unsigned int seen = 0;
    int result = 1;

    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open policy device");
        return 2;
    }
    ring = mmap(NULL, IDA_VTDBG_SHARED_BYTES, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        perror("mmap policy ring");
        close(fd);
        return 3;
    }
    if (ring->magic != IDA_VTDBG_SHARED_MAGIC ||
        ring->version != IDA_VTDBG_SHARED_VERSION ||
        ring->header_size >= IDA_VTDBG_SHARED_BYTES ||
        ring->slot_count != IDA_VTDBG_SHARED_RING_SLOTS) {
        fprintf(stderr, "bad shared header magic=%08x version=%u header=%u slots=%u\n",
                ring->magic, ring->version, ring->header_size,
                ring->slot_count);
        goto out;
    }
    memset(&session, 0, sizeof(session));
    session.abi = IDA_VTDBG_POLICY_ABI;
    session.target_pid = (uint32_t)parent;
    session.flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS;
    if (ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session) < 0) {
        perror("register");
        goto out;
    }

    child = fork();
    if (child < 0) {
        perror("fork");
        goto unregister;
    }
    if (child == 0)
        _exit(0);
    (void)waitpid(child, NULL, 0);

    for (unsigned int pass = 0; pass < 100 && seen == 0; ++pass) {
        struct pollfd descriptor = {.fd = fd, .events = POLLIN};
        int poll_result = poll(&descriptor, 1, 20);
        uint64_t producer;
        uint64_t consumer;

        if (poll_result < 0 && errno == EINTR)
            continue;
        producer = load_u64(&ring->producer);
        consumer = load_u64(&ring->consumer);
        while (consumer < producer) {
            struct ida_vtdbg_policy_event event;
            struct ida_vtdbg_shared_slot *slot =
                &ring->slots[consumer % ring->slot_count];
            memcpy(&event, &slot->event, sizeof(event));
            if (event.type == IDA_VTDBG_EVENT_FORK &&
                event.parent_tgid == (uint32_t)parent &&
                event.pid == (uint32_t)child)
                ++seen;
            ++consumer;
        }
        store_u64(&ring->consumer, consumer);
    }
    if (seen != 1) {
        fprintf(stderr, "shared ring did not deliver child event (seen=%u producer=%llu dropped=%llu)\n",
                seen, (unsigned long long)load_u64(&ring->producer),
                (unsigned long long)load_u64(&ring->dropped));
        goto unregister;
    }
    if (ioctl(fd, IDA_VTDBG_IOC_SHARED_RESET, 0) < 0) {
        perror("shared reset");
        goto unregister;
    }
    puts("policy-mmap-smoke: shared ring PASS");
    result = 0;

unregister:
    (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
out:
    if (ring != MAP_FAILED)
        munmap(ring, IDA_VTDBG_SHARED_BYTES);
    if (fd >= 0)
        close(fd);
    return result;
}
