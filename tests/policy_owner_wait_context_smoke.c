/* Deterministic owner wait-frame lifetime/sequence test. No timing sleeps. */
#include "joint_debug_abi.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

struct owner_thread_test {
    int fd;
    unsigned int index;
    unsigned int tid;
    unsigned long long sequence;
};
static pthread_barrier_t owner_gate;

static void *owner_thread(void *opaque)
{
    struct owner_thread_test *test = opaque;
    test->tid = syscall(SYS_gettid);
    for (unsigned int round = 0; round < 64; ++round) {
        struct ida_vtdbg_owner_wait_context frame = {
            .abi = IDA_VTDBG_POLICY_ABI, .target_pid = getpid(),
            .owner_tid = test->tid, .operation = IDA_VTDBG_OWNER_WAIT_ENTER,
            .kind = test->index, .caller_ip = 0x1000 + test->index,
        };
        frame.regs[16] = 0x2000 + test->index;
        frame.regs[19] = 0x3000 + round;
        assert(ioctl(test->fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == 0);
        test->sequence = frame.sequence;
        pthread_barrier_wait(&owner_gate); /* main can query both held frames */
        pthread_barrier_wait(&owner_gate); /* main finished identity checks */
        frame.operation = IDA_VTDBG_OWNER_WAIT_LEAVE;
        assert(ioctl(test->fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == 0);
        pthread_barrier_wait(&owner_gate);
    }
    return NULL;
}

int main(void)
{
    int fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    assert(fd >= 0);
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI, .target_pid = getpid(),
    };
    assert(ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session) == 0);
    struct ida_vtdbg_owner_wait_context frame = {
        .abi = IDA_VTDBG_POLICY_ABI, .target_pid = getpid(),
        .owner_tid = syscall(SYS_gettid), .operation = IDA_VTDBG_OWNER_WAIT_ENTER,
        .kind = 3, .caller_ip = 0x1234,
    };
    frame.regs[16] = 0x5678;
    frame.regs[19] = 0x9876;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == 0);
    assert(frame.sequence > 0 && frame.state == IDA_VTDBG_OWNER_WAIT_ACTIVE);
    unsigned long long first = frame.sequence;
    errno = 0;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == -1 && errno == EBUSY);
    struct ida_vtdbg_owner_wait_context query = frame;
    query.operation = IDA_VTDBG_OWNER_WAIT_QUERY;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &query) == 0);
    assert(query.sequence == first && query.regs[16] == 0x5678 && query.regs[19] == 0x9876);
    frame.operation = IDA_VTDBG_OWNER_WAIT_LEAVE;
    frame.sequence = first + 1;
    errno = 0;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == -1 && errno == ESTALE);
    frame.sequence = first;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == 0);
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &query) == 0 && query.state == 0);
    frame.operation = IDA_VTDBG_OWNER_WAIT_ENTER;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == 0 && frame.sequence > first);
    frame.operation = IDA_VTDBG_OWNER_WAIT_LEAVE;
    assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &frame) == 0);
    pthread_t threads[2];
    struct owner_thread_test owners[2] = {{.fd = fd, .index = 0}, {.fd = fd, .index = 1}};
    assert(pthread_barrier_init(&owner_gate, NULL, 3) == 0);
    for (unsigned int n = 0; n < 2; ++n)
        assert(pthread_create(&threads[n], NULL, owner_thread, &owners[n]) == 0);
    for (unsigned int round = 0; round < 64; ++round) {
        pthread_barrier_wait(&owner_gate);
        assert(owners[0].tid != owners[1].tid && owners[0].sequence != owners[1].sequence);
        for (unsigned int n = 0; n < 2; ++n) {
            struct ida_vtdbg_owner_wait_context concurrent = {
                .abi = IDA_VTDBG_POLICY_ABI, .target_pid = getpid(),
                .owner_tid = owners[n].tid, .operation = IDA_VTDBG_OWNER_WAIT_QUERY,
            };
            assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &concurrent) == 0);
            assert(concurrent.state == IDA_VTDBG_OWNER_WAIT_ACTIVE &&
                   concurrent.sequence == owners[n].sequence &&
                   concurrent.regs[16] == 0x2000 + n && concurrent.regs[19] == 0x3000 + round);
            concurrent.operation = IDA_VTDBG_OWNER_WAIT_LEAVE;
            errno = 0;
            assert(ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &concurrent) == -1 && errno == EPERM);
        }
        pthread_barrier_wait(&owner_gate);
        pthread_barrier_wait(&owner_gate);
    }
    for (unsigned int n = 0; n < 2; ++n) assert(pthread_join(threads[n], NULL) == 0);
    assert(pthread_barrier_destroy(&owner_gate) == 0);
    assert(ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session) == 0);
    close(fd);
    puts("POLICY_OWNER_WAIT_CONTEXT_PASS two_owner_tids=128 frames isolation+authority+sequences");
    return 0;
}
