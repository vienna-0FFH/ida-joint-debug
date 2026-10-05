#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "joint_debug_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

__attribute__((naked, noinline)) static void marker0(void) { __asm__("nop; ret"); }
__attribute__((naked, noinline)) static void marker1(void) { __asm__("nop; ret"); }
__attribute__((naked, noinline)) static void marker2(void) { __asm__("nop; ret"); }
__attribute__((naked, noinline)) static void marker3(void) { __asm__("nop; ret"); }

static unsigned long dr_offset(unsigned int index)
{
    return offsetof(struct user, u_debugreg[0]) + index * sizeof(unsigned long);
}

static long bridge(int fd, pid_t owner, pid_t child, int request,
                   unsigned int index, unsigned long *value)
{
    struct ida_vtdbg_ptrace_command command = {
        .abi = IDA_VTDBG_POLICY_ABI, .target_pid = owner, .pid = child,
        .request = request, .addr = dr_offset(index), .value = *value,
    };
    for (;;) {
        if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command))
            return -errno;
        if (command.result != -EAGAIN) {
            *value = command.value;
            if (command.result)
                fprintf(stderr, "DR bridge req=%d index=%u value=%#lx result=%lld error=%u\n",
                        request, index, *value, (long long)command.result, command.error);
            return command.result;
        }
        /* The ioctl checks scheduler completion. Retry that explicit state,
         * not a guessed delay after wait status delivery. alarm bounds failure. */
        sched_yield();
    }
}

static int child_owner(int output)
{
    int status;
    pid_t child;
    const uintptr_t sites[4] = {(uintptr_t)marker0, (uintptr_t)marker1,
                                (uintptr_t)marker2, (uintptr_t)marker3};

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) return 31;
    child = fork();
    if (!child) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(32);
        raise(SIGSTOP);
        marker0(); marker1(); marker2(); marker3();
        _exit(37);
    }
    if (child < 0) return 33;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) return 34;
    /* Allocate with the real owner's native ptrace, keeping Linux's original
     * perf overflow callback/lifetime. The bridge must update, not emulate it. */
    for (unsigned int n = 0; n < 4; ++n)
        if (ptrace(PTRACE_POKEUSER, child, (void *)dr_offset(n), (void *)sites[n])) return 35;
    if (ptrace(PTRACE_POKEUSER, child, (void *)dr_offset(7), (void *)0x100ul)) return 36;
    if (write(output, &child, sizeof(child)) != sizeof(child)) return 38;
    raise(SIGSTOP); /* root updates DR0..3/6/7 while this real owner cannot run */
    for (unsigned int n = 0; n < 4; ++n) {
        if (ptrace(PTRACE_POKEUSER, child, (void *)dr_offset(6), (void *)0xffff0ff0ul)) return 39;
        if (ptrace(PTRACE_CONT, child, NULL, NULL)) return 40;
        if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status) ||
            WSTOPSIG(status) != SIGTRAP) return 41;
        struct user_regs_struct regs;
        siginfo_t info;
        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) ||
            ptrace(PTRACE_GETSIGINFO, child, NULL, &info)) return 42;
        errno = 0;
        unsigned long dr6 = ptrace(PTRACE_PEEKUSER, child, (void *)dr_offset(6), NULL);
        if (errno || regs.rip != sites[n] || info.si_code != TRAP_HWBKPT ||
            (dr6 & 15) != (1ul << n)) return 43;
        unsigned long dr7 = ptrace(PTRACE_PEEKUSER, child, (void *)dr_offset(7), NULL);
        if (ptrace(PTRACE_POKEUSER, child, (void *)dr_offset(7),
                   (void *)(dr7 & ~(3ul << (2 * n))))) return 44;
    }
    if (ptrace(PTRACE_CONT, child, NULL, NULL)) return 45;
    if (waitpid(child, &status, __WALL) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 37) return 46;
    return 0;
}

int main(void)
{
    int channels[2], status, fd = -1, result = 1;
    pid_t owner = -1, child = -1;
    const uintptr_t sites[4] = {(uintptr_t)marker0, (uintptr_t)marker1,
                                (uintptr_t)marker2, (uintptr_t)marker3};
    const char *stage = "create owner";
    alarm(30);
    if (pipe(channels)) return 2;
    owner = fork();
    if (!owner) {
        close(channels[0]);
        _exit(child_owner(channels[1]));
    }
    if (owner < 0) return 3;
    close(channels[1]);
    while (waitpid(owner, &status, __WALL) == owner) {
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) break;
        if (!WIFSTOPPED(status) || ptrace(PTRACE_CONT, owner, NULL, NULL)) goto cleanup;
    }
    if (read(channels[0], &child, sizeof(child)) != sizeof(child)) goto cleanup;
    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    struct ida_vtdbg_policy_session session = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = owner, .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS};
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session)) goto cleanup;
    stage = "DR0..3 update and readback";
    for (unsigned int n = 0; n < 4; ++n) {
        unsigned long value = sites[n];
        if (bridge(fd, owner, child, PTRACE_POKEUSER, n, &value)) goto cleanup;
        value = 0;
        if (bridge(fd, owner, child, PTRACE_PEEKUSER, n, &value) || value != sites[n]) goto cleanup;
    }
    unsigned long value = 0xffff0ff0ul;
    stage = "DR6 update and readback";
    if (bridge(fd, owner, child, PTRACE_POKEUSER, 6, &value)) goto cleanup;
    value = 0;
    if (bridge(fd, owner, child, PTRACE_PEEKUSER, 6, &value) || value != 0xffff0ff0ul) goto cleanup;
    value = 0x155ul;
    stage = "DR7 update and readback";
    if (bridge(fd, owner, child, PTRACE_POKEUSER, 7, &value)) goto cleanup;
    value = 0;
    if (bridge(fd, owner, child, PTRACE_PEEKUSER, 7, &value) || value != 0x155ul) goto cleanup;
    value = 0x155ul | (4ul << 16); /* invalid execute length; bank must remain intact */
    stage = "invalid DR7 execute length";
    if (bridge(fd, owner, child, PTRACE_POKEUSER, 7, &value) != -EINVAL) goto cleanup;
    value = 0;
    stage = "invalid DR7 rollback";
    if (bridge(fd, owner, child, PTRACE_PEEKUSER, 7, &value) || value != 0x155ul) goto cleanup;
    stage = "invalid DR4";
    if (bridge(fd, owner, child, PTRACE_POKEUSER, 4, &value) != -EIO) goto cleanup;
    stage = "nontracer authority";
    pid_t denied = fork();
    if (!denied) {
        unsigned long attempt = sites[0];
        _exit(bridge(fd, owner, child, PTRACE_POKEUSER, 0, &attempt) == -EPERM ? 0 : 71);
    }
    if (denied < 0 || waitpid(denied, &status, 0) != denied ||
        !WIFEXITED(status) || WEXITSTATUS(status)) goto cleanup;
    stage = "native hardware hits";
    if (ptrace(PTRACE_CONT, owner, NULL, NULL)) goto cleanup;
    while (waitpid(owner, &status, __WALL) == owner) {
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status)) {
                fprintf(stderr, "real ptrace owner verification failed code=%d\n", WEXITSTATUS(status));
                goto cleanup;
            }
            result = 0;
            break;
        }
        if (!WIFSTOPPED(status) || ptrace(PTRACE_CONT, owner, NULL, NULL)) goto cleanup;
    }
cleanup:
    if (result) {
        fprintf(stderr, "stopped debugreg smoke failed stage=%s errno=%d\n", stage, errno);
        if (child > 0) kill(child, SIGKILL);
        if (owner > 0) {
            kill(owner, SIGKILL);
            while (waitpid(owner, &status, __WALL) == owner && WIFSTOPPED(status))
                ptrace(PTRACE_CONT, owner, NULL, (void *)(uintptr_t)SIGKILL);
        }
    }
    if (fd >= 0) close(fd);
    close(channels[0]);
    if (!result) puts("policy-stopped-debugregs: 4 real HW traps + DR6/7 + validation + authority PASS");
    return result;
}
