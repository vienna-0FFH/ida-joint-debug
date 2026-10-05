#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "joint_debug_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <elf.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned long marker = 0x5644544250415245ul;

int main(void)
{
    int channel[2], status, result = 1;
    pid_t owner = -1, child = -1;
    int fd = -1;
    alarm(20);
    if (pipe(channel)) return 2;
    owner = fork();
    if (!owner) {
        close(channel[0]);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(31);
        child = fork();
        if (!child) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(32);
            raise(SIGSTOP);
            _exit(37);
        }
        if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) _exit(33);
        if (write(channel[1], &child, sizeof(child)) != sizeof(child)) _exit(34);
        raise(SIGSTOP); /* the real parent is deliberately stopped here */
        if (ptrace(PTRACE_CONT, child, NULL, NULL)) _exit(35);
        if (waitpid(child, &status, __WALL) != child) _exit(36);
        _exit(0);
    }
    if (owner < 0) return 3;
    close(channel[1]);
    /* An outer-traced owner can first stop for SIGCHLD while waiting for its
     * own child. Consume/resume that event before waiting on its pipe write;
     * blocking read first deadlocks a perfectly healthy nested tracer. */
    while (waitpid(owner, &status, __WALL) == owner) {
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) break;
        if (!WIFSTOPPED(status) || ptrace(PTRACE_CONT, owner, NULL, NULL)) goto cleanup;
    }
    if (read(channel[0], &child, sizeof(child)) != sizeof(child)) goto cleanup;
    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    struct ida_vtdbg_policy_session session = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS};
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session)) goto cleanup;
    struct ida_vtdbg_ptrace_command command = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .pid = (uint32_t)child,
        .request = IDA_VTDBG_NESTED_QUERY_STOP};
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) ||
        command.result != 1 || command.value != (uint64_t)owner) goto cleanup;
    struct user_regs_struct regs = {0};
    command.request = PTRACE_GETREGS;
    command.data = (uintptr_t)&regs;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result || !regs.rip)
        goto cleanup;
    struct user_regs_struct changed = regs, observed;
    changed.rax ^= 1;
    command.request = PTRACE_SETREGS;
    command.data = (uintptr_t)&changed;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result) goto cleanup;
    command.request = PTRACE_GETREGS;
    command.data = (uintptr_t)&observed;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result ||
        observed.rax != changed.rax || observed.rip != changed.rip) goto cleanup;
    command.request = PTRACE_SETREGS;
    command.data = (uintptr_t)&regs;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result) goto cleanup;
    struct iovec regs_iov = {.iov_base = &observed, .iov_len = sizeof(observed)};
    command.request = PTRACE_GETREGSET;
    command.addr = NT_PRSTATUS;
    command.data = (uintptr_t)&regs_iov;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result ||
        regs_iov.iov_len != sizeof(regs) || memcmp(&observed, &regs, sizeof(regs))) goto cleanup;
    struct user_fpregs_struct fpregs = {0};
    command.request = PTRACE_GETFPREGS;
    command.addr = 0;
    command.data = (uintptr_t)&fpregs;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result) goto cleanup;
    command.request = PTRACE_SETFPREGS;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result) goto cleanup;
    command.request = PTRACE_PEEKUSER;
    command.addr = offsetof(struct user, regs.rip);
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result ||
        command.value != regs.rip) goto cleanup;
    siginfo_t signal_info = {0};
    command.request = PTRACE_GETSIGINFO;
    command.addr = 0;
    command.data = (uintptr_t)&signal_info;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result ||
        signal_info.si_signo != SIGSTOP) goto cleanup;
    command.request = PTRACE_PEEKDATA;
    command.addr = (uintptr_t)&marker;
    command.data = 0;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result ||
        command.value != marker) goto cleanup;
    command.request = PTRACE_POKEDATA;
    command.value ^= 1;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result) goto cleanup;
    command.request = PTRACE_PEEKDATA;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) || command.result ||
        command.value != (marker ^ 1)) goto cleanup;
    command.request = PTRACE_CONT;
    errno = 0;
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) != -1 || errno != EINVAL)
        goto cleanup;
    char path[96], line[160];
    int tracer = 0;
    snprintf(path, sizeof(path), "/proc/%d/status", child);
    FILE *status_file = fopen(path, "r");
    if (!status_file) goto cleanup;
    while (fgets(line, sizeof(line), status_file))
        if (sscanf(line, "TracerPid: %d", &tracer) == 1) break;
    fclose(status_file);
    if (tracer != owner) goto cleanup;
    printf("stopped-owner: child=%d actual_tracer=%d preserved; GPR/FP/REGSET/SIGINFO/PEEK/POKE PASS\n", child, tracer);
    result = 0;
cleanup:
    if (result) perror("stopped-owner-smoke");
    if (child > 0) kill(child, SIGKILL);
    if (owner > 0) {
        kill(owner, SIGKILL);
        while (waitpid(owner, &status, __WALL) == owner && WIFSTOPPED(status))
            ptrace(PTRACE_CONT, owner, NULL, (void *)(uintptr_t)SIGKILL);
    }
    if (fd >= 0) close(fd);
    close(channel[0]);
    if (!result) puts("policy-stopped-owner-smoke: PASS");
    return result;
}
