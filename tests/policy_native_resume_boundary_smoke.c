#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "joint_debug_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

extern long boundary_ptrace(long request, long child, void *address, void *data);
extern char boundary_ptrace_return, boundary_child_start;
__asm__(
    ".text\n.global boundary_ptrace,boundary_ptrace_return\n"
    "boundary_ptrace:\n endbr64\n mov %rcx,%r10\n mov $101,%eax\n syscall\n"
    "boundary_ptrace_return:\n ret\n"
    ".global boundary_child_run,boundary_child_start\n"
    "boundary_child_run:\n endbr64\n int3\n"
    "boundary_child_start:\n nop\n nop\n ret\n");
extern void boundary_child_run(void);

static int stop_owner(pid_t owner, int signal_number)
{
    int status;
    for (;;) {
        if (waitpid(owner, &status, __WALL) != owner) return -1;
        if (!WIFSTOPPED(status)) {
            fprintf(stderr, "boundary owner exited status=0x%x\n", status);
            return -1;
        }
        if (WSTOPSIG(status) == signal_number) return 0;
        if (WSTOPSIG(status) != SIGCHLD || ptrace(PTRACE_CONT, owner, NULL, NULL)) return -1;
    }
}

static int run_once(void)
{
    int info_pipe[2], gate[2], status, fd = -1, result = 1;
    pid_t owner = -1, child = -1;
    if (pipe(info_pipe) || pipe(gate)) return 2;
    owner = fork();
    if (owner == 0) {
        close(info_pipe[0]); close(gate[1]);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(30);
        child = fork();
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(31);
            boundary_child_run();
            _exit(37);
        }
        if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) _exit(32);
        if (write(info_pipe[1], &child, sizeof(child)) != sizeof(child)) _exit(33);
        raise(SIGSTOP);
        int own_fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
        struct ida_vtdbg_ptrace_command old = {.abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (uint32_t)getpid()};
        if (ioctl(own_fd, IDA_VTDBG_IOC_NEXT_COMMAND, &old)) _exit(34);
        long native = boundary_ptrace(old.request, child, NULL, NULL);
        /* The controller's BP stops us BEFORE this callback executes. */
        old.result = native;
        errno = 0;
        if (ioctl(own_fd, IDA_VTDBG_IOC_COMPLETE_COMMAND, &old) != -1 || errno != EALREADY)
            _exit(35);
        struct ida_vtdbg_ptrace_command fresh = {.abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (uint32_t)getpid()};
        if (ioctl(own_fd, IDA_VTDBG_IOC_NEXT_COMMAND, &fresh) || fresh.sequence <= old.sequence)
            _exit(36);
        struct user_regs_struct regs;
        fresh.result = ptrace(PTRACE_GETREGS, child, NULL, &regs);
        fresh.error = fresh.result ? (uint32_t)errno : 0;
        fresh.payload_len = fresh.result ? 0 : sizeof(regs);
        memcpy(fresh.payload, &regs, fresh.payload_len);
        if (ioctl(own_fd, IDA_VTDBG_IOC_COMPLETE_COMMAND, &fresh)) _exit(38);
        int ack = EALREADY;
        if (write(info_pipe[1], &ack, sizeof(ack)) != sizeof(ack)) _exit(39);
        raise(SIGSTOP);
        char marker;
        if (read(gate[0], &marker, 1) != 1) _exit(40);
        _exit(0);
    }
    close(info_pipe[1]); close(gate[0]);
    printf("boundary stage=initial_owner_stop owner=%d\n", owner);
    if (owner < 0 || stop_owner(owner, SIGSTOP)) goto cleanup;
    if (read(info_pipe[0], &child, sizeof(child)) != sizeof(child)) goto cleanup;
    printf("boundary stage=submit child=%d\n", child);
    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    struct ida_vtdbg_policy_session session = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS};
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session)) goto cleanup;
    struct ida_vtdbg_ptrace_command action = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .pid = (uint32_t)child,
        .request = PTRACE_SINGLESTEP, .flags = IDA_VTDBG_COMMAND_F_NATIVE_RESUME};
    if (ioctl(fd, IDA_VTDBG_IOC_SUBMIT_COMMAND, &action)) goto cleanup;
    errno = 0;
    uintptr_t address = (uintptr_t)&boundary_ptrace_return;
    long original = ptrace(PTRACE_PEEKDATA, owner, (void *)address, NULL);
    if ((original == -1 && errno) || ptrace(PTRACE_POKEDATA, owner,
        (void *)address, (void *)((original & ~0xffUL) | 0xccUL))) goto cleanup;
    if (ptrace(PTRACE_CONT, owner, NULL, NULL) || stop_owner(owner, SIGTRAP)) goto cleanup;
    puts("boundary stage=owner_return_bp");
    struct user_regs_struct parent_regs;
    if (ptrace(PTRACE_GETREGS, owner, NULL, &parent_regs) || parent_regs.rip != address + 1)
        goto cleanup;
    if (ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, &action) || action.result || action.error ||
        action.payload_len) goto cleanup;
    puts("boundary stage=kernel_resume_result");
    struct user_regs_struct child_regs;
    struct ida_vtdbg_ptrace_command direct = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .pid = (uint32_t)child,
        .request = PTRACE_GETREGS, .data = (uintptr_t)&child_regs};
    /* A completed resume syscall means the child was made runnable, NOT
     * that it has executed its instruction and scheduled out at the next
     * stop. Ask actual saved-state readiness until the kernel confirms it;
     * never guess a delay between the independent parent/child tasks. */
    int query_ok = 0;
    for (unsigned int n = 0; n < 100000; ++n) {
        int queried = ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &direct);
        if (!queried && !direct.result) { query_ok = 1; break; }
        int query_error = queried ? errno : (int)direct.error;
        if (query_error != EAGAIN) {
            fprintf(stderr, "boundary GETREGS result=%lld error=%d\n",
                    (long long)direct.result, query_error);
            goto cleanup;
        }
        sched_yield();
    }
    if (!query_ok || child_regs.rip != (uintptr_t)&boundary_child_start + 1) {
        fprintf(stderr, "boundary actual child stop ready=%d rip=0x%llx expected=0x%llx\n",
                query_ok, (unsigned long long)child_regs.rip,
                (unsigned long long)(uintptr_t)&boundary_child_start + 1);
        goto cleanup;
    }
    struct ida_vtdbg_ptrace_command fresh = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .pid = (uint32_t)child, .request = PTRACE_GETREGS};
    if (ioctl(fd, IDA_VTDBG_IOC_SUBMIT_COMMAND, &fresh)) goto cleanup;
    parent_regs.rip = address;
    if (ptrace(PTRACE_POKEDATA, owner, (void *)address, (void *)original) ||
        ptrace(PTRACE_SETREGS, owner, NULL, &parent_regs) ||
        ptrace(PTRACE_CONT, owner, NULL, NULL)) goto cleanup;
    puts("boundary stage=old_callback_resume");
    if (stop_owner(owner, SIGSTOP)) goto cleanup;
    int ack = 0;
    if (read(info_pipe[0], &ack, sizeof(ack)) != sizeof(ack) || ack != EALREADY ||
        ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, &fresh) || fresh.result ||
        fresh.payload_len != sizeof(child_regs)) goto cleanup;
    struct user_regs_struct reply;
    memcpy(&reply, fresh.payload, sizeof(reply));
    if (reply.rip != child_regs.rip) goto cleanup;
    puts("native-resume-boundary: real syscall completed before owner user-BP; stale COMPLETE=EALREADY; newer sequence intact");
    result = 0;
cleanup:
    if (result) perror("native-resume-boundary");
    if (child > 0) kill(child, SIGKILL);
    if (owner > 0) {
        kill(owner, SIGKILL);
        while (waitpid(owner, &status, __WALL) == owner && WIFSTOPPED(status))
            ptrace(PTRACE_CONT, owner, NULL, (void *)(uintptr_t)SIGKILL);
    }
    if (fd >= 0) close(fd);
    close(info_pipe[0]); close(gate[1]);
    return result;
}

int main(void)
{
    setbuf(stdout, NULL);
    alarm(25); /* only a failure bound; all synchronization uses actual stops/pipes */
    for (int n = 0; n < 20; ++n) if (run_once()) return 10;
    puts("policy-native-resume-boundary-smoke: 20/20 PASS");
    return 0;
}
