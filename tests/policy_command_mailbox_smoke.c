#define _GNU_SOURCE

#include "joint_debug_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile unsigned long mailbox_marker = 0x1122334455667788UL;

static long raw_ptrace(enum __ptrace_request request, pid_t pid, void *addr,
                       void *data)
{
    errno = 0;
    return syscall(SYS_ptrace, (long)request, (long)pid,
                   (unsigned long)addr, (unsigned long)data);
}

static int next_command(int fd, pid_t owner,
                        struct ida_vtdbg_ptrace_command *command)
{
    memset(command, 0, sizeof(*command));
    command->abi = IDA_VTDBG_POLICY_ABI;
    command->target_pid = (uint32_t)owner;
    for (unsigned int pass = 0; pass < 2000; ++pass) {
        if (ioctl(fd, IDA_VTDBG_IOC_NEXT_COMMAND, command) == 0)
            return 0;
        if (errno != EAGAIN)
            return -1;
        usleep(1000);
    }
    errno = ETIMEDOUT;
    return -1;
}

static int worker_submit(int fd, pid_t owner, pid_t child, uint32_t request,
                         uint64_t addr, uint64_t expected)
{
    struct ida_vtdbg_ptrace_command command;

    memset(&command, 0, sizeof(command));
    command.abi = IDA_VTDBG_POLICY_ABI;
    command.target_pid = (uint32_t)owner;
    command.request = request;
    command.pid = (uint32_t)child;
    command.addr = addr;
    command.length = request == PTRACE_GETREGS
                         ? sizeof(struct user_regs_struct) : 0;
    if (ioctl(fd, IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND, &command) < 0)
        return -1;
    for (unsigned int pass = 0; pass < 2000; ++pass) {
        if (ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, &command) == 0)
            break;
        if (errno != EAGAIN)
            return -1;
        usleep(1000);
    }
    if (command.result < 0) {
        errno = command.error != 0 ? (int)command.error : EIO;
        return -1;
    }
    if (request == PTRACE_GETREGS) {
        struct user_regs_struct regs;
        if (command.payload_len != sizeof(regs)) {
            errno = EPROTO;
            return -1;
        }
        memcpy(&regs, command.payload, sizeof(regs));
        if (regs.rip == 0 || regs.rsp == 0) {
            errno = EPROTO;
            return -1;
        }
        printf("mailbox: child=%d rip=0x%llx rsp=0x%llx\n", child,
               (unsigned long long)regs.rip,
               (unsigned long long)regs.rsp);
    } else if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKUSER) {
        if ((expected != 0 && command.value != expected) ||
            (expected == 0 && command.value == 0)) {
            fprintf(stderr, "mailbox peek request=%u value=0x%llx expected=0x%llx\n",
                    request, (unsigned long long)command.value,
                    (unsigned long long)expected);
            errno = EPROTO;
            return -1;
        }
        printf("mailbox: peek request=%u value=0x%llx\n", request,
               (unsigned long long)command.value);
    }
    return 0;
}

int main(void)
{
    int fd;
    int ready[2];
    pid_t owner = getpid();
    pid_t child;
    pid_t worker;
    int status;
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner,
        .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
    };

    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session) < 0) {
        perror("register owner");
        return 2;
    }
    if (pipe(ready) < 0)
        return 3;
    child = fork();
    if (child == 0) {
        close(ready[0]);
        close(ready[1]);
        if (raw_ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
            _exit(20);
        raise(SIGSTOP);
        __asm__ volatile("nop; nop; nop" ::: "memory");
        _exit(0);
    }
    if (child < 0)
        return 4;
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status))
        return 5;

    worker = fork();
    if (worker == 0) {
        int worker_fd;
        close(ready[0]);
        worker_fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
        if (worker_fd < 0)
            _exit(30);
        if (write(ready[1], "g", 1) != 1 ||
            worker_submit(worker_fd, owner, child, PTRACE_GETREGS, 0, 0) < 0)
            _exit(31);
        if (write(ready[1], "p", 1) != 1 ||
            worker_submit(worker_fd, owner, child, PTRACE_PEEKDATA,
                          (uint64_t)(uintptr_t)&mailbox_marker,
                          (uint64_t)mailbox_marker) < 0)
            _exit(32);
        if (write(ready[1], "u", 1) != 1 ||
            worker_submit(worker_fd, owner, child, PTRACE_PEEKUSER,
                          offsetof(struct user, regs.rip), 0) < 0)
            _exit(33);
        if (write(ready[1], "s", 1) != 1 ||
            worker_submit(worker_fd, owner, child, PTRACE_SINGLESTEP, 0, 0) < 0)
            _exit(34);
        close(worker_fd);
        _exit(0);
    }
    if (worker < 0)
        return 6;
    close(ready[1]);
    for (unsigned int index = 0; index < 4; ++index) {
        char marker;
        struct ida_vtdbg_ptrace_command command;
        long result;
        struct user_regs_struct regs;
        long peek_value = 0;

        if (read(ready[0], &marker, 1) != 1 ||
            next_command(fd, owner, &command) < 0) {
            perror("next command");
            return 7;
        }
        if (command.request == PTRACE_GETREGS) {
            result = raw_ptrace(PTRACE_GETREGS, child, NULL, &regs);
            command.result = result;
            command.error = result < 0 ? (uint32_t)errno : 0;
            if (result == 0) {
                command.payload_len = sizeof(regs);
                memcpy(command.payload, &regs, sizeof(regs));
            }
        } else if (command.request == PTRACE_SINGLESTEP) {
            result = raw_ptrace(PTRACE_SINGLESTEP, child, NULL, NULL);
            command.result = result;
            command.error = result < 0 ? (uint32_t)errno : 0;
        } else if (command.request == PTRACE_PEEKDATA ||
                   command.request == PTRACE_PEEKUSER) {
            result = raw_ptrace((enum __ptrace_request)command.request, child,
                                (void *)(uintptr_t)command.addr, &peek_value);
            command.result = result;
            command.error = result < 0 ? (uint32_t)errno : 0;
            if (result == 0)
                command.value = (uint64_t)peek_value;
        } else {
            command.result = -1;
            command.error = EINVAL;
        }
        if (ioctl(fd, IDA_VTDBG_IOC_COMPLETE_COMMAND, &command) < 0) {
            perror("complete command");
            return 8;
        }
    }
    if (waitpid(worker, &status, 0) != worker || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0) {
        fprintf(stderr, "mailbox worker failed status=0x%x\n", status);
        return 9;
    }
    if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status) ||
        WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "mailbox single-step stop missing status=0x%x\n",
                status);
        return 10;
    }
    (void)raw_ptrace(PTRACE_KILL, child, NULL, NULL);
    (void)waitpid(child, &status, __WALL);
    (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
    close(fd);
    puts("policy-command-mailbox-smoke: PASS");
    return 0;
}
