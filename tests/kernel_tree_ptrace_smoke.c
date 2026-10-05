#define _GNU_SOURCE

#include "joint_debug_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static long raw_ptrace(enum __ptrace_request request, pid_t pid, void *addr,
                       void *data)
{
    return syscall(SYS_ptrace, (long)request, (long)pid,
                   (unsigned long)addr, (unsigned long)data);
}

int main(void)
{
    int fd;
    int gate[2];
    pid_t tracee;
    int status;
    int saw_tree_event = 0;
    int tracee_exit = -1;
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)getpid(),
        .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
    };

    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR);
    if (fd < 0) {
        perror("open policy device");
        return 2;
    }
    if (ioctl(fd, IDA_VTDBG_IOC_REGISTER_TRACER, &session) < 0) {
        perror("register tracer");
        return 3;
    }
    if (pipe(gate) < 0) {
        perror("pipe");
        return 4;
    }
    tracee = fork();
    if (tracee < 0) {
        perror("fork tracee");
        return 5;
    }
    if (tracee == 0) {
        char byte;
        pid_t grandchild;

        close(gate[1]);
        if (read(gate[0], &byte, 1) != 1)
            _exit(20);
        close(gate[0]);
        errno = 0;
        if (raw_ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
            _exit(21);
        grandchild = fork();
        if (grandchild < 0)
            _exit(22);
        if (grandchild == 0)
            _exit(0);
        (void)waitpid(grandchild, NULL, 0);
        _exit(0);
    }
    close(gate[0]);
    if (raw_ptrace(PTRACE_SEIZE, tracee, NULL, NULL) < 0 ||
        raw_ptrace(PTRACE_INTERRUPT, tracee, NULL, NULL) < 0 ||
        waitpid(tracee, &status, __WALL) != tracee || !WIFSTOPPED(status)) {
        perror("seize/interrupt");
        return 6;
    }
    if (write(gate[1], "x", 1) != 1) {
        perror("release tracee");
        return 7;
    }
    close(gate[1]);
    if (raw_ptrace(PTRACE_CONT, tracee, NULL, NULL) < 0) {
        perror("continue tracee");
        return 8;
    }

    for (unsigned int pass = 0; pass < 1000 && tracee_exit < 0; ++pass) {
        pid_t stopped = waitpid(-1, &status, __WALL);
        if (stopped < 0) {
            if (errno == EINTR)
                continue;
            perror("waitpid");
            return 9;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (stopped == tracee)
                tracee_exit = WIFEXITED(status) ? WEXITSTATUS(status)
                                                : 128 + WTERMSIG(status);
            continue;
        }
        if (!WIFSTOPPED(status))
            continue;
        if (WSTOPSIG(status) == SIGTRAP &&
            (((unsigned int)status >> 16) == PTRACE_EVENT_FORK ||
             ((unsigned int)status >> 16) == PTRACE_EVENT_CLONE)) {
            unsigned long new_pid = 0;
            if (raw_ptrace(PTRACE_GETEVENTMSG, stopped, NULL, &new_pid) == 0 &&
                new_pid != 0) {
                printf("kernel-tree: event=%u parent=%d child=%lu\n",
                       (unsigned int)status >> 16, stopped, new_pid);
                saw_tree_event = 1;
            }
        }
        if (raw_ptrace(PTRACE_CONT, stopped, NULL, NULL) < 0 && errno != ESRCH) {
            perror("continue stopped task");
            return 10;
        }
    }
    (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session);
    close(fd);
    if (tracee_exit != 0) {
        fprintf(stderr, "kernel-tree: tracee exit=%d (TRACEME was not virtualized)\n",
                tracee_exit);
        return 11;
    }
    if (!saw_tree_event) {
        fputs("kernel-tree: missing normalized tree event\n", stderr);
        return 12;
    }
    puts("kernel-tree-ptrace-smoke: PASS");
    return 0;
}
