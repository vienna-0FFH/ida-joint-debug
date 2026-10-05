#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

static void child_recovery(void)
{
    write(STDOUT_FILENO, "EXCEPTION_RECOVERED\n", 20);
    _exit(42);
}

static void child_fault(void)
{
    volatile uint32_t *bad = (volatile uint32_t *)(uintptr_t)0;
    *bad = 0x56445442u;
}

int main(void)
{
    pid_t child = fork();
    int status = 0;

    if (child < 0)
        return 2;
    if (child == 0) {
        /* The parent-owned shim supplies the real TRACEME/initial stop before
         * returning from fork.  The child then executes a genuine SIGSEGV. */
        child_fault();
        _exit(3);
    }

    for (;;) {
        pid_t waited = waitpid(child, &status, __WALL);
        if (waited < 0) {
            if (errno == EINTR)
                continue;
            return 4;
        }
        if (!WIFSTOPPED(status)) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 42)
                return 0;
            return 5;
        }
        if (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTRAP) {
            if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0)
                return 6;
            continue;
        }
        if (WSTOPSIG(status) == SIGSEGV) {
            struct user_regs_struct regs;

            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0)
                return 7;
            regs.rip = (uintptr_t)&child_recovery;
            if (ptrace(PTRACE_SETREGS, child, NULL, &regs) < 0)
                return 8;
            if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0)
                return 9;
            continue;
        }
        if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0)
            return 10;
    }
}
