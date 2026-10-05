/* Native ptrace harness for testing the Linux server shim without IDA. */
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    pid_t child;
    int status;
    int gate[2];
    if (argc < 2) {
        fprintf(stderr, "usage: %s TARGET [ARGS...]\n", argv[0]);
        return 2;
    }
    if (pipe(gate) < 0) {
        perror("pipe");
        return 1;
    }
    child = fork();
    if (child < 0) {
        perror("fork");
        close(gate[0]);
        close(gate[1]);
        return 1;
    }
    if (child == 0) {
        char release;
        close(gate[1]);
        if (read(gate[0], &release, 1) != 1)
            _exit(126);
        close(gate[0]);
        execv(argv[1], argv + 1);
        perror("execv");
        _exit(127);
    }
    close(gate[0]);

    if (ptrace(PTRACE_SEIZE, child, NULL,
               (void *)(uintptr_t)(PTRACE_O_TRACEEXEC |
                                   PTRACE_O_TRACECLONE |
                                   PTRACE_O_TRACESYSGOOD)) < 0) {
        perror("PTRACE_SEIZE");
        (void)kill(child, SIGKILL);
        return 1;
    }
    if (ptrace(PTRACE_INTERRUPT, child, NULL, NULL) < 0 ||
        waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) {
        perror("PTRACE_INTERRUPT/waitpid");
        close(gate[1]);
        (void)kill(child, SIGKILL);
        return 1;
    }
    if (ptrace(PTRACE_GETREGS, child, NULL, NULL) < 0) {
        /* Ensure the interposer classifies/returns normal RPC-style operations. */
        if (errno != EFAULT) {
            perror("PTRACE_GETREGS");
            (void)kill(child, SIGKILL);
            return 1;
        }
    }
    char release = 1;
    if (write(gate[1], &release, 1) != 1) {
        perror("release target");
        close(gate[1]);
        (void)kill(child, SIGKILL);
        return 1;
    }
    close(gate[1]);
    if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) {
        perror("PTRACE_SYSCALL");
        (void)kill(child, SIGKILL);
        return 1;
    }

    for (;;) {
        if (waitpid(child, &status, __WALL) != child) {
            if (errno == EINTR)
                continue;
            perror("waitpid");
            (void)kill(child, SIGKILL);
            return 1;
        }
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        if (WIFSIGNALED(status))
            return 128 + WTERMSIG(status);
        if (!WIFSTOPPED(status))
            continue;

        int signal_number = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;
        int deliver = signal_number;
        /* SIGTRAP|0x80 is the synthetic syscall-stop signal, not a real
         * signal to reinject into the tracee. */
        if (signal_number == (SIGTRAP | 0x80) ||
            (signal_number == SIGTRAP && event != 0))
            deliver = 0;
        if (ptrace(PTRACE_SYSCALL, child, NULL,
                   (void *)(intptr_t)deliver) < 0 && errno != ESRCH) {
            perror("PTRACE_SYSCALL");
            (void)kill(child, SIGKILL);
            return 1;
        }
    }
}
