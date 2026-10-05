/* Real parent ptrace fixture: a call contains two program-owned INT3s and
 * a raw syscall, then RETURNS. The parent rejects any extra debug stop. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

extern long fixture_run(void);
extern char fixture_after_protocol_1, fixture_after_protocol_2;

__asm__(
    ".text\n"
    ".global fixture_run,fixture_callsite,fixture_call_return\n"
    ".global fixture_inside,fixture_syscall,fixture_after_syscall\n"
    ".global fixture_after_protocol_1,fixture_after_protocol_2\n"
    ".global fixture_hardware_unused\n"
    "fixture_run:\n push %rbp\n mov %rsp,%rbp\n"
    "fixture_callsite:\n call fixture_callee\n"
    "fixture_call_return:\n pop %rbp\n ret\n"
    "fixture_callee:\n push %rbp\n mov %rsp,%rbp\n"
    "fixture_inside:\n nop\n nop\n nop\n nop\n int3\n"
    "fixture_after_protocol_1:\n mov $39,%eax\n"
    "fixture_syscall:\n syscall\n"
    "fixture_after_syscall:\n nop\n int3\n"
    "fixture_after_protocol_2:\n mov $0x123,%eax\n pop %rbp\n ret\n"
    "fixture_hardware_unused:\n nop\n nop\n nop\n nop\n ret\n");

int main(void)
{
    pid_t child = fork();
    int status, protocol_count = 0;
    if (child < 0) return 2;
    if (child == 0) {
        /* Under VTDBG the shim already established this same real parent
         * owner. Native execution uses the normal TRACEME/initial SIGSTOP. */
        (void)ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        _exit(fixture_run() == 0x123 ? 37 : 38);
    }
    for (;;) {
        pid_t waited = waitpid(child, &status, __WALL);
        if (waited < 0 && errno == EINTR) continue;
        if (waited != child) return 3;
        if (WIFEXITED(status)) {
            int accepted = WEXITSTATUS(status) == 37 && protocol_count == 2;
            printf("CALL_FIXTURE_%s child_exit=%d program_protocols=%d\n",
                   accepted ? "PASS" : "FAIL", WEXITSTATUS(status), protocol_count);
            return accepted ? 0 : 4;
        }
        if (!WIFSTOPPED(status)) return 5;
        if (WSTOPSIG(status) == SIGTRAP) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) return 6;
            if (regs.rip != (unsigned long)&fixture_after_protocol_1 &&
                regs.rip != (unsigned long)&fixture_after_protocol_2) {
                printf("CALL_FIXTURE_WRONG_PARENT_EVENT rip=%llx\n", regs.rip);
                return 7;
            }
            ++protocol_count;
        } else if (WSTOPSIG(status) != SIGSTOP) {
            return 8;
        }
        if (ptrace(PTRACE_CONT, child, NULL, NULL) != 0) return 9;
    }
}
