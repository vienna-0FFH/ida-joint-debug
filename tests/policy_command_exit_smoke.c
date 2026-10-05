#define _GNU_SOURCE
#include "joint_debug_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (unsigned)getpid(),
        .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
    };
    int fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    alarm(15); /* failure budget, never protocol synchronization */
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session)) return 2;
    for (int inflight = 0; inflight < 2; ++inflight) {
        int gate[2], status;
        if (pipe(gate)) return 3;
        pid_t child = fork();
        if (child < 0) return 4;
        if (!child) {
            char marker;
            close(fd);
            close(gate[1]);
            (void)read(gate[0], &marker, 1);
            _exit(37);
        }
        close(gate[0]);
        struct ida_vtdbg_ptrace_command command = {
            .abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (unsigned)getpid(),
            .pid = (unsigned)child,
            .request = PTRACE_GETREGS,
        };
        if (ioctl(fd, IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND, &command)) return 5;
        if (inflight) {
            struct ida_vtdbg_ptrace_command fetched = {
                .abi = IDA_VTDBG_POLICY_ABI,
                .target_pid = (unsigned)getpid(),
            };
            if (ioctl(fd, IDA_VTDBG_IOC_NEXT_COMMAND, &fetched) ||
                fetched.sequence != command.sequence) return 6;
        }
        if (write(gate[1], "x", 1) != 1) return 7;
        close(gate[1]);
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 37) return 8;
        /* waitpid confirms actual exit, so cancellation must already exist. */
        if (ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, &command) ||
            command.result != -1 || command.error != ESRCH || command.payload_len)
            return 9;
        errno = 0;
        if (ioctl(fd, IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND, &command) != -1 ||
            errno != ESRCH) return 10;
        errno = 0;
        if (ioctl(fd, IDA_VTDBG_IOC_COMPLETE_COMMAND, &command) != -1 ||
            errno != EINVAL) return 11;
        printf("mailbox-exit: %s cancelled, dead target rejected, stale completion rejected\n",
               inflight ? "INFLIGHT" : "PENDING");
    }
    if (ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session)) return 12;
    close(fd);
    puts("policy-command-exit-smoke: PASS");
    return 0;
}
