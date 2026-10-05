#include "joint_debug_abi.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void)
{
    int fd;
    pid_t pid = getpid();
    struct ida_vtdbg_policy_session session = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (unsigned int)pid,
        .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
    };
    struct ida_vtdbg_policy_syscall query = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (unsigned int)pid,
        .syscall_nr = 101,
        .args = {0},
    };
    struct ida_vtdbg_policy_buffer buffer = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (unsigned int)pid,
    };

    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open policy device");
        return 1;
    }
    query.args[0] = 0;
    if (ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session) < 0) {
        perror("register");
        close(fd);
        return 2;
    }
    if (ioctl(fd, IDA_VTDBG_IOC_QUERY_SYSCALL, &query) < 0) {
        perror("query");
        close(fd);
        return 3;
    }
    memcpy(buffer.data, "TracerPid: 123\n", 15);
    buffer.length = 15;
    if (ioctl(fd, IDA_VTDBG_IOC_FILTER_BUFFER, &buffer) < 0) {
        perror("filter");
        close(fd);
        return 4;
    }
    if (buffer.changed == 0 || strstr((char *)buffer.data, "TracerPid: 000") == NULL) {
        fprintf(stderr, "unexpected filter result changed=%u data=%s\n",
                buffer.changed, buffer.data);
        close(fd);
        return 5;
    }
    if (ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &session) < 0) {
        perror("unregister");
        close(fd);
        return 6;
    }
    close(fd);
    printf("policy-ioctl: query_action=%u filter_changed=%u PASS\n",
           query.action, buffer.changed);
    return 0;
}
