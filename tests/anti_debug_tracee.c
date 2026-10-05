#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>

static volatile sig_atomic_t trap_seen;

static void trap_handler(int signal_number)
{
    if (signal_number == SIGTRAP) {
        trap_seen = 1;
    }
}

static int parse_tracer_pid(const char *buffer, ssize_t length)
{
    const char *field = buffer;
    const char *end = buffer + length;
    while (field < end) {
        const char *line_end = memchr(field, '\n', (size_t)(end - field));
        size_t line_length = line_end == NULL ? (size_t)(end - field)
                                              : (size_t)(line_end - field);
        if (line_length >= 10 && strncmp(field, "TracerPid:", 10) == 0)
            return atoi(field + 10);
        if (line_end == NULL)
            break;
        field = line_end + 1;
    }
    errno = ENOENT;
    return -1;
}

static int check_tracer_pid_readv(void)
{
    int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    char buffer[4096];
    struct iovec vector = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer) - 1,
    };
    ssize_t length;

    if (fd < 0)
        return -1;
    length = syscall(SYS_readv, fd, &vector, 1);
    close(fd);
    if (length <= 0)
        return -1;
    buffer[length] = '\0';
    return parse_tracer_pid(buffer, length);
}

static int check_task_tracer_pid(void)
{
    char path[128];
    (void)snprintf(path, sizeof(path), "/proc/self/task/%ld/status",
                   (long)syscall(SYS_gettid));
    FILE *file = fopen(path, "r");
    char line[256];
    if (file == NULL) {
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer = atoi(line + 10);
            fclose(file);
            return tracer;
        }
    }
    fclose(file);
    return -1;
}

int main(void)
{
    if (getenv("IDA_VTDBG_COMPAT") != NULL) {
        puts("ANTI_DEBUG=shim-config-leaked-into-target");
        return 17;
    }
    const char *preload = getenv("LD_PRELOAD");
    if (preload != NULL && (strstr(preload, "libida_joint_shim.so") != NULL ||
                            strstr(preload, "libida_vtdbg_shim.so") != NULL)) {
        puts("ANTI_DEBUG=shim-preload-leaked-into-target");
        return 18;
    }
    errno = 0;
    long result = syscall(SYS_ptrace, PTRACE_TRACEME, 0, NULL, NULL);
    if (result < 0) {
        printf("ANTI_DEBUG=ptrace-detected errno=%d\n", errno);
        return 10;
    }

    int tracer = check_tracer_pid_readv();
    if (tracer < 0) {
        perror("TracerPid");
        return 11;
    }
    if (tracer != 0) {
        printf("ANTI_DEBUG=tracerpid-detected value=%d\n", tracer);
        return 12;
    }
    errno = 0;
    int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
    if (dumpable != 1) {
        printf("ANTI_DEBUG=dumpable-detected value=%d errno=%d\n", dumpable,
               errno);
        return 16;
    }
    tracer = check_task_tracer_pid();
    if (tracer != 0) {
        printf("ANTI_DEBUG=task-tracerpid-detected value=%d\n", tracer);
        return 13;
    }
    if (signal(SIGTRAP, trap_handler) == SIG_ERR) {
        perror("signal");
        return 14;
    }
    __asm__ volatile("int3");
    if (!trap_seen) {
        puts("ANTI_DEBUG=int3-handler-missed");
        return 15;
    }
    puts("ANTI_DEBUG=passed");
    return 0;
}
