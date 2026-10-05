#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "joint_debug_abi.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

struct query_race {
    int fd, ready_fd;
    pid_t owner, child;
    unsigned int good, rejected;
    int error;
    bool debug_registers;
};

static bool race_debug_registers;

static void *query_until_exit(void *argument)
{
    struct query_race *race = argument;
    struct user_regs_struct regs;
    bool ready = false;
    for (unsigned int n = 0; n < 100000; ++n) {
        struct ida_vtdbg_ptrace_command query = {.abi = IDA_VTDBG_POLICY_ABI,
            .target_pid = (uint32_t)race->owner, .pid = (uint32_t)race->child,
            .request = race->debug_registers ? PTRACE_POKEUSER : PTRACE_GETREGS,
            .data = (uintptr_t)&regs};
        if (race->debug_registers) {
            query.addr = offsetof(struct user, u_debugreg[7]);
            query.data = 0;
            query.value = (n & 1) ? 0x100 : 0x101;
        }
        int reply = ioctl(race->fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &query);
        int error = reply ? errno : query.result < 0 ? (int)query.error : 0;
        if (!error && (race->debug_registers || regs.rip)) {
            ++race->good;
            if (!ready) {
                ready = true;
                if (write(race->ready_fd, "r", 1) != 1) { race->error = EIO; break; }
            }
        } else if (error == ESRCH || error == EPERM) {
            ++race->rejected;
            break;
        } else if (error != EAGAIN) {
            race->error = error ? error : EPROTO;
            break;
        }
    }
    if (!ready) (void)close(race->ready_fd);
    return NULL;
}

static int run_once(void)
{
    int info[2], started[2], fd = -1, status, result = 1;
    pid_t owner = -1, child = -1;
    pthread_t reader;
    bool thread_created = false;
    if (pipe(info) || pipe(started)) return 2;
    owner = fork();
    if (owner == 0) {
        close(info[0]);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(30);
        child = fork();
        if (child == 0) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) _exit(31);
            raise(SIGSTOP);
            _exit(37);
        }
        if (waitpid(child, &status, __WALL) != child || !WIFSTOPPED(status)) _exit(32);
        if (race_debug_registers &&
            (ptrace(PTRACE_POKEUSER, child,
                (void *)offsetof(struct user, u_debugreg[0]), (void *)(uintptr_t)run_once) ||
             ptrace(PTRACE_POKEUSER, child,
                (void *)offsetof(struct user, u_debugreg[7]), (void *)0x100ul))) _exit(34);
        if (write(info[1], &child, sizeof(child)) != sizeof(child)) _exit(33);
        raise(SIGSTOP);
        _exit(0);
    }
    close(info[1]);
    if (owner < 0) goto cleanup;
    while (waitpid(owner, &status, __WALL) == owner) {
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) break;
        if (!WIFSTOPPED(status) || ptrace(PTRACE_CONT, owner, NULL, NULL)) goto cleanup;
    }
    if (read(info[0], &child, sizeof(child)) != sizeof(child)) goto cleanup;
    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    struct ida_vtdbg_policy_session session = {.abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)owner, .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS};
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_REGISTER, &session)) goto cleanup;
    struct query_race race = {.fd = fd, .ready_fd = started[1], .owner = owner, .child = child,
                             .debug_registers = race_debug_registers};
    if (pthread_create(&reader, NULL, query_until_exit, &race)) goto cleanup;
    thread_created = true;
    char marker;
    if (read(started[0], &marker, 1) != 1 || kill(child, SIGKILL)) goto cleanup;
    /* Driver reads race actual fatal wake/stack teardown. No timer or sleep
     * controls which interleaving runs; native task state is authoritative. */
    pthread_join(reader, NULL);
    thread_created = false;
    if (race.error || !race.good || !race.rejected) {
        fprintf(stderr, "stopped-query-exit race good=%u rejected=%u errno=%d\n",
                race.good, race.rejected, race.error);
        goto cleanup;
    }
    result = 0;
cleanup:
    if (child > 0) kill(child, SIGKILL);
    if (thread_created) pthread_join(reader, NULL);
    if (owner > 0) {
        kill(owner, SIGKILL);
        while (waitpid(owner, &status, __WALL) == owner && WIFSTOPPED(status))
            ptrace(PTRACE_CONT, owner, NULL, (void *)(uintptr_t)SIGKILL);
    }
    if (fd >= 0) close(fd);
    close(info[0]); close(started[0]); close(started[1]);
    return result;
}

int main(int argc, char **argv)
{
    race_debug_registers = argc == 2 && !strcmp(argv[1], "--debug-registers");
    if (argc > 2 || (argc == 2 && !race_debug_registers)) return 2;
    alarm(30); /* failure bound only */
    for (int n = 0; n < 128; ++n) if (run_once()) return 10;
    puts(race_debug_registers
        ? "policy-stopped-debugreg-exit-race-smoke: 128/128 PASS (native DR7 update vs SIGKILL/fatal unfreeze)"
        : "policy-stopped-query-exit-race-smoke: 128/128 PASS (live GETREGS vs SIGKILL/stack teardown)");
    return 0;
}
