#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static _Atomic int stop_threads;
static volatile unsigned long parent_counter;
static volatile unsigned long child_counter;

static void *parent_worker(void *opaque)
{
    unsigned long salt = (unsigned long)(uintptr_t)opaque;
    while (!atomic_load_explicit(&stop_threads, memory_order_relaxed)) {
        parent_counter += salt + 1u;
        sched_yield();
    }
    return NULL;
}

static void *child_worker(void *opaque)
{
    unsigned long salt = (unsigned long)(uintptr_t)opaque;
    while (!atomic_load_explicit(&stop_threads, memory_order_relaxed)) {
        child_counter += salt + 1u;
        sched_yield();
    }
    return NULL;
}

static int start_threads(pthread_t *threads, size_t count,
                         void *(*entry)(void *))
{
    for (size_t index = 0; index < count; ++index) {
        if (pthread_create(&threads[index], NULL, entry,
                           (void *)(uintptr_t)(index + 1u)) != 0)
            return -1;
    }
    return 0;
}

int main(void)
{
    pthread_t parent_threads[3];
    pthread_t child_threads[3];
    pid_t child;
    int status;

    (void)prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
    if (start_threads(parent_threads, 3, parent_worker) < 0)
        return 2;
    printf("NESTED_MT_PARENT_READY pid=%ld tgid=%ld\n",
           (long)getpid(), (long)getpid());
    fflush(stdout);
    sleep(1);

    child = fork();
    if (child < 0)
        return 3;
    if (child == 0) {
        atomic_store_explicit(&stop_threads, 0, memory_order_relaxed);
        if (start_threads(child_threads, 3, child_worker) < 0)
            _exit(4);
        printf("NESTED_MT_CHILD_READY pid=%ld ppid=%ld\n",
               (long)getpid(), (long)getppid());
        fflush(stdout);
        sleep(2);
        atomic_store_explicit(&stop_threads, 1, memory_order_relaxed);
        for (size_t index = 0; index < 3; ++index)
            pthread_join(child_threads[index], NULL);
        _exit(0);
    }

    if (waitpid(child, &status, 0) != child)
        return 5;
    atomic_store_explicit(&stop_threads, 1, memory_order_relaxed);
    for (size_t index = 0; index < 3; ++index)
        pthread_join(parent_threads[index], NULL);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return 6;
    printf("NESTED_MT_DONE parent_counter=%lu child_counter=%lu\n",
           parent_counter, child_counter);
    return 0;
}
