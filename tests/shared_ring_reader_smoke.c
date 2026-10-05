#include "shared_event_reader.h"

#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define READER_COUNT 2u
#define EVENT_COUNT 50000u

struct shared_test_state {
    struct ida_vtdbg_shared_ring ring;
    uint32_t readers_ready;
    uint32_t start;
    uint32_t consumed;
    uint32_t seen[EVENT_COUNT + 1u];
};

static bool test_ring_push(struct ida_vtdbg_shared_ring *ring,
                           uint64_t sequence)
{
    uint64_t producer = __atomic_load_n(&ring->producer, __ATOMIC_RELAXED);
    uint64_t consumer = __atomic_load_n(&ring->consumer, __ATOMIC_ACQUIRE);
    struct ida_vtdbg_shared_slot *slot;

    if (producer - consumer >= ring->slot_count)
        return false;
    slot = &ring->slots[producer % ring->slot_count];
    memset(&slot->event, 0, sizeof(slot->event));
    slot->event.abi = IDA_VTDBG_POLICY_ABI;
    slot->event.sequence = sequence;
    slot->event.pid = (uint32_t)sequence;
    slot->sequence = sequence;
    __atomic_store_n(&ring->producer, producer + 1u, __ATOMIC_RELEASE);
    return true;
}

static void reader_main(struct shared_test_state *state)
{
    __atomic_add_fetch(&state->readers_ready, 1u, __ATOMIC_RELEASE);
    while (__atomic_load_n(&state->start, __ATOMIC_ACQUIRE) == 0)
        sched_yield();

    for (;;) {
        struct ida_vtdbg_policy_event event;

        if (ida_vtdbg_shared_ring_next(&state->ring, &event)) {
            if (event.sequence == 0 || event.sequence > EVENT_COUNT)
                _exit(10);
            __atomic_add_fetch(&state->seen[event.sequence], 1u,
                               __ATOMIC_RELAXED);
            __atomic_add_fetch(&state->consumed, 1u, __ATOMIC_RELEASE);
            continue;
        }
        if (__atomic_load_n(&state->consumed, __ATOMIC_ACQUIRE) >=
                EVENT_COUNT &&
            __atomic_load_n(&state->ring.producer, __ATOMIC_ACQUIRE) >=
                EVENT_COUNT)
            break;
        sched_yield();
    }
    _exit(0);
}

int main(void)
{
    struct shared_test_state *state;
    pid_t readers[READER_COUNT];
    unsigned int produced = 0;
    int status;

    alarm(20);
    state = mmap(NULL, sizeof(*state), PROT_READ | PROT_WRITE,
                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (state == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(state, 0, sizeof(*state));
    state->ring.magic = IDA_VTDBG_SHARED_MAGIC;
    state->ring.version = IDA_VTDBG_SHARED_VERSION;
    state->ring.slot_count = IDA_VTDBG_SHARED_RING_SLOTS;

    for (unsigned int index = 0; index < READER_COUNT; ++index) {
        readers[index] = fork();
        if (readers[index] < 0) {
            perror("fork");
            return 1;
        }
        if (readers[index] == 0)
            reader_main(state);
    }

    while (__atomic_load_n(&state->readers_ready, __ATOMIC_ACQUIRE) !=
           READER_COUNT)
        sched_yield();
    __atomic_store_n(&state->start, 1u, __ATOMIC_RELEASE);

    while (produced < EVENT_COUNT) {
        if (test_ring_push(&state->ring, (uint64_t)produced + 1u))
            ++produced;
        else
            sched_yield();
    }

    for (unsigned int index = 0; index < READER_COUNT; ++index) {
        if (waitpid(readers[index], &status, 0) != readers[index] ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            fprintf(stderr, "shared-ring-reader: reader %u failed\n", index);
            return 1;
        }
    }

    for (unsigned int sequence = 1; sequence <= EVENT_COUNT; ++sequence) {
        uint32_t count = __atomic_load_n(&state->seen[sequence],
                                         __ATOMIC_ACQUIRE);
        if (count != 1u) {
            fprintf(stderr,
                    "shared-ring-reader: sequence %u consumed %u times\n",
                    sequence, count);
            return 1;
        }
    }
    if (__atomic_load_n(&state->ring.consumer, __ATOMIC_ACQUIRE) !=
        __atomic_load_n(&state->ring.producer, __ATOMIC_ACQUIRE)) {
        fprintf(stderr, "shared-ring-reader: consumer did not drain ring\n");
        return 1;
    }

    puts("shared-ring-reader: cross-process CAS consumption PASS");
    (void)munmap(state, sizeof(*state));
    return 0;
}
