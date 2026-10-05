#ifndef IDA_JOINT_SHARED_EVENT_READER_H
#define IDA_JOINT_SHARED_EVENT_READER_H

#include "joint_debug_abi.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Multiple linux_server processes can inherit one mmap of the policy ring.
 * Copy before committing so the kernel producer cannot reuse the slot, then
 * claim the consumer index with CAS.  A losing reader discards its copy and
 * retries at the new index instead of delivering the same event twice.
 */
static inline bool ida_vtdbg_shared_ring_next(
    struct ida_vtdbg_shared_ring *ring,
    struct ida_vtdbg_policy_event *event)
{
    uint64_t producer;
    uint64_t consumer;

    if (ring == NULL || event == NULL || ring->slot_count == 0 ||
        ring->slot_count > IDA_VTDBG_SHARED_RING_SLOTS)
        return false;

    for (;;) {
        struct ida_vtdbg_shared_slot *slot;
        uint64_t expected;

        producer = __atomic_load_n(&ring->producer, __ATOMIC_ACQUIRE);
        consumer = __atomic_load_n(&ring->consumer, __ATOMIC_ACQUIRE);
        if (consumer >= producer)
            return false;

        slot = &ring->slots[consumer % ring->slot_count];
        memcpy(event, &slot->event, sizeof(*event));
        expected = consumer;
        if (__atomic_compare_exchange_n(&ring->consumer, &expected,
                                        consumer + 1u, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            return true;
    }
}

#endif
