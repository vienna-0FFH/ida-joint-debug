#ifndef IDA_JOINT_DEBUG_ABI_H
#define IDA_JOINT_DEBUG_ABI_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define IDA_VTDBG_POLICY_DEVICE "vtdbg_policy"
#define IDA_VTDBG_POLICY_ABI 1u
#define IDA_VTDBG_POLICY_MAX_BUFFER 512u

/*
 * A file descriptor opened on /dev/vtdbg_policy owns one shared event page.
 * Control and compatibility decisions continue to use ioctl(2), while the
 * high-rate fork/clone notifications are published into this page.  The
 * layout is deliberately fixed-width and independent of the kernel's
 * PAGE_SIZE so a 64-bit userspace client can validate it before consuming it.
 */
#define IDA_VTDBG_SHARED_MAGIC 0x56545348u /* "VTSH" */
#define IDA_VTDBG_SHARED_VERSION 1u
#define IDA_VTDBG_SHARED_BYTES 4096u
#define IDA_VTDBG_SHARED_RING_SLOTS 32u

#define IDA_VTDBG_POLICY_F_PTRACE_TRACEME (1u << 0)
#define IDA_VTDBG_POLICY_F_TRACER_PID (1u << 1)
#define IDA_VTDBG_POLICY_F_DUMPABLE (1u << 2)
#define IDA_VTDBG_POLICY_DEFAULT_FLAGS \
    (IDA_VTDBG_POLICY_F_PTRACE_TRACEME | IDA_VTDBG_POLICY_F_TRACER_PID | \
     IDA_VTDBG_POLICY_F_DUMPABLE)
/* Registration-only option: let linux_server complete its own trace-fork
 * capability probe before the driver arms process-tree ptrace options. */
#define IDA_VTDBG_POLICY_F_DEFER_TREE_ARM (1u << 31)
/* Event subscription only: retain this reader on the root tree even if an
 * exec closes the transient owner's fd and recreates its policy session. */
#define IDA_VTDBG_SUBSCRIBE_F_PERSISTENT_TREE (1u << 30)

enum ida_vtdbg_policy_action {
    IDA_VTDBG_ACTION_PASS = 0,
    IDA_VTDBG_ACTION_EMULATE = 1,
};

struct ida_vtdbg_policy_session {
    __u32 abi;
    __u32 target_pid;
    __u32 flags;
    __u32 reserved;
};

struct ida_vtdbg_policy_syscall {
    __u32 abi;
    __u32 target_pid;
    __u64 syscall_nr;
    __u64 args[6];
    __s64 result;
    __u32 action;
    __u32 reserved;
};

struct ida_vtdbg_policy_buffer {
    __u32 abi;
    __u32 target_pid;
    __u32 length;
    __u32 changed;
    __u8 data[IDA_VTDBG_POLICY_MAX_BUFFER];
};

#define IDA_VTDBG_IOC_REGISTER \
    _IOW('V', 0x40, struct ida_vtdbg_policy_session)
#define IDA_VTDBG_IOC_UNREGISTER \
    _IOW('V', 0x41, struct ida_vtdbg_policy_session)
#define IDA_VTDBG_IOC_QUERY_SYSCALL \
    _IOWR('V', 0x42, struct ida_vtdbg_policy_syscall)
#define IDA_VTDBG_IOC_FILTER_BUFFER \
    _IOWR('V', 0x43, struct ida_vtdbg_policy_buffer)

/* Kernel-assisted nested-debug event stream.  The event stream is
 * intentionally orthogonal to ptrace ownership: it records process-tree
 * changes from the scheduler fork tracepoint without making linux_server's
 * wait/reaper thread consume a second wait status. */
#define IDA_VTDBG_EVENT_F_NONBLOCK (1u << 0)
#define IDA_VTDBG_EVENT_F_ANY_TARGET (1u << 1)
#define IDA_VTDBG_EVENT_F_INITIAL_STOP (1u << 2)
/* A parent-owned child stop created by the debugger's protocol-step observer,
 * not by the target's own INT3 dispatcher. */
#define IDA_VTDBG_EVENT_F_SYNTHETIC_STEP (1u << 3)
#define IDA_VTDBG_EVENT_F_EXCEPTION_RESUME (1u << 4)
/* Legacy flag for TRACEME syscall metadata. It does not represent a wait
 * status: PTRACE_TRACEME itself neither stops the tracee nor emits SIGTRAP. */
#define IDA_VTDBG_EVENT_F_TRACEME_STOP (1u << 5)
/* The real target parent is consuming this protocol status. It is audit
 * only, not a new server-held stop; do not send ptrace queries/replay for it. */
#define IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED (1u << 6)
#define IDA_VTDBG_EVENT_F_KERNEL_LIFECYCLE (1u << 7)

enum ida_vtdbg_policy_event_type {
    IDA_VTDBG_EVENT_NONE = 0,
    IDA_VTDBG_EVENT_FORK = 1,
    IDA_VTDBG_EVENT_EXIT = 2,
    IDA_VTDBG_EVENT_STOP = 3,
    IDA_VTDBG_EVENT_TRACEME_METADATA = 4,
};

struct ida_vtdbg_policy_event {
    __u32 abi;
    __u32 target_pid;
    __u32 type;
    __u32 flags;
    __u32 pid;
    __u32 tgid;
    __u32 parent_pid;
    __u32 parent_tgid;
    __u32 status;
    __u32 reserved;
    __u64 sequence;
};

struct ida_vtdbg_shared_slot {
    __u64 sequence;
    struct ida_vtdbg_policy_event event;
};

struct ida_vtdbg_shared_ring {
    __u32 magic;
    __u32 version;
    __u32 header_size;
    __u32 slot_size;
    __u32 slot_count;
    __u32 reserved0[3];
    __u64 producer;
    __u64 consumer;
    __u64 dropped;
    __u64 generation;
    struct ida_vtdbg_shared_slot slots[IDA_VTDBG_SHARED_RING_SLOTS];
};

#define IDA_VTDBG_IOC_SHARED_RESET \
    _IO('V', 0x4a)
#define IDA_VTDBG_IOC_REGISTER_TRACER \
    _IOW('V', 0x4b, struct ida_vtdbg_policy_session)

#define IDA_VTDBG_IOC_NEXT_EVENT \
    _IOWR('V', 0x44, struct ida_vtdbg_policy_event)
#define IDA_VTDBG_IOC_REPORT_EVENT \
    _IOW('V', 0x45, struct ida_vtdbg_policy_event)

#define IDA_VTDBG_COMMAND_PAYLOAD_MAX 1024u
/* Pure owner-executed resume: publish its native syscall result even if the
 * owner hits a user breakpoint before returning to the mailbox callback. */
#define IDA_VTDBG_COMMAND_F_NATIVE_RESUME (1u << 21)
#define IDA_VTDBG_COMMAND_SYNC_BREAKPOINTS 0x56540001u

struct ida_vtdbg_ptrace_command {
    __u32 abi;
    __u32 target_pid;
    __u32 request;
    __u32 flags;
    __u32 pid;
    __u32 error;
    __s64 result;
    __u64 addr;
    __u64 data;
    __u64 length;
    __u64 value;
    __u64 sequence;
    __u32 payload_len;
    __u32 reserved;
    __u8 payload[IDA_VTDBG_COMMAND_PAYLOAD_MAX];
};

#define IDA_VTDBG_IOC_SUBMIT_COMMAND \
    _IOWR('V', 0x46, struct ida_vtdbg_ptrace_command)
#define IDA_VTDBG_IOC_NEXT_COMMAND \
    _IOWR('V', 0x47, struct ida_vtdbg_ptrace_command)
#define IDA_VTDBG_IOC_COMPLETE_COMMAND \
    _IOW('V', 0x48, struct ida_vtdbg_ptrace_command)
#define IDA_VTDBG_IOC_GET_RESPONSE \
    _IOWR('V', 0x49, struct ida_vtdbg_ptrace_command)
#define IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND \
    _IOWR('V', 0x4c, struct ida_vtdbg_ptrace_command)
#define IDA_VTDBG_IOC_SUBSCRIBE_EVENTS \
    _IOW('V', 0x4d, struct ida_vtdbg_policy_session)

/* One word of a registered debug-session address space. This is for the
 * real parent, which must stay runnable while it services child ptrace RPCs
 * and therefore cannot accept ordinary PTRACE_POKEDATA at that moment. */
struct ida_vtdbg_memory_word {
    __u32 abi;
    __u32 target_pid;
    __u32 flags;
    __u32 reserved;
    __u64 addr;
    __u64 value;
};
#define IDA_VTDBG_MEMORY_F_WRITE 1u
#define IDA_VTDBG_IOC_MEMORY_WORD \
    _IOWR('V', 0x4e, struct ida_vtdbg_memory_word)

/* Query an original parent's stopped tracee without altering its ptracer.
 * READ/WRITE bridge requests require a native-stopped owner OR an owner-
 * reported held child with no concurrent state-changing mailbox operation.
 * Metadata-only synchronization may be in flight. The bridge validates
 * stopped/off-CPU/lifecycle state under siglock and keeps the real ptracer. */
#define IDA_VTDBG_NESTED_QUERY_STOP 0xffffffffu
#define IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE \
    _IOWR('V', 0x4f, struct ida_vtdbg_ptrace_command)

/* Logical blocking wait frame, distinct from the owner's physical mailbox
 * execution context. The entry registers are captured before an interposer
 * prologue. Only the owner may ENTER/LEAVE; readers cannot change task regs.
 * QUERY/LEAVE use a pinned PID identity and a per-session monotonic sequence.
 * The x86-64 GPR layout is Linux user_regs_struct (27 fixed-width words).
 */
#define IDA_VTDBG_OWNER_WAIT_QUERY 0u
#define IDA_VTDBG_OWNER_WAIT_ENTER 1u
#define IDA_VTDBG_OWNER_WAIT_LEAVE 2u
#define IDA_VTDBG_OWNER_WAIT_ACTIVE 1u
#define IDA_VTDBG_OWNER_WAIT_GPR_WORDS 27u
struct ida_vtdbg_owner_wait_context {
    __u32 abi;
    __u32 target_pid;
    __u32 owner_tid;
    __u32 operation;
    __u32 state;
    __u32 kind;
    __u64 sequence;
    __u64 caller_ip;
    __u64 regs[IDA_VTDBG_OWNER_WAIT_GPR_WORDS];
};
#define IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT \
    _IOWR('V', 0x50, struct ida_vtdbg_owner_wait_context)

#endif
