#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pid.h>
#include <linux/prctl.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/sched/signal.h>
#include <asm/unistd.h>
#include <linux/wait.h>
#include <linux/kprobes.h>
#include <linux/rcupdate.h>
#include <linux/mm.h>
#include <linux/poll.h>
#include <linux/refcount.h>
#include <linux/smp.h>
#include <linux/ktime.h>
#include <linux/vmalloc.h>
#include <linux/regset.h>
#include <linux/elf.h>
#include <asm/user.h>
#include <asm/debugreg.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/uio.h>

#include "joint_debug_abi.h"

#define IDA_VTDBG_EVENT_QUEUE_MAX 256u
#define IDA_VTDBG_READER_TASKS_MAX 512u

struct ida_vtdbg_reader_task {
    struct pid *pid;
    u32 tgid;
    u32 parent_pid;
    u32 parent_tgid;
    bool exit_reported;
};

struct ida_vtdbg_channel {
    void *memory;
    struct ida_vtdbg_shared_ring *ring;
    spinlock_t lock;
    wait_queue_head_t wait;
    refcount_t references;
};

/* A tracer process and the process that owns the child-trace control fd can
 * consume the same kernel event stream independently.  Each subscriber has
 * its own mmap-backed channel/cursor; polling by one process cannot steal an
 * event from another. */
struct ida_vtdbg_event_reader {
    struct list_head link;
    struct file *file;
    struct ida_vtdbg_channel *channel;
    u32 tree_root_tgid;
    struct ida_vtdbg_reader_task tasks[IDA_VTDBG_READER_TASKS_MAX];
};

struct ida_vtdbg_session {
    struct list_head link;
    struct list_head event_readers;
    struct list_head owner_waits;
    u64 owner_wait_sequence;
    struct pid *tgid;
    u32 target_pid;
    kuid_t owner;
    u32 flags;
    struct file *owner_file;
    struct ida_vtdbg_channel *channel;
    struct ida_vtdbg_ptrace_command command;
    struct pid *command_pid; /* pinned identity, not a reusable numeric PID */
    u32 command_state;
    u64 command_sequence;
    struct pid *proxy_stops[IDA_VTDBG_READER_TASKS_MAX];
    u64 native_resume_sequence;
    bool tracer_scope;
    bool defer_tree_arm;
    u32 probe_target;
};

#define IDA_VTDBG_COMMAND_IDLE 0u
#define IDA_VTDBG_COMMAND_PENDING 1u
#define IDA_VTDBG_COMMAND_INFLIGHT 2u
#define IDA_VTDBG_COMMAND_COMPLETE 3u

static LIST_HEAD(ida_vtdbg_sessions);
static LIST_HEAD(ida_vtdbg_tree_readers);
static DEFINE_MUTEX(ida_vtdbg_lock);
static DEFINE_SPINLOCK(ida_vtdbg_session_lock);
static DEFINE_SPINLOCK(ida_vtdbg_event_lock);
static DECLARE_WAIT_QUEUE_HEAD(ida_vtdbg_command_wait);
static atomic64_t ida_vtdbg_command_generation = ATOMIC64_INIT(0);
static struct ida_vtdbg_policy_event ida_vtdbg_pending_events[
    IDA_VTDBG_EVENT_QUEUE_MAX];
static u32 ida_vtdbg_pending_head;
static u32 ida_vtdbg_pending_count;
static u64 ida_vtdbg_pending_sequence;

static void ida_vtdbg_wake_command_waiters(void)
{
    atomic64_inc(&ida_vtdbg_command_generation);
    wake_up_interruptible(&ida_vtdbg_command_wait);
}

#define IDA_VTDBG_CLONE_PROBE_COUNT 4u

struct ida_vtdbg_ptrace_probe_data {
    unsigned long request;
    u32 pid;
};

struct ida_vtdbg_wait_probe_data {
    int __user *status;
};


static struct task_struct *ida_vtdbg_get_target(u32 pid);
static struct ida_vtdbg_session *ida_vtdbg_find_locked(struct pid *tgid);
static void ida_vtdbg_owner_wait_free(struct ida_vtdbg_session *session);

static void ida_vtdbg_proxy_stop_free(struct ida_vtdbg_session *session)
{
    for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n)
        put_pid(session->proxy_stops[n]);
}

/* event_lock serializes these pinned task identities with mailbox ownership.
 * A held report means the real owner is serving debugger requests, not its
 * VM dispatcher. A successful native resume or consumed report ends it. */
static void ida_vtdbg_proxy_stop_set(struct ida_vtdbg_session *session,
                                    struct pid *pid, bool held)
{
    size_t free_slot = IDA_VTDBG_READER_TASKS_MAX;
    for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n) {
        if (session->proxy_stops[n] == pid) {
            if (!held) {
                put_pid(session->proxy_stops[n]);
                session->proxy_stops[n] = NULL;
            }
            return;
        }
        if (!session->proxy_stops[n] && free_slot == IDA_VTDBG_READER_TASKS_MAX)
            free_slot = n;
    }
    if (held && free_slot != IDA_VTDBG_READER_TASKS_MAX)
        session->proxy_stops[free_slot] = get_pid(pid);
}

static bool ida_vtdbg_proxy_stop_has(struct ida_vtdbg_session *session,
                                    struct pid *pid)
{
    for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n)
        if (session->proxy_stops[n] == pid)
            return true;
    return false;
}

static bool ida_vtdbg_task_descends_from_tgid(struct task_struct *task,
                                               u32 ancestor_tgid)
{
    unsigned int depth = 0;

    while (task && depth++ != 32u) {
        if ((u32)task_tgid_vnr(task) == ancestor_tgid)
            return true;
        if (task == rcu_access_pointer(task->real_parent))
            break;
        task = rcu_dereference(task->real_parent);
    }
    return false;
}

static u32 ida_vtdbg_task_tracer_scope_flags(struct task_struct *task)
{
    struct ida_vtdbg_session *session;
    u32 flags = 0;

    rcu_read_lock();
    spin_lock(&ida_vtdbg_session_lock);
    list_for_each_entry(session, &ida_vtdbg_sessions, link) {
        if (!session->tracer_scope || !session->tgid)
            continue;
        if (ida_vtdbg_task_descends_from_tgid(
                task, (u32)pid_vnr(session->tgid))) {
            flags = session->flags;
            break;
        }
    }
    spin_unlock(&ida_vtdbg_session_lock);
    rcu_read_unlock();
    return flags;
}

static bool ida_vtdbg_should_arm_tree_options(struct task_struct *task,
                                               u32 target_pid)
{
    struct ida_vtdbg_session *session;
    bool arm = false;

    rcu_read_lock();
    spin_lock(&ida_vtdbg_session_lock);
    list_for_each_entry(session, &ida_vtdbg_sessions, link) {
        if (!session->tracer_scope || !session->tgid ||
            !ida_vtdbg_task_descends_from_tgid(
                task, (u32)pid_vnr(session->tgid)))
            continue;
        if (!(session->flags & IDA_VTDBG_POLICY_F_PTRACE_TRACEME))
            break;
        if (session->defer_tree_arm && session->probe_target == 0) {
            session->probe_target = target_pid;
            pr_info_ratelimited("ida_vtdbg_policy: deferred tree arm tracer=%d probe_target=%u\n",
                                task_pid_vnr(task), target_pid);
            break;
        }
        if (!session->defer_tree_arm || target_pid != session->probe_target)
            arm = true;
        break;
    }
    spin_unlock(&ida_vtdbg_session_lock);
    rcu_read_unlock();
    return arm;
}

static bool ida_vtdbg_should_translate_tree_event(struct task_struct *task,
                                                  u32 stopped_pid)
{
    struct ida_vtdbg_session *session;
    bool translate = false;

    rcu_read_lock();
    spin_lock(&ida_vtdbg_session_lock);
    list_for_each_entry(session, &ida_vtdbg_sessions, link) {
        if (!session->tracer_scope || !session->tgid ||
            !ida_vtdbg_task_descends_from_tgid(
                task, (u32)pid_vnr(session->tgid)))
            continue;
        /* Preserve linux_server's private trace-fork capability probe. */
        translate = !session->defer_tree_arm ||
                    (session->probe_target != 0 &&
                     session->probe_target != stopped_pid);
        break;
    }
    spin_unlock(&ida_vtdbg_session_lock);
    rcu_read_unlock();
    return translate;
}

/* Return the policy flags for current's whole process ancestry.  This is used
 * only in kretprobe context, therefore it takes no sleeping locks and never
 * returns a session pointer whose lifetime could outlast the lock. */
static u32 ida_vtdbg_current_tree_flags(void)
{
    struct task_struct *task;
    u32 flags = 0;
    unsigned int depth = 0;

    rcu_read_lock();
    spin_lock(&ida_vtdbg_session_lock);
    task = current;
    while (task && depth++ != 32u) {
        struct ida_vtdbg_session *session;
        u32 tgid = (u32)task_tgid_vnr(task);

        list_for_each_entry(session, &ida_vtdbg_sessions, link) {
            if (session->tgid && (u32)pid_vnr(session->tgid) == tgid) {
                flags = session->flags;
                goto out;
            }
        }
        if (task == task->real_parent)
            break;
        task = rcu_dereference(task->real_parent);
    }
out:
    spin_unlock(&ida_vtdbg_session_lock);
    rcu_read_unlock();
    return flags;
}

static u32 ida_vtdbg_current_tracer_flags(void)
{
    struct task_struct *tracer;
    u32 flags = 0;

    rcu_read_lock();
    tracer = ptrace_parent(current);
    if (tracer)
        get_task_struct(tracer);
    rcu_read_unlock();
    if (!tracer)
        return 0;
    flags = ida_vtdbg_task_tracer_scope_flags(tracer);
    put_task_struct(tracer);
    return flags;
}

static void ida_vtdbg_channel_put(struct ida_vtdbg_channel *channel)
{
    if (channel && refcount_dec_and_test(&channel->references)) {
        vfree(channel->memory);
        kfree(channel);
    }
}

static void ida_vtdbg_reader_free(struct ida_vtdbg_event_reader *reader)
{
    if (!reader)
        return;
    for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n)
        put_pid(reader->tasks[n].pid);
    kfree(reader);
}

static void ida_vtdbg_event_readers_free(struct ida_vtdbg_session *session)
{
    struct ida_vtdbg_event_reader *reader, *next;

    list_for_each_entry_safe(reader, next, &session->event_readers, link) {
        list_del(&reader->link);
        ida_vtdbg_reader_free(reader);
    }
}

static void ida_vtdbg_shared_push(struct ida_vtdbg_channel *channel,
                                  const struct ida_vtdbg_policy_event *event)
{
    struct ida_vtdbg_shared_ring *ring;
    struct ida_vtdbg_shared_slot *slot;
    unsigned long flags;
    u64 producer;
    u64 consumer;

    if (!channel || !channel->ring)
        return;
    ring = channel->ring;
    spin_lock_irqsave(&channel->lock, flags);
    producer = READ_ONCE(ring->producer);
    consumer = READ_ONCE(ring->consumer);
    if (producer - consumer >= IDA_VTDBG_SHARED_RING_SLOTS) {
        /* A debugger-visible initial/synthetic stop is more important than
         * an older diagnostic fork/exit record.  When the ring is full,
         * advance the reader cursor by one for these control events so the
         * new stop is retained; ordinary diagnostics keep the original
         * drop-new behavior.  This is bounded, lock-protected, and does not
         * change the userspace ABI. */
        if (event->type == IDA_VTDBG_EVENT_EXIT ||
            (event->type == IDA_VTDBG_EVENT_STOP &&
             (event->flags & (IDA_VTDBG_EVENT_F_INITIAL_STOP |
                              IDA_VTDBG_EVENT_F_SYNTHETIC_STEP)) != 0)) {
            WRITE_ONCE(ring->consumer, consumer + 1u);
            consumer++;
            WRITE_ONCE(ring->dropped, READ_ONCE(ring->dropped) + 1u);
        } else {
            WRITE_ONCE(ring->dropped, READ_ONCE(ring->dropped) + 1u);
            spin_unlock_irqrestore(&channel->lock, flags);
            return;
        }
    }
    slot = &ring->slots[producer % IDA_VTDBG_SHARED_RING_SLOTS];
    slot->event = *event;
    WRITE_ONCE(slot->sequence, event->sequence);
    smp_wmb();
    WRITE_ONCE(ring->producer, producer + 1u);
    spin_unlock_irqrestore(&channel->lock, flags);
    wake_up_interruptible(&channel->wait);
}

static int ida_vtdbg_open(struct inode *inode, struct file *file)
{
    struct ida_vtdbg_channel *channel;

    (void)inode;
    channel = kzalloc(sizeof(*channel), GFP_KERNEL);
    if (!channel)
        return -ENOMEM;
    channel->memory = vmalloc_user(IDA_VTDBG_SHARED_BYTES);
    if (!channel->memory) {
        kfree(channel);
        return -ENOMEM;
    }
    channel->ring = channel->memory;
    spin_lock_init(&channel->lock);
    init_waitqueue_head(&channel->wait);
    refcount_set(&channel->references, 1);
    channel->ring->magic = IDA_VTDBG_SHARED_MAGIC;
    channel->ring->version = IDA_VTDBG_SHARED_VERSION;
    channel->ring->header_size = offsetof(struct ida_vtdbg_shared_ring,
                                          slots);
    channel->ring->slot_size = sizeof(struct ida_vtdbg_shared_slot);
    channel->ring->slot_count = IDA_VTDBG_SHARED_RING_SLOTS;
    channel->ring->generation = ktime_get_ns();
    file->private_data = channel;
    return 0;
}

static void ida_vtdbg_vma_open(struct vm_area_struct *vma)
{
    struct ida_vtdbg_channel *channel = vma->vm_private_data;

    if (channel)
        refcount_inc(&channel->references);
}

static void ida_vtdbg_vma_close(struct vm_area_struct *vma)
{
    ida_vtdbg_channel_put(vma->vm_private_data);
}

static const struct vm_operations_struct ida_vtdbg_vm_ops = {
    .open = ida_vtdbg_vma_open,
    .close = ida_vtdbg_vma_close,
};

static int ida_vtdbg_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct ida_vtdbg_channel *channel = file->private_data;
    unsigned long length;
    int result;

    if (!channel || !channel->memory)
        return -ENODEV;
    length = vma->vm_end - vma->vm_start;
    if (length == 0 || length > IDA_VTDBG_SHARED_BYTES)
        return -EINVAL;
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
    result = remap_vmalloc_range(vma, channel->memory, 0);
    if (result)
        return result;
    /* A VMA can outlive the file descriptor.  Hold one reference for this
     * mapping and release it from vm_ops.close rather than file.release. */
    refcount_inc(&channel->references);
    vma->vm_ops = &ida_vtdbg_vm_ops;
    vma->vm_private_data = channel;
    return 0;
}

static __poll_t ida_vtdbg_poll(struct file *file, poll_table *wait)
{
    struct ida_vtdbg_channel *channel = file->private_data;
    __poll_t mask = 0;

    if (!channel || !channel->ring)
        return EPOLLERR;
    poll_wait(file, &channel->wait, wait);
    if (READ_ONCE(channel->ring->producer) !=
        READ_ONCE(channel->ring->consumer))
        mask |= EPOLLIN | EPOLLRDNORM;
    return mask;
}

static long ida_vtdbg_shared_reset(struct file *file)
{
    struct ida_vtdbg_channel *channel = file->private_data;
    unsigned long flags;

    if (!channel || !channel->ring)
        return -ENODEV;
    spin_lock_irqsave(&channel->lock, flags);
    WRITE_ONCE(channel->ring->consumer, READ_ONCE(channel->ring->producer));
    WRITE_ONCE(channel->ring->dropped, 0);
    spin_unlock_irqrestore(&channel->lock, flags);
    return 0;
}

static struct ida_vtdbg_session *ida_vtdbg_find_for_pid_locked(u32 pid)
{
    struct task_struct *target;
    struct task_struct *origin;
    struct ida_vtdbg_session *session;
    unsigned int depth = 0;

    target = ida_vtdbg_get_target(pid);
    if (!target)
        return NULL;
    origin = target;
    rcu_read_lock();
    session = NULL;
    while (target && depth++ != 32u) {
        struct pid *tgid = get_task_pid(target, PIDTYPE_TGID);

        if (tgid) {
            session = ida_vtdbg_find_locked(tgid);
            put_pid(tgid);
            if (session)
                break;
        }
        if (target == rcu_dereference(target->real_parent))
            break;
        target = rcu_dereference(target->real_parent);
    }
    rcu_read_unlock();
    /* target is held only for the initial lookup; parent traversal used RCU. */
    put_task_struct(origin);
    return session;
}

/* Pin child identity on the subscriber, not the target's temporary exec fd.
 * This lets a persistent server reader receive a real exit even when the
 * original parent exits without another wait and the child is reparented. */
static void ida_vtdbg_reader_track_locked(struct ida_vtdbg_event_reader *reader,
                                         const struct ida_vtdbg_policy_event *event)
{
    struct pid *pid;
    struct ida_vtdbg_reader_task *slot = NULL;

    if ((event->type != IDA_VTDBG_EVENT_FORK &&
         event->type != IDA_VTDBG_EVENT_STOP) || event->pid == 0)
        return;
    pid = find_vpid((pid_t)event->pid); /* caller holds RCU read lock */
    if (!pid)
        return;
    for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n) {
        if (reader->tasks[n].pid == pid)
            return;
        if ((!reader->tasks[n].pid || reader->tasks[n].exit_reported) && !slot)
            slot = &reader->tasks[n];
    }
    if (slot) {
        put_pid(slot->pid);
        memset(slot, 0, sizeof(*slot));
        slot->pid = get_pid(pid);
        slot->tgid = event->tgid;
        slot->parent_pid = event->parent_pid;
        slot->parent_tgid = event->parent_tgid;
    }
}

static void ida_vtdbg_pending_push_locked(struct ida_vtdbg_session *session,
                                          u32 type, u32 target_pid, u32 parent_pid,
                                          u32 parent_tgid, u32 child_pid,
                                          u32 child_tgid, u32 status,
                                          u32 event_flags)
{
    struct ida_vtdbg_policy_event *event;
    struct ida_vtdbg_policy_event audit_event;
    struct ida_vtdbg_event_reader *reader;
    struct task_struct *origin = NULL;
    u32 slot;
    bool queue_pending =
        (event_flags & IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED) == 0;

    for (u32 offset = 0; queue_pending && offset < ida_vtdbg_pending_count; ++offset) {
        u32 existing_slot = (ida_vtdbg_pending_head + offset) %
                            IDA_VTDBG_EVENT_QUEUE_MAX;
        if (type == IDA_VTDBG_EVENT_FORK &&
            ida_vtdbg_pending_events[existing_slot].type == type &&
            ida_vtdbg_pending_events[existing_slot].target_pid == target_pid &&
            ida_vtdbg_pending_events[existing_slot].parent_tgid == parent_tgid &&
            ida_vtdbg_pending_events[existing_slot].pid == child_pid)
            return;
    }

    if (queue_pending) {
        if (ida_vtdbg_pending_count == IDA_VTDBG_EVENT_QUEUE_MAX) {
            ida_vtdbg_pending_head =
                (ida_vtdbg_pending_head + 1u) % IDA_VTDBG_EVENT_QUEUE_MAX;
            --ida_vtdbg_pending_count;
        }
        slot = (ida_vtdbg_pending_head + ida_vtdbg_pending_count) %
               IDA_VTDBG_EVENT_QUEUE_MAX;
        event = &ida_vtdbg_pending_events[slot];
    } else {
        /* Parent-owned protocol events are already consumed by the real
         * tracer. Keep them in the mmap reader for audit/handler logs, but
         * never enqueue them into the legacy NEXT_EVENT wait FIFO. That FIFO
         * has no reader in the shared-ring server path and otherwise fills
         * permanently at 256 entries, evicting real lifecycle events. */
        memset(&audit_event, 0, sizeof(audit_event));
        event = &audit_event;
    }
    memset(event, 0, sizeof(*event));
    event->abi = IDA_VTDBG_POLICY_ABI;
    event->target_pid = target_pid;
    event->type = type;
    event->pid = child_pid;
    event->tgid = child_tgid;
    event->parent_pid = parent_pid;
    event->parent_tgid = parent_tgid;
    event->status = status;
    event->flags = event_flags;
    event->sequence = ++ida_vtdbg_pending_sequence;
    if (session && type == IDA_VTDBG_EVENT_STOP) {
        struct pid *pid_ref = find_vpid(child_pid);
        if (pid_ref)
            ida_vtdbg_proxy_stop_set(session, pid_ref, queue_pending);
    }
    if (queue_pending) {
        ++ida_vtdbg_pending_count;
        pr_info_ratelimited("ida_vtdbg_policy: pending type=%u flags=0x%x pid=%u parent=%u status=0x%x seq=%llu count=%u\n",
                            event->type, event->flags, event->pid,
                            event->parent_tgid, event->status,
                            (unsigned long long)event->sequence,
                            ida_vtdbg_pending_count);
    }
    ida_vtdbg_shared_push(session ? session->channel : NULL, event);
    if (session) {
        list_for_each_entry(reader, &session->event_readers, link) {
            rcu_read_lock();
            ida_vtdbg_reader_track_locked(reader, event);
            rcu_read_unlock();
            ida_vtdbg_shared_push(reader->channel, event);
        }
        if (session->tgid)
            origin = get_pid_task(session->tgid, PIDTYPE_TGID);
        if (origin) {
            rcu_read_lock();
            list_for_each_entry(reader, &ida_vtdbg_tree_readers, link) {
                if (reader->tree_root_tgid != 0 &&
                    ida_vtdbg_task_descends_from_tgid(
                        origin, reader->tree_root_tgid)) {
                    ida_vtdbg_reader_track_locked(reader, event);
                    ida_vtdbg_shared_push(reader->channel, event);
                }
            }
            rcu_read_unlock();
            put_task_struct(origin);
        }
    }
}

static void ida_vtdbg_reader_report_exit_locked(
    struct ida_vtdbg_event_reader *reader, u32 target_pid, u32 status)
{
    struct ida_vtdbg_policy_event event;
    for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n) {
        struct ida_vtdbg_reader_task *task = &reader->tasks[n];
        if (!task->pid || task->pid != task_pid(current) ||
            task->exit_reported)
            continue;
        task->exit_reported = true;
        memset(&event, 0, sizeof(event));
        event.abi = IDA_VTDBG_POLICY_ABI;
        event.target_pid = target_pid;
        event.type = IDA_VTDBG_EVENT_EXIT;
        event.flags = IDA_VTDBG_EVENT_F_KERNEL_LIFECYCLE;
        event.pid = (u32)task_pid_vnr(current);
        event.tgid = task->tgid;
        event.parent_pid = task->parent_pid;
        event.parent_tgid = task->parent_tgid;
        event.status = status;
        event.sequence = ++ida_vtdbg_pending_sequence;
        ida_vtdbg_shared_push(reader->channel, &event);
        break;
    }
}

static int ida_vtdbg_task_exit_pre(struct kprobe *probe, struct pt_regs *regs)
{
    struct ida_vtdbg_event_reader *reader;
    struct ida_vtdbg_session *session;
    u32 status = (u32)regs_get_kernel_argument(regs, 0);
    bool cancelled = false;
    (void)probe;
    spin_lock(&ida_vtdbg_session_lock);
    spin_lock(&ida_vtdbg_event_lock);
    list_for_each_entry(reader, &ida_vtdbg_tree_readers, link)
        ida_vtdbg_reader_report_exit_locked(reader, reader->tree_root_tgid, status);
    list_for_each_entry(session, &ida_vtdbg_sessions, link) {
        if (session->command_pid == task_pid(current) &&
            (session->command_state == IDA_VTDBG_COMMAND_PENDING ||
             session->command_state == IDA_VTDBG_COMMAND_INFLIGHT)) {
            session->command.result = -1;
            session->command.error = ESRCH;
            session->command.payload_len = 0;
            session->command.value = 0;
            session->command_state = IDA_VTDBG_COMMAND_COMPLETE;
            cancelled = true;
        }
        list_for_each_entry(reader, &session->event_readers, link)
            ida_vtdbg_reader_report_exit_locked(reader, session->target_pid, status);
    }
    spin_unlock(&ida_vtdbg_event_lock);
    spin_unlock(&ida_vtdbg_session_lock);
    if (cancelled)
        ida_vtdbg_wake_command_waiters();
    return 0;
}

static struct kprobe ida_vtdbg_exit_probe = {
    .symbol_name = "do_exit",
    .pre_handler = ida_vtdbg_task_exit_pre,
};

static int ida_vtdbg_kernel_clone_ret(struct kretprobe_instance *instance,
                                      struct pt_regs *regs)
{
    long child_pid;
    struct task_struct *child;
    struct ida_vtdbg_session *session;
    u32 parent_pid;
    u32 parent_tgid;
    u32 child_tgid;

    (void)instance;
    child_pid = regs_return_value(regs);
    if (child_pid <= 0 || child_pid > 0x7fffffffL)
        return 0;
    parent_pid = (u32)task_pid_vnr(current);
    parent_tgid = (u32)task_tgid_vnr(current);
    child = ida_vtdbg_get_target((u32)child_pid);
    if (child) {
        child_tgid = (u32)task_tgid_vnr(child);
        put_task_struct(child);
    } else {
        /* At a very early fork-stop the child can be returned by the syscall
         * before it is visible to get_pid_task().  Treat the new PID as a
         * process child; later duplicate events are removed by the ring. */
        child_tgid = (u32)child_pid;
    }
    if (child_tgid == parent_tgid)
        return 0;
    /* Kretprobe handlers may run in atomic context.  The list therefore has
     * its own spinlock; never sleep here while publishing an event. */
    spin_lock(&ida_vtdbg_session_lock);
    spin_lock(&ida_vtdbg_event_lock);
    list_for_each_entry(session, &ida_vtdbg_sessions, link) {
        if (session->tgid && (u32)pid_vnr(session->tgid) == parent_tgid) {
            pr_info_ratelimited("ida_vtdbg_policy: matched target=%u parent=%u child=%u\n",
                                session->target_pid, parent_tgid,
                                (u32)child_pid);
            ida_vtdbg_pending_push_locked(session, IDA_VTDBG_EVENT_FORK,
                                           session->target_pid, parent_pid,
                                           parent_tgid, (u32)child_pid,
                                           child_tgid, 0, 0);
        }
    }
    spin_unlock(&ida_vtdbg_event_lock);
    spin_unlock(&ida_vtdbg_session_lock);
    return 0;
}

static int ida_vtdbg_ptrace_entry(struct kretprobe_instance *instance,
                                  struct pt_regs *regs)
{
    struct ida_vtdbg_ptrace_probe_data *data =
        (struct ida_vtdbg_ptrace_probe_data *)instance->data;
    struct pt_regs *user_regs =
        (struct pt_regs *)regs_get_kernel_argument(regs, 0);

    data->request = user_regs ? user_regs->di : ~0UL;
    data->pid = user_regs ? (u32)user_regs->si : 0;
    if (user_regs &&
        (data->request == PTRACE_SETOPTIONS ||
         data->request == PTRACE_SEIZE) &&
        ida_vtdbg_should_arm_tree_options(current, (u32)user_regs->si)) {
        unsigned long options = user_regs->r10;

        options |= PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXEC;
        user_regs->r10 = options;
        pr_info_ratelimited("ida_vtdbg_policy: armed ptrace tree options tracer=%d target=%ld flags=0x%lx\n",
                            task_pid_vnr(current), (long)user_regs->si,
                            options);
    }
    return 0;
}

static int ida_vtdbg_ptrace_ret(struct kretprobe_instance *instance,
                                struct pt_regs *regs)
{
    struct ida_vtdbg_ptrace_probe_data *data =
        (struct ida_vtdbg_ptrace_probe_data *)instance->data;
    long result = regs_return_value(regs);

    if (data->request == PTRACE_CONT || data->request == PTRACE_SINGLESTEP ||
        data->request == PTRACE_SYSCALL) {
        bool completed = false;
        struct ida_vtdbg_session *session;
        spin_lock(&ida_vtdbg_session_lock);
        spin_lock(&ida_vtdbg_event_lock);
        list_for_each_entry(session, &ida_vtdbg_sessions, link) {
            if (session->tgid != task_tgid(current)) continue;
            if (!result) {
                struct pid *pid_ref = find_vpid(data->pid);
                if (pid_ref) ida_vtdbg_proxy_stop_set(session, pid_ref, false);
            }
            if (session->command_state == IDA_VTDBG_COMMAND_INFLIGHT &&
                session->command.pid == data->pid &&
                session->command.request == data->request &&
                (session->command.flags & IDA_VTDBG_COMMAND_F_NATIVE_RESUME) != 0) {
                /* Complete at the actual syscall return, before the owner
                 * can hit its own user BP in libc. The owner still executes
                 * the command; the kernel only publishes its real result. */
                session->command.result = result < 0 ? -1 : result;
                session->command.error = result < 0 ? (u32)-result : 0;
                session->command.payload_len = 0;
                session->native_resume_sequence = session->command.sequence;
                session->command_state = IDA_VTDBG_COMMAND_COMPLETE;
                completed = true;
            }
        }
        spin_unlock(&ida_vtdbg_event_lock);
        spin_unlock(&ida_vtdbg_session_lock);
        if (completed) ida_vtdbg_wake_command_waiters();
        return 0;
    }

    if (data->request != PTRACE_TRACEME)
        return 0;
    if (!((ida_vtdbg_current_tree_flags() |
           ida_vtdbg_current_tracer_flags()) &
          IDA_VTDBG_POLICY_F_PTRACE_TRACEME))
        return 0;
    /* Preserve the debugger's existing ptrace relationship.  We only change
     * the observable return value of the target self-check. */
    if (result == -EPERM)
        regs_set_return_value(regs, 0);
    pr_info_ratelimited("ida_vtdbg_policy: virtualized PTRACE_TRACEME pid=%d result=%ld\n",
                        task_pid_vnr(current), result);
    /* This is syscall metadata, NOT a stopped task. PTRACE_TRACEME does not
     * itself generate SIGTRAP. A later stop can be an IDA breakpoint or a
     * program-owned exception and must retain its own provenance. In
     * particular, do not make userspace issue mailbox GETREGS before the
     * real parent has reached waitpid and can service that mailbox. */
    if (result == -EPERM || result == 0) {
        struct task_struct *parent = rcu_dereference(current->real_parent);
        u32 parent_pid = parent ? (u32)task_pid_vnr(parent) : 0;
        u32 parent_tgid = parent ? (u32)task_tgid_vnr(parent) : 0;
        struct ida_vtdbg_session *session;

        spin_lock(&ida_vtdbg_session_lock);
        spin_lock(&ida_vtdbg_event_lock);
        list_for_each_entry(session, &ida_vtdbg_sessions, link) {
            if (!session->tgid ||
                !ida_vtdbg_task_descends_from_tgid(
                    current, (u32)pid_vnr(session->tgid)))
                continue;
            ida_vtdbg_pending_push_locked(
                session, IDA_VTDBG_EVENT_TRACEME_METADATA, session->target_pid,
                parent_pid, parent_tgid, (u32)task_pid_vnr(current),
                (u32)task_tgid_vnr(current), 0,
                IDA_VTDBG_EVENT_F_TRACEME_STOP);
        }
        spin_unlock(&ida_vtdbg_event_lock);
        spin_unlock(&ida_vtdbg_session_lock);
    }
    return 0;
}

static int ida_vtdbg_wait_entry(struct kretprobe_instance *instance,
                                struct pt_regs *regs)
{
    struct ida_vtdbg_wait_probe_data *data =
        (struct ida_vtdbg_wait_probe_data *)instance->data;
    struct pt_regs *user_regs =
        (struct pt_regs *)regs_get_kernel_argument(regs, 0);

    data->status = user_regs ? (int __user *)user_regs->si : NULL;
    return 0;
}

static int ida_vtdbg_wait_ret(struct kretprobe_instance *instance,
                              struct pt_regs *regs)
{
    struct ida_vtdbg_wait_probe_data *data =
        (struct ida_vtdbg_wait_probe_data *)instance->data;
    long stopped = regs_return_value(regs);
    int status;
    unsigned int event;

    if (stopped <= 0 || !data->status ||
        !ida_vtdbg_should_translate_tree_event(current, (u32)stopped))
        return 0;
    pagefault_disable();
    if (__get_user(status, data->status)) {
        pagefault_enable();
        return 0;
    }
    event = (unsigned int)status >> 16;
    if ((status & 0xff) == 0x7f && ((status >> 8) & 0xff) == SIGTRAP &&
        (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK)) {
        status = (status & 0x0000ffff) | (PTRACE_EVENT_CLONE << 16);
        if (!__put_user(status, data->status))
            pr_info_ratelimited("ida_vtdbg_policy: normalized debuggee fork stop tracer=%d parent=%ld\n",
                                task_pid_vnr(current), stopped);
    }
    pagefault_enable();
    return 0;
}

static struct kretprobe ida_vtdbg_wait_probe = {
    .kp.symbol_name = "__x64_sys_wait4",
    .entry_handler = ida_vtdbg_wait_entry,
    .handler = ida_vtdbg_wait_ret,
    .data_size = sizeof(struct ida_vtdbg_wait_probe_data),
    .maxactive = 128,
};

static struct kretprobe ida_vtdbg_ptrace_probe = {
    .kp.symbol_name = "__x64_sys_ptrace",
    .entry_handler = ida_vtdbg_ptrace_entry,
    .handler = ida_vtdbg_ptrace_ret,
    .data_size = sizeof(struct ida_vtdbg_ptrace_probe_data),
    .maxactive = 128,
};

static struct kretprobe ida_vtdbg_clone_probes[IDA_VTDBG_CLONE_PROBE_COUNT] = {
    {
        .kp.symbol_name = "kernel_clone",
        .handler = ida_vtdbg_kernel_clone_ret,
        .maxactive = 64,
    },
    {
        .kp.symbol_name = "__x64_sys_fork",
        .handler = ida_vtdbg_kernel_clone_ret,
        .maxactive = 64,
    },
    {
        .kp.symbol_name = "__x64_sys_clone",
        .handler = ida_vtdbg_kernel_clone_ret,
        .maxactive = 64,
    },
    {
        .kp.symbol_name = "__x64_sys_clone3",
        .handler = ida_vtdbg_kernel_clone_ret,
        .maxactive = 64,
    },
};

static struct task_struct *ida_vtdbg_get_target(u32 pid)
{
    struct pid *pid_ref;
    struct task_struct *task;

    pid_ref = find_get_pid((pid_t)pid);
    if (!pid_ref)
        return NULL;
    task = get_pid_task(pid_ref, PIDTYPE_PID);
    put_pid(pid_ref);
    return task;
}

static struct ida_vtdbg_session *ida_vtdbg_find_locked(struct pid *tgid)
{
    struct ida_vtdbg_session *session;
    struct ida_vtdbg_session *result = NULL;

    spin_lock(&ida_vtdbg_session_lock);
    list_for_each_entry(session, &ida_vtdbg_sessions, link) {
        if (session->tgid == tgid) {
            result = session;
            break;
        }
    }
    spin_unlock(&ida_vtdbg_session_lock);
    return result;
}

static bool ida_vtdbg_may_manage(struct task_struct *target)
{
    return uid_eq(current_euid(), task_euid(target)) ||
           capable(CAP_SYS_PTRACE);
}

static long ida_vtdbg_register(struct file *file, unsigned long arg,
                               bool remove, bool tracer_scope)
{
    struct ida_vtdbg_policy_session request;
    struct ida_vtdbg_session *session;
    struct task_struct *target;
    struct pid *tgid;
    long result = 0;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI || request.target_pid == 0)
        return -EINVAL;

    if (remove) {
        struct ida_vtdbg_session *removed = NULL;

        mutex_lock(&ida_vtdbg_lock);
        spin_lock(&ida_vtdbg_session_lock);
        list_for_each_entry(session, &ida_vtdbg_sessions, link) {
            if (session->target_pid == request.target_pid) {
                if (!uid_eq(current_euid(), session->owner) &&
                    !capable(CAP_SYS_PTRACE)) {
                    spin_unlock(&ida_vtdbg_session_lock);
                    mutex_unlock(&ida_vtdbg_lock);
                    return -EPERM;
                }
                list_del(&session->link);
                removed = session;
                break;
            }
        }
        spin_unlock(&ida_vtdbg_session_lock);
        mutex_unlock(&ida_vtdbg_lock);
        if (removed) {
            ida_vtdbg_event_readers_free(removed);
            ida_vtdbg_proxy_stop_free(removed);
            ida_vtdbg_owner_wait_free(removed);
            put_pid(removed->command_pid);
            put_pid(removed->tgid);
            kfree(removed);
            ida_vtdbg_wake_command_waiters();
        }
        return 0;
    }

    target = ida_vtdbg_get_target(request.target_pid);
    if (!target)
        return -ESRCH;
    if (!ida_vtdbg_may_manage(target)) {
        put_task_struct(target);
        return -EPERM;
    }
    tgid = get_task_pid(target, PIDTYPE_TGID);
    put_task_struct(target);
    if (!tgid)
        return -ESRCH;

    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_find_locked(tgid);
    if (session) {
        spin_lock(&ida_vtdbg_session_lock);
        session->flags = request.flags & IDA_VTDBG_POLICY_DEFAULT_FLAGS;
        session->defer_tree_arm =
            (request.flags & IDA_VTDBG_POLICY_F_DEFER_TREE_ARM) != 0;
        session->probe_target = 0;
        session->owner_file = file;
        session->channel = file->private_data;
        session->tracer_scope = tracer_scope;
        spin_unlock(&ida_vtdbg_session_lock);
    } else {
        session = kzalloc(sizeof(*session), GFP_KERNEL);
        if (!session) {
            result = -ENOMEM;
        } else {
            INIT_LIST_HEAD(&session->event_readers);
            INIT_LIST_HEAD(&session->owner_waits);
            session->tgid = get_pid(tgid);
            session->target_pid = request.target_pid;
            session->owner = current_euid();
            session->flags = request.flags & IDA_VTDBG_POLICY_DEFAULT_FLAGS;
            session->defer_tree_arm =
                (request.flags & IDA_VTDBG_POLICY_F_DEFER_TREE_ARM) != 0;
            session->probe_target = 0;
            session->owner_file = file;
            session->channel = file->private_data;
            session->tracer_scope = tracer_scope;
            spin_lock(&ida_vtdbg_session_lock);
            list_add(&session->link, &ida_vtdbg_sessions);
            spin_unlock(&ida_vtdbg_session_lock);
        }
    }
    mutex_unlock(&ida_vtdbg_lock);
    put_pid(tgid);
    return result;
}

static u32 ida_vtdbg_session_flags(u32 pid)
{
    struct task_struct *target;
    struct pid *tgid;
    struct ida_vtdbg_session *session;
    u32 flags = 0;

    target = ida_vtdbg_get_target(pid);
    if (!target)
        return 0;
    tgid = get_task_pid(target, PIDTYPE_TGID);
    put_task_struct(target);
    if (!tgid)
        return 0;

    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_find_locked(tgid);
    if (session && (uid_eq(current_euid(), session->owner) ||
                    capable(CAP_SYS_PTRACE)))
        flags = session->flags;
    mutex_unlock(&ida_vtdbg_lock);
    put_pid(tgid);
    return flags;
}

static long ida_vtdbg_query_syscall(unsigned long arg)
{
    struct ida_vtdbg_policy_syscall request;
    u32 flags;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI)
        return -EINVAL;

    request.action = IDA_VTDBG_ACTION_PASS;
    request.result = 0;
    flags = ida_vtdbg_session_flags(request.target_pid);
    if ((flags & IDA_VTDBG_POLICY_F_PTRACE_TRACEME) &&
        request.syscall_nr == __NR_ptrace &&
        request.args[0] == PTRACE_TRACEME) {
        request.action = IDA_VTDBG_ACTION_EMULATE;
        request.result = 0;
    } else if ((flags & IDA_VTDBG_POLICY_F_DUMPABLE) &&
               request.syscall_nr == __NR_prctl &&
               request.args[0] == PR_GET_DUMPABLE) {
        request.action = IDA_VTDBG_ACTION_EMULATE;
        request.result = 1;
    }
    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
    return 0;
}

static long ida_vtdbg_filter_buffer(unsigned long arg)
{
    struct ida_vtdbg_policy_buffer request;
    char *field;
    char *digits;
    size_t index;
    u32 flags;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI ||
        request.length > IDA_VTDBG_POLICY_MAX_BUFFER)
        return -EINVAL;
    request.changed = 0;
    flags = ida_vtdbg_session_flags(request.target_pid);
    if (flags & IDA_VTDBG_POLICY_F_TRACER_PID) {
        field = strnstr((char *)request.data, "TracerPid:", request.length);
        if (field) {
            digits = field + strlen("TracerPid:");
            while ((size_t)(digits - (char *)request.data) < request.length &&
                   (*digits == ' ' || *digits == '\t'))
                ++digits;
            for (index = 0;
                 (size_t)(digits - (char *)request.data) + index < request.length &&
                 digits[index] >= '0' && digits[index] <= '9';
                 ++index)
                digits[index] = '0';
            request.changed = index != 0;
        }
    }
    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
    return 0;
}

static long ida_vtdbg_next_event(unsigned long arg)
{
    struct ida_vtdbg_policy_event request;
    struct ida_vtdbg_session *session;
    u32 parent_tgid;
    u32 offset;
    bool found = false;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI)
        return -EINVAL;

    mutex_lock(&ida_vtdbg_lock);
    if (request.flags & IDA_VTDBG_EVENT_F_ANY_TARGET) {
        session = NULL;
        parent_tgid = 0;
    } else {
        session = ida_vtdbg_find_for_pid_locked(request.target_pid);
        if (!session || (session->owner_file == NULL)) {
            mutex_unlock(&ida_vtdbg_lock);
            return -ENOENT;
        }
        parent_tgid = (u32)pid_vnr(session->tgid);
    }
    spin_lock(&ida_vtdbg_event_lock);
    for (offset = 0; offset < ida_vtdbg_pending_count; ++offset) {
        u32 slot = (ida_vtdbg_pending_head + offset) %
                   IDA_VTDBG_EVENT_QUEUE_MAX;
        if (!(request.flags & IDA_VTDBG_EVENT_F_ANY_TARGET) &&
            ida_vtdbg_pending_events[slot].parent_tgid != parent_tgid)
            continue;
        request = ida_vtdbg_pending_events[slot];
        for (u32 move = offset; move + 1u < ida_vtdbg_pending_count; ++move) {
            u32 from = (ida_vtdbg_pending_head + move + 1u) %
                       IDA_VTDBG_EVENT_QUEUE_MAX;
            u32 to = (ida_vtdbg_pending_head + move) %
                     IDA_VTDBG_EVENT_QUEUE_MAX;
            ida_vtdbg_pending_events[to] = ida_vtdbg_pending_events[from];
        }
        --ida_vtdbg_pending_count;
        found = true;
        break;
    }
    spin_unlock(&ida_vtdbg_event_lock);
    mutex_unlock(&ida_vtdbg_lock);

    if (!found)
        return -EAGAIN;

    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
    return 0;
}

static long ida_vtdbg_subscribe_events(struct file *file, unsigned long arg)
{
    struct ida_vtdbg_policy_session request;
    struct ida_vtdbg_event_reader *reader;
    struct ida_vtdbg_event_reader *existing;
    struct ida_vtdbg_session *session;
    struct ida_vtdbg_channel *channel = file->private_data;
    struct task_struct *tree_root;
    u32 tree_root_tgid;
    long result = 0;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI || request.target_pid == 0)
        return -EINVAL;
    if (!channel)
        return -ENODEV;

    reader = kzalloc(sizeof(*reader), GFP_KERNEL);
    if (!reader)
        return -ENOMEM;
    reader->file = file;
    reader->channel = channel;

    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_find_for_pid_locked(request.target_pid);
    if (session && !(request.flags & IDA_VTDBG_SUBSCRIBE_F_PERSISTENT_TREE)) {
        if (!uid_eq(current_euid(), session->owner) &&
            !capable(CAP_SYS_PTRACE)) {
            result = -EPERM;
            goto out_unlock;
        }

        /* The session owner's ring already receives events.  A second open
         * file gets an independent reader without replacing the command
         * mailbox owner or policy flags. */
        if (session->owner_file == file)
            result = 0;
        else {
            spin_lock(&ida_vtdbg_event_lock);
            list_for_each_entry(existing, &session->event_readers, link) {
                if (existing->file != file)
                    continue;
                spin_unlock(&ida_vtdbg_event_lock);
                result = 0;
                goto out_unlock;
            }
            list_add_tail(&reader->link, &session->event_readers);
            spin_unlock(&ida_vtdbg_event_lock);
            reader = NULL;
        }
        goto out_unlock;
    }

    /* linux_server's launch helper can be an ancestor of the actual target
     * process, whose tracer-policy session is registered only after exec.
     * Keep a tree-scoped reader on this channel so descendant sessions fan
     * out events here without sending a file descriptor or socket message. */
    tree_root = ida_vtdbg_get_target(request.target_pid);
    if (!tree_root) {
        result = -ESRCH;
        goto out_unlock;
    }
    if (!ida_vtdbg_may_manage(tree_root)) {
        put_task_struct(tree_root);
        result = -EPERM;
        goto out_unlock;
    }
    tree_root_tgid = (u32)task_tgid_vnr(tree_root);
    reader->tasks[0].pid = get_task_pid(tree_root, PIDTYPE_TGID);
    reader->tasks[0].tgid = tree_root_tgid;
    rcu_read_lock();
    reader->tasks[0].parent_pid =
        (u32)task_pid_vnr(rcu_dereference(tree_root->real_parent));
    reader->tasks[0].parent_tgid =
        (u32)task_tgid_vnr(rcu_dereference(tree_root->real_parent));
    rcu_read_unlock();
    put_task_struct(tree_root);

    spin_lock(&ida_vtdbg_event_lock);
    list_for_each_entry(existing, &ida_vtdbg_tree_readers, link) {
        if (existing->file == file &&
            existing->tree_root_tgid == tree_root_tgid) {
            spin_unlock(&ida_vtdbg_event_lock);
            result = 0;
            goto out_unlock;
        }
    }
    reader->tree_root_tgid = tree_root_tgid;
    list_add_tail(&reader->link, &ida_vtdbg_tree_readers);
    spin_unlock(&ida_vtdbg_event_lock);
    reader = NULL;

out_unlock:
    mutex_unlock(&ida_vtdbg_lock);
    ida_vtdbg_reader_free(reader);
    return result;
}

static long ida_vtdbg_report_event(unsigned long arg)
{
    struct ida_vtdbg_policy_event request;
    struct ida_vtdbg_session *session;
    struct task_struct *current_task = current;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI ||
        (request.type != IDA_VTDBG_EVENT_FORK &&
         request.type != IDA_VTDBG_EVENT_STOP &&
         request.type != IDA_VTDBG_EVENT_EXIT) || request.pid == 0)
        return -EINVAL;
    if ((u32)task_tgid_vnr(current_task) != request.parent_tgid)
        return -EPERM;

    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_find_for_pid_locked(request.target_pid);
    if (!session || session->owner_file == NULL) {
        mutex_unlock(&ida_vtdbg_lock);
        return -ENOENT;
    }
    spin_lock(&ida_vtdbg_event_lock);
    if ((request.flags & IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED) == 0)
        pr_info_ratelimited("ida_vtdbg_policy: report type=%u flags=0x%x pid=%u parent=%u target=%u status=0x%x\n",
                            request.type, request.flags, request.pid,
                            request.parent_tgid, request.target_pid,
                            request.status);
    ida_vtdbg_pending_push_locked(session, request.type,
                                  session->target_pid,
                                  request.parent_pid,
                                  request.parent_tgid, request.pid,
                                  request.tgid != 0 ? request.tgid : request.pid,
                                  request.status, request.flags);
    spin_unlock(&ida_vtdbg_event_lock);
    mutex_unlock(&ida_vtdbg_lock);
    return 0;
}

static struct ida_vtdbg_session *ida_vtdbg_command_session_locked(u32 pid)
{
    return ida_vtdbg_find_for_pid_locked(pid);
}

/* The exit probe runs before PF_EXITING is set. The pinned reader tombstone
 * also covers that interval, so no request can be queued after do_exit's
 * lifecycle event but before task flags change. Caller holds event_lock. */
static bool ida_vtdbg_command_task_exited_locked(struct ida_vtdbg_session *session,
                                                struct task_struct *task)
{
    struct ida_vtdbg_event_reader *reader;
    if (READ_ONCE(task->exit_state) || (READ_ONCE(task->flags) & PF_EXITING))
        return true;
    list_for_each_entry(reader, &ida_vtdbg_tree_readers, link)
        for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n)
            if (reader->tasks[n].pid == task_pid(task) &&
                reader->tasks[n].exit_reported)
                return true;
    list_for_each_entry(reader, &session->event_readers, link)
        for (size_t n = 0; n < IDA_VTDBG_READER_TASKS_MAX; ++n)
            if (reader->tasks[n].pid == task_pid(task) &&
                reader->tasks[n].exit_reported)
                return true;
    return false;
}

static long ida_vtdbg_submit_command_common(unsigned long arg, bool wait_busy)
{
    struct ida_vtdbg_ptrace_command request;
    struct ida_vtdbg_session *session;
    long result;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI ||
        request.payload_len > IDA_VTDBG_COMMAND_PAYLOAD_MAX)
        return -EINVAL;
    for (;;) {
        u64 observed_generation =
            (u64)atomic64_read(&ida_vtdbg_command_generation);

        mutex_lock(&ida_vtdbg_lock);
        session = ida_vtdbg_command_session_locked(request.target_pid);
        if (!session || session->owner_file == NULL) {
            mutex_unlock(&ida_vtdbg_lock);
            return -ENOENT;
        }
        struct task_struct *command_task = ida_vtdbg_get_target(request.pid);
        if (!command_task) {
            mutex_unlock(&ida_vtdbg_lock);
            return -ESRCH;
        }
        spin_lock(&ida_vtdbg_event_lock);
        if (ida_vtdbg_command_task_exited_locked(session, command_task)) {
            spin_unlock(&ida_vtdbg_event_lock);
            put_task_struct(command_task);
            mutex_unlock(&ida_vtdbg_lock);
            return -ESRCH;
        }
        if (session->command_state == IDA_VTDBG_COMMAND_IDLE) {
            put_pid(session->command_pid);
            session->command_pid = get_task_pid(command_task, PIDTYPE_PID);
            session->command = request;
            session->command.sequence = ++session->command_sequence;
            session->command_state = IDA_VTDBG_COMMAND_PENDING;
            request.sequence = session->command.sequence;
            spin_unlock(&ida_vtdbg_event_lock);
            put_task_struct(command_task);
            mutex_unlock(&ida_vtdbg_lock);
            ida_vtdbg_wake_command_waiters();
            if (copy_to_user((void __user *)arg, &request, sizeof(request)))
                return -EFAULT;
            return 0;
        }
        spin_unlock(&ida_vtdbg_event_lock);
        put_task_struct(command_task);
        mutex_unlock(&ida_vtdbg_lock);
        if (!wait_busy)
            return -EBUSY;
        result = wait_event_interruptible(
            ida_vtdbg_command_wait,
            (u64)atomic64_read(&ida_vtdbg_command_generation) !=
                observed_generation);
        if (result)
            return result;
    }
}

static long ida_vtdbg_submit_command(unsigned long arg)
{
    return ida_vtdbg_submit_command_common(arg, false);
}

static long ida_vtdbg_wait_submit_command(unsigned long arg)
{
    return ida_vtdbg_submit_command_common(arg, true);
}

static long ida_vtdbg_next_command(unsigned long arg)
{
    struct ida_vtdbg_ptrace_command request;
    struct ida_vtdbg_session *session;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI)
        return -EINVAL;
    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_command_session_locked(request.target_pid);
    if (!session) {
        mutex_unlock(&ida_vtdbg_lock);
        return -ENOENT;
    }
    spin_lock(&ida_vtdbg_event_lock);
    if (session->command_state != IDA_VTDBG_COMMAND_PENDING) {
        spin_unlock(&ida_vtdbg_event_lock);
        mutex_unlock(&ida_vtdbg_lock);
        return -EAGAIN;
    }
    request = session->command;
    session->command_state = IDA_VTDBG_COMMAND_INFLIGHT;
    spin_unlock(&ida_vtdbg_event_lock);
    mutex_unlock(&ida_vtdbg_lock);
    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
    return 0;
}

static long ida_vtdbg_complete_command(unsigned long arg)
{
    struct ida_vtdbg_ptrace_command request;
    struct ida_vtdbg_session *session;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI ||
        request.payload_len > IDA_VTDBG_COMMAND_PAYLOAD_MAX)
        return -EINVAL;
    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_command_session_locked(request.target_pid);
    if (!session) {
        mutex_unlock(&ida_vtdbg_lock);
        return -ENOENT;
    }
    spin_lock(&ida_vtdbg_event_lock);
    if (request.sequence && request.sequence == session->native_resume_sequence) {
        spin_unlock(&ida_vtdbg_event_lock);
        mutex_unlock(&ida_vtdbg_lock);
        return -EALREADY;
    }
    if (session->command_state != IDA_VTDBG_COMMAND_INFLIGHT ||
        session->command.sequence != request.sequence) {
        spin_unlock(&ida_vtdbg_event_lock);
        mutex_unlock(&ida_vtdbg_lock);
        return -EINVAL;
    }
    session->command = request;
    session->command_state = IDA_VTDBG_COMMAND_COMPLETE;
    spin_unlock(&ida_vtdbg_event_lock);
    mutex_unlock(&ida_vtdbg_lock);
    return 0;
}

static long ida_vtdbg_get_response(unsigned long arg)
{
    struct ida_vtdbg_ptrace_command request;
    struct ida_vtdbg_session *session;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI)
        return -EINVAL;
    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_command_session_locked(request.target_pid);
    if (!session) {
        mutex_unlock(&ida_vtdbg_lock);
        return -ENOENT;
    }
    spin_lock(&ida_vtdbg_event_lock);
    if (session->command_state != IDA_VTDBG_COMMAND_COMPLETE ||
        session->command.sequence != request.sequence) {
        spin_unlock(&ida_vtdbg_event_lock);
        mutex_unlock(&ida_vtdbg_lock);
        return -EAGAIN;
    }
    request = session->command;
    session->command_state = IDA_VTDBG_COMMAND_IDLE;
    put_pid(session->command_pid);
    session->command_pid = NULL;
    spin_unlock(&ida_vtdbg_event_lock);
    mutex_unlock(&ida_vtdbg_lock);
    ida_vtdbg_wake_command_waiters();
    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
    return 0;
}

static long ida_vtdbg_memory_word(unsigned long arg)
{
    struct ida_vtdbg_memory_word request;
    struct ida_vtdbg_session *session;
    struct task_struct *task;
    unsigned int flags = FOLL_FORCE;
    int copied;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI || request.target_pid == 0 ||
        (request.flags & ~IDA_VTDBG_MEMORY_F_WRITE) != 0)
        return -EINVAL;
    /* Never expose an unrestricted process-memory operation. The target
     * must resolve to a registered session and the caller must be that
     * session's uid or have CAP_SYS_PTRACE. */
    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_find_for_pid_locked(request.target_pid);
    if (!session || !session->owner_file) {
        mutex_unlock(&ida_vtdbg_lock);
        return -ENOENT;
    }
    if (!uid_eq(current_euid(), session->owner) && !capable(CAP_SYS_PTRACE)) {
        mutex_unlock(&ida_vtdbg_lock);
        return -EPERM;
    }
    task = ida_vtdbg_get_target(request.target_pid);
    mutex_unlock(&ida_vtdbg_lock);
    if (!task)
        return -ESRCH;
    if (!ida_vtdbg_may_manage(task)) {
        put_task_struct(task);
        return -EPERM;
    }
    if (request.flags & IDA_VTDBG_MEMORY_F_WRITE)
        flags |= FOLL_WRITE;
    copied = access_process_vm(task, (unsigned long)request.addr,
                              &request.value, sizeof(request.value), flags);
    put_task_struct(task);
    if (copied != sizeof(request.value))
        return -EFAULT;
    if (copy_to_user((void __user *)arg, &request, sizeof(request)))
        return -EFAULT;
    return 0;
}

static bool ida_vtdbg_bridge_request_allowed(u32 request)
{
    switch (request) {
    case PTRACE_PEEKTEXT: case PTRACE_PEEKDATA: case PTRACE_PEEKUSR:
    case PTRACE_POKETEXT: case PTRACE_POKEDATA: case PTRACE_POKEUSR:
    case PTRACE_GETREGS: case PTRACE_SETREGS:
    case PTRACE_GETFPREGS: case PTRACE_SETFPREGS:
    case PTRACE_GETREGSET: case PTRACE_SETREGSET:
    case PTRACE_GETSIGINFO: case PTRACE_SETSIGINFO:
    case PTRACE_GETEVENTMSG:
        return true;
    default:
        return false; /* never ATTACH, DETACH, CONT, STEP or replace parent */
    }
}

/* A task_struct ref alone does NOT retain saved pt_regs after do_exit releases
 * its stack. Resolve the regset view only AFTER the stopped/off-CPU/fatal
 * checks under siglock, and keep siglock through the saved-state callback.
 * SIGKILL/native ptrace resume cannot wake the task during this critical
 * section. Query state via exported regset APIs with native validation.
 * callbacks for writes. No kallsyms, arch_ptrace or other private calls.
 * Buffers/user copies are prepared outside the siglock; only non-sleeping
 * GPR/FX register callbacks and fixed saved-state copies run under it. */
#include "stopped_debugregs.inc"

static long ida_vtdbg_stopped_state(struct task_struct *child,
                                    struct task_struct *owner,
                                    struct ida_vtdbg_ptrace_command *command,
                                    bool proxy_held)
{
    const struct user_regset_view *view = NULL;
    const struct user_regset *regset = NULL;
    struct sighand_struct *sighand;
    struct iovec iov = {0};
    siginfo_t signal_info = {0};
    unsigned long flags, value = 0;
    unsigned int note = 0, count = 0, offset = 0;
    void *buffer = NULL;
    void __user *data = (void __user *)(unsigned long)command->data;
    bool write = false, word = false, iovec_request = false;
    long result = -EIO;

    switch (command->request) {
    case PTRACE_GETREGS: case PTRACE_SETREGS:
        note = NT_PRSTATUS;
        count = sizeof(struct user_regs_struct);
        write = command->request == PTRACE_SETREGS;
        break;
    case PTRACE_GETFPREGS: case PTRACE_SETFPREGS:
        note = NT_PRFPREG;
        count = sizeof(struct user_i387_struct);
        write = command->request == PTRACE_SETFPREGS;
        break;
    case PTRACE_GETREGSET: case PTRACE_SETREGSET:
        if (copy_from_user(&iov, data, sizeof(iov))) return -EFAULT;
        note = command->addr;
        write = command->request == PTRACE_SETREGSET;
        iovec_request = true;
        data = iov.iov_base;
        break;
    case PTRACE_PEEKUSR: case PTRACE_POKEUSR:
        if (command->addr & (sizeof(unsigned long) - 1)) return -EIO;
        word = true;
        write = command->request == PTRACE_POKEUSR;
        if (command->addr < sizeof(struct user_regs_struct)) {
            note = NT_PRSTATUS;
            count = write ? sizeof(value) : sizeof(struct user_regs_struct);
            offset = write ? command->addr : 0;
        } else if (write) {
            unsigned long first = offsetof(struct user, u_debugreg[0]);
            unsigned long last = offsetof(struct user, u_debugreg[7]);
            if (command->addr < first || command->addr > last)
                return -EIO;
            return ida_vtdbg_stopped_debugreg_write(child, owner, command);
        }
        break;
    case PTRACE_GETSIGINFO: case PTRACE_GETEVENTMSG:
        break;
    case PTRACE_SETSIGINFO:
        if (copy_from_user(&signal_info, data, sizeof(signal_info))) return -EFAULT;
        write = true;
        break;
    default:
        return -EOPNOTSUPP;
    }
    if (note) {
        if (iovec_request) {
            if (iov.iov_len > 65536) return -EINVAL;
            count = (unsigned int)iov.iov_len;
            /* Extended-state writebacks may allocate; do not call them in
             * this spinlocked bridge. GPR/FX writes have no such path. */
            if (write && note != NT_PRSTATUS && note != NT_PRFPREG)
                return -EOPNOTSUPP;
        }
        if (count > 65536) return -EINVAL;
        buffer = kzalloc(max_t(unsigned int, count, 1), GFP_KERNEL);
        if (!buffer) return -ENOMEM;
        if (write) {
            if (word) memcpy(buffer, &command->value, sizeof(value));
            else if (copy_from_user(buffer, data, count)) {
                kfree(buffer);
                return -EFAULT;
            }
        }
    }
    rcu_read_lock();
    sighand = rcu_dereference(child->sighand);
    if (!sighand) goto out_rcu;
    spin_lock_irqsave(&sighand->siglock, flags);
    if (rcu_access_pointer(child->sighand) != sighand ||
        !child->ptrace || child->parent != owner || !owner->ptrace ||
        !same_thread_group(rcu_dereference(owner->parent), current) ||
        (!proxy_held && !task_is_traced(owner)) || !task_is_traced(child) ||
        (child->jobctl & (JOBCTL_LISTENING | JOBCTL_PTRACE_FROZEN)) ||
        (child->flags & PF_EXITING) || READ_ONCE(child->exit_state) ||
        __fatal_signal_pending(child) || !task_stack_page(child)) {
        result = -EAGAIN;
        goto out_lock;
    }
#ifdef CONFIG_SMP
    /* Native wait status alone precedes schedule-out. Require the actual
     * scheduler completion (acquire), not a guessed delay or polling time. */
    if (smp_load_acquire(&child->on_cpu) ||
        (!proxy_held && smp_load_acquire(&owner->on_cpu))) {
        result = -EAGAIN;
        goto out_lock;
    }
#endif
    if (note) {
        view = task_user_regset_view(child);
        if (!view || view->e_machine != EM_X86_64) {
            result = -EOPNOTSUPP;
            goto out_lock;
        }
        for (unsigned int n = 0; n < view->n; ++n)
            if (view->regsets[n].core_note_type == note) {
                regset = &view->regsets[n];
                break;
            }
        if (!regset) { result = -EINVAL; goto out_lock; }
        if (iovec_request) {
            if (iov.iov_len % regset->size) { result = -EINVAL; goto out_lock; }
            iov.iov_len = min_t(size_t, iov.iov_len, regset->n * regset->size);
            count = (unsigned int)iov.iov_len;
        }
        if (count > regset->n * regset->size) { result = -EINVAL; goto out_lock; }
    }
    if (regset) {
        if (write)
            result = regset->set ? regset->set(child, regset, offset, count, buffer, NULL)
                                 : -EOPNOTSUPP;
        else {
            result = regset_get(child, regset, count, buffer);
            if (result >= 0) result = 0;
        }
        if (!result && word && !write)
            memcpy(&value, buffer + command->addr, sizeof(value));
    } else if (word) {
        unsigned long first = offsetof(struct user, u_debugreg[0]);
        unsigned long last = offsetof(struct user, u_debugreg[7]);
        if (command->addr >= first && command->addr <= last) {
            unsigned int index = (command->addr - first) / sizeof(value);
            if (index < HBP_NUM) {
                struct perf_event *bp = child->thread.ptrace_bps[index];
                if (bp) value = bp->hw.info.address;
            } else if (index == 6)
                value = child->thread.virtual_dr6 ^ DR6_RESERVED;
            else if (index == 7)
                value = child->thread.ptrace_dr7;
        }
        result = command->addr < sizeof(struct user) ? 0 : -EIO;
    } else if (command->request == PTRACE_GETEVENTMSG) {
        value = child->ptrace_message;
        result = 0;
    } else if (child->last_siginfo) {
        if (write) memcpy(child->last_siginfo, &signal_info, sizeof(kernel_siginfo_t));
        else copy_siginfo_to_external(&signal_info, child->last_siginfo);
        result = 0;
    } else result = -EINVAL;
out_lock:
    spin_unlock_irqrestore(&sighand->siglock, flags);
out_rcu:
    rcu_read_unlock();
    if (!result) {
        if (word) command->value = value;
        else if (regset && !write && copy_to_user(data, buffer, count)) result = -EFAULT;
        else if (command->request == PTRACE_GETSIGINFO &&
                 copy_to_user(data, &signal_info, sizeof(signal_info))) result = -EFAULT;
        else if (command->request == PTRACE_GETEVENTMSG &&
                 copy_to_user(data, &value, sizeof(value))) result = -EFAULT;
        if (!result && iovec_request &&
            copy_to_user((void __user *)(unsigned long)command->data, &iov, sizeof(iov)))
            result = -EFAULT;
    }
    kfree(buffer);
    return result;
}

static long ida_vtdbg_nested_stopped_ptrace(unsigned long arg)
{
    struct ida_vtdbg_ptrace_command command;
    struct ida_vtdbg_session *session;
    struct task_struct *child = NULL, *owner = NULL;
    bool proxy_held = false;
    long result = -ESRCH;
    if (copy_from_user(&command, (void __user *)arg, sizeof(command)))
        return -EFAULT;
    if (command.abi != IDA_VTDBG_POLICY_ABI || command.pid == 0 ||
        command.pid == command.target_pid ||
        (command.request != IDA_VTDBG_NESTED_QUERY_STOP &&
         !ida_vtdbg_bridge_request_allowed(command.request)))
        return -EINVAL;
    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_command_session_locked(command.target_pid);
    if (!session || !session->owner_file) { result = -ENOENT; goto unlock; }
    if (!uid_eq(current_euid(), session->owner) && !capable(CAP_SYS_PTRACE)) {
        result = -EPERM;
        goto unlock;
    }
    child = ida_vtdbg_get_target(command.pid);
    if (!child) goto unlock;
    spin_lock(&ida_vtdbg_event_lock);
    bool exited = ida_vtdbg_command_task_exited_locked(session, child);
    spin_unlock(&ida_vtdbg_event_lock);
    if (exited) { result = -ESRCH; goto unlock; }
    rcu_read_lock();
    if (child->ptrace) {
        owner = rcu_dereference(child->parent);
        if (owner) get_task_struct(owner);
    }
    rcu_read_unlock();
    if (!owner || task_tgid(owner) != session->tgid) {
        result = -EPERM;
        goto unlock;
    }
    if (!ida_vtdbg_may_manage(child)) { result = -EPERM; goto unlock; }
    if (command.request == IDA_VTDBG_NESTED_QUERY_STOP) {
        command.result = task_is_traced(child) ? 1 : 0;
        command.value = (u64)task_pid_vnr(owner);
        command.error = 0;
        result = 0;
        goto unlock;
    }
    spin_lock(&ida_vtdbg_event_lock);
    proxy_held = (session->command_state != IDA_VTDBG_COMMAND_INFLIGHT ||
                  session->command.request == IDA_VTDBG_COMMAND_SYNC_BREAKPOINTS) &&
                 ida_vtdbg_proxy_stop_has(session, task_pid(child));
    spin_unlock(&ida_vtdbg_event_lock);
    if (!proxy_held && !task_is_traced(owner)) { result = -EAGAIN; goto unlock; }
    if (command.request == PTRACE_PEEKDATA || command.request == PTRACE_PEEKTEXT ||
        command.request == PTRACE_POKEDATA || command.request == PTRACE_POKETEXT) {
        unsigned int vm_flags = FOLL_FORCE;
        if (!task_is_traced(child)) { result = -EAGAIN; goto unlock; }
        if (command.request == PTRACE_POKEDATA || command.request == PTRACE_POKETEXT)
            vm_flags |= FOLL_WRITE;
        command.result = access_process_vm(child, command.addr, &command.value,
                                           sizeof(command.value), vm_flags) == sizeof(command.value)
                             ? 0 : -EIO;
    } else {
        command.result = ida_vtdbg_stopped_state(child, owner, &command, proxy_held);
        /* EOPNOTSUPP permits the userspace transport to use the real-owner
         * mailbox only while that owner can run. A native-stopped owner must
         * receive a terminal retryable error, never a mailbox fallback. */
        if (command.result == -EOPNOTSUPP && task_is_traced(owner))
            command.result = -EBUSY;
    }
    command.error = command.result < 0 ? (u32)-command.result : 0;
    result = 0;
unlock:
    mutex_unlock(&ida_vtdbg_lock);
    if (owner) put_task_struct(owner);
    if (child) put_task_struct(child);
    if (result) return result;
    if (copy_to_user((void __user *)arg, &command, sizeof(command))) return -EFAULT;
    return 0;
}

#include "owner_wait_context.inc"

static long ida_vtdbg_ioctl(struct file *file, unsigned int command,
                            unsigned long arg)
{
    switch (command) {
    case IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT:
        return ida_vtdbg_owner_wait_context(arg);
    case IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE:
        return ida_vtdbg_nested_stopped_ptrace(arg);
    case IDA_VTDBG_IOC_MEMORY_WORD:
        return ida_vtdbg_memory_word(arg);
    case IDA_VTDBG_IOC_REGISTER:
        return ida_vtdbg_register(file, arg, false, false);
    case IDA_VTDBG_IOC_UNREGISTER:
        return ida_vtdbg_register(file, arg, true, false);
    case IDA_VTDBG_IOC_REGISTER_TRACER:
        return ida_vtdbg_register(file, arg, false, true);
    case IDA_VTDBG_IOC_QUERY_SYSCALL:
        return ida_vtdbg_query_syscall(arg);
    case IDA_VTDBG_IOC_FILTER_BUFFER:
        return ida_vtdbg_filter_buffer(arg);
    case IDA_VTDBG_IOC_NEXT_EVENT:
        return ida_vtdbg_next_event(arg);
    case IDA_VTDBG_IOC_SUBSCRIBE_EVENTS:
        return ida_vtdbg_subscribe_events(file, arg);
    case IDA_VTDBG_IOC_REPORT_EVENT:
        return ida_vtdbg_report_event(arg);
    case IDA_VTDBG_IOC_SUBMIT_COMMAND:
        return ida_vtdbg_submit_command(arg);
    case IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND:
        return ida_vtdbg_wait_submit_command(arg);
    case IDA_VTDBG_IOC_NEXT_COMMAND:
        return ida_vtdbg_next_command(arg);
    case IDA_VTDBG_IOC_COMPLETE_COMMAND:
        return ida_vtdbg_complete_command(arg);
    case IDA_VTDBG_IOC_GET_RESPONSE:
        return ida_vtdbg_get_response(arg);
    case IDA_VTDBG_IOC_SHARED_RESET:
        return ida_vtdbg_shared_reset(file);
    default:
        return -ENOTTY;
    }
}

static int ida_vtdbg_release(struct inode *inode, struct file *file)
{
    struct ida_vtdbg_session *session, *next;
    struct ida_vtdbg_event_reader *reader, *reader_next;
    LIST_HEAD(reclaim);
    struct ida_vtdbg_channel *channel = file->private_data;

    (void)inode;
    mutex_lock(&ida_vtdbg_lock);
    spin_lock(&ida_vtdbg_session_lock);
    spin_lock(&ida_vtdbg_event_lock);
    list_for_each_entry_safe(session, next, &ida_vtdbg_sessions, link) {
        list_for_each_entry_safe(reader, reader_next,
                                 &session->event_readers, link) {
            if (reader->file == file) {
                list_del(&reader->link);
                ida_vtdbg_reader_free(reader);
            }
        }
        if (session->owner_file == file)
            list_move_tail(&session->link, &reclaim);
    }
    list_for_each_entry_safe(reader, reader_next, &ida_vtdbg_tree_readers,
                             link) {
        if (reader->file == file) {
            list_del(&reader->link);
            ida_vtdbg_reader_free(reader);
        }
    }
    spin_unlock(&ida_vtdbg_event_lock);
    spin_unlock(&ida_vtdbg_session_lock);
    mutex_unlock(&ida_vtdbg_lock);
    list_for_each_entry_safe(session, next, &reclaim, link) {
        list_del(&session->link);
        ida_vtdbg_event_readers_free(session);
        ida_vtdbg_proxy_stop_free(session);
        ida_vtdbg_owner_wait_free(session);
        put_pid(session->command_pid);
        put_pid(session->tgid);
        kfree(session);
    }
    ida_vtdbg_wake_command_waiters();
    if (channel) {
        ida_vtdbg_channel_put(channel);
        file->private_data = NULL;
    }
    return 0;
}

static const struct file_operations ida_vtdbg_fops = {
    .owner = THIS_MODULE,
    .open = ida_vtdbg_open,
    .unlocked_ioctl = ida_vtdbg_ioctl,
    .mmap = ida_vtdbg_mmap,
    .poll = ida_vtdbg_poll,
    .release = ida_vtdbg_release,
#ifdef CONFIG_COMPAT
    .compat_ioctl = ida_vtdbg_ioctl,
#endif
};

static struct miscdevice ida_vtdbg_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = IDA_VTDBG_POLICY_DEVICE,
    .fops = &ida_vtdbg_fops,
    .mode = 0666,
};

static int __init ida_vtdbg_init(void)
{
    int result;
    size_t registered = 0;

    result = misc_register(&ida_vtdbg_device);
    if (result)
        return result;
    result = register_kretprobe(&ida_vtdbg_ptrace_probe);
    if (result) {
        misc_deregister(&ida_vtdbg_device);
        return result;
    }
    result = register_kretprobe(&ida_vtdbg_wait_probe);
    if (result) {
        unregister_kretprobe(&ida_vtdbg_ptrace_probe);
        misc_deregister(&ida_vtdbg_device);
        return result;
    }
    for (registered = 0; registered < IDA_VTDBG_CLONE_PROBE_COUNT;
         ++registered) {
        result = register_kretprobe(&ida_vtdbg_clone_probes[registered]);
        if (result)
            break;
    }
    if (!result)
        result = register_kprobe(&ida_vtdbg_exit_probe);
    if (result) {
        while (registered != 0) {
            --registered;
            unregister_kretprobe(&ida_vtdbg_clone_probes[registered]);
        }
        unregister_kretprobe(&ida_vtdbg_wait_probe);
        unregister_kretprobe(&ida_vtdbg_ptrace_probe);
        misc_deregister(&ida_vtdbg_device);
        return result;
    }
    pr_info("ida_vtdbg_policy: ptrace policy + clone probes registered=%u\n",
            IDA_VTDBG_CLONE_PROBE_COUNT);
    return 0;
}

static void __exit ida_vtdbg_exit(void)
{
    struct ida_vtdbg_session *session, *next;
    struct ida_vtdbg_event_reader *reader, *reader_next;
    LIST_HEAD(reclaim);

    unregister_kprobe(&ida_vtdbg_exit_probe);
    unregister_kretprobe(&ida_vtdbg_wait_probe);
    unregister_kretprobe(&ida_vtdbg_ptrace_probe);
    for (size_t index = 0; index < IDA_VTDBG_CLONE_PROBE_COUNT; ++index)
        unregister_kretprobe(&ida_vtdbg_clone_probes[index]);
    misc_deregister(&ida_vtdbg_device);
    mutex_lock(&ida_vtdbg_lock);
    spin_lock(&ida_vtdbg_session_lock);
    list_for_each_entry_safe(session, next, &ida_vtdbg_sessions, link) {
        list_move_tail(&session->link, &reclaim);
    }
    spin_unlock(&ida_vtdbg_session_lock);
    spin_lock(&ida_vtdbg_event_lock);
    list_for_each_entry_safe(reader, reader_next, &ida_vtdbg_tree_readers,
                             link) {
        list_del(&reader->link);
        ida_vtdbg_reader_free(reader);
    }
    spin_unlock(&ida_vtdbg_event_lock);
    mutex_unlock(&ida_vtdbg_lock);
    list_for_each_entry_safe(session, next, &reclaim, link) {
        list_del(&session->link);
        ida_vtdbg_event_readers_free(session);
        ida_vtdbg_proxy_stop_free(session);
        ida_vtdbg_owner_wait_free(session);
        put_pid(session->tgid);
        put_pid(session->command_pid);
        kfree(session);
    }
}

module_init(ida_vtdbg_init);
module_exit(ida_vtdbg_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ida-joint-debug contributors");
MODULE_DESCRIPTION("Kernel-assisted parent-child joint debugging for IDA Linux server");
