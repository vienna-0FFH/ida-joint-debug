/* Stop-safe updates of an existing native ptrace hardware breakpoint bank.
 *
 * Do not call arch_ptrace or create module-owned perf callbacks. linux_server
 * has already allocated the child's ptrace_bps through its real owner; those
 * events keep Linux's own overflow handler, validation and lifetime. While
 * both child and actual owner are frozen/off-CPU, the exported perf API can
 * update that bank without asking the stopped owner to run a mailbox loop.
 * New, unallocated slots remain explicitly unsupported at this boundary.
 */
static void ida_vtdbg_debugreg_unfreeze(struct task_struct *task)
{
    unsigned long flags;
    struct sighand_struct *sighand;

    rcu_read_lock();
    sighand = rcu_dereference(task->sighand);
    if (sighand) {
        spin_lock_irqsave(&sighand->siglock, flags);
        if (rcu_access_pointer(task->sighand) == sighand) {
            task->jobctl &= ~JOBCTL_PTRACE_FROZEN;
            if (__fatal_signal_pending(task)) {
                /* Exactly the native ptrace-unfreeze fatal-signal wake, via
                 * the exported waitqueue wake callback. wake_up_state itself
                 * is not exported to modules on this kernel. */
                wait_queue_entry_t wake = { .private = task };
                task->jobctl &= ~JOBCTL_TRACED;
                default_wake_function(&wake, __TASK_TRACED, 0, NULL);
            }
        }
        spin_unlock_irqrestore(&sighand->siglock, flags);
    }
    rcu_read_unlock();
}

static bool ida_vtdbg_debugreg_freeze(struct task_struct *task,
                                      struct task_struct *tracer)
{
    unsigned long flags;
    struct sighand_struct *sighand;
    bool frozen = false;

    rcu_read_lock();
    sighand = rcu_dereference(task->sighand);
    if (sighand) {
        spin_lock_irqsave(&sighand->siglock, flags);
        if (rcu_access_pointer(task->sighand) == sighand &&
            task->ptrace && task->parent == tracer && task_is_traced(task) &&
            !(task->jobctl & (JOBCTL_LISTENING | JOBCTL_PTRACE_FROZEN)) &&
            !(task->flags & PF_EXITING) && !READ_ONCE(task->exit_state) &&
            !__fatal_signal_pending(task)) {
            task->jobctl |= JOBCTL_PTRACE_FROZEN;
            frozen = true;
        }
        spin_unlock_irqrestore(&sighand->siglock, flags);
    }
    rcu_read_unlock();
    if (frozen) {
#ifdef CONFIG_SMP
        /* Native status delivery precedes schedule-out. Refuse an operation
         * before scheduler completion, never infer readiness from a delay. */
        if (smp_load_acquire(&task->on_cpu)) {
            ida_vtdbg_debugreg_unfreeze(task);
            return false;
        }
#endif
    }
    return frozen;
}

static int ida_vtdbg_debugreg_attr(struct perf_event_attr *attr,
                                   unsigned long dr7, unsigned int index)
{
    unsigned int field = (dr7 >> (16u + 4u * index)) & 0xfu;
    unsigned int rw = field & 3u, length = field >> 2;
    static const unsigned int lengths[4] = {1, 2, 8, 4};

    switch (rw) {
    case 0: attr->bp_type = HW_BREAKPOINT_X; break;
    case 1: attr->bp_type = HW_BREAKPOINT_W; break;
    case 3: attr->bp_type = HW_BREAKPOINT_R | HW_BREAKPOINT_W; break;
    default: return -EINVAL; /* I/O breakpoints have no native perf equivalent */
    }
    if (rw == 0) {
        if (length != 0)
            return -EINVAL;
        attr->bp_type = HW_BREAKPOINT_X;
        attr->bp_len = sizeof(long); /* x86 execute breakpoint sentinel */
    } else {
        attr->bp_len = lengths[length];
    }
    attr->disabled = (dr7 & (3ul << (2u * index))) == 0;
    return 0;
}

static long ida_vtdbg_debugreg_write_frozen(struct task_struct *child,
                                            unsigned int index,
                                            unsigned long value)
{
    struct perf_event *bp;
    struct perf_event_attr attr;

    if (index < HBP_NUM) {
        bp = child->thread.ptrace_bps[index];
        if (!bp)
            return -EBUSY; /* no fake ACK and no stopped-owner mailbox fallback */
        attr = bp->attr;
        attr.bp_addr = value;
        return modify_user_hw_breakpoint(bp, &attr);
    }
    if (index == 6) {
        child->thread.virtual_dr6 = value ^ DR6_RESERVED;
        return 0;
    }
    if (index == 7) {
        struct perf_event_attr *saved, *desired;
        unsigned int n, changed = 0;
        long result;
        unsigned long hardware_value = value & ~DR_CONTROL_RESERVED;

        saved = kcalloc(2 * HBP_NUM, sizeof(*saved), GFP_KERNEL);
        if (!saved)
            return -ENOMEM;
        desired = saved + HBP_NUM;

        /* Validate the full requested bank before changing any slot. Keep
         * saved attributes for an atomic transaction rollback on perf error. */
        for (n = 0; n < HBP_NUM; ++n) {
            bp = child->thread.ptrace_bps[n];
            if (!bp) {
                if (hardware_value & (3ul << (2u * n))) {
                    result = -EBUSY;
                    goto release_bank;
                }
                continue;
            }
            saved[n] = desired[n] = bp->attr;
            result = ida_vtdbg_debugreg_attr(&desired[n], hardware_value, n);
            if (result)
                goto release_bank;
        }
        for (n = 0; n < HBP_NUM; ++n) {
            bp = child->thread.ptrace_bps[n];
            if (!bp)
                continue;
            result = modify_user_hw_breakpoint(bp, &desired[n]);
            if (result) {
                /* modify_user_hw_breakpoint validates before copying attrs;
                 * the failing slot is unchanged. Restore preceding slots. */
                for (unsigned int rollback = 0; rollback < changed; ++rollback) {
                    struct perf_event *old = child->thread.ptrace_bps[rollback];
                    if (old && modify_user_hw_breakpoint(old, &saved[rollback]))
                        pr_err("ida_vtdbg_policy: DR7 rollback failed child=%d slot=%u\n",
                               task_pid_vnr(child), rollback);
                }
                goto release_bank;
            }
            changed = n + 1;
        }
        child->thread.ptrace_dr7 = value;
        result = 0;
release_bank:
        kfree(saved);
        return result;
    }
    return -EIO; /* DR4/5 have no registers */
}

static long ida_vtdbg_stopped_debugreg_write(struct task_struct *child,
                                             struct task_struct *owner,
                                             struct ida_vtdbg_ptrace_command *command)
{
    unsigned long first = offsetof(struct user, u_debugreg[0]);
    struct task_struct *outer;
    long result = -EAGAIN;

    rcu_read_lock();
    outer = rcu_dereference(owner->parent);
    if (outer)
        get_task_struct(outer);
    rcu_read_unlock();
    if (!outer)
        return -ESRCH;
    /* These are existing session/actual ptrace relationships, not a generic
     * CAP_SYS_PTRACE backdoor into another tracer's hardware registers. */
    if (!owner->ptrace || !same_thread_group(outer, current)) {
        result = -EPERM;
        goto release_outer;
    }
    if (!task_is_traced(owner)) {
        result = -EOPNOTSUPP; /* running owner can service the ordinary mailbox */
        goto release_outer;
    }
    if (!ida_vtdbg_debugreg_freeze(owner, outer))
        goto release_outer;
    if (!ida_vtdbg_debugreg_freeze(child, owner))
        goto unfreeze_owner;
    result = ida_vtdbg_debugreg_write_frozen(child,
        (command->addr - first) / sizeof(unsigned long), command->value);
    ida_vtdbg_debugreg_unfreeze(child);
unfreeze_owner:
    ida_vtdbg_debugreg_unfreeze(owner);
release_outer:
    put_task_struct(outer);
    return result;
}
