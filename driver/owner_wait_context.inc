/* Opaque owner wait-frame tracking: no task stack or architecture ptrace
 * callbacks are accessed here. Records and PID refs use the policy lock.
 */
struct ida_vtdbg_owner_wait_record {
    struct list_head link;
    struct pid *pid;
    struct ida_vtdbg_owner_wait_context context;
};

static void ida_vtdbg_owner_wait_free(struct ida_vtdbg_session *session)
{
    struct ida_vtdbg_owner_wait_record *record, *next;
    list_for_each_entry_safe(record, next, &session->owner_waits, link) {
        list_del(&record->link);
        put_pid(record->pid);
        kfree(record);
    }
}

static long ida_vtdbg_owner_wait_context(unsigned long arg)
{
    struct ida_vtdbg_owner_wait_context request;
    struct ida_vtdbg_owner_wait_record *record, *found = NULL;
    struct ida_vtdbg_session *session;
    struct task_struct *owner = NULL;
    long result = 0;

    if (copy_from_user(&request, (void __user *)arg, sizeof(request)))
        return -EFAULT;
    if (request.abi != IDA_VTDBG_POLICY_ABI || !request.owner_tid ||
        request.operation > IDA_VTDBG_OWNER_WAIT_LEAVE)
        return -EINVAL;
    mutex_lock(&ida_vtdbg_lock);
    session = ida_vtdbg_command_session_locked(request.target_pid);
    if (!session || !session->owner_file) { result = -ENOENT; goto unlock; }
    if (!uid_eq(current_euid(), session->owner) && !capable(CAP_SYS_PTRACE)) {
        result = -EPERM;
        goto unlock;
    }
    owner = ida_vtdbg_get_target(request.owner_tid);
    if (!owner || task_tgid(owner) != session->tgid ||
        READ_ONCE(owner->exit_state) || (READ_ONCE(owner->flags) & PF_EXITING)) {
        result = -ESRCH;
        goto unlock;
    }
    if (request.operation != IDA_VTDBG_OWNER_WAIT_QUERY && owner != current) {
        result = -EPERM;
        goto unlock;
    }
    list_for_each_entry(record, &session->owner_waits, link)
        if (record->pid == task_pid(owner)) { found = record; break; }
    if (request.operation == IDA_VTDBG_OWNER_WAIT_ENTER) {
        if (request.kind > 4 || request.caller_ip == 0 || request.regs[16] == 0) {
            result = -EINVAL;
            goto unlock;
        }
        if (found && found->context.state == IDA_VTDBG_OWNER_WAIT_ACTIVE) {
            result = -EBUSY; /* signal-handler nested wait cannot replace it */
            goto unlock;
        }
        if (!found) {
            found = kzalloc(sizeof(*found), GFP_KERNEL);
            if (!found) { result = -ENOMEM; goto unlock; }
            found->pid = get_task_pid(owner, PIDTYPE_PID);
            list_add_tail(&found->link, &session->owner_waits);
        }
        request.sequence = ++session->owner_wait_sequence;
        request.state = IDA_VTDBG_OWNER_WAIT_ACTIVE;
        found->context = request;
    } else if (request.operation == IDA_VTDBG_OWNER_WAIT_LEAVE) {
        if (!found || found->context.sequence != request.sequence ||
            found->context.state != IDA_VTDBG_OWNER_WAIT_ACTIVE) {
            result = -ESTALE;
            goto unlock;
        }
        found->context.state = 0;
        request.state = 0;
    } else {
        if (found) request = found->context;
        else {
            request.state = 0;
            request.sequence = 0;
            request.caller_ip = 0;
            memset(request.regs, 0, sizeof(request.regs));
        }
        request.operation = IDA_VTDBG_OWNER_WAIT_QUERY;
    }
unlock:
    mutex_unlock(&ida_vtdbg_lock);
    if (owner) put_task_struct(owner);
    if (result) return result;
    if (copy_to_user((void __user *)arg, &request, sizeof(request))) return -EFAULT;
    return 0;
}
