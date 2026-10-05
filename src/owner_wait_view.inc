/* The kernel owns the wait ENTER/LEAVE generation. This layer only formats
 * its saved entry frame for the synthetic IDA parent view. No address from
 * a target-specific address or libc layout is involved; no saved frame is written to
 * the physical owner (which must keep servicing the ptrace mailbox).
 */
_Static_assert(sizeof(struct user_regs_struct) ==
               sizeof(((struct ida_vtdbg_owner_wait_context *)0)->regs),
               "owner wait entry GPR ABI");

static bool parent_owned_wait_query(pid_t tid,
                                    struct ida_vtdbg_owner_wait_context *context)
{
    if (!parent_owned_mode || !nested_server || nested_server_outer_pid <= 0 ||
        tid <= 0 || nested_is_shadow(tid))
        return false;
    struct ida_vtdbg_owner_wait_context request = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)nested_server_outer_pid,
        .owner_tid = (uint32_t)tid,
        .operation = IDA_VTDBG_OWNER_WAIT_QUERY,
    };
    int saved_errno = errno;
    int fd = ensure_policy_fd();
    bool waiting = fd >= 0 &&
        ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &request) == 0 &&
        request.state == IDA_VTDBG_OWNER_WAIT_ACTIVE;
    if (waiting && context != NULL)
        *context = request;
    errno = saved_errno;
    return waiting;
}

static bool parent_owned_wait_view(pid_t tid, struct user_regs_struct *regs)
{
    /* Actual parent user breakpoints retain actual registers. A logical
     * wait snapshot must never rewind their architectural instruction PC. */
    if (tid == nested_server_outer_pid &&
        (atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire) ||
         atomic_load_explicit(&nested_parent_debug_event_presented, memory_order_acquire)))
        return false;
    struct ida_vtdbg_owner_wait_context context;
    if (!parent_owned_wait_query(tid, &context))
        return false;
    if (regs != NULL)
        memcpy(regs, context.regs, sizeof(*regs));
    return true;
}

static uint64_t parent_owned_wait_enter(struct user_regs_struct *regs,
                                        unsigned int kind)
{
    if (!parent_owned_mode || !nested_target || nested_target_launcher)
        return 0;
    struct ida_vtdbg_owner_wait_context request = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)getpid(),
        .owner_tid = (uint32_t)current_tid(),
        .operation = IDA_VTDBG_OWNER_WAIT_ENTER,
        .kind = kind,
    };
    request.caller_ip = *(const uintptr_t *)(uintptr_t)regs->rsp;
    /* FS/GS were not changed by the assembly entry; query their live bases
     * without touching a task stack or using an undocumented kernel symbol. */
    (void)real_syscall(SYS_arch_prctl, 0x1003, &regs->fs_base);
    (void)real_syscall(SYS_arch_prctl, 0x1004, &regs->gs_base);
    memcpy(request.regs, regs, sizeof(*regs));
    /* Keep the ACTUAL public ABI entry that was executed and will execute
     * on the next program wait call. Substituting libc wait here is wrong:
     * our wait implementation services real_waitpid, so a user F2 at that
     * unexecuted libc entry would never hit. This entry snapshot is explicitly
     * logical, while native user stops still use physical registers. */
    int fd = nested_target_event_fd;
    if (fd < 0 && nested_parent_driver_setup() == 0)
        fd = nested_target_event_fd;
    if (fd < 0 || ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &request) < 0) {
        event_trace_log("[ida-vtdbg-shim] owner-wait-enter failed tid=%u fd=%d kind=%u error=%d\n",
                        request.owner_tid, fd, kind, errno);
        return 0;
    }
    event_trace_log("[ida-vtdbg-shim] owner-wait-enter tid=%u kind=%u seq=%llu entry=0x%llx caller=0x%llx\n",
                    request.owner_tid, kind, (unsigned long long)request.sequence,
                    (unsigned long long)regs->rip, (unsigned long long)request.caller_ip);
    return request.sequence;
}

static void parent_owned_wait_leave(uint64_t sequence)
{
    if (sequence == 0)
        return;
    struct ida_vtdbg_owner_wait_context request = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)getpid(),
        .owner_tid = (uint32_t)current_tid(),
        .operation = IDA_VTDBG_OWNER_WAIT_LEAVE,
        .sequence = sequence,
    };
    int saved_errno = errno;
    int fd = nested_target_event_fd;
    if (fd >= 0)
        (void)ioctl(fd, IDA_VTDBG_IOC_OWNER_WAIT_CONTEXT, &request);
    event_trace_log("[ida-vtdbg-shim] owner-wait-leave tid=%u seq=%llu\n",
                    request.owner_tid, (unsigned long long)sequence);
    errno = saved_errno;
}
