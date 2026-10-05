/* Server-side action ownership for parent-child joint debugging.
 * A native stop and an IDA step intent are different facts: neither a
 * snapshot nor a freeze/thaw request transfers the user's action to a parent.
 */
static pid_t nested_ida_step_intent_child(pid_t scope_tid,
                                         uintptr_t *ip_out,
                                         bool *prefer_software)
{
    pid_t child = 0;
    uintptr_t ip = 0;
    bool soft = false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        const struct nested_ida_step_intent *intent = &nested_ida_step_intents[n];
        if (!intent->active || (scope_tid > 0 && intent->child != scope_tid))
            continue;
        child = intent->child;
        ip = intent->ip;
        soft = intent->prefer_software;
        break;
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (ip_out != NULL)
        *ip_out = ip;
    if (prefer_software != NULL)
        *prefer_software = soft;
    return child;
}

static void nested_ida_step_intent_clear(pid_t child)
{
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
        if (nested_ida_step_intents[n].active && nested_ida_step_intents[n].child == child)
            memset(&nested_ida_step_intents[n], 0, sizeof(nested_ida_step_intents[n]));
    pthread_mutex_unlock(&nested_event_lock);
}

/* This gate belongs below BOTH libc/raw wrappers and internal freeze/thaw
 * calls. The wait broker has already consumed this real parent stop but the
 * backend has not yet presented it to IDA. A successful thaw is only an ACK
 * here, never permission to execute past an unseen user breakpoint.
 * Startup probes (no joint view), tracee-side ptrace, KILL and metadata
 * queries deliberately do not participate in this gate.
 */
static bool parent_owned_keep_unpresented_stop(enum __ptrace_request request,
                                              pid_t pid, const char *route)
{
    if (!parent_owned_mode || !nested_server || pid <= 0 ||
        pid != nested_server_outer_pid || !nested_resume_request(request))
        return false;
    if (nested_parent_resume_scope &&
        atomic_load_explicit(&nested_parent_debug_event_presented, memory_order_acquire) &&
        !atomic_load_explicit(&nested_parent_stop_unpresented, memory_order_acquire))
        return false;
    pthread_mutex_lock(&nested_event_lock);
    bool joint_view = nested_shadow_count != 0;
    pthread_mutex_unlock(&nested_event_lock);
    if (!joint_view)
        return false; /* linux_server's own startup/tracefork probes */
    bool unpresented = atomic_load_explicit(&nested_parent_stop_unpresented,
                                            memory_order_acquire);
    /* The actual wait status can be captured on the broker thread before
     * its local flag is published.  Validate the kernel's current stop here
     * too, before virtual thaw/freeze can issue a physical CONT. Metadata
     * queries do not recurse into this resume-only gate. */
    if (!unpresented) {
        int saved_errno = errno;
        struct user_regs_struct regs = {0};
        siginfo_t info = {0};
        bool debugger_stop = ptrace_internal(PTRACE_GETREGS, pid, NULL, &regs) == 0 &&
            ptrace_internal(PTRACE_GETSIGINFO, pid, NULL, &info) == 0 &&
            info.si_signo == SIGTRAP &&
            (info.si_code == TRAP_HWBKPT ||
             (regs.rip > 0 && nested_breakpoint_address_known((uintptr_t)regs.rip - 1u, NULL)));
        errno = saved_errno;
        if (!debugger_stop)
            return false;
        atomic_store_explicit(&nested_parent_stop_unpresented, true, memory_order_release);
        atomic_store_explicit(&nested_parent_real_stopped, true, memory_order_release);
    }
    uintptr_t ip = 0;
    pid_t intent = nested_ida_step_intent_child(0, &ip, NULL);
    event_trace_log("[ida-vtdbg-shim] resume-route blocked-unpresented-parent route=%s request=%d target_tid=%d step_tid=%d step_ip=0x%llx\n",
                    route, request, pid, intent, (unsigned long long)ip);
    return true;
}

static bool parent_owned_reject_wait_step(enum __ptrace_request request,
                                         pid_t tid)
{
    if (request != PTRACE_SINGLESTEP || !parent_owned_wait_view(tid, NULL))
        return false;
    event_trace_log("[ida-vtdbg-shim] resume-route rejected-wait-step request=%d target_tid=%d\n",
                    request, tid);
    errno = EAGAIN;
    return true;
}
