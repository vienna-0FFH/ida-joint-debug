/* Runtime-only IDA 9.0 Linux server event and breakpoint adapter.
 *
 * The unmodified Linux backend identifies STEP from its per-thread resume
 * flag, not siginfo.si_code. F8 over an INT3 instead uses an address-specific
 * temporary hardware breakpoint. A real parent tracer changes that address;
 * consequently ptrace metadata alone cannot express completion at the new PC.
 *
 * Translate ONLY stops explicitly tagged SYNTHETIC_STEP by our driver. All
 * target exceptions and all ordinary IDA breakpoints pass through unchanged.
 * Resolve local symbols from the currently running ELF, validate the exact
 * relocation-free prologue, and detour in memory during the constructor,
 * before any server worker exists. No commercial file on disk is altered.
 */

struct ida90_event_header {
    int32_t pid;
    int32_t tid;
    uint64_t ea;
    uint8_t handled;
    uint8_t padding[3];
    uint32_t eid;
};
_Static_assert(sizeof(struct ida90_event_header) == 24,
               "IDA 9 event header layout");

typedef int (*ida90_get_event_fn)(void *, void *, int);
typedef void (*ida90_set_code_fn)(void *, uint32_t);
typedef void (*ida90_copy_event_fn)(void *, const void *);
typedef int (*ida90_add_bpt_fn)(void *, void *, int, uint64_t, int);
typedef int (*ida90_del_bpt_fn)(void *, int, uint64_t, const uint8_t *, int);
typedef int (*ida90_ioctl_fn)(void *, int, const void *, size_t, void **, ssize_t *);
typedef int (*ida90_continue_fn)(void *, const void *);
typedef bool (*ida90_check_events_fn)(void *, void *, bool *);
static ida90_get_event_fn ida90_real_get_event;
static ida90_set_code_fn ida90_set_event_code;
static ida90_copy_event_fn ida90_copy_event;
static ida90_add_bpt_fn ida90_real_add_bpt;
static ida90_del_bpt_fn ida90_real_del_bpt;
static ida90_ioctl_fn ida90_real_ioctl;
static ida90_continue_fn ida90_real_continue;
static ida90_check_events_fn ida90_real_check_events;
static uintptr_t ida90_update_bpt_add_return;
static _Atomic bool ida90_process_exited;

#define IDA90_VTDBG_ACTION_IOCTL 0x5644

/* Layout is validated against the same IDA 9.0 ELF as the other adapters.
 * These are thread-table presentation fields, NOT tracee kernel state.
 * A shadow child frozen by IDA can acquire a real new stop from its original
 * tracer while its outer parent is being stepped. Native ptrace has only one
 * owner, so this late delivery must use IDA's own pending-status semantics.
 */
static uint8_t *ida90_thread_node(void *backend, int tid)
{
    uintptr_t node = 0, sentinel = (uintptr_t)backend + 0x470u;
    memcpy(&node, (uint8_t *)backend + 0x478u, sizeof(node));
    for (size_t n = 0; node != 0 && node != sentinel && n < SHIM_MAX_TIDS; ++n) {
        int key = 0;
        memcpy(&key, (const uint8_t *)node + 0x20u, sizeof(key));
        if (key == tid) return (uint8_t *)node;
        memcpy(&node, (const uint8_t *)node + (tid < key ? 0x10u : 0x18u), sizeof(node));
    }
    return NULL;
}

struct ida90_deferred_stop {
    void *backend;
    int tid, status;
    bool extended;
};
static struct ida90_deferred_stop ida90_deferred_stops[NESTED_QUEUE_MAX];
static size_t ida90_deferred_stop_count;

static void ida90_clear_deferred_stops(void *backend, int tid)
{
    for (size_t n = 0; n < ida90_deferred_stop_count;) {
        if (ida90_deferred_stops[n].backend != backend ||
            (tid > 0 && ida90_deferred_stops[n].tid != tid)) { ++n; continue; }
        memmove(ida90_deferred_stops + n, ida90_deferred_stops + n + 1,
                (--ida90_deferred_stop_count - n) * sizeof(ida90_deferred_stops[0]));
    }
}

static bool ida90_take_deferred_stop(void *backend, void *signal, bool *extended)
{
    if (atomic_load_explicit(&nested_parent_trace_requested, memory_order_acquire))
        return false; /* the parent's selected instruction must complete first */
    for (size_t n = 0; n < ida90_deferred_stop_count; ++n) {
        const struct ida90_deferred_stop *pending = &ida90_deferred_stops[n];
        if (pending->backend != backend) continue;
        uint8_t *node = ida90_thread_node(backend, pending->tid);
        int state = 0, suspended = 0, user_suspend = 0;
        if (node == NULL) continue;
        memcpy(&state, node + 0x3cu, sizeof(state));
        memcpy(&suspended, node + 0x2cu, sizeof(suspended));
        memcpy(&user_suspend, node + 0x30u, sizeof(user_suspend));
        if (state != 0 || suspended > 0 || user_suspend > 0) continue;
        memcpy(signal, &pending->tid, 4);
        memcpy((uint8_t *)signal + 4, &pending->status, 4);
        if (extended != NULL) *extended = pending->extended;
        memmove(ida90_deferred_stops + n, ida90_deferred_stops + n + 1,
                (--ida90_deferred_stop_count - n) * sizeof(ida90_deferred_stops[0]));
        return true;
    }
    return false;
}

static bool ida90_check_events_adapter(void *backend, void *signal, bool *extended)
{
    /* Retain each concrete status while its native thread presentation is
     * suspended, then admit it when counters/state allow. No timed retry. */
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        bool result = ida90_real_check_events(backend, signal, extended);
        if (signal == NULL || !parent_owned_mode || !nested_server)
            return result;
        if (!result) return ida90_take_deferred_stop(backend, signal, extended);
        int tid = 0, status = 0;
        memcpy(&tid, signal, sizeof(tid));
        memcpy(&status, (const uint8_t *)signal + 4, sizeof(status));
        if (!nested_is_shadow(tid) || !WIFSTOPPED(status) ||
            WSTOPSIG(status) == SIGSTOP || ((unsigned int)status >> 16) != 0)
            return result;
        uint8_t *node = ida90_thread_node(backend, tid);
        int state = 0, suspend_count = 0, user_suspend = 0;
        if (node == NULL) return result;
        memcpy(&state, node + 0x3cu, sizeof(state));
        memcpy(&suspend_count, node + 0x2cu, sizeof(suspend_count));
        memcpy(&user_suspend, node + 0x30u, sizeof(user_suspend));
        if (state != 1 || (suspend_count <= 0 && user_suspend <= 0))
            return result;
        if (ida90_deferred_stop_count == NESTED_QUEUE_MAX) return result;
        ida90_deferred_stops[ida90_deferred_stop_count++] = (struct ida90_deferred_stop){
            .backend = backend, .tid = tid, .status = status,
            .extended = extended != NULL && *extended,
        };
        /* Preserve separately: stock has_pending_events() counts native
         * pending statuses even for user-suspended threads and would block
         * parent thaw. Do not alter the backend table or any tracee register.
         * Native thaw marks RUNNING after its already accepted resume ACK;
         * only then, with suspension counts clear, deliver this exact stop. */
        handler_trace_log("[ida-vtdbg-shim] debugger-frozen-child-pending tid=%d status=0x%x suspend=%d user_suspend=%d\n",
                          tid, (unsigned int)status, suspend_count, user_suspend);
    }
    return false;
}

static int ida90_ioctl_adapter(void *backend, int function, const void *buffer,
                              size_t length, void **output, ssize_t *output_size)
{
    if (function == IDA90_VTDBG_ACTION_IOCTL) {
        char text[96] = {0};
        unsigned int child = 0, prefer_soft = 0;
        int consumed = 0;
        unsigned long long ip = 0;
        if (output != NULL) *output = NULL;
        if (output_size != NULL) *output_size = 0;
        if (!parent_owned_mode || !nested_server || buffer == NULL ||
            length == 0 || length >= sizeof(text))
            return -1;
        memcpy(text, buffer, length);
        unsigned int reg = 0, part = 0;
        if (sscanf(text, "VTDBGDR/1 %u %u %u%n", &child, &reg, &part, &consumed) == 3 &&
            consumed > 0 && text[consumed] == '\0' && reg < 8 && part < 4 &&
            nested_is_shadow((pid_t)child)) {
            /* Read-only diagnostic through the actual server identity. An
             * external helper is not authorized to query saved DR state.
             * Return a 16-bit piece + 1, preserving zero as a valid value. */
            long result = 0;
            uintptr_t offset = offsetof(struct user, u_debugreg[0]) +
                               reg * sizeof(uintptr_t);
            if (!nested_kernel_stopped_ptrace(PTRACE_PEEKUSER, (pid_t)child,
                                              (void *)offset, NULL, &result) ||
                (result == -1 && errno != 0))
                return -1;
            return (int)(((uintptr_t)result >> (part * 16u)) & 0xffffu) + 1;
        }
        child = 0;
        consumed = 0;
        if (sscanf(text, "VTDBGWAIT/1 %u%n", &child, &consumed) == 1 &&
            consumed > 0 && text[consumed] == '\0')
            return parent_owned_wait_view((pid_t)child, NULL) ? 1 : 0;
        child = 0;
        consumed = 0;
        if (sscanf(text, "VTDBGSTEP/2 %u %llx %u%n", &child, &ip, &prefer_soft, &consumed) != 3 ||
            prefer_soft > 1 || consumed <= 0 || text[consumed] != '\0' ||
            child == 0 || ip == 0 ||
            (!nested_is_shadow((pid_t)child) &&
             (child != (unsigned int)nested_server_outer_pid ||
              !atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire))))
            return -1;
        struct user_regs_struct regs;
        bool real_parent = child == (unsigned int)nested_server_outer_pid &&
            !nested_is_shadow((pid_t)child);
        if ((real_parent ? ptrace_internal(PTRACE_GETREGS, (pid_t)child, NULL, &regs)
                         : nested_driver_forward_ptrace(PTRACE_GETREGS, (pid_t)child, NULL, &regs)) < 0 ||
            regs.rip != ip)
            return -1;
        bool recorded = false;
        pthread_mutex_lock(&nested_event_lock);
        for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
            struct nested_ida_step_intent *intent = &nested_ida_step_intents[n];
            if (!intent->active || intent->child == (pid_t)child) {
                intent->child = (pid_t)child;
                intent->ip = (uintptr_t)ip;
                intent->active = true;
                intent->prefer_software = prefer_soft != 0;
                recorded = true;
                break;
            }
        }
        pthread_mutex_unlock(&nested_event_lock);
        handler_trace_log("[ida-vtdbg-shim] debugger-explicit-step-over child=%u ip=0x%llx recorded=%d\n",
                          child, ip, recorded ? 1 : 0);
        return recorded ? 1 : -1;
    }
    return ida90_real_ioctl(backend, function, buffer, length, output, output_size);
}

static int ida90_del_bpt_adapter(void *backend, int type, uint64_t address,
                                const uint8_t *original, int length)
{
    if (atomic_load_explicit(&ida90_process_exited, memory_order_acquire) &&
        atomic_load_explicit(&nested_parent_kernel_exit_confirmed, memory_order_acquire))
        return 1; /* only the current fixed root's confirmed terminal cleanup */
    nested_ida_transaction_begin();
    nested_breakpoint_memory_begin();
    if (type == 8) {
        uint8_t byte = 0;
        bool found = false;
        size_t slot = 0;
        pthread_mutex_lock(&nested_event_lock);
        for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
            if (nested_ida_software_steps[n].active &&
                nested_ida_software_steps[n].address == (uintptr_t)address) {
                byte = nested_ida_software_steps[n].original;
                slot = n;
                found = true;
                break;
            }
        pthread_mutex_unlock(&nested_event_lock);
        if (found) {
            int result = ida90_real_del_bpt(backend, 4, address, &byte, 1);
            if (result > 0) {
                nested_breakpoint_remove(nested_server_outer_pid, (uintptr_t)address, byte);
                pthread_mutex_lock(&nested_event_lock);
                memset(&nested_ida_software_steps[slot], 0,
                       sizeof(nested_ida_software_steps[slot]));
                pthread_mutex_unlock(&nested_event_lock);
            }
            nested_breakpoint_memory_end();
            nested_ida_transaction_end();
            return result;
        }
    }
    int result = ida90_real_del_bpt(backend, type, address, original, length);
    if (result > 0 && type == 4 && original != NULL)
        nested_breakpoint_remove(nested_server_outer_pid, (uintptr_t)address, original[0]);
    nested_breakpoint_memory_end();
    nested_ida_transaction_end();
    return result;
}

static int ida90_add_bpt_adapter(void *backend, void *original_bytes,
                                int type, uint64_t address, int length)
{
    nested_ida_transaction_begin();
    nested_breakpoint_memory_begin();
    struct ida_bpt_request_context_state previous = ida_bpt_request_context;
    uintptr_t caller = (uintptr_t)__builtin_extract_return_addr(
        __builtin_return_address(0));
    memset(&ida_bpt_request_context, 0, sizeof(ida_bpt_request_context));
    ida_bpt_request_context.active = true;
    ida_bpt_request_context.type = type;
    ida_bpt_request_context.address = (uintptr_t)address;
    /* Both user and F8 breakpoint updates pass a byte vector. Only the
     * checked debmod_t::dbg_update_bpts call site proves that this vector
     * is at +8 inside a 0x38-byte update_bpt_info_t decoded from the RPC.
     * Never infer temporary/user provenance from a null vector or 0xCC. */
    if (caller == ida90_update_bpt_add_return && original_bytes != NULL) {
        const uint8_t *item = (const uint8_t *)original_bytes - 8;
        uint64_t item_address;
        int32_t item_type;
        memcpy(&item_address, item, sizeof(item_address));
        memcpy(&item_type, item + 0x20, sizeof(item_type));
        if (item_address == address && item_type == type) {
            ida_bpt_request_context.client_update = true;
            memcpy(&ida_bpt_request_context.scope_pid, item + 0x2c, 4);
            memcpy(&ida_bpt_request_context.scope_tid, item + 0x30, 4);
        }
    }
    handler_trace_log("[ida-vtdbg-shim] debugger-bpt-request type=%d addr=0x%llx client_update=%d scope_pid=%d scope_tid=%d\n",
                      type, (unsigned long long)address,
                      ida_bpt_request_context.client_update ? 1 : 0,
                      ida_bpt_request_context.scope_pid,
                      ida_bpt_request_context.scope_tid);
    uintptr_t intent_ip = 0;
    bool intent_prefer_software = false;
    pid_t intent_child = nested_ida_step_intent_child(
        ida_bpt_request_context.scope_tid, &intent_ip,
        &intent_prefer_software);
    bool parent_native_stop = atomic_load_explicit(
        &nested_parent_real_stopped, memory_order_acquire);
    /* A pending IDA F8 intent wins over the fact that the outer parent is
     * currently stopped.  This is the crucial wait(2) semantic: a child F8
     * must step the child, while the parent remains stopped/inside its wait;
     * only the target's protocol stop later wakes the parent. */
    pid_t child = intent_child > 0
        ? intent_child
        : (parent_native_stop ? nested_server_outer_pid
                               : nested_protocol_hw_step_child(nested_server_outer_pid));
    bool parent_step = child == nested_server_outer_pid &&
                       (intent_child == 0 || intent_child == child);
    bool call_over = child > 0 && nested_ida_call_return_request(child,
                                                               (uintptr_t)address);
    uintptr_t protocol_ip = 0;
    bool protocol_soft = type == 4 && intent_child > 0 && intent_ip != 0 &&
        address == intent_ip + 1u &&
        nested_server_at_program_int3(intent_child, &protocol_ip) &&
        protocol_ip == intent_ip;
    bool soft_fallback = false;
    size_t fallback_slot = NESTED_QUEUE_MAX;
    if (call_over && type == 8 && original_bytes != NULL) {
        /* Native linux_server broadcasts HW BPs to its synthetic thread
         * list. A scoped parent F8 must not require its stopped ptrace-owner
         * to service a child DR write; use the ordinary physical SW temp.
         * Only explicit step provenance + decoded CALL proves this case. */
        soft_fallback = parent_step || intent_prefer_software;
        pthread_mutex_lock(&nested_event_lock);
        for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
            if (nested_ida_step_intents[n].active &&
                nested_ida_step_intents[n].child == child &&
                nested_ida_step_intents[n].prefer_software)
                soft_fallback = true;
        if (soft_fallback)
            for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
                if (!nested_ida_software_steps[n].active) {
                    fallback_slot = n;
                    break;
                }
        pthread_mutex_unlock(&nested_event_lock);
        soft_fallback = soft_fallback && fallback_slot < NESTED_QUEUE_MAX;
    }
    int actual_type = soft_fallback ? 4 : type;
    if (protocol_soft) {
        pthread_mutex_lock(&nested_event_lock);
        for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
            if (!nested_ida_software_steps[n].active) { fallback_slot = n; break; }
        pthread_mutex_unlock(&nested_event_lock);
    }
    int result = ida90_real_add_bpt(backend, original_bytes, actual_type,
                                   address, soft_fallback ? 1 : length);
    if (result > 0 && actual_type == 4 && original_bytes != NULL) {
        /* A user BP can target an original INT3. No physical byte changes
         * in that case; only the checked exact dbg_add_bpt address proves
         * debugger ownership. Adjacent unchanged CC bytes in the same POKE
         * word must never be registered as debugger breakpoints. */
        const uint8_t *data = NULL;
        size_t size = 0;
        memcpy(&data, original_bytes, sizeof(data));
        memcpy(&size, (const uint8_t *)original_bytes + 8, sizeof(size));
        if (data != NULL && size > 0) {
            nested_breakpoint_record((uintptr_t)address, data[0]);
            if ((soft_fallback || protocol_soft) && fallback_slot < NESTED_QUEUE_MAX) {
                pthread_mutex_lock(&nested_event_lock);
                nested_ida_software_steps[fallback_slot].address = (uintptr_t)address;
                nested_ida_software_steps[fallback_slot].original = data[0];
                nested_ida_software_steps[fallback_slot].child = child;
                nested_ida_software_steps[fallback_slot].protocol = protocol_soft;
                nested_ida_software_steps[fallback_slot].active = true;
                pthread_mutex_unlock(&nested_event_lock);
                handler_trace_log("[ida-vtdbg-shim] debugger-call-over-software-fallback child=%d target=0x%llx\n",
                                  child, (unsigned long long)address);
            }
        }
    }
    if (result > 0 && call_over) {
        /* Parent F8 over wait/ptrace is also a scoped call-over action. The
         * child's program-owned protocol must reach its real owner until
         * that parent returns, but child IDA BPs remain interruptible. */
        nested_generic_hw_step_start(child, child, (uintptr_t)address);
        nested_ida_step_intent_clear(child);
        handler_trace_log("[ida-vtdbg-shim] debugger-call-over-armed child=%d target=0x%llx type=%d\n",
                          child, (unsigned long long)address, type);
    }
    ida_bpt_request_context = previous;
    nested_breakpoint_memory_end();
    nested_ida_transaction_end();
    return result;
}

static int ida90_continue_adapter(void *backend, const void *event)
{
    bool previous_scope = nested_parent_resume_scope;
    const struct ida90_event_header *header = event;
    nested_parent_resume_scope = event != NULL &&
        header->tid == nested_server_outer_pid &&
        (header->eid == 16u || header->eid == 32u || header->eid == 64u) &&
        atomic_load_explicit(&nested_parent_debug_event_presented, memory_order_acquire);
    nested_ida_transaction_begin();
    int result = ida90_real_continue(backend, event);
    nested_ida_transaction_end();
    nested_parent_resume_scope = previous_scope;
    return result;
}

static int ida90_get_event_adapter(void *backend, void *event, int timeout)
{
    /* ProcessExit has now been acknowledged through its RPC. At a real
     * parent stop the native backend may not call waitpid again until it
     * observes an exit; commit the queued tree termination at this next
     * event-request boundary, not inside the earlier ProcessExit response. */
    if (parent_owned_mode && nested_server)
        parent_owned_execute_queued_process_exit();
    int result = ida90_real_get_event(backend, event, timeout);
    struct ida90_event_header *header = event;
    uintptr_t address = 0;

    if (result > 0 && event != NULL) {
        if (header->eid == 1u)
            atomic_store_explicit(&ida90_process_exited, false, memory_order_release);
        else if (header->eid == 2u)
            atomic_store_explicit(&ida90_process_exited, true, memory_order_release);
        if (header->eid == 1u || header->eid == 2u)
            ida90_clear_deferred_stops(backend, 0);
        else if (header->eid == 8u)
            ida90_clear_deferred_stops(backend, header->tid);
        if (header->eid == 16u || header->eid == 32u || header->eid == 64u)
            parent_owned_debugger_stop_presented(header->tid);
        if ((header->eid == 16u || header->eid == 32u || header->eid == 64u) &&
            header->tid == nested_server_outer_pid) {
            atomic_store_explicit(&nested_parent_stop_unpresented, false, memory_order_release);
            atomic_store_explicit(&nested_parent_debug_event_presented, true, memory_order_release);
        }
        nested_ida_step_intent_clear(header->tid);
        if (header->eid == 16u || header->eid == 32u || header->eid == 64u ||
            header->eid == 2u || header->eid == 8u)
            nested_generic_hw_step_clear(header->tid);
    }

    if (result > 0 && event != NULL && parent_owned_mode && nested_server &&
        (header->eid == 64u || header->eid == 16u || header->eid == 32u) &&
        parent_owned_get_synthetic_step_stop(header->tid, &address) &&
        address != 0) {
        uint32_t previous = header->eid;
        bool trace = parent_owned_synthetic_is_trace(header->tid);
        uintptr_t hardware_target = trace ? 0 :
            nested_protocol_hw_step_target(header->tid);
        uint32_t displayed = hardware_target != 0 ? 16u : 32u;
        pthread_mutex_lock(&nested_event_lock);
        for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
            if (nested_ida_software_steps[n].active &&
                nested_ida_software_steps[n].protocol &&
                nested_ida_software_steps[n].child == header->tid)
                displayed = 16u; /* IDA's actual software-temp F8 completion */
        pthread_mutex_unlock(&nested_event_lock);
        ida90_set_event_code(event, displayed); /* frees old exception union */
        if (displayed == 16u) {
            uint64_t *bpt = (uint64_t *)((uint8_t *)event + 24);
            bpt[0] = UINT64_MAX;
            bpt[1] = UINT64_MAX;
        }
        header->ea = (uint64_t)address;
        header->handled = 0;
        /* get_debug_event stores a copy at +0xc0 before returning. Keep its
         * last-event state identical to the event sent to the IDA client. */
        ida90_copy_event((uint8_t *)backend + 0xc0u, event);
        handler_trace_log("[ida-vtdbg-shim] debugger-event-normalized child=%d from=%u to=%u rip=0x%llx hw=0x%llx\n",
                          header->tid, previous, displayed,
                          (unsigned long long)address, (unsigned long long)hardware_target);
    }
    return result;
}

static uintptr_t ida90_elf_symbol(const uint8_t *file, size_t length,
                                 const char *name)
{
    const Elf64_Ehdr *elf = (const Elf64_Ehdr *)file;
    const Elf64_Shdr *sections;

    if (length < sizeof(*elf) || memcmp(elf->e_ident, ELFMAG, SELFMAG) != 0 ||
        elf->e_ident[EI_CLASS] != ELFCLASS64 || elf->e_type != ET_EXEC ||
        elf->e_machine != EM_X86_64 || elf->e_shentsize != sizeof(Elf64_Shdr) ||
        elf->e_shoff > length ||
        (size_t)elf->e_shnum > (length - elf->e_shoff) / sizeof(Elf64_Shdr))
        return 0;
    sections = (const Elf64_Shdr *)(file + elf->e_shoff);
    for (size_t i = 0; i < elf->e_shnum; ++i) {
        const Elf64_Shdr *section = &sections[i];
        const Elf64_Shdr *strings;
        const Elf64_Sym *symbols;
        if (section->sh_type != SHT_SYMTAB ||
            section->sh_entsize != sizeof(Elf64_Sym) ||
            section->sh_link >= elf->e_shnum ||
            section->sh_offset > length ||
            section->sh_size > length - section->sh_offset)
            continue;
        strings = &sections[section->sh_link];
        if (strings->sh_offset > length ||
            strings->sh_size > length - strings->sh_offset)
            continue;
        symbols = (const Elf64_Sym *)(file + section->sh_offset);
        for (size_t n = 0; n < section->sh_size / sizeof(*symbols); ++n) {
            const Elf64_Sym *symbol = &symbols[n];
            const char *text;
            if (symbol->st_name >= strings->sh_size ||
                ELF64_ST_TYPE(symbol->st_info) != STT_FUNC ||
                symbol->st_shndx == SHN_UNDEF)
                continue;
            text = (const char *)(file + strings->sh_offset + symbol->st_name);
            if (memchr(text, '\0', strings->sh_size - symbol->st_name) != NULL &&
                strcmp(text, name) == 0)
                return (uintptr_t)symbol->st_value;
        }
    }
    return 0;
}

static void ida90_jump(uint8_t *destination, uintptr_t address)
{
    const uint8_t prefix[6] = {0xff, 0x25, 0, 0, 0, 0};
    memcpy(destination, prefix, sizeof(prefix));
    memcpy(destination + sizeof(prefix), &address, sizeof(address));
}

static bool ida90_install_event_adapter(void)
{
    static const uint8_t expected[16] = {
        0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,
        0x49,0x89,0xf4,0x55,0x48,0x89,0xfd,0x53};
    static const uint8_t set_code_signature[9] = {
        0x48,0x85,0xff,0x0f,0x84,0x8f,0x01,0x00,0x00};
    static const uint8_t add_bpt_signature[14] = {
        0x41,0x56,0x41,0x55,0x41,0x54,0x41,0x89,
        0xd4,0x55,0x48,0x89,0xfd,0x53};
    static const uint8_t del_bpt_signature[17] = {
        0x41,0x54,0x41,0x89,0xf4,0x48,0x89,0xd6,
        0x55,0x48,0x89,0xfd,0x53,0x48,0x83,0xec,0x10};
    static const uint8_t update_bpt_signature[15] = {
        0x41,0x57,0x41,0x56,0x41,0x55,0x49,0x89,
        0xd5,0x41,0x54,0x55,0x89,0xcd,0x53};
    static const uint8_t update_bpt_add_call[26] = {
        0x48,0x8b,0x03,0x48,0x8d,0x75,0x08,0x44,
        0x8b,0x44,0x24,0x2c,0x48,0x89,0xdf,0x48,
        0x8b,0x4c,0x24,0x30,0xff,0x90,0x20,0x01,0x00,0x00};
    static const uint8_t ioctl_signature[20] = {
        0x55,0x53,0x48,0x83,0xec,0x28,0x64,0x48,
        0x8b,0x04,0x25,0x28,0,0,0,0x48,0x89,0x44,0x24,0x18};
    static const uint8_t continue_signature[28] = {
        0x41,0x54,0x55,0x53,0x48,0x81,0xec,0xe0,0,0,0,
        0x64,0x48,0x8b,0x04,0x25,0x28,0,0,0,
        0x48,0x89,0x84,0x24,0xd8,0,0,0};
    static const uint8_t check_events_signature[14] = {
        0x41,0x56,0x49,0x89,0xd6,0x41,0x55,0x41,
        0x54,0x55,0x48,0x89,0xf5,0x53};
    static const uint8_t store_pending_signature[11] = {
        0x41,0x54,0x49,0x89,0xfc,0x55,0x89,0xf5,
        0x53,0x89,0xd3};
    struct stat status;
    uint8_t *file = MAP_FAILED;
    uint8_t *trampoline = MAP_FAILED;
    uint8_t *add_trampoline = MAP_FAILED;
    uint8_t *del_trampoline = MAP_FAILED;
    uint8_t *ioctl_trampoline = MAP_FAILED;
    uint8_t *continue_trampoline = MAP_FAILED;
    uint8_t *check_trampoline = MAP_FAILED;
    uintptr_t get_address = 0, set_address = 0, copy_address = 0, add_address = 0;
    uintptr_t update_address = 0;
    uintptr_t del_address = 0;
    uintptr_t ioctl_address = 0;
    uintptr_t continue_address = 0;
    uintptr_t check_address = 0, store_pending_address = 0;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t writable_pages[12] = {0};
    size_t writable_count = 0;
    int fd;
    bool installed = false;

    if (!parent_owned_mode || !nested_server || !shim_is_linux_server_image())
        return false;
    fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || fstat(fd, &status) < 0 || status.st_size <= 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    file = mmap(NULL, (size_t)status.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (file == MAP_FAILED)
        return false;
    get_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t15get_debug_eventEP13debug_event_ti");
    set_address = ida90_elf_symbol(file, (size_t)status.st_size,
                                 "set_debug_event_code");
    copy_address = ida90_elf_symbol(file, (size_t)status.st_size,
                                  "copy_debug_event");
    add_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t11dbg_add_bptEP9bytevec_tiyi");
    del_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t11dbg_del_bptEiyPKhi");
    update_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN8debmod_t15dbg_update_bptsEPiP17update_bpt_info_tiiP8_qstringIcE");
    ioctl_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t12handle_ioctlEiPKvmPPvPl");
    continue_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t24dbg_continue_after_eventEPK13debug_event_t");
    check_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t20check_for_new_eventsEP17chk_signal_info_tPb");
    store_pending_address = ida90_elf_symbol(file, (size_t)status.st_size,
        "_ZN14linux_debmod_t20store_pending_signalEii");
    if (get_address == 0 || set_address == 0 || copy_address == 0 ||
        add_address == 0 || update_address == 0 ||
        ioctl_address == 0 || del_address == 0 || continue_address == 0 ||
        check_address == 0 || store_pending_address == 0 ||
        memcmp((const void *)get_address, expected, sizeof(expected)) != 0 ||
        memcmp((const void *)add_address, add_bpt_signature,
               sizeof(add_bpt_signature)) != 0 ||
        memcmp((const void *)del_address, del_bpt_signature,
               sizeof(del_bpt_signature)) != 0 ||
        memcmp((const void *)update_address, update_bpt_signature,
               sizeof(update_bpt_signature)) != 0 ||
        memcmp((const void *)(update_address + 0xf1u), update_bpt_add_call,
               sizeof(update_bpt_add_call)) != 0 ||
        memcmp((const void *)ioctl_address, ioctl_signature,
               sizeof(ioctl_signature)) != 0 ||
        memcmp((const void *)continue_address, continue_signature,
               sizeof(continue_signature)) != 0 ||
        memcmp((const void *)check_address, check_events_signature,
               sizeof(check_events_signature)) != 0 ||
        memcmp((const void *)store_pending_address, store_pending_signature,
               sizeof(store_pending_signature)) != 0 ||
        memcmp((const void *)set_address, set_code_signature,
               sizeof(set_code_signature)) != 0)
        goto done;
    trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (trampoline == MAP_FAILED)
        goto done;
    memcpy(trampoline, "\xf3\x0f\x1e\xfa", 4); /* ENDBR64 */
    memcpy(trampoline + 4, expected, sizeof(expected));
    ida90_jump(trampoline + 4 + sizeof(expected), get_address + sizeof(expected));
    if (mprotect(trampoline, page_size, PROT_READ | PROT_EXEC) < 0)
        goto done;
    memcpy(&ida90_real_get_event, &trampoline, sizeof(ida90_real_get_event));
    memcpy(&ida90_set_event_code, &set_address, sizeof(ida90_set_event_code));
    memcpy(&ida90_copy_event, &copy_address, sizeof(ida90_copy_event));
    add_trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (add_trampoline == MAP_FAILED)
        goto done;
    memcpy(add_trampoline, "\xf3\x0f\x1e\xfa", 4);
    memcpy(add_trampoline + 4, add_bpt_signature, sizeof(add_bpt_signature));
    ida90_jump(add_trampoline + 4 + sizeof(add_bpt_signature),
               add_address + sizeof(add_bpt_signature));
    if (mprotect(add_trampoline, page_size, PROT_READ | PROT_EXEC) < 0)
        goto done;
    memcpy(&ida90_real_add_bpt, &add_trampoline, sizeof(ida90_real_add_bpt));
    del_trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (del_trampoline == MAP_FAILED) goto done;
    memcpy(del_trampoline, "\xf3\x0f\x1e\xfa", 4);
    memcpy(del_trampoline + 4, del_bpt_signature, sizeof(del_bpt_signature));
    ida90_jump(del_trampoline + 4 + sizeof(del_bpt_signature),
               del_address + sizeof(del_bpt_signature));
    if (mprotect(del_trampoline, page_size, PROT_READ | PROT_EXEC) < 0) goto done;
    memcpy(&ida90_real_del_bpt, &del_trampoline, sizeof(ida90_real_del_bpt));
    ida90_update_bpt_add_return = update_address + 0x10bu;
    ioctl_trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ioctl_trampoline == MAP_FAILED)
        goto done;
    memcpy(ioctl_trampoline, "\xf3\x0f\x1e\xfa", 4);
    memcpy(ioctl_trampoline + 4, ioctl_signature, sizeof(ioctl_signature));
    ida90_jump(ioctl_trampoline + 4 + sizeof(ioctl_signature),
               ioctl_address + sizeof(ioctl_signature));
    if (mprotect(ioctl_trampoline, page_size, PROT_READ | PROT_EXEC) < 0)
        goto done;
    memcpy(&ida90_real_ioctl, &ioctl_trampoline, sizeof(ida90_real_ioctl));
    continue_trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (continue_trampoline == MAP_FAILED) goto done;
    memcpy(continue_trampoline, "\xf3\x0f\x1e\xfa", 4);
    memcpy(continue_trampoline + 4, continue_signature, sizeof(continue_signature));
    ida90_jump(continue_trampoline + 4 + sizeof(continue_signature),
               continue_address + sizeof(continue_signature));
    if (mprotect(continue_trampoline, page_size, PROT_READ | PROT_EXEC) < 0) goto done;
    memcpy(&ida90_real_continue, &continue_trampoline, sizeof(ida90_real_continue));
    check_trampoline = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (check_trampoline == MAP_FAILED) goto done;
    memcpy(check_trampoline, "\xf3\x0f\x1e\xfa", 4);
    memcpy(check_trampoline + 4, check_events_signature, sizeof(check_events_signature));
    ida90_jump(check_trampoline + 4 + sizeof(check_events_signature),
               check_address + sizeof(check_events_signature));
    if (mprotect(check_trampoline, page_size, PROT_READ | PROT_EXEC) < 0) goto done;
    memcpy(&ida90_real_check_events, &check_trampoline, sizeof(ida90_real_check_events));
    /* Prepare every trampoline and every write permission before changing
     * any entry. A failed late mprotect must not leave an installed jump
     * pointing to a trampoline freed by the failure path. */
    const uintptr_t targets[] = {get_address, add_address, ioctl_address, del_address, continue_address, check_address};
    const size_t lengths[] = {sizeof(expected), sizeof(add_bpt_signature),
                              sizeof(ioctl_signature), sizeof(del_bpt_signature), 28, sizeof(check_events_signature)};
    const uintptr_t adapters[] = {(uintptr_t)ida90_get_event_adapter,
                                  (uintptr_t)ida90_add_bpt_adapter,
                                  (uintptr_t)ida90_ioctl_adapter,
                                  (uintptr_t)ida90_del_bpt_adapter,
                                  (uintptr_t)ida90_continue_adapter,
                                  (uintptr_t)ida90_check_events_adapter};
    for (size_t n = 0; n < 6; ++n) {
        uintptr_t first = targets[n] & ~(page_size - 1u);
        uintptr_t last = (targets[n] + lengths[n] - 1u) & ~(page_size - 1u);
        for (uintptr_t page = first; page <= last; page += page_size) {
            bool existing = false;
            for (size_t p = 0; p < writable_count; ++p)
                if (writable_pages[p] == page) existing = true;
            if (existing) continue;
            if (mprotect((void *)page, page_size,
                         PROT_READ | PROT_WRITE | PROT_EXEC) < 0)
                goto done;
            writable_pages[writable_count++] = page;
        }
    }
    for (size_t n = 0; n < 6; ++n) {
        ida90_jump((uint8_t *)targets[n], adapters[n]);
        memset((uint8_t *)targets[n] + 14, 0x90, lengths[n] - 14u);
        __builtin___clear_cache((char *)targets[n],
                                (char *)targets[n] + lengths[n]);
    }
    installed = true;
done:
    for (size_t p = 0; p < writable_count; ++p)
        if (mprotect((void *)writable_pages[p], page_size,
                     PROT_READ | PROT_EXEC) < 0)
            (void)fprintf(stderr, "[ida-vtdbg-shim] could not restore RX permission for adapter page\n");
    if (!installed && trampoline != MAP_FAILED)
        munmap(trampoline, page_size);
    if (!installed && add_trampoline != MAP_FAILED)
        munmap(add_trampoline, page_size);
    if (!installed && ioctl_trampoline != MAP_FAILED)
        munmap(ioctl_trampoline, page_size);
    if (!installed && del_trampoline != MAP_FAILED)
        munmap(del_trampoline, page_size);
    if (!installed && continue_trampoline != MAP_FAILED)
        munmap(continue_trampoline, page_size);
    if (!installed && check_trampoline != MAP_FAILED)
        munmap(check_trampoline, page_size);
    munmap(file, (size_t)status.st_size);
    (void)fprintf(stderr, "[ida-vtdbg-shim] runtime IDA event adapter %s (commercial ELF unchanged)\n",
                  installed ? "installed" : "unavailable: checked ABI mismatch");
    return installed;
}
