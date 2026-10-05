#include "joint_debug_abi.h"
#include "shared_event_reader.h"

#include <dlfcn.h>
#include <elf.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <libgen.h>
#include <linux/futex.h>
#include <stdatomic.h>
#include <sched.h>

#if !defined(__x86_64__)
#error "The IDA linux_server shim currently supports x86-64 only"
#endif

#ifndef PTRACE_GET_SYSCALL_INFO
#define PTRACE_GET_SYSCALL_INFO 0x420e
#endif
#define PTRACE_SYSCALL_INFO_NONE 0
#define PTRACE_SYSCALL_INFO_ENTRY 1
#define PTRACE_SYSCALL_INFO_EXIT 2
#define PTRACE_SYSCALL_INFO_SECCOMP 3

struct ptrace_syscall_info {
    uint8_t op;
    uint8_t pad[3];
    uint32_t arch;
    uint64_t instruction_pointer;
    uint64_t stack_pointer;
    union {
        struct {
            uint64_t nr;
            uint64_t args[6];
        } entry;
        struct {
            int64_t rval;
            uint8_t is_error;
        } exit;
        struct {
            uint64_t nr;
            uint64_t args[6];
            uint32_t ret_data;
        } seccomp;
    };
};

#define SHIM_MAX_TARGETS 256
#define SHIM_MAX_TIDS 512
#define SHIM_READ_CHUNK IDA_VTDBG_POLICY_MAX_BUFFER
#define SHIM_MAX_IOVECS 16

typedef long (*ptrace_fn)(enum __ptrace_request, ...);
typedef long (*syscall_fn)(long, ...);
typedef pid_t (*waitpid_fn)(pid_t, int *, int);
typedef pid_t (*wait4_fn)(pid_t, int *, int, struct rusage *);
typedef pid_t (*wait_fn)(int *);
typedef int (*waitid_fn)(idtype_t, id_t, siginfo_t *, int);
typedef pid_t (*fork_fn)(void);
typedef FILE *(*fopen_fn)(const char *, const char *);
typedef int (*execve_fn)(const char *, char *const[], char *const[]);
typedef int (*execveat_fn)(int, const char *, char *const[], char *const[],
                          int);
typedef int (*fexecve_fn)(int, char *const[], char *const[]);

struct shim_target {
    pid_t pid;
    pid_t tgid;
    pid_t owner_tid;
    unsigned int continue_count;
    bool startup_ready;
    bool anti_checks_started;
    bool active;
    /* Keep an exited target as a tombstone until IDA consumes its final
     * THREAD_EXITED/PROCESS_EXITED notifications. */
    bool exit_pending;
};

struct shim_tid {
    pid_t tid;
    bool active;
    bool syscall_phase_known;
    bool next_syscall_is_entry;
    bool emulate_result;
    int64_t emulated_result;
    bool filter_read;
    uint64_t read_buffer;
    size_t read_iovec_count;
    struct {
        uint64_t base;
        uint64_t length;
    } read_iovecs[SHIM_MAX_IOVECS];
};

static ptrace_fn real_ptrace;
static syscall_fn real_syscall;
static waitpid_fn real_waitpid;
static waitpid_fn real___waitpid;
static wait4_fn real_wait4;
static wait_fn real_wait;
static waitid_fn real_waitid;
static fork_fn real_fork;
static fopen_fn real_fopen;
static fopen_fn real_fopen64;
static execve_fn real_execve;
static execveat_fn real_execveat;
static fexecve_fn real_fexecve;
static pthread_once_t resolve_once = PTHREAD_ONCE_INIT;
static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static struct shim_target targets[SHIM_MAX_TARGETS];
static struct shim_tid tids[SHIM_MAX_TIDS];
static int policy_fd = -1;
struct shim_shared_map {
    int fd;
    struct ida_vtdbg_shared_ring *ring;
};
static struct shim_shared_map policy_shared = {
    .fd = -1,
    .ring = NULL,
};
static struct shim_shared_map worker_shared = {
    .fd = -1,
    .ring = NULL,
};
struct oneshot_shared_state {
    uint32_t magic;
    uint32_t armed;
    uint64_t address;
};
static int oneshot_shared_fd = -1;
static struct oneshot_shared_state *oneshot_shared;
static int nested_target_event_fd = -1;
static bool compat_enabled;
static bool test_policy;
static bool syscall_mediation;
static bool trace_enabled;
static bool event_trace_enabled;
static bool state_trace_enabled;
static bool handler_trace_enabled;
static bool repeat_handler_breakpoints;
static bool auto_continue_protocol;
static char handler_log_path[PATH_MAX];
static uintptr_t handler_text_start = 0x400000u;
static uintptr_t handler_text_end = 0x607000u;
static _Atomic unsigned long long handler_trace_sequence;
static bool nested_server;
static bool nested_target;
/* Optional target-owned protocol INT3 address presented as an IDA stop
 * without installing/removing an IDA software breakpoint on the 0xCC byte. */
static uintptr_t nested_protocol_int3_address;
static bool nested_kernel_events;
static bool nested_target_launcher;
static bool nested_event_worker;
static bool shared_memory_enabled;
static bool parent_owned_mode;
/* A long-lived linux_server inherits one regular stdin file description for
 * every start_process call.  Parent-owned fork targets normally read their
 * input from the fork child; after the first session that description is at
 * EOF, so a second session can take a different control-flow path before IDA
 * ever sees the configured algorithm breakpoint.  Rewind only regular-file
 * stdin in the target's fork child; TTYs/pipes and explicit opt-out are left
 * untouched. */
static bool replay_stdin_enabled;
static bool target_oneshot_overlay_enabled;
/* Optional one-shot breakpoint suppression used by the parent-owned
 * tradre validation path.  The breakpoint remains physically present until
 * the target's own ptrace VM restores it; we only stop replaying it into new
 * child views and make the current visible stop resumable. */
static bool oneshot_algorithm_enabled;
static uintptr_t oneshot_algorithm_address;
static bool oneshot_algorithm_done;
/* Direct-target mode is an opt-in compatibility path for samples such as
 * tradre that call PTRACE_TRACEME after fork.  linux_server remains the only
 * real ptrace owner; the injected child only sees a virtual success result. */
static bool direct_target_injection;
static bool direct_target;
static char shim_path[PATH_MAX];
static char nested_socket_path[PATH_MAX];
static __thread bool inside_wait_broker;
static __thread int child_exec_depth;
static __thread bool nested_skip_breakpoint_commit;
static __thread bool nested_direct_debug_register_rpc;
static __thread bool nested_syncing_breakpoint_provenance;
static __thread uint32_t nested_sync_breakpoint_flags;
static __thread size_t nested_sync_breakpoint_length;
static __thread uint8_t nested_sync_breakpoint_payload[IDA_VTDBG_COMMAND_PAYLOAD_MAX];
/* Set by the runtime IDA dbg_add_bpt adapter, never inferred from CC bytes. */
struct ida_bpt_request_context_state {
    bool active;
    bool client_update;
    int type;
    uintptr_t address;
    int32_t scope_pid;
    int32_t scope_tid;
};
static __thread struct ida_bpt_request_context_state ida_bpt_request_context;
static unsigned int target_peek_diag_count;

#define NESTED_MAGIC 0x5644544eU
#define NESTED_PAYLOAD_MAX 1024U
#define NESTED_QUEUE_MAX 128U
#define NESTED_BREAKPOINT_MAX 256U
#define PARENT_OWNED_COMMAND_F_PROTOCOL_ACK (1u << 31)
#define PARENT_OWNED_COMMAND_F_STEP_OBSERVE (1u << 30)
#define PARENT_OWNED_COMMAND_F_EXCEPTION_OBSERVE (1u << 29)
#define PARENT_OWNED_COMMAND_F_HARDWARE_STEP (1u << 28)
#define PARENT_OWNED_COMMAND_F_STALE_PROTOCOL_RIP (1u << 27)
#define PARENT_OWNED_COMMAND_F_DEBUGGER_WRITE (1u << 26)
#define PARENT_OWNED_COMMAND_F_GENERIC_HW_STEP (1u << 25)
#define PARENT_OWNED_COMMAND_F_CANCEL_CALL_OVER (1u << 24)
#define PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS (1u << 23)
#define PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS_FIRST (1u << 22)
#define PARENT_OWNED_COMMAND_SYNC_BREAKPOINTS IDA_VTDBG_COMMAND_SYNC_BREAKPOINTS

struct nested_debugger_write_metadata {
    uint8_t original[sizeof(uintptr_t)];
    uint8_t recorded_mask;
};

struct nested_debugger_bp_metadata {
    uintptr_t address;
    uint8_t original;
    uint8_t reserved[7];
};

struct nested_async_resume {
    struct ida_vtdbg_ptrace_command action;
    struct ida_vtdbg_ptrace_command inflight;
    struct nested_debugger_bp_metadata metadata[NESTED_BREAKPOINT_MAX];
    size_t metadata_count, metadata_offset;
    uint64_t metadata_revision;
    bool captured, submitted, action_submitted, local_failure;
};
static pthread_mutex_t nested_async_lock = PTHREAD_MUTEX_INITIALIZER;
static struct nested_async_resume *nested_async_resumes[NESTED_QUEUE_MAX];
static size_t nested_async_count;
static _Atomic uint64_t nested_breakpoint_revision;
static void nested_async_resume_pump(void);
static long nested_async_resume_enqueue(const struct ida_vtdbg_ptrace_command *action);

enum nested_packet_type {
    NESTED_HELLO = 1,
    NESTED_EVENT = 2,
    NESTED_COMMAND = 3,
    NESTED_RESPONSE = 4,
};

#define NESTED_EVENT_HELLO 1u
#define NESTED_EVENT_FORK 2u
#define NESTED_EVENT_WAIT 3u
#define NESTED_EVENT_PTRACE 4u

struct nested_packet {
    uint32_t magic;
    uint32_t type;
    uint32_t request;
    uint32_t flags;
    int32_t pid;
    int32_t aux_pid;
    int32_t status;
    int32_t error;
    uint64_t addr;
    uint64_t data;
    uint64_t length;
    uint64_t value;
    uint32_t payload_len;
    uint32_t owner_tid;
    uint8_t payload[NESTED_PAYLOAD_MAX];
};

struct nested_user_breakpoint {
    uintptr_t address;
    uint8_t original_byte;
    bool active;
    bool suppressed;
    uint64_t restore_pending_mask[(NESTED_QUEUE_MAX + 63u) / 64u];
};

/* IDA uses a one-shot debug-register breakpoint to implement F8 over a
 * target-owned INT3.  In parent-owned mode that breakpoint belongs to a
 * shadow child, while linux_server may issue POKEUSER against the outer pid.
 * Track this narrow step-over request and translate its CONT into the
 * parent's native protocol-resume path instead of programming DR0/DR7. */
struct nested_protocol_hw_step {
    pid_t request_pid;
    pid_t child_pid;
    uintptr_t target;
    uintptr_t debug_regs[8];
    bool protocol;
    bool active;
    bool resume_issued;
    bool completed;
};

struct nested_generic_hw_step {
    pid_t request_pid;
    pid_t child_pid;
    uintptr_t target;
    bool active;
};

/* Explicit IDA processor step-over notification, supplied by our small
 * IDAPython adapter. The stock RPC has identical user/F8 bpt fields. */
struct nested_ida_step_intent {
    pid_t child;
    uintptr_t ip;
    bool active;
    bool prefer_software;
};

struct nested_ida_software_step {
    uintptr_t address;
    uint8_t original;
    pid_t child;
    bool protocol;
    bool active;
};

struct nested_breakpoint_write {
    pid_t pid;
    uintptr_t address;
    uintptr_t before;
    uintptr_t after;
    bool valid;
};

struct nested_queued_event {
    pid_t pid;
    int status;
    pid_t aux_pid;
    bool virtual_fork;
    bool initial_stop;
};

struct nested_virtual_fork {
    pid_t parent_pid;
    pid_t child_pid;
    bool active;
    bool event_delivered;
    bool message_pending;
    bool resume_requested;
    bool outer_stop_held;
    bool child_attach_ready;
    bool child_initial_delivered;
};

struct parent_owned_child_state {
    pid_t pid;
    pid_t owner_tid;
    bool active;
    bool initial_proxy_pending;
    bool initial_stop_visible;
    bool step_after_protocol;
    bool proxy_step_pending;
    bool oneshot_visible;
    bool proxy_stop_held;
    bool debugger_resume_accepted;
    bool exit_event_queued;
    /* The source belongs to a physical stop, not to the mutable IDA RIP or
     * breakpoint table. IDA rewinds RIP and temporarily deletes an ordinary
     * software breakpoint before F7/F8/F9 resumes that SAME stop. */
    uint64_t stop_source_sequence;
    bool stop_source_captured;
    bool debugger_owned_stop;
    uintptr_t stop_source_rip;
    uintptr_t stop_source_address;
    int stop_source_code;
    bool protocol_int3_stop;
    uintptr_t protocol_int3_address;
    bool program_exception_stop;
    int program_exception_signal;
    int program_exception_code;
    uintptr_t program_exception_rip;
    bool exception_resume_pending;
    uintptr_t exception_resume_rip;
    /* A real parent-owned protocol stop has been consumed and the target
     * parent is redirecting the child to its selected resume address.  While
     * that resume is in flight, the kernel event ring can still contain the
     * old post-INT3 stop; remember its RIP so the server does not re-present
     * it as a fresh debugger event. */
    bool resume_observation_inflight;
    uintptr_t resume_stale_rip;
    uintptr_t resume_expected_rip;
    bool synthetic_step_stop;
    bool synthetic_trace_stop;
    uintptr_t synthetic_step_address;
    uintptr_t last_synthetic_step_address;
    unsigned int resume_request;
    bool traceme_pending;
    uintptr_t trace_anchor_rbp;
};

struct parent_owned_owner_state {
    pid_t tid;
    struct user_regs_struct regs;
    bool active;
    bool regs_valid;
    bool virtual_stop;
};

struct nested_target_protocol_step_state {
    pid_t child;
    uintptr_t address;
    uintptr_t aligned;
    uint8_t original_byte;
    uintptr_t stale_address;
    bool requested;
    bool armed;
    bool trace_step_pending;
};

#define PARENT_OWNED_RESUME_NONE 0u
#define PARENT_OWNED_RESUME_CONT 1u
#define PARENT_OWNED_RESUME_STEP 2u
#define PARENT_OWNED_RESUME_PROTOCOL 3u

static pthread_mutex_t nested_io_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nested_event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t nested_driver_command_lock = PTHREAD_MUTEX_INITIALIZER;
/* Serialize physical SW-BP transactions with event-ring replay. The native
 * broker must never wait on this lock: replay uses trylock and is retried at
 * the next stopped query/action, while IDA's own add/del owns the transaction. */
static pthread_mutex_t nested_breakpoint_memory_lock = PTHREAD_MUTEX_INITIALIZER;
static __thread unsigned int nested_breakpoint_memory_depth;

static void nested_breakpoint_memory_begin(void)
{
    if (nested_breakpoint_memory_depth++ == 0)
        pthread_mutex_lock(&nested_breakpoint_memory_lock);
}

static void nested_breakpoint_memory_end(void)
{
    if (--nested_breakpoint_memory_depth == 0)
        pthread_mutex_unlock(&nested_breakpoint_memory_lock);
}
static int nested_listen_fd = -1;
static int nested_conn_fd = -1;
static int nested_worker_event_fd = -1;
static int nested_worker_listen_fd = -1;
static int nested_worker_conn_fd = -1;
static int nested_pending_target_fd = -1;
static char nested_worker_socket_path[PATH_MAX];
static struct nested_queued_event nested_events[NESTED_QUEUE_MAX];
static size_t nested_event_count;
/* Memory-only diagnostic journal: records event ownership without logging
 * I/O, sleeps or changes to debugger behavior. Inspect after an assertion. */
struct nested_event_audit_entry {
    uint64_t order, sequence;
    uint32_t operation, flags;
    pid_t pid, caller;
    int status;
    uintptr_t rip;
};
static volatile struct nested_event_audit_entry nested_event_audit[128];
static volatile uint64_t nested_event_audit_order;
static void nested_event_audit_locked(uint32_t operation, pid_t pid, int status,
                                      uint32_t flags, uint64_t sequence, uintptr_t rip)
{
    uint64_t order = ++nested_event_audit_order;
    nested_event_audit[(order - 1u) % 128u] = (struct nested_event_audit_entry){
        .order = order, .sequence = sequence, .operation = operation,
        .flags = flags, .pid = pid, .caller = gettid(), .status = status, .rip = rip,
    };
}
static pid_t nested_shadow_pids[NESTED_QUEUE_MAX];
static size_t nested_shadow_count;
static struct nested_virtual_fork nested_virtual_forks[NESTED_QUEUE_MAX];
static struct parent_owned_child_state parent_owned_children[NESTED_QUEUE_MAX];
static struct parent_owned_owner_state parent_owned_owners[NESTED_QUEUE_MAX];
static struct nested_target_protocol_step_state nested_target_protocol_step;
static struct nested_user_breakpoint nested_user_breakpoints[
    NESTED_BREAKPOINT_MAX];
static struct nested_protocol_hw_step nested_protocol_hw_steps[
    NESTED_QUEUE_MAX];
static struct nested_generic_hw_step nested_generic_hw_steps[NESTED_QUEUE_MAX];
static struct nested_ida_step_intent nested_ida_step_intents[NESTED_QUEUE_MAX];
static struct nested_ida_software_step nested_ida_software_steps[NESTED_QUEUE_MAX];
static _Atomic bool nested_parent_real_stopped;
static _Atomic bool nested_parent_debug_event_presented;
static __thread bool nested_parent_resume_scope;
/* A native parent stop may be consumed by child_waiter during an unrelated
 * child F8/BP update, before IDA has displayed it. Thaw is then only an
 * action ACK: never physically resume this parent until its event is shown. */
static _Atomic bool nested_parent_stop_unpresented;
static bool parent_owned_wait_view(pid_t tid, struct user_regs_struct *regs);
static bool parent_owned_wait_query(pid_t tid,
                                    struct ida_vtdbg_owner_wait_context *context);
static _Atomic bool nested_parent_trace_requested;
static pid_t nested_target_owner_tid;
static pid_t nested_target_child_pid;
static pid_t nested_server_owner_tid;
static pid_t nested_server_outer_pid;
static pid_t nested_event_subscription_pid;
/* Keep the last parent/child proxy metadata alive until IDA has consumed the
 * final THREAD_EXITED/PROCESS_EXITED events.  Resetting it at the first real
 * parent exit leaves IDA's selected child TID without a shadow record and
 * produces "selected thread not available" during teardown. */
static bool nested_server_session_end_pending;
static pid_t nested_server_session_end_root;
static _Atomic bool nested_parent_kernel_exit_confirmed;
static bool parent_owned_process_exit_pending;
static pid_t parent_owned_process_exit_root;
static pid_t parent_owned_process_exit_children[NESTED_QUEUE_MAX];
static size_t parent_owned_process_exit_child_count;
static pthread_t nested_kernel_poller_thread;
static bool nested_kernel_poller_started;
static volatile bool nested_kernel_poller_running;
static pthread_mutex_t nested_kernel_poll_lock = PTHREAD_MUTEX_INITIALIZER;
/* Native wait statuses can arrive while the main IDA backend is thawing or
 * installing a breakpoint. Never let child_waiter mutate that backend's
 * thread state inside such a transaction. Keep the real stop, publish later. */
static _Atomic unsigned int nested_ida_transaction_depth;
static pthread_mutex_t nested_native_stop_lock = PTHREAD_MUTEX_INITIALIZER;
static struct nested_queued_event nested_native_stops[NESTED_QUEUE_MAX];
static size_t nested_native_stop_count;

static void nested_ida_transaction_begin(void)
{
    pthread_mutex_lock(&nested_native_stop_lock);
    atomic_fetch_add_explicit(&nested_ida_transaction_depth, 1, memory_order_acq_rel);
    pthread_mutex_unlock(&nested_native_stop_lock);
}

static void nested_ida_transaction_end(void)
{
    atomic_fetch_sub_explicit(&nested_ida_transaction_depth, 1, memory_order_release);
}

static bool nested_native_stop_take(pid_t requested, int *status, pid_t *tid)
{
    bool found = false;
    pthread_mutex_lock(&nested_native_stop_lock);
    if (atomic_load_explicit(&nested_ida_transaction_depth, memory_order_acquire) == 0) {
        for (size_t n = 0; n < nested_native_stop_count; ++n) {
            if (requested > 0 && nested_native_stops[n].pid != requested) continue;
            *tid = nested_native_stops[n].pid;
            *status = nested_native_stops[n].status;
            memmove(nested_native_stops + n, nested_native_stops + n + 1,
                    (--nested_native_stop_count - n) * sizeof(nested_native_stops[0]));
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_native_stop_lock);
    return found;
}

static bool nested_native_stop_defer(pid_t tid, int status)
{
    bool deferred = false;
    pthread_mutex_lock(&nested_native_stop_lock);
    if (atomic_load_explicit(&nested_ida_transaction_depth, memory_order_acquire) != 0 &&
        nested_native_stop_count < NESTED_QUEUE_MAX) {
        nested_native_stops[nested_native_stop_count++] = (struct nested_queued_event){
            .pid = tid, .status = status,
        };
        deferred = true;
    }
    pthread_mutex_unlock(&nested_native_stop_lock);
    return deferred;
}

static struct parent_owned_child_state *parent_owned_child_locked(pid_t pid,
                                                                   bool create)
{
    struct parent_owned_child_state *free_slot = NULL;

    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        if (parent_owned_children[index].active &&
            parent_owned_children[index].pid == pid)
            return &parent_owned_children[index];
        if (!parent_owned_children[index].active && free_slot == NULL)
            free_slot = &parent_owned_children[index];
    }
    if (!create || free_slot == NULL)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->active = true;
    free_slot->pid = pid;
    return free_slot;
}

static struct parent_owned_owner_state *parent_owned_owner_locked(
    pid_t tid, bool create)
{
    struct parent_owned_owner_state *free_slot = NULL;

    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        if (parent_owned_owners[index].active &&
            parent_owned_owners[index].tid == tid)
            return &parent_owned_owners[index];
        if (!parent_owned_owners[index].active && free_slot == NULL)
            free_slot = &parent_owned_owners[index];
    }
    if (!create || free_slot == NULL)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->active = true;
    free_slot->tid = tid;
    return free_slot;
}

static void parent_owned_owner_capture_regs(
    pid_t tid, const struct user_regs_struct *regs)
{
    if (tid <= 0 || regs == NULL)
        return;
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_owner_state *owner =
            parent_owned_owner_locked(tid, true);
        if (owner != NULL) {
            owner->regs = *regs;
            owner->regs_valid = true;
            /* The outer task is resumed after the broker captures this
             * SIGCHLD stop.  Keep the snapshot as an IDA-readable virtual
             * stop until IDA acknowledges it with CONT. */
            owner->virtual_stop = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_owner_copy_regs(pid_t tid,
                                         struct user_regs_struct *regs)
{
    bool copied = false;

    if (tid <= 0 || regs == NULL)
        return false;
    if (tid == nested_server_outer_pid &&
        (atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire) ||
         atomic_load_explicit(&nested_parent_debug_event_presented, memory_order_acquire)))
        return false;
    if (parent_owned_wait_view(tid, regs))
        return true;
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_owner_state *owner =
            parent_owned_owner_locked(tid, false);
        if (owner != NULL && owner->virtual_stop && owner->regs_valid) {
            *regs = owner->regs;
            copied = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return copied;
}

static bool parent_owned_owner_consume_virtual_resume(pid_t tid)
{
    bool consumed = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_owner_state *owner =
            parent_owned_owner_locked(tid, false);
        if (owner != NULL && owner->virtual_stop) {
            owner->virtual_stop = false;
            consumed = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return consumed;
}

static void parent_owned_owner_real_stop(pid_t tid)
{
    pthread_mutex_lock(&nested_event_lock);
    struct parent_owned_owner_state *owner = parent_owned_owner_locked(tid, false);
    if (owner != NULL) {
        /* SIGCHLD snapshots only describe a virtual stop while the parent
         * runs its VM. A subsequent native wait STOP is authoritative: IDA
         * must read actual regs and really CONT the task, not acknowledge a
         * stale virtual snapshot. */
        owner->virtual_stop = false;
        owner->regs_valid = false;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static void parent_owned_note_unpresented_stop(pid_t tid, int status)
{
    if (!nested_server || tid != nested_server_outer_pid ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        ((unsigned int)status >> 16) != 0)
        return;
    pthread_mutex_lock(&nested_event_lock);
    bool joint_view = nested_shadow_count != 0;
    pthread_mutex_unlock(&nested_event_lock);
    if (joint_view)
        atomic_store_explicit(&nested_parent_stop_unpresented, true, memory_order_release);
}

static void event_trace_log(const char *format, ...);
static long ptrace_internal(enum __ptrace_request request, pid_t pid,
                            void *addr, void *data);
static long nested_driver_forward_ptrace(enum __ptrace_request request,
                                         pid_t pid, void *addr, void *data);
static bool nested_server_should_observe_parent_resume(pid_t child,
                                                       uintptr_t *rip_out);
static bool nested_server_should_observe_program_exception(pid_t child);
static bool nested_breakpoint_address_known(uintptr_t address,
                                            uint8_t *original);

static bool parent_owned_virtual_owner_ptrace(
    enum __ptrace_request request, pid_t tid, void *data, long *result)
{
    if (!parent_owned_mode || (!nested_event_worker && !nested_server) ||
        result == NULL)
        return false;
    if (request == PTRACE_GETREGS && data != NULL &&
        parent_owned_owner_copy_regs(tid,
                                     (struct user_regs_struct *)data)) {
        *result = 0;
        return true;
    }
    if ((request == PTRACE_CONT || request == PTRACE_SYSCALL) &&
        parent_owned_owner_consume_virtual_resume(tid)) {
        /* A real SIGSTOP can become pending after the SIGCHLD snapshot was
         * captured (for example IDA's freeze pass as a child exits). A
         * virtual acknowledgement must not strand that real ptrace stop.
         * The kernel, on the actual tracer thread, determines whether CONT
         * is needed: success resumes it; ESRCH means it is already running
         * or gone. No elapsed-time or procfs-state guess is involved. */
        if (nested_server) {
            int saved_errno = errno;
            long resumed = ptrace_internal(request, tid, NULL, data);
            int resume_error = resumed < 0 ? errno : 0;
            event_trace_log("[ida-vtdbg-shim] virtual owner resume verified tid=%d request=%d result=%ld errno=%d\n",
                            tid, request, resumed, resume_error);
            if (resumed < 0 && resume_error != ESRCH) {
                *result = -1;
                return true;
            }
            errno = saved_errno;
        }
        if (request == PTRACE_CONT && nested_server) {
            pid_t held_children[NESTED_QUEUE_MAX];
            size_t held_count = 0;

            pthread_mutex_lock(&nested_event_lock);
            for (size_t index = 0; index < nested_shadow_count &&
                                    held_count < NESTED_QUEUE_MAX; ++index) {
                pid_t child = nested_shadow_pids[index];
                struct parent_owned_child_state *state =
                    parent_owned_child_locked(child, false);

                if (state != NULL && state->active &&
                    state->owner_tid == tid && state->proxy_stop_held)
                    held_children[held_count++] = child;
            }
            pthread_mutex_unlock(&nested_event_lock);

            for (size_t index = 0; index < held_count; ++index) {
                uintptr_t resume_rip = 0;

                if (!nested_server_should_observe_parent_resume(
                        held_children[index], &resume_rip) ||
                    !nested_breakpoint_address_known(resume_rip, NULL))
                    continue;
                event_trace_log("[ida-vtdbg-shim] owner CONT triggers protocol-resume observer owner=%d child=%d resume=0x%llx\n",
                                tid, held_children[index],
                                (unsigned long long)resume_rip);
                (void)nested_driver_forward_ptrace(
                    PTRACE_CONT, held_children[index], NULL, NULL);
            }
        }
        *result = 0;
        return true;
    }
    return false;
}

static void parent_owned_set_owner_tid(pid_t child, pid_t owner_tid)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(child, true);
        if (state != NULL && owner_tid > 0)
            state->owner_tid = owner_tid;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool nested_breakpoint_address_recorded(uintptr_t address,
                                               uint8_t *original);
static void nested_propagate_breakpoint_delta_to_child(
    pid_t parent, pid_t child, uintptr_t address, uintptr_t value,
    uintptr_t before_word, bool before_valid);

static pid_t parent_owned_get_owner_tid(pid_t child)
{
    pid_t owner_tid = 0;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(child, false);
        if (state != NULL)
            owner_tid = state->owner_tid;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return owner_tid > 0 ? owner_tid : nested_target_owner_tid;
}

/* A PTRACE_TRACEME handshake stop is normally hidden from IDA, but an
 * explicit user breakpoint at the child's entry must remain visible.  The
 * target reports the handshake flag before the server has a normal event;
 * use the stopped child's architectural RIP and logical breakpoint table to
 * distinguish the two cases without guessing from adjacent 0xCC padding. */
static bool parent_owned_traceme_stop_has_user_breakpoint(pid_t child)
{
    struct user_regs_struct regs;
    uintptr_t candidates[2];

    if (child <= 0 || !parent_owned_mode || !nested_server)
        return false;
    memset(&regs, 0, sizeof(regs));
    if (nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0 ||
        regs.rip == 0)
        return false;
    candidates[0] = (uintptr_t)regs.rip;
    candidates[1] = regs.rip > 0 ? (uintptr_t)regs.rip - 1u : 0;
    for (size_t index = 0; index < 2; ++index) {
        uint8_t original = 0;

        if (candidates[index] != 0 &&
            nested_breakpoint_address_recorded(candidates[index],
                                               &original) &&
            original != 0xccu) {
            event_trace_log("[ida-vtdbg-shim] expose TRACEME stop as user breakpoint child=%d rip=0x%llx bpt=0x%llx original=0x%02x\n",
                            child, (unsigned long long)regs.rip,
                            (unsigned long long)candidates[index],
                            (unsigned int)original);
            return true;
        }
    }
    return false;
}

static void parent_owned_set_initial_visible(pid_t child, bool visible)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(child, visible);
        if (state != NULL)
            state->initial_stop_visible = visible;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_initial_visible(pid_t child)
{
    bool visible = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(child, false);
        if (state != NULL)
            visible = state->initial_stop_visible;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return visible;
}

static void parent_owned_begin_physical_stop(pid_t child, uint64_t sequence)
{
    pthread_mutex_lock(&nested_event_lock);
    struct parent_owned_child_state *state = parent_owned_child_locked(child, true);
    if (state != NULL && state->stop_source_sequence != sequence) {
        state->stop_source_sequence = sequence;
        state->stop_source_captured = false;
        state->debugger_owned_stop = false;
        state->stop_source_rip = state->stop_source_address = 0;
        state->stop_source_code = 0;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static void parent_owned_capture_stop_source(pid_t child, bool debugger_owned,
                                             uintptr_t rip, uintptr_t address,
                                             int si_code)
{
    pthread_mutex_lock(&nested_event_lock);
    struct parent_owned_child_state *state = parent_owned_child_locked(child, true);
    if (state != NULL && !state->stop_source_captured) {
        state->stop_source_captured = true;
        state->debugger_owned_stop = debugger_owned;
        state->stop_source_rip = rip;
        state->stop_source_address = address;
        state->stop_source_code = si_code;
        nested_event_audit_locked(6, child, si_code, debugger_owned ? 1u : 0u,
                                  state->stop_source_sequence, rip);
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_debugger_owned_stop(pid_t child)
{
    bool owned = false;
    pthread_mutex_lock(&nested_event_lock);
    const struct parent_owned_child_state *state = parent_owned_child_locked(child, false);
    if (state != NULL)
        owned = state->stop_source_captured && state->debugger_owned_stop;
    pthread_mutex_unlock(&nested_event_lock);
    return owned;
}

/* A root breakpoint write must never be mistaken for IDA's replay of the
 * synthetic child.  The replay guard is valid only while the child fork
 * record is active and its initial stop is still pending. */
static bool parent_owned_initial_replay_pending(pid_t child)
{
    bool pending = false;

    if (!parent_owned_mode || child <= 0)
        return false;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        const struct nested_virtual_fork *fork_event =
            &nested_virtual_forks[index];
        if (!fork_event->active || fork_event->child_pid != child)
            continue;
        pending = !fork_event->child_attach_ready &&
                  !fork_event->child_initial_delivered;
        break;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static void parent_owned_set_traceme_pending(pid_t child, bool pending)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(child, pending);
        if (state != NULL)
            state->traceme_pending = pending;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_take_traceme_pending(pid_t child)
{
    bool pending = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(child, false);
        if (state != NULL && state->traceme_pending) {
            state->traceme_pending = false;
            pending = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static bool parent_owned_has_initial_child_pending(void)
{
    bool pending = false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        const struct parent_owned_child_state *state =
            &parent_owned_children[index];
        if (state->active &&
            (state->initial_proxy_pending || state->initial_stop_visible)) {
            pending = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static void parent_owned_mark_virtual_outer_stop_held(pid_t parent)
{
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        struct nested_virtual_fork *fork_event = &nested_virtual_forks[index];
        if (fork_event->active && fork_event->event_delivered &&
            fork_event->parent_pid == parent) {
            fork_event->outer_stop_held = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static void parent_owned_request_step_after_protocol(pid_t pid)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, true);
        if (state != NULL)
            state->step_after_protocol = true;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static void parent_owned_mark_initial_proxy(pid_t pid)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, true);
        if (state != NULL)
            state->initial_proxy_pending = true;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_take_initial_proxy(pid_t pid)
{
    bool pending = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->initial_proxy_pending) {
            state->initial_proxy_pending = false;
            pending = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static bool parent_owned_take_step_after_protocol(pid_t pid)
{
    bool step = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->step_after_protocol) {
            state->step_after_protocol = false;
            state->proxy_step_pending = true;
            step = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return step;
}

static bool parent_owned_proxy_step_pending(pid_t pid, bool clear)
{
    bool pending = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL) {
            pending = state->proxy_step_pending;
            if (pending && clear)
                state->proxy_step_pending = false;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static void parent_owned_set_oneshot_visible(pid_t pid, bool visible)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, visible);
        if (state != NULL)
            state->oneshot_visible = visible;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_oneshot_visible(pid_t pid)
{
    bool visible = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL)
            visible = state->oneshot_visible;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return visible;
}

static void parent_owned_set_synthetic_step_stop(pid_t pid, bool active,
                                                 uintptr_t address, bool trace)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, active);
        if (state != NULL) {
            state->synthetic_step_stop = active;
            state->synthetic_trace_stop = active && trace;
            state->synthetic_step_address = active ? address : 0;
            if (active)
                state->last_synthetic_step_address = address;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_get_synthetic_step_stop(pid_t pid,
                                                uintptr_t *address)
{
    bool active = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->synthetic_step_stop) {
            active = true;
            if (address != NULL)
                *address = state->synthetic_step_address;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return active;
}

static bool parent_owned_synthetic_is_trace(pid_t pid)
{
    bool trace = false;
    pthread_mutex_lock(&nested_event_lock);
    struct parent_owned_child_state *state = parent_owned_child_locked(pid, false);
    if (state != NULL)
        trace = state->synthetic_step_stop && state->synthetic_trace_stop;
    pthread_mutex_unlock(&nested_event_lock);
    return trace;
}

static void parent_owned_set_protocol_int3_stop(pid_t pid, bool active,
                                                uintptr_t address)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, active);
        if (state != NULL) {
            state->protocol_int3_stop = active;
            state->protocol_int3_address = active ? address : 0;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_get_protocol_int3_stop(pid_t pid,
                                                 uintptr_t *address)
{
    bool active = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->protocol_int3_stop) {
            active = true;
            if (address != NULL)
                *address = state->protocol_int3_address;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return active;
}

static void parent_owned_set_program_exception(pid_t pid, bool active,
                                               int signal_number, int si_code,
                                               uintptr_t rip)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, active);
        if (state != NULL) {
            state->program_exception_stop = active;
            state->program_exception_signal = active ? signal_number : 0;
            state->program_exception_code = active ? si_code : 0;
            state->program_exception_rip = active ? rip : 0;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_get_program_exception(pid_t pid,
                                               uintptr_t *rip,
                                               int *signal_number,
                                               int *si_code)
{
    bool active = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->program_exception_stop) {
            active = true;
            if (rip != NULL)
                *rip = state->program_exception_rip;
            if (signal_number != NULL)
                *signal_number = state->program_exception_signal;
            if (si_code != NULL)
                *si_code = state->program_exception_code;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return active;
}

static void parent_owned_clear_program_exception(pid_t pid)
{
    parent_owned_set_program_exception(pid, false, 0, 0, 0);
}

static void parent_owned_set_exception_resume(pid_t pid, bool active,
                                              uintptr_t rip)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, active);
        if (state != NULL) {
            state->exception_resume_pending = active;
            state->exception_resume_rip = active ? rip : 0;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_get_exception_resume(pid_t pid, uintptr_t *rip)
{
    bool active = false;
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->exception_resume_pending) {
            active = true;
            if (rip != NULL)
                *rip = state->exception_resume_rip;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return active;
}

static bool parent_owned_consume_exception_resume(pid_t pid,
                                                  uintptr_t *rip)
{
    bool active = false;
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->exception_resume_pending) {
            active = true;
            if (rip != NULL)
                *rip = state->exception_resume_rip;
            state->exception_resume_pending = false;
            state->exception_resume_rip = 0;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return active;
}

static void parent_owned_set_resume_observation(pid_t pid, bool active,
                                                uintptr_t stale_rip,
                                                uintptr_t expected_rip)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, active);
        if (state != NULL) {
            state->resume_observation_inflight = active;
            state->resume_stale_rip = active ? stale_rip : 0;
            state->resume_expected_rip = active ? expected_rip : 0;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool parent_owned_get_resume_observation(pid_t pid,
                                                uintptr_t *stale_rip,
                                                uintptr_t *expected_rip)
{
    bool active = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->resume_observation_inflight) {
            active = true;
            if (stale_rip != NULL)
                *stale_rip = state->resume_stale_rip;
            if (expected_rip != NULL)
                *expected_rip = state->resume_expected_rip;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return active;
}

static bool parent_owned_consume_resume_observation(pid_t pid)
{
    bool active = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->resume_observation_inflight) {
            state->resume_observation_inflight = false;
            state->resume_stale_rip = 0;
            state->resume_expected_rip = 0;
            active = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (active)
        event_trace_log("[ida-vtdbg-shim] resume observation completed child=%d\n",
                        pid);
    return active;
}

static bool parent_owned_consume_synthetic_step_stop(pid_t pid)
{
    bool active = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->synthetic_step_stop) {
            state->synthetic_step_stop = false;
            state->synthetic_trace_stop = false;
            state->synthetic_step_address = 0;
            active = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (active)
        event_trace_log("[ida-vtdbg-shim] consumed synthetic step stop child=%d\n",
                        pid);
    return active;
}

static uintptr_t parent_owned_last_synthetic_step_address(pid_t pid)
{
    uintptr_t address = 0;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL)
            address = state->last_synthetic_step_address;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return address;
}

static bool parent_owned_proxy_stop_held(pid_t pid, bool set, bool value)
{
    bool held = false;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, set);
        if (state != NULL) {
            if (set) {
                state->proxy_stop_held = value;
            }
            held = state->proxy_stop_held;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return held;
}

static void parent_owned_debugger_stop_presented(pid_t child)
{
    pthread_mutex_lock(&nested_event_lock);
    nested_event_audit_locked(3, child, 0, 0, 0, 0);
    struct parent_owned_child_state *state = parent_owned_child_locked(child, false);
    if (state != NULL) state->debugger_resume_accepted = false;
    pthread_mutex_unlock(&nested_event_lock);
}

static void parent_owned_set_resume_request(pid_t pid,
                                            unsigned int request)
{
    unsigned int mapped = PARENT_OWNED_RESUME_NONE;
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, true);
        if (state != NULL) {
            if (request == PTRACE_SINGLESTEP)
                mapped = state->resume_request = PARENT_OWNED_RESUME_STEP;
            else if (request == PTRACE_CONT || request == PTRACE_SYSCALL)
                mapped = state->resume_request = PARENT_OWNED_RESUME_CONT;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] resume request set pid=%d req=%u mapped=%u process=%d\n",
                    pid, request, mapped, getpid());
}

static void parent_owned_set_protocol_request(pid_t pid)
{
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, true);
        if (state != NULL)
            state->resume_request = PARENT_OWNED_RESUME_PROTOCOL;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static unsigned int parent_owned_take_resume_request(pid_t pid)
{
    unsigned int request = PARENT_OWNED_RESUME_NONE;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL) {
            request = state->resume_request;
            state->resume_request = PARENT_OWNED_RESUME_NONE;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (request != PARENT_OWNED_RESUME_NONE)
        event_trace_log("[ida-vtdbg-shim] resume request take pid=%d value=%u process=%d\n",
                        pid, request, getpid());
    return request;
}

static struct shim_target *find_target_locked(pid_t pid);
static long ptrace_dispatch(enum __ptrace_request request, pid_t pid,
                            void *addr, void *data);
static long ptrace_via_owner(pid_t owner, enum __ptrace_request request,
                             pid_t pid, void *addr, void *data);
static bool nested_resume_request(enum __ptrace_request request);
static bool tid_is_compat(pid_t tid);
static bool note_continue_and_should_mediate(pid_t pid);
static void register_best_effort(pid_t pid);
static void unregister_tid_best_effort(pid_t tid);
static pid_t current_tid(void);
static bool shim_is_linux_server_image(void);
static bool target_startup_ready(pid_t pid);
static bool restore_running_parent_word(pid_t pid, void *addr, void *data);
static bool nested_breakpoint_word_registered(uintptr_t address);
static long server_ptrace_call(enum __ptrace_request request, pid_t pid,
                               void *addr, void *data);
static void set_target_owner(pid_t pid, pid_t owner);
static void prepare_fork_child(pid_t pid);
static pid_t tracer_pid_of(pid_t tid);
static void mark_anti_checks_started(pid_t pid);
static bool anti_checks_started(pid_t pid);
static int nested_server_setup(void);
static int nested_target_connect(void);
static int nested_parent_driver_setup(void);
static void nested_server_subscribe_events(pid_t target);
static void nested_server_reset_parent_owned_session(void);
static void nested_server_reset_parent_owned_session_from_poll(void);
static void nested_server_finalize_deferred_session(void);
static void nested_target_report_child(pid_t child, int status);
static void nested_poll_messages(void);
static bool nested_pop_event(pid_t requested, int *status, pid_t *event_pid);
static bool nested_is_shadow(pid_t pid);
static bool nested_kernel_child_stopped(pid_t child);
static bool nested_kernel_stopped_ptrace(enum __ptrace_request request,
                                        pid_t child, void *addr, void *data,
                                        long *result);
static bool nested_server_is_owner_thread(void);
static void nested_server_wake_outer_target(void);
static bool nested_virtual_ptrace(enum __ptrace_request request, pid_t pid,
                                  void *data, long *result);
static void nested_note_parent_breakpoint_write(pid_t pid, void *addr,
                                                void *data, long result,
                                                const struct nested_breakpoint_write *write);
static bool nested_breakpoint_word_registered(uintptr_t address);
static bool nested_breakpoint_address_recorded(uintptr_t address,
                                               uint8_t *original);
static bool nested_protocol_hw_step_write(pid_t pid, uintptr_t offset,
                                          uintptr_t value);
static bool nested_protocol_hw_step_peek(pid_t pid, uintptr_t offset,
                                         uintptr_t *value);
static bool nested_protocol_hw_step_pending(pid_t pid);
static bool nested_generic_hw_step_pending(pid_t pid, uintptr_t *target);
static void nested_generic_hw_step_start(pid_t request_pid, pid_t child,
                                          uintptr_t target);
static void nested_generic_hw_step_complete(pid_t child);
static void nested_generic_hw_step_clear(pid_t pid);
static bool nested_ida_call_return_request(pid_t child, uintptr_t target);
static bool nested_ida_step_intended(pid_t child, uintptr_t ip);
static pid_t nested_ida_step_intent_child(pid_t scope_tid,
                                          uintptr_t *ip_out,
                                          bool *prefer_software);
static void nested_ida_step_intent_clear(pid_t child);
static long nested_driver_sync_breakpoint_provenance(pid_t child);
static bool nested_protocol_hw_step_take(pid_t pid, pid_t *child,
                                         bool *protocol);
static uintptr_t nested_protocol_hw_step_target(pid_t pid);
static bool nested_protocol_hw_step_already_issued(pid_t pid);
static void nested_protocol_hw_step_reset(pid_t child);
static bool nested_server_at_program_int3(pid_t child, uintptr_t *rip_out);
static bool nested_auto_suppress_breakpoint(pid_t child, uintptr_t address);
static void nested_parent_report_stop(pid_t child, int status,
                                      bool initial_stop, uint32_t extra_flags);
static void nested_target_request_protocol_step(pid_t child,
                                                uintptr_t stale_address);
static bool nested_target_capture_protocol_regs(
    pid_t child, const struct user_regs_struct *regs);
static bool nested_target_capture_protocol_regset(pid_t child, void *addr,
                                                  void *data);
static bool nested_target_arm_protocol_step(pid_t child);
static bool nested_target_resume_synthetic_step(pid_t child,
                                                unsigned int resume);
static bool nested_target_protocol_step_pending(pid_t child);
static bool nested_target_protocol_step_requested(pid_t child);
static bool nested_target_is_synthetic_stop(
    pid_t child, int status, struct user_regs_struct *regs);
static int nested_target_hold_synthetic_stop(pid_t child, int *status,
                                             struct rusage *usage,
                                             bool use_wait4);
static bool nested_target_restore_synthetic_step(pid_t child);
static bool nested_overlay_target_breakpoint_value(pid_t pid, void *addr,
                                                    void *data);
static void nested_breakpoint_write_prepare_local(
    pid_t pid, void *addr, uintptr_t after,
    struct nested_breakpoint_write *write);
static bool nested_breakpoint_word_has_cc(void *data);
static void nested_propagate_breakpoints_to_child(pid_t parent, pid_t child);
static bool nested_virtual_breakpoint_peek(pid_t pid, void *addr,
                                           long *value);
static bool nested_breakpoint_address_recorded(uintptr_t address,
                                               uint8_t *original);
static long nested_driver_forward_ptrace(enum __ptrace_request request,
                                         pid_t pid, void *addr, void *data);
static bool nested_server_should_observe_parent_resume(pid_t child,
                                                       uintptr_t *rip_out);
static int nested_driver_protocol_ack(pid_t child);
static void nested_breakpoint_write_prepare(
    pid_t pid, void *addr, uintptr_t after,
    struct nested_breakpoint_write *write);
static void nested_breakpoint_write_commit(
    const struct nested_breakpoint_write *write);
static bool parent_owned_visible_child_stop(pid_t child);
static void nested_server_note_exception_resume(pid_t child);
static void nested_poll_kernel_events(void);
static void *nested_kernel_poller(void *unused);
static pid_t nested_worker_wait_event(pid_t requested, int *status,
                                     int options);
static int ensure_policy_fd(void);
static void shared_map_attach(struct shim_shared_map *map, int fd);
static void shared_map_detach(struct shim_shared_map *map);
static bool shared_map_next(struct shim_shared_map *map,
                            struct ida_vtdbg_policy_event *event);
static long nested_forward_ptrace(enum __ptrace_request request, pid_t pid,
                                  void *addr, void *data);
static pid_t nested_target_waitpid(pid_t pid, int *status, int options);
static pid_t nested_target_wait4(pid_t pid, int *status, int options,
                                 struct rusage *usage);
static pid_t nested_target_wait(int *status);
static int nested_target_service_command(bool defer_resume,
                                         bool *release_wait);
static int nested_driver_service_command(bool defer_resume,
                                         bool *release_wait);
static long nested_driver_forward_ptrace(enum __ptrace_request request,
                                         pid_t pid, void *addr, void *data);
static long nested_execute_command(const struct nested_packet *command,
                                   struct nested_packet *response,
                                   bool defer_resume, bool *release_wait);

struct shim_ptrace_rpc {
    enum __ptrace_request request;
    pid_t pid;
    void *addr;
    void *data;
    long result;
    int error;
};

static pthread_mutex_t rpc_lock = PTHREAD_MUTEX_INITIALIZER;
static struct shim_ptrace_rpc rpc_request;
static _Atomic int rpc_state;
static struct sigaction rpc_old_action;
static bool rpc_signal_installed;
#define SHIM_PTRACE_RPC_SIGNAL SIGUSR2

extern char **environ;
static void shim_init(void);
static pid_t target_tgid(pid_t tid);

/* Adapter-owned syscalls have a distinct code range. A user breakpoint in
 * the target's libc must not be hit by debugger telemetry or bookkeeping. */
static long shim_syscall6(long number, unsigned long a1, unsigned long a2,
                          unsigned long a3, unsigned long a4,
                          unsigned long a5, unsigned long a6)
{
    register unsigned long r10 __asm__("r10") = a4;
    register unsigned long r8 __asm__("r8") = a5;
    register unsigned long r9 __asm__("r9") = a6;
    long result;
    __asm__ volatile("syscall" : "=a"(result)
                     : "a"(number), "D"(a1), "S"(a2), "d"(a3),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    if ((unsigned long)result >= (unsigned long)-4095) {
        errno = (int)-result;
        return -1;
    }
    return result;
}

static void shim_diagnostic_vlog(const char *format, va_list ap)
{
    int saved_errno = errno;
    char line[4096];
    int length = vsnprintf(line, sizeof(line), format, ap);
    if (length > 0) {
        size_t count = (size_t)length < sizeof(line) ? (size_t)length : sizeof(line) - 1;
        (void)shim_syscall6(SYS_write, STDERR_FILENO, (uintptr_t)line, count, 0, 0, 0);
    }
    errno = saved_errno;
}

static void trace_log(const char *format, ...)
{
    va_list ap;

    if (!trace_enabled)
        return;
    va_start(ap, format);
    shim_diagnostic_vlog(format, ap);
    va_end(ap);
}

static bool restore_running_parent_word(pid_t pid, void *addr, void *data)
{
    struct ida_vtdbg_memory_word word = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)pid,
        .flags = IDA_VTDBG_MEMORY_F_WRITE,
        .addr = (uint64_t)(uintptr_t)addr,
        .value = (uint64_t)(uintptr_t)data,
    };
    if (!parent_owned_mode || !nested_server || pid != nested_server_outer_pid ||
        (!nested_breakpoint_word_registered((uintptr_t)addr) &&
         !nested_breakpoint_word_has_cc(data)) || policy_fd < 0)
        return false;
    int result = ioctl(policy_fd, IDA_VTDBG_IOC_MEMORY_WORD, &word);
    event_trace_log("[ida-vtdbg-shim] driver running-parent word restore pid=%d addr=0x%llx result=%d errno=%d\n",
                    pid, (unsigned long long)word.addr, result, result < 0 ? errno : 0);
    if (result == 0)
        errno = 0;
    return result == 0;
}

static void event_trace_log(const char *format, ...)
{
    va_list ap;

    if (!event_trace_enabled)
        return;
    va_start(ap, format);
    shim_diagnostic_vlog(format, ap);
    va_end(ap);
}

/* Handler records are a user-facing trace stream, not general diagnostics.
 * Keep them independent of IDA_VTDBG_TRACE_EVENTS so enabling handler
 * recording does not flood the server log with ptrace/mailbox chatter.  If a
 * path is configured, append complete lines under flock so records from the
 * server and its fork/exec target processes cannot interleave. */
static void handler_trace_vlog(bool enabled, const char *format, va_list ap)
{
    char line[8192];
    int length;
    int fd = STDERR_FILENO;
    bool close_fd = false;
    size_t written = 0;

    if (!enabled)
        return;
    length = vsnprintf(line, sizeof(line), format, ap);
    if (length < 0)
        return;
    if ((size_t)length >= sizeof(line))
        length = (int)sizeof(line) - 1;
    if (length == 0 || line[length - 1] != '\n') {
        if ((size_t)length + 1 < sizeof(line))
            line[length++] = '\n';
    }
    if (handler_log_path[0] != '\0') {
        fd = open(handler_log_path,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        if (fd < 0)
            return;
        close_fd = true;
        (void)flock(fd, LOCK_EX);
    }
    while (written < (size_t)length) {
        ssize_t result = shim_syscall6(SYS_write, (unsigned long)fd,
            (uintptr_t)(line + written), (size_t)length - written, 0, 0, 0);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0)
            break;
        written += (size_t)result;
    }
    if (close_fd) {
        (void)flock(fd, LOCK_UN);
        close(fd);
    }
}

static void handler_trace_log(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    handler_trace_vlog(handler_trace_enabled, format, ap);
    va_end(ap);
}

static void handler_state_log(const char *format, ...)
{
    va_list ap;

    va_start(ap, format);
    handler_trace_vlog(state_trace_enabled, format, ap);
    va_end(ap);
}

static void shared_map_detach(struct shim_shared_map *map)
{
    if (map == NULL)
        return;
    if (map->ring != NULL)
        (void)munmap(map->ring, IDA_VTDBG_SHARED_BYTES);
    map->ring = NULL;
    map->fd = -1;
}

static void shared_map_attach(struct shim_shared_map *map, int fd)
{
    void *address;
    struct ida_vtdbg_shared_ring *ring;

    if (map == NULL || !shared_memory_enabled || fd < 0)
        return;
    if (map->ring != NULL && map->fd == fd)
        return;
    shared_map_detach(map);
    address = mmap(NULL, IDA_VTDBG_SHARED_BYTES, PROT_READ | PROT_WRITE,
                   MAP_SHARED, fd, 0);
    if (address == MAP_FAILED) {
        trace_log("[ida-vtdbg-shim] shared mmap fd=%d failed errno=%d (%s)\n",
                  fd, errno, strerror(errno));
        return;
    }
    ring = address;
    if (ring->magic != IDA_VTDBG_SHARED_MAGIC ||
        ring->version != IDA_VTDBG_SHARED_VERSION ||
        ring->header_size >= IDA_VTDBG_SHARED_BYTES ||
        ring->slot_size != sizeof(struct ida_vtdbg_shared_slot) ||
        ring->slot_count == 0 ||
        ring->slot_count > IDA_VTDBG_SHARED_RING_SLOTS) {
        trace_log("[ida-vtdbg-shim] shared header rejected fd=%d magic=%08x version=%u header=%u slot=%u count=%u\n",
                  fd, ring->magic, ring->version, ring->header_size,
                  ring->slot_size, ring->slot_count);
        (void)munmap(address, IDA_VTDBG_SHARED_BYTES);
        return;
    }
    map->fd = fd;
    map->ring = ring;
    trace_log("[ida-vtdbg-shim] shared ring attached fd=%d producer=%llu consumer=%llu\n",
              fd, (unsigned long long)__atomic_load_n(&ring->producer,
                                                      __ATOMIC_ACQUIRE),
              (unsigned long long)__atomic_load_n(&ring->consumer,
                                                      __ATOMIC_ACQUIRE));
}

static bool shared_map_next(struct shim_shared_map *map,
                            struct ida_vtdbg_policy_event *event)
{
    return map != NULL && map->ring != NULL &&
           ida_vtdbg_shared_ring_next(map->ring, event);
}

/* The target parent and linux_server share the policy mmap across fork.  Keep
 * the optional one-shot algorithm-breakpoint contract in the otherwise
 * reserved ring header instead of enabling a synthetic 0xcc merely because
 * the environment variable is present.  The target parent must observe the
 * overlay only after IDA has actually installed the logical breakpoint. */
#define SHARED_CONTROL_ONESHOT_ARMED 1u
#define ONESHOT_SHARED_MAGIC 0x56544f53u

static void oneshot_shared_open(void)
{
    const char *path = "/tmp/ida_vtdbg_oneshot_state.bin";
    void *map;

    if (oneshot_shared != NULL)
        return;
    oneshot_shared_fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (oneshot_shared_fd < 0)
        return;
    if (ftruncate(oneshot_shared_fd, (off_t)sizeof(*oneshot_shared)) < 0) {
        close(oneshot_shared_fd);
        oneshot_shared_fd = -1;
        return;
    }
    map = mmap(NULL, sizeof(*oneshot_shared), PROT_READ | PROT_WRITE,
               MAP_SHARED, oneshot_shared_fd, 0);
    if (map == MAP_FAILED) {
        close(oneshot_shared_fd);
        oneshot_shared_fd = -1;
        return;
    }
    oneshot_shared = map;
    if (nested_server) {
        __atomic_store_n(&oneshot_shared->magic, ONESHOT_SHARED_MAGIC,
                         __ATOMIC_RELEASE);
        __atomic_store_n(&oneshot_shared->armed, 0u, __ATOMIC_RELEASE);
        __atomic_store_n(&oneshot_shared->address, 0u, __ATOMIC_RELEASE);
    }
}

static void oneshot_shared_close(void)
{
    if (oneshot_shared != NULL)
        munmap(oneshot_shared, sizeof(*oneshot_shared));
    oneshot_shared = NULL;
    if (oneshot_shared_fd >= 0)
        close(oneshot_shared_fd);
    oneshot_shared_fd = -1;
}

static void shared_set_oneshot_control(bool armed, uintptr_t address)
{
    struct ida_vtdbg_shared_ring *ring = policy_shared.ring;
    uint64_t value = (uint64_t)address;

    oneshot_shared_open();
    if (oneshot_shared != NULL) {
        __atomic_store_n(&oneshot_shared->address, value, __ATOMIC_RELEASE);
        __atomic_store_n(&oneshot_shared->armed,
                         armed ? SHARED_CONTROL_ONESHOT_ARMED : 0u,
                         __ATOMIC_RELEASE);
    }
    if (ring == NULL)
        return;
    __atomic_store_n(&ring->reserved0[1], (uint32_t)value,
                     __ATOMIC_RELEASE);
    __atomic_store_n(&ring->reserved0[2], (uint32_t)(value >> 32),
                     __ATOMIC_RELEASE);
    __atomic_store_n(&ring->reserved0[0],
                     armed ? SHARED_CONTROL_ONESHOT_ARMED : 0u,
                     __ATOMIC_RELEASE);
}

static bool shared_get_oneshot_control(uintptr_t address)
{
    struct ida_vtdbg_shared_ring *ring = policy_shared.ring;
    uint32_t flags;
    uint64_t low;
    uint64_t high;

    oneshot_shared_open();
    if (oneshot_shared != NULL &&
        __atomic_load_n(&oneshot_shared->armed, __ATOMIC_ACQUIRE) ==
            SHARED_CONTROL_ONESHOT_ARMED &&
        (uintptr_t)__atomic_load_n(&oneshot_shared->address,
                                   __ATOMIC_ACQUIRE) == address)
        return true;
    if (ring == NULL)
        return false;
    flags = __atomic_load_n(&ring->reserved0[0], __ATOMIC_ACQUIRE);
    low = __atomic_load_n(&ring->reserved0[1], __ATOMIC_ACQUIRE);
    high = __atomic_load_n(&ring->reserved0[2], __ATOMIC_ACQUIRE);
    return (flags & SHARED_CONTROL_ONESHOT_ARMED) != 0 &&
           (uintptr_t)(low | (high << 32)) == address;
}

static bool target_oneshot_restore_word(void *addr, void *data)
{
    uintptr_t request_address = (uintptr_t)addr;
    uintptr_t word = (uintptr_t)data;
    size_t offset;

    if (!oneshot_algorithm_enabled || oneshot_algorithm_address == 0 ||
        request_address == 0 ||
        oneshot_algorithm_address < request_address ||
        oneshot_algorithm_address >= request_address + sizeof(uintptr_t))
        return false;
    offset = (size_t)(oneshot_algorithm_address - request_address);
    return (uint8_t)(word >> (offset * 8u)) != 0xccu;
}

/* Use the kernel entry point for broker-internal ptrace operations.  Calling
 * the interposed libc variadic wrapper from a wait hook is fragile when the
 * request carries a size value (PTRACE_GET_SYSCALL_INFO) and can report
 * ESRCH even though the tracee is visibly stopped. */
static long ptrace_internal(enum __ptrace_request request, pid_t pid,
                            void *addr, void *data)
{
    return ptrace_dispatch(request, pid, addr, data);
}

static long ptrace_raw(enum __ptrace_request request, pid_t pid, void *addr,
                       void *data)
{
    return real_syscall((long)SYS_ptrace, (long)request, (long)pid,
                        (unsigned long)addr, (unsigned long)data);
}

static void parent_owned_note_real_resume(enum __ptrace_request request,
                                          pid_t pid, long result)
{
    if (result == 0 && parent_owned_mode && nested_server && pid > 0 &&
        pid == nested_server_outer_pid &&
        (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
         request == PTRACE_SINGLESTEP)) {
        atomic_store_explicit(&nested_parent_real_stopped, false, memory_order_release);
        atomic_store_explicit(&nested_parent_debug_event_presented, false, memory_order_release);
        atomic_store_explicit(&nested_parent_trace_requested,
                              request == PTRACE_SINGLESTEP, memory_order_release);
    }
}

static long real_syscall6(long number, unsigned long a1, unsigned long a2,
                          unsigned long a3, unsigned long a4,
                          unsigned long a5, unsigned long a6)
{
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}

static void parent_owned_queue_process_exit(pid_t requested_root,
                                            pid_t requested_child)
{
    pid_t root;
    size_t child_count;

    pthread_mutex_lock(&nested_event_lock);
    parent_owned_process_exit_pending = true;
    parent_owned_process_exit_root = requested_root > 0
                                         ? requested_root
                                         : nested_server_outer_pid;
    root = parent_owned_process_exit_root;
    if (requested_child > 0 &&
        parent_owned_process_exit_child_count < NESTED_QUEUE_MAX) {
        bool duplicate = false;
        for (size_t index = 0;
             index < parent_owned_process_exit_child_count; ++index) {
            if (parent_owned_process_exit_children[index] == requested_child) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
            parent_owned_process_exit_children[
                parent_owned_process_exit_child_count++] = requested_child;
    }
    if (parent_owned_process_exit_child_count == 0) {
        for (size_t index = 0;
             index < nested_shadow_count &&
             parent_owned_process_exit_child_count < NESTED_QUEUE_MAX;
             ++index)
            parent_owned_process_exit_children[
                parent_owned_process_exit_child_count++] =
                nested_shadow_pids[index];
    }
    child_count = parent_owned_process_exit_child_count;
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] queued ProcessExit root=%d children=%zu for next server wait\n",
                    root, child_count);
}

static void parent_owned_execute_queued_process_exit(void)
{
    pid_t root = 0;
    pid_t children[NESTED_QUEUE_MAX];
    size_t child_count = 0;
    bool pending = false;

    pthread_mutex_lock(&nested_event_lock);
    if (parent_owned_process_exit_pending) {
        pending = true;
        root = parent_owned_process_exit_root;
        parent_owned_process_exit_pending = false;
        parent_owned_process_exit_root = 0;
        child_count = parent_owned_process_exit_child_count;
        if (child_count > NESTED_QUEUE_MAX)
            child_count = NESTED_QUEUE_MAX;
        for (size_t index = 0; index < child_count; ++index)
            children[index] = parent_owned_process_exit_children[index];
        memset(parent_owned_process_exit_children, 0,
               sizeof(parent_owned_process_exit_children));
        parent_owned_process_exit_child_count = 0;
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (!pending || root <= 0)
        return;

    event_trace_log("[ida-vtdbg-shim] execute queued ProcessExit root=%d children=%zu at server wait\n",
                    root, child_count);
    for (size_t index = 0; index < child_count; ++index) {
        long sent = real_syscall6(SYS_kill, (unsigned long)children[index],
                                  (unsigned long)SIGKILL, 0, 0, 0, 0);
        event_trace_log("[ida-vtdbg-shim] queued ProcessExit kill child=%d result=%ld errno=%d\n",
                        children[index], sent, sent < 0 ? errno : 0);
    }
    {
        long sent = real_syscall6(SYS_kill, (unsigned long)root,
                                  (unsigned long)SIGKILL, 0, 0, 0, 0);
        event_trace_log("[ida-vtdbg-shim] queued ProcessExit kill root=%d result=%ld errno=%d\n",
                        root, sent, sent < 0 ? errno : 0);
    }
}

static void ptrace_rpc_handler(int signal_number, siginfo_t *info,
                               void *context)
{
    int expected = 1;
    int saved_errno = errno;
    static const char marker[] = "[ida-vtdbg-shim] rpc-handler\n";

    (void)info;
    (void)context;
    if (signal_number != SHIM_PTRACE_RPC_SIGNAL ||
        !atomic_compare_exchange_strong_explicit(
            &rpc_state, &expected, 3, memory_order_acq_rel,
            memory_order_acquire))
        return;
    if (trace_enabled) {
        ssize_t ignored = write(STDERR_FILENO, marker, sizeof(marker) - 1);
        (void)ignored;
    }
    rpc_request.result = ptrace_raw(rpc_request.request, rpc_request.pid,
                                    rpc_request.addr, rpc_request.data);
    parent_owned_note_real_resume(rpc_request.request, rpc_request.pid, rpc_request.result);
    rpc_request.error = rpc_request.result < 0 ? errno : 0;
    atomic_store_explicit(&rpc_state, 2, memory_order_release);
    (void)real_syscall6(SYS_futex, (unsigned long)&rpc_state, FUTEX_WAKE, 1,
                        0, 0, 0);
    /* The callback interrupted the owner's unrelated IDA operation. The
     * RPC result carries its own errno; never corrupt that interrupted call. */
    errno = saved_errno;
}

static void install_ptrace_rpc_handler(void)
{
    struct sigaction action;

    memset(&action, 0, sizeof(action));
    action.sa_sigaction = ptrace_rpc_handler;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    if (sigaction(SHIM_PTRACE_RPC_SIGNAL, &action, &rpc_old_action) == 0)
        rpc_signal_installed = true;
}

static pid_t current_tid(void)
{
    /* This is adapter bookkeeping, not a target syscall. Do not traverse
     * libc's generic syscall trampoline: a parent's user BP at that return
     * PC must not prevent us from even entering the real child ptrace. */
    return gettid();
}

static bool shim_is_linux_server_image(void)
{
    char executable[PATH_MAX];
    ssize_t count = readlink("/proc/self/exe", executable,
                             sizeof(executable) - 1);

    if (count <= 0)
        return false;
    executable[count] = '\0';
    return strstr(executable, "linux_server") != NULL;
}

static bool nested_server_is_owner_thread(void)
{
    return (!nested_server && !nested_event_worker) ||
           nested_server_owner_tid <= 0 ||
           current_tid() == nested_server_owner_tid;
}

static void nested_server_wake_outer_target(void)
{
    long result;

    if ((!nested_server && !nested_event_worker) ||
        nested_server_outer_pid <= 0)
        return;
    /* A relay command can arrive while the outer target is stopped at one of
     * linux_server's syscall stops.  Let it run freely long enough for its
     * wait-hook to service the socket; the next debugger-visible stop will be
     * handled by the normal broker path. */
    result = ptrace_via_owner(nested_server_owner_tid, PTRACE_CONT,
                              nested_server_outer_pid, NULL, NULL);
    if (result < 0 && errno != ESRCH && errno != EIO && errno != EINVAL)
        trace_log("[ida-vtdbg-shim] wake outer target pid=%d failed errno=%d (%s)\n",
                  nested_server_outer_pid, errno, strerror(errno));
}

static pid_t target_owner_tid(pid_t pid)
{
    pid_t owner = 0;

    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        if (target != NULL)
            owner = target->owner_tid;
    }
    pthread_mutex_unlock(&state_lock);
    return owner;
}

static void set_target_owner(pid_t pid, pid_t owner)
{
    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        if (target != NULL)
            target->owner_tid = owner;
    }
    pthread_mutex_unlock(&state_lock);
    trace_log("[ida-vtdbg-shim] owner pid=%d tid=%d\n", pid, owner);
}

static void mark_anti_checks_started(pid_t pid)
{
    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        if (target != NULL)
            target->anti_checks_started = true;
    }
    pthread_mutex_unlock(&state_lock);
}

static bool anti_checks_started(pid_t pid)
{
    bool started = false;

    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        started = target != NULL && target->anti_checks_started;
    }
    pthread_mutex_unlock(&state_lock);
    return started;
}

static pid_t tracer_pid_of(pid_t tid)
{
    char path[64];
    char line[128];
    FILE *status;
    int tracer = 0;

    if (tid <= 0)
        return 0;
    (void)snprintf(path, sizeof(path), "/proc/%d/status", tid);
    status = fopen(path, "r");
    if (status == NULL)
        return 0;
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "TracerPid:\t%d", &tracer) == 1)
            break;
    }
    fclose(status);
    return (pid_t)tracer;
}

#include "parent_resume_semantics.inc"
#include "owner_wait_view.inc"

static long ptrace_via_owner(pid_t owner, enum __ptrace_request request,
                             pid_t pid, void *addr, void *data)
{
    pid_t self = current_tid();
    long result;
    int saved_errno;

    if (parent_owned_keep_unpresented_stop(request, pid, "internal-owner"))
        return 0;
    if (parent_owned_reject_wait_step(request, pid))
        return -1;

    if (parent_owned_mode && nested_server &&
        request == PTRACE_POKEUSER &&
        nested_protocol_hw_step_write(pid, (uintptr_t)addr,
                                      (uintptr_t)data))
        return 0;
    if (parent_owned_mode && nested_server &&
        request == PTRACE_PEEKUSER) {
        uintptr_t debug_value = 0;
        if (nested_protocol_hw_step_peek(pid, (uintptr_t)addr,
                                         &debug_value))
            return (long)debug_value;
    }
    if (parent_owned_mode && nested_server &&
        (request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
        nested_protocol_hw_step_pending(pid) &&
        !(pid == nested_server_outer_pid && !nested_is_shadow(pid)))
        return nested_driver_forward_ptrace(request, pid, addr, data);

    trace_log("[ida-vtdbg-shim] internal-ptrace request=%d pid=%d self=%d owner=%d rpc=%d\n",
              request, pid, self, owner, rpc_signal_installed);
    if (owner <= 0 || owner == self || !rpc_signal_installed) {
        result = ptrace_raw(request, pid, addr, data);
        parent_owned_note_real_resume(request, pid, result);
        if (result == 0 &&
            (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT))
            (void)nested_overlay_target_breakpoint_value(pid, addr, data);
        trace_log("[ida-vtdbg-shim] internal-ptrace direct request=%d pid=%d result=%ld errno=%d\n",
                  request, pid, result, result < 0 ? errno : 0);
        return result;
    }

    pthread_mutex_lock(&rpc_lock);
    for (;;) {
        int state = atomic_load_explicit(&rpc_state, memory_order_acquire);
        if (state == 0)
            break;
        (void)real_syscall6(SYS_futex, (unsigned long)&rpc_state, FUTEX_WAIT,
                            (unsigned long)state, 0, 0, 0);
    }
    rpc_request.request = request;
    rpc_request.pid = pid;
    rpc_request.addr = addr;
    rpc_request.data = data;
    rpc_request.result = -1;
    rpc_request.error = ESRCH;
    atomic_store_explicit(&rpc_state, 1, memory_order_release);
    /* linux_server installs its own signal dispositions during startup;
     * restore our private RPC disposition immediately before delivery. */
    install_ptrace_rpc_handler();
    if (real_syscall(SYS_tgkill, (unsigned long)getpid(), (unsigned long)owner,
                     SHIM_PTRACE_RPC_SIGNAL) < 0) {
        saved_errno = errno;
        atomic_store_explicit(&rpc_state, 0, memory_order_release);
        pthread_mutex_unlock(&rpc_lock);
        errno = saved_errno;
        return -1;
    }
    trace_log("[ida-vtdbg-shim] internal-ptrace signal sent request=%d pid=%d owner=%d\n",
              request, pid, owner);
    for (;;) {
        /* One acquire snapshot is both the condition and futex expected
         * value. Never wait on the terminal state: a completion between
         * two previous loads could otherwise leave us asleep after its one
         * FUTEX_WAKE had already happened. The kernel handles changes after
         * this single snapshot with EAGAIN, without any timing heuristic. */
        int state = atomic_load_explicit(&rpc_state, memory_order_acquire);
        if (state == 2)
            break;
        (void)real_syscall6(SYS_futex, (unsigned long)&rpc_state, FUTEX_WAIT,
                            (unsigned long)state, 0, 0, 0);
    }
    result = rpc_request.result;
    saved_errno = rpc_request.error;
    atomic_store_explicit(&rpc_state, 0, memory_order_release);
    pthread_mutex_unlock(&rpc_lock);
    if (result < 0)
        errno = saved_errno;
    if (result == 0 &&
        (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT))
        (void)nested_overlay_target_breakpoint_value(pid, addr, data);
    trace_log("[ida-vtdbg-shim] internal-ptrace rpc result request=%d pid=%d result=%ld errno=%d\n",
              request, pid, result, result < 0 ? saved_errno : 0);
    return result;
}

static long ptrace_dispatch(enum __ptrace_request request, pid_t pid,
                            void *addr, void *data)
{
    return ptrace_via_owner(target_owner_tid(pid), request, pid, addr, data);
}

static long server_ptrace_call(enum __ptrace_request request, pid_t pid,
                               void *addr, void *data)
{
    struct nested_breakpoint_write breakpoint_write;
    long result;
    long virtual_value;
    uintptr_t debug_value;

    if (parent_owned_keep_unpresented_stop(request, pid, "server-raw"))
        return 0;
    if (parent_owned_reject_wait_step(request, pid))
        return -1;

    memset(&breakpoint_write, 0, sizeof(breakpoint_write));

    if (parent_owned_mode && nested_server &&
        nested_server_session_end_pending &&
        (pid == nested_server_session_end_root || nested_is_shadow(pid)) &&
        (request == PTRACE_POKETEXT || request == PTRACE_POKEDATA ||
         request == PTRACE_POKEUSER || request == PTRACE_CONT ||
         request == PTRACE_DETACH || request == PTRACE_KILL)) {
        /* Real native root exit is already confirmed. No address space/DR
         * remains to restore; IDA's final cleanup is an idempotent no-op. */
        errno = 0;
        return 0;
    }

    if (parent_owned_mode && nested_server &&
        request == PTRACE_POKEUSER &&
        nested_protocol_hw_step_write(pid, (uintptr_t)addr,
                                      (uintptr_t)data))
        return 0;
    if (parent_owned_mode && nested_server &&
        request == PTRACE_PEEKUSER &&
        nested_protocol_hw_step_peek(pid, (uintptr_t)addr,
                                     &debug_value))
        return (long)debug_value;
    if (parent_owned_mode && nested_server &&
        (request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
        nested_protocol_hw_step_pending(pid) &&
        !(pid == nested_server_outer_pid && !nested_is_shadow(pid))) {
        event_trace_log("[ida-vtdbg-shim] route root CONT for virtual protocol hardware-step pid=%d\n",
                        pid);
        return nested_driver_forward_ptrace(request, pid, addr, data);
    }

    if (parent_owned_mode && nested_server &&
        (request == PTRACE_KILL || request == PTRACE_DETACH))
        event_trace_log("[ida-vtdbg-shim] ProcessExit ptrace request=%d pid=%d outer=%d caller=%d owner=%d\n",
                        request, pid, nested_server_outer_pid,
                        current_tid(), nested_server_owner_tid);

    /* PTRACE_KILL is acknowledged now and executed at the next server wait.
     * Killing inline lets the wait broker observe root exit before IDA gets
     * the ProcessExit response, which turns a successful termination into a
     * remote-command failure. */
    if (parent_owned_mode && nested_server &&
        request == PTRACE_KILL && pid > 0 &&
        pid == nested_server_outer_pid) {
        parent_owned_queue_process_exit(pid, 0);
        return 0;
    }

    /* The one-shot algorithm breakpoint is physically restored as soon as
     * its first child stop is presented.  IDA may later delete that logical
     * BPT while the session is still live (notably during ProcessExit); treat
     * a restore of its original byte as an idempotent success rather than
     * forwarding a write against the parent-owned child mapping. */
    if (parent_owned_mode && nested_server && oneshot_algorithm_enabled &&
        oneshot_algorithm_done &&
        (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
        addr != NULL) {
        uintptr_t aligned_algorithm = oneshot_algorithm_address &
                                      ~(sizeof(uintptr_t) - 1u);
        uintptr_t aligned_addr = (uintptr_t)addr &
                                 ~(sizeof(uintptr_t) - 1u);
        uint8_t original_byte = 0;

        if (aligned_addr == aligned_algorithm &&
            nested_breakpoint_address_recorded(
                oneshot_algorithm_address, &original_byte)) {
            size_t offset = (size_t)(oneshot_algorithm_address - aligned_addr);
            uint8_t requested_byte = (uint8_t)(
                (uintptr_t)data >> (offset * 8u));

            if (requested_byte == original_byte) {
                trace_log("[ida-vtdbg-shim] virtualize active one-shot BPT restore pid=%d addr=0x%llx original=0x%02x\n",
                          pid,
                          (unsigned long long)oneshot_algorithm_address,
                          (unsigned int)original_byte);
                return 0;
            }
        }
    }

    /* IDA performs a final breakpoint cleanup after PROCESS_EXITED.  At that
     * point the real tracee is already gone and the parent-owned session has
     * been reset, so Linux quite correctly returns ESRCH for the restore POKE.
     * The breakpoint was already physically restored by one-shot handling;
     * make this post-exit cleanup idempotent instead of surfacing a spurious
     * BPT_WRITE_ERROR to the harness. */
    if (parent_owned_mode && nested_server &&
        nested_server_outer_pid <= 0 && oneshot_algorithm_enabled &&
        (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
        addr != NULL &&
        ((uintptr_t)addr & ~(sizeof(uintptr_t) - 1u)) ==
            (oneshot_algorithm_address & ~(sizeof(uintptr_t) - 1u))) {
        trace_log("[ida-vtdbg-shim] virtualize post-exit one-shot cleanup pid=%d addr=0x%llx\n",
                  pid, (unsigned long long)(uintptr_t)addr);
        return 0;
    }

    /* IDA sends ProcessExit cleanup requests after the parent-owned session
     * has already been torn down.  The tracee/tid is then legitimately gone;
     * report cleanup as idempotent success instead of surfacing ESRCH as a
     * failed ProcessExit command. */
    if (parent_owned_mode && nested_server && nested_server_outer_pid <= 0 &&
        (request == PTRACE_DETACH || request == PTRACE_KILL ||
         request == PTRACE_CONT || request == PTRACE_SINGLESTEP ||
         request == PTRACE_SYSCALL || request == PTRACE_SETOPTIONS ||
         request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
        pid > 0 && !nested_is_shadow(pid)) {
        trace_log("[ida-vtdbg-shim] idempotent ProcessExit cleanup request=%d pid=%d\n",
                  request, pid);
        return 0;
    }

    if ((request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) &&
        nested_virtual_breakpoint_peek(pid, addr, &virtual_value))
        return virtual_value;

    if (syscall_mediation && request == PTRACE_SETOPTIONS) {
        unsigned long options = (unsigned long)(uintptr_t)data;
        unsigned long requested_options = options;
        options |= PTRACE_O_TRACESYSGOOD;
        if (!parent_owned_mode)
            options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
        trace_log("[ida-vtdbg-shim] server ptrace SETOPTIONS pid=%d requested=0x%lx effective=0x%lx parent_owned=%d\n",
                  pid, requested_options, options, parent_owned_mode ? 1 : 0);
        data = (void *)(uintptr_t)options;
    }
    if (syscall_mediation && request == PTRACE_SEIZE) {
        unsigned long options = (unsigned long)(uintptr_t)data;
        unsigned long requested_options = options;
        options |= PTRACE_O_TRACESYSGOOD;
        if (!parent_owned_mode)
            options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
        trace_log("[ida-vtdbg-shim] server ptrace SEIZE pid=%d requested=0x%lx effective=0x%lx parent_owned=%d\n",
                  pid, requested_options, options, parent_owned_mode ? 1 : 0);
        data = (void *)(uintptr_t)options;
    }
    if (!parent_owned_mode && syscall_mediation && request == PTRACE_CONT &&
        tid_is_compat(pid)) {
        unsigned long tree_options = PTRACE_O_TRACESYSGOOD |
                                     PTRACE_O_TRACEFORK |
                                     PTRACE_O_TRACEVFORK;

        /* linux_server's initial option programming varies between its
         * launch paths.  PTRACE_CONT is always issued while this tracee is
         * stopped, so it is the reliable owner-thread point to enable real
         * process-tree notifications before the target reaches fork(). */
        if (ptrace_raw(PTRACE_SETOPTIONS, pid, NULL,
                       (void *)(uintptr_t)tree_options) < 0)
            trace_log("[ida-vtdbg-shim] tree options pid=%d unavailable errno=%d (%s)\n",
                      pid, errno, strerror(errno));
        else
            trace_log("[ida-vtdbg-shim] tree options armed pid=%d flags=0x%lx\n",
                      pid, tree_options);
    }
    if (parent_owned_mode && nested_target && !nested_target_launcher &&
        request == PTRACE_CONT)
        (void)nested_target_arm_protocol_step(pid);
    if (syscall_mediation && request == PTRACE_CONT &&
        tid_is_compat(pid) && note_continue_and_should_mediate(pid))
        request = PTRACE_SYSCALL;
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT)
        nested_breakpoint_write_prepare_local(
            pid, addr, (uintptr_t)data, &breakpoint_write);
    trace_log("[ida-vtdbg-shim] syscall-ptrace request=%d pid=%d self=%d\n",
              request, pid, current_tid());
    result = ptrace_raw(request, pid, addr, data);
    trace_log("[ida-vtdbg-shim] syscall-ptrace result request=%d pid=%d result=%ld errno=%d\n",
              request, pid, result, result < 0 ? errno : 0);
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) {
        if (result < 0 && restore_running_parent_word(pid, addr, data))
            result = 0;
        if (result < 0 && parent_owned_mode &&
            (nested_breakpoint_word_has_cc(data) ||
             nested_breakpoint_word_registered((uintptr_t)addr)) &&
            (errno == ESRCH || errno == EIO || errno == EFAULT ||
             errno == EPERM)) {
            trace_log("[ida-vtdbg-shim] virtualize failed breakpoint write pid=%d addr=0x%llx errno=%d\n",
                      pid, (unsigned long long)(uintptr_t)addr, errno);
            nested_note_parent_breakpoint_write(pid, addr, data, 0,
                                                &breakpoint_write);
            result = 0;
        } else {
            nested_note_parent_breakpoint_write(pid, addr, data, result,
                                                &breakpoint_write);
        }
    }
    if (result == 0) {
        parent_owned_note_real_resume(request, pid, result);
        if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
            set_target_owner(pid, current_tid());
            if (parent_owned_mode && nested_event_worker) {
                nested_server_outer_pid = pid;
                nested_server_owner_tid = current_tid();
            }
            register_best_effort(pid);
        } else if (request == PTRACE_DETACH || request == PTRACE_KILL)
            unregister_tid_best_effort(pid);
    }
    return result;
}

static bool nested_write_full(int fd, const void *buffer, size_t length)
{
    const uint8_t *cursor = (const uint8_t *)buffer;

    while (length != 0) {
        ssize_t written = send(fd, cursor, length, MSG_NOSIGNAL);
        if (written <= 0)
            return false;
        cursor += (size_t)written;
        length -= (size_t)written;
    }
    return true;
}

static bool nested_read_full(int fd, void *buffer, size_t length)
{
    uint8_t *cursor = (uint8_t *)buffer;

    while (length != 0) {
        ssize_t received = recv(fd, cursor, length, 0);
        if (received <= 0)
            return false;
        cursor += (size_t)received;
        length -= (size_t)received;
    }
    return true;
}

static bool nested_send_packet(const struct nested_packet *packet)
{
    bool ok;

    pthread_mutex_lock(&nested_io_lock);
    ok = nested_conn_fd >= 0 &&
         nested_write_full(nested_conn_fd, packet, sizeof(*packet));
    pthread_mutex_unlock(&nested_io_lock);
    return ok;
}

static void nested_queue_event(const struct nested_packet *packet)
{
    size_t index;
    size_t shadow_count_snapshot;
    size_t event_count_snapshot;

    event_trace_log("[ida-vtdbg-shim] queue nested request=%u pid=%d aux=%d owner=%u status=0x%x flags=0x%x process=%d tid=%d\n",
                    packet->request, packet->pid, packet->aux_pid,
                    packet->owner_tid,
                    (unsigned int)packet->status, packet->flags,
                    getpid(), current_tid());

    if (parent_owned_mode && packet->owner_tid != 0) {
        pid_t child = packet->request == NESTED_EVENT_FORK
                          ? (pid_t)packet->aux_pid
                          : packet->request == NESTED_EVENT_WAIT
                                ? (pid_t)packet->pid
                                : 0;
        if (child > 0)
            parent_owned_set_owner_tid(child,
                                       (pid_t)packet->owner_tid);
    }

    /* This helper takes nested_event_lock internally.  Do it before the queue
     * lock: invoking it from the WAIT branch below deadlocks the event poller
     * exactly when a parent-owned child hits a visible breakpoint. */
    if (packet->request == NESTED_EVENT_WAIT && parent_owned_mode &&
        packet->pid > 0)
        (void)parent_owned_proxy_stop_held((pid_t)packet->pid, true,
                                          WIFSTOPPED(packet->status));

    pthread_mutex_lock(&nested_event_lock);
    nested_event_audit_locked(1, (pid_t)packet->pid, packet->status,
                              packet->flags, packet->value, 0);
    if (packet->request == NESTED_EVENT_HELLO) {
        if ((nested_server || nested_event_worker) &&
            nested_server_outer_pid <= 0)
            nested_server_outer_pid = (pid_t)packet->pid;
        pthread_mutex_unlock(&nested_event_lock);
        if ((nested_server || nested_event_worker) && packet->pid > 0)
            register_best_effort((pid_t)packet->pid);
        trace_log("[ida-vtdbg-shim] nested hello outer pid=%d\n",
                  packet->pid);
        return;
    }
    if (packet->request == NESTED_EVENT_FORK) {
        bool shadow_known = false;
        if (parent_owned_mode && packet->pid > 0 &&
            nested_server_outer_pid <= 0)
            nested_server_outer_pid = (pid_t)packet->pid;
        for (index = 0; index < nested_shadow_count; ++index) {
            if (nested_shadow_pids[index] == (pid_t)packet->aux_pid) {
                shadow_known = true;
                break;
            }
        }
        if (shadow_known) {
            pthread_mutex_unlock(&nested_event_lock);
            event_trace_log("[ida-vtdbg-shim] nested duplicate fork parent=%d child=%d ignored\n",
                            packet->pid, packet->aux_pid);
            return;
        }
        if (nested_shadow_count < NESTED_QUEUE_MAX)
            nested_shadow_pids[nested_shadow_count++] = (pid_t)packet->aux_pid;
        if (parent_owned_mode)
            (void)parent_owned_child_locked((pid_t)packet->aux_pid, true);
        for (index = 0; index < NESTED_QUEUE_MAX; ++index) {
            if (!nested_virtual_forks[index].active) {
                nested_virtual_forks[index].parent_pid = (pid_t)packet->pid;
                nested_virtual_forks[index].child_pid = (pid_t)packet->aux_pid;
                nested_virtual_forks[index].active = true;
                nested_virtual_forks[index].event_delivered = false;
                nested_virtual_forks[index].message_pending = false;
                nested_virtual_forks[index].resume_requested = false;
                nested_virtual_forks[index].child_attach_ready = false;
                nested_virtual_forks[index].child_initial_delivered = false;
                break;
            }
        }
        if (nested_event_count < NESTED_QUEUE_MAX) {
            nested_events[nested_event_count].pid = (pid_t)packet->pid;
            nested_events[nested_event_count].status =
                (SIGTRAP << 8) | 0x7f |
                /* linux_server's extended-wait path exposes clone events as
                 * IDA threads; it deliberately ignores fork events.  The
                 * shadow child is a separate process in the kernel, but the
                 * clone-shaped event lets IDA attach it without a second
                 * debugging session. */
                ((int)PTRACE_EVENT_CLONE << 16);
            nested_events[nested_event_count].aux_pid =
                (pid_t)packet->aux_pid;
            nested_events[nested_event_count].virtual_fork = true;
            nested_events[nested_event_count].initial_stop = false;
            ++nested_event_count;
        }
        /* Queue the real child stop under the same lock as the synthetic
         * parent fork event.  linux_server consumes the parent event first,
         * then immediately waits for its child; both records must already be
         * visible before that second wait begins.  Legacy relay sessions do
         * not report real parent-owned stops, so retain their old bootstrap. */
        if (packet->aux_pid > 0 && nested_event_count < NESTED_QUEUE_MAX &&
            parent_owned_mode &&
            (packet->flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) != 0) {
            nested_events[nested_event_count].pid =
                (pid_t)packet->aux_pid;
            nested_events[nested_event_count].status = packet->status;
            nested_events[nested_event_count].aux_pid = 0;
            nested_events[nested_event_count].virtual_fork = false;
            nested_events[nested_event_count].initial_stop = true;
            ++nested_event_count;
        } else if (!parent_owned_mode && packet->aux_pid > 0 &&
                   nested_event_count < NESTED_QUEUE_MAX) {
            nested_events[nested_event_count].pid = (pid_t)packet->aux_pid;
            nested_events[nested_event_count].status =
                (SIGSTOP << 8) | 0x7f;
            nested_events[nested_event_count].aux_pid = 0;
            nested_events[nested_event_count].virtual_fork = false;
            nested_events[nested_event_count].initial_stop = false;
            ++nested_event_count;
        }
        shadow_count_snapshot = nested_shadow_count;
        event_count_snapshot = nested_event_count;
        pthread_mutex_unlock(&nested_event_lock);
        nested_propagate_breakpoints_to_child((pid_t)packet->pid,
                                              (pid_t)packet->aux_pid);
        event_trace_log("[ida-vtdbg-shim] nested fork queued process=%d tid=%d parent=%d child=%d shadows=%zu events=%zu\n",
                        getpid(), current_tid(), packet->pid,
                        packet->aux_pid, shadow_count_snapshot,
                        event_count_snapshot);
        return;
    }
    if (packet->request != NESTED_EVENT_WAIT) {
        pthread_mutex_unlock(&nested_event_lock);
        return;
    }
    if (nested_event_worker && packet->pid > 0 &&
        nested_server_outer_pid > 0) {
        bool shadow_known = false;
        for (index = 0; index < nested_shadow_count; ++index) {
            if (nested_shadow_pids[index] == (pid_t)packet->pid) {
                shadow_known = true;
                break;
            }
        }
        if (!shadow_known && nested_shadow_count < NESTED_QUEUE_MAX) {
            nested_shadow_pids[nested_shadow_count++] = (pid_t)packet->pid;
            for (index = 0; index < NESTED_QUEUE_MAX; ++index) {
                if (!nested_virtual_forks[index].active) {
                    nested_virtual_forks[index].parent_pid =
                        nested_server_outer_pid;
                    nested_virtual_forks[index].child_pid = (pid_t)packet->pid;
                    nested_virtual_forks[index].active = true;
                    nested_virtual_forks[index].event_delivered = false;
                    nested_virtual_forks[index].message_pending = false;
                    nested_virtual_forks[index].resume_requested = false;
                    nested_virtual_forks[index].child_attach_ready = false;
                    nested_virtual_forks[index].child_initial_delivered = false;
                    break;
                }
            }
            if (nested_event_count < NESTED_QUEUE_MAX) {
                nested_events[nested_event_count].pid =
                    nested_server_outer_pid;
                nested_events[nested_event_count].status =
                    (SIGTRAP << 8) | 0x7f |
                    ((int)PTRACE_EVENT_CLONE << 16);
                nested_events[nested_event_count].aux_pid =
                    (pid_t)packet->pid;
                nested_events[nested_event_count].virtual_fork = true;
                nested_events[nested_event_count].initial_stop = false;
                ++nested_event_count;
            }
        }
    }
    if (nested_event_count < NESTED_QUEUE_MAX) {
        nested_events[nested_event_count].pid = (pid_t)packet->pid;
        nested_events[nested_event_count].status = packet->status;
        nested_events[nested_event_count].aux_pid = 0;
        nested_events[nested_event_count].virtual_fork = false;
        nested_events[nested_event_count].initial_stop = false;
        ++nested_event_count;
    }
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] nested wait queued pid=%d status=0x%x\n",
                    packet->pid, (unsigned int)packet->status);
}

static void nested_consume_packet(const struct nested_packet *packet)
{
    if (packet->magic != NESTED_MAGIC)
        return;
    if (packet->type == NESTED_EVENT)
        nested_queue_event(packet);
}

static bool nested_is_internal_server_peer(int fd)
{
    struct ucred credentials;
    socklen_t length = sizeof(credentials);
    char path[64];
    char executable[PATH_MAX];
    ssize_t count;

    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) < 0 ||
        credentials.pid <= 0)
        return false;
    (void)snprintf(path, sizeof(path), "/proc/%d/exe", credentials.pid);
    count = readlink(path, executable, sizeof(executable) - 1);
    if (count <= 0)
        return false;
    executable[count] = '\0';
    return strstr(executable, "linux_server") != NULL;
}

static void nested_poll_messages(void)
{
    struct nested_packet packet;
    int accepted;

    if (!nested_event_worker && !nested_server)
        return;
    if (nested_conn_fd < 0 && nested_listen_fd >= 0) {
        /* Keep the connected endpoint blocking.  The polling path uses
         * MSG_DONTWAIT explicitly, while synchronous ptrace RPCs need a
         * blocking receive for their response. */
        for (;;) {
            accepted = accept4(nested_listen_fd, NULL, NULL, SOCK_CLOEXEC);
            if (accepted < 0)
                break;
            if (nested_is_internal_server_peer(accepted)) {
                trace_log("[ida-vtdbg-shim] ignoring linux_server self-test relay fd=%d\n",
                          accepted);
                close(accepted);
                continue;
            }
            nested_conn_fd = accepted;
            trace_log("[ida-vtdbg-shim] nested relay connected fd=%d\n",
                      accepted);
            break;
        }
    }
    if (nested_conn_fd < 0)
        return;
    pthread_mutex_lock(&nested_io_lock);
    for (;;) {
        ssize_t count = recv(nested_conn_fd, &packet, sizeof(packet),
                             MSG_DONTWAIT);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            break;
        if (count <= 0 || (size_t)count != sizeof(packet)) {
            close(nested_conn_fd);
            nested_conn_fd = -1;
            break;
        }
        trace_log("[ida-vtdbg-shim] nested packet type=%u request=%u pid=%d aux=%d status=0x%x\n",
                  packet.type, packet.request, packet.pid, packet.aux_pid,
                  (unsigned int)packet.status);
        nested_consume_packet(&packet);
    }
    pthread_mutex_unlock(&nested_io_lock);
}

static bool nested_pop_event(pid_t requested, int *status, pid_t *event_pid)
{
    size_t index;
    bool found = false;

    pthread_mutex_lock(&nested_event_lock);
    for (index = 0; index < nested_event_count; ++index) {
        bool child_wait_blocked = false;

        if (requested > 0 && nested_events[index].pid != requested)
            continue;
        if (parent_owned_mode && !nested_events[index].virtual_fork &&
            nested_events[index].initial_stop) {
            for (size_t vindex = 0; vindex < NESTED_QUEUE_MAX; ++vindex) {
                struct nested_virtual_fork *fork_event =
                    &nested_virtual_forks[vindex];

                if (!fork_event->active ||
                    fork_event->child_pid != nested_events[index].pid)
                    continue;
                /* linux_server's child bootstrap is two-phase.  It first
                 * acknowledges the synthetic parent fork (GETEVENTMSG),
                 * then applies PTRACE_SETOPTIONS/attach to the reported
                 * child, and only then waits for the child's initial stop.
                 * Do not expose the queued initial SIGSTOP in the interval
                 * between those operations: returning it early makes the
                 * backend consume it once, apply SETOPTIONS, and wait for a
                 * second stop that can never arrive. */
                if (fork_event->message_pending ||
                    !fork_event->child_attach_ready ||
                    requested != fork_event->child_pid)
                    child_wait_blocked = true;
                break;
            }
        }
        if (child_wait_blocked) {
            event_trace_log("[ida-vtdbg-shim] nested pop blocked requested=%d pid=%d initial=%d remaining=%zu\n",
                            requested, nested_events[index].pid,
                            nested_events[index].initial_stop ? 1 : 0,
                            nested_event_count);
            continue;
        }
        if (status != NULL)
            *status = nested_events[index].status;
        if (event_pid != NULL)
            *event_pid = nested_events[index].pid;
        bool popped_virtual_fork = nested_events[index].virtual_fork;
        nested_event_audit_locked(2, nested_events[index].pid,
                                  nested_events[index].status, 0, 0, 0);
        bool popped_initial_stop = nested_events[index].initial_stop;
        pid_t popped_aux_pid = nested_events[index].aux_pid;
        pid_t popped_pid = nested_events[index].pid;
        if (nested_events[index].virtual_fork) {
            for (size_t vindex = 0; vindex < NESTED_QUEUE_MAX; ++vindex) {
                if (nested_virtual_forks[vindex].active &&
                    nested_virtual_forks[vindex].parent_pid ==
                        nested_events[index].pid &&
                    nested_virtual_forks[vindex].child_pid ==
                        nested_events[index].aux_pid) {
                    nested_virtual_forks[vindex].event_delivered = true;
                    nested_virtual_forks[vindex].message_pending = true;
                    break;
                }
            }
        } else if (parent_owned_mode && popped_initial_stop) {
            for (size_t vindex = 0; vindex < NESTED_QUEUE_MAX; ++vindex) {
                struct nested_virtual_fork *fork_event =
                    &nested_virtual_forks[vindex];

                if (!fork_event->active ||
                    (fork_event->child_pid != popped_aux_pid &&
                     fork_event->child_pid != popped_pid))
                    continue;
                fork_event->child_initial_delivered = true;
                if (fork_event->resume_requested &&
                    !fork_event->message_pending)
                    fork_event->active = false;
                break;
            }
        }
        for (size_t move = index + 1; move < nested_event_count; ++move)
            nested_events[move - 1] = nested_events[move];
        --nested_event_count;
        found = true;
        event_trace_log("[ida-vtdbg-shim] nested pop requested=%d pid=%d virtual_fork=%d initial_stop=%d aux=%d status=0x%x remaining=%zu\n",
                        requested, event_pid != NULL ? *event_pid : 0,
                        popped_virtual_fork ? 1 : 0,
                        popped_initial_stop ? 1 : 0, popped_aux_pid,
                        status != NULL ? (unsigned int)*status : 0,
                        nested_event_count);
        break;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return found;
}

static bool nested_is_shadow(pid_t pid)
{
    bool found = false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < nested_shadow_count; ++index) {
        if (nested_shadow_pids[index] == pid) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return found;
}

/* IDA's Linux backend freezes its complete thread list before exposing a
 * debug event.  It uses tkill(SIGSTOP) for that pass, then waits for a
 * SIGSTOP status from every task it believes was running.  A parent-owned
 * fork child can already be held at its real ptrace stop by the traced
 * parent; sending another SIGSTOP only queues a signal behind that stop and
 * can never satisfy IDA's wait.  Report an acknowledgement through the
 * ordinary waitpid interposer when the driver-backed owner state confirms
 * that this shadow task is already stopped.  No server-private waiter state
 * or debug-server code is modified.
 */
static bool parent_owned_frozen_child_stop(pid_t pid)
{
    const int stop_status = (SIGSTOP << 8) | 0x7f;
    bool queued = false;

    if (!parent_owned_mode || (!nested_event_worker && !nested_server) ||
        pid <= 0 ||
        !nested_is_shadow(pid) ||
        (!parent_owned_proxy_stop_held(pid, false, false) &&
         !nested_kernel_child_stopped(pid)))
        return false;

    pthread_mutex_lock(&nested_event_lock);
    nested_event_audit_locked(4, pid, stop_status, 0, 0, 0);
    for (size_t index = 0; index < nested_event_count; ++index) {
        if (nested_events[index].pid == pid &&
            nested_events[index].status == stop_status &&
            !nested_events[index].virtual_fork) {
            queued = true;
            break;
        }
    }
    if (!queued && nested_event_count < NESTED_QUEUE_MAX) {
        nested_events[nested_event_count].pid = pid;
        nested_events[nested_event_count].status = stop_status;
        nested_events[nested_event_count].aux_pid = 0;
        nested_events[nested_event_count].virtual_fork = false;
        nested_events[nested_event_count].initial_stop = false;
        ++nested_event_count;
        queued = true;
    }
    pthread_mutex_unlock(&nested_event_lock);

    event_trace_log("[ida-vtdbg-shim] parent-owned freeze stop ack pid=%d status=0x%x queued=%d\n",
                    pid, (unsigned int)stop_status, queued ? 1 : 0);
    return queued;
}

/* The ptrace-owner thread of a visible fork child is parked inside
 * nested_target_wait_common()/parent_owned_hold_proxy_stop(), where it must
 * remain runnable to service the driver's ptrace mailbox.  IDA nevertheless
 * sends SIGSTOP to every thread in its synthetic process view while building
 * an exception event.  Acknowledge that one owner-thread freeze request via
 * waitpid without stopping the mailbox worker; other parent threads still
 * take real SIGSTOPs, and the child remains at its genuine ptrace stop.
 */
static bool parent_owned_frozen_owner_stop(pid_t tid)
{
    const int stop_status = (SIGSTOP << 8) | 0x7f;
    bool child_held = false;
    bool queued = false;
    bool resume_outer = false;

    if (!parent_owned_mode || (!nested_event_worker && !nested_server) ||
        tid <= 0 ||
        (tid == nested_server_outer_pid &&
         atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire)))
        return false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        struct parent_owned_child_state *child =
            &parent_owned_children[index];
        if (child->active && child->owner_tid == tid &&
            child->proxy_stop_held) {
            child_held = true;
            break;
        }
    }
    if (!child_held) {
        pthread_mutex_unlock(&nested_event_lock);
        return false;
    }

    for (size_t index = 0; index < nested_event_count; ++index) {
        if (nested_events[index].pid == tid &&
            nested_events[index].status == stop_status &&
            !nested_events[index].virtual_fork) {
            queued = true;
            break;
        }
    }
    if (!queued && nested_event_count < NESTED_QUEUE_MAX) {
        nested_events[nested_event_count].pid = tid;
        nested_events[nested_event_count].status = stop_status;
        nested_events[nested_event_count].aux_pid = 0;
        nested_events[nested_event_count].virtual_fork = false;
        nested_events[nested_event_count].initial_stop = false;
        ++nested_event_count;
        queued = true;
    }
    if (queued) {
        struct parent_owned_owner_state *owner =
            parent_owned_owner_locked(tid, true);
        if (owner != NULL)
            owner->virtual_stop = true;
        else
            queued = false;
        /* The outer parent is the real ptrace owner of the VM child.  When the
         * child reaches a synthetic resume breakpoint, the parent can be in a
         * real SIGCHLD ptrace-stop at the same time IDA performs its thread
         * freeze pass.  Acknowledging IDA's virtual SIGSTOP without releasing
         * that real owner stop deadlocks the parent before it can consume the
         * child event.  Keep the virtual acknowledgement, but continue the
         * real outer task; PTRACE_CONT on an already-running task is harmless
         * and returns ESRCH, which is intentionally ignored below. */
        resume_outer = queued && nested_server &&
                       tid == nested_server_outer_pid;
    }
    pthread_mutex_unlock(&nested_event_lock);

    if (resume_outer) {
        long resumed = ptrace_internal(PTRACE_CONT, tid, NULL, NULL);
        event_trace_log("[ida-vtdbg-shim] parent-owned owner freeze release tid=%d result=%ld errno=%d\n",
                        tid, resumed, resumed < 0 ? errno : 0);
        if (resumed < 0 && errno != ESRCH && errno != EBUSY)
            trace_log("[ida-vtdbg-shim] owner freeze release unexpected tid=%d errno=%d (%s)\n",
                      tid, errno, strerror(errno));
    }

    event_trace_log("[ida-vtdbg-shim] parent-owned owner freeze ack tid=%d status=0x%x queued=%d\n",
                    tid, (unsigned int)stop_status, queued ? 1 : 0);
    return queued;
}

static bool nested_breakpoint_address_known(uintptr_t address,
                                            uint8_t *original)
{
    bool found = false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        if (nested_user_breakpoints[index].active &&
            !nested_user_breakpoints[index].suppressed &&
            nested_user_breakpoints[index].address == address) {
            if (original != NULL)
                *original = nested_user_breakpoints[index].original_byte;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return found;
}

/* Unlike nested_breakpoint_address_known(), include one-shot suppressed
 * breakpoints. Their physical byte may already be restored while PEEKDATA is
 * still logically overlaid as 0xCC; protocol-step classification must not
 * mistake that debugger breakpoint for a target-owned INT3. */
static bool nested_breakpoint_address_recorded(uintptr_t address,
                                               uint8_t *original)
{
    bool found = false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        const struct nested_user_breakpoint *breakpoint =
            &nested_user_breakpoints[index];
        if ((!breakpoint->active && !breakpoint->suppressed) ||
            breakpoint->address != address)
            continue;
        if (original != NULL)
            *original = breakpoint->original_byte;
        found = true;
        break;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return found;
}

static bool nested_breakpoint_word_registered(uintptr_t address)
{
    uintptr_t aligned = address & ~(sizeof(uintptr_t) - 1u);
    bool found = false;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        if ((nested_user_breakpoints[index].active ||
             nested_user_breakpoints[index].suppressed) &&
            (nested_user_breakpoints[index].address &
             ~(sizeof(uintptr_t) - 1u)) == aligned) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return found;
}

static pid_t nested_protocol_hw_step_child(pid_t request_pid)
{
    pid_t child = 0;
    uintptr_t stop_address = 0;

    if (request_pid > 0 && nested_is_shadow(request_pid) &&
        parent_owned_proxy_stop_held(request_pid, false, false))
        return request_pid;

    child = nested_target_child_pid;
    if (child > 0 &&
        parent_owned_get_synthetic_step_stop(child, &stop_address))
        return child;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        const struct parent_owned_child_state *state =
            &parent_owned_children[index];

        if (!state->active || !state->proxy_stop_held)
            continue;
        if (child != 0 && child != state->pid) {
            child = 0;
            break;
        }
        child = state->pid;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return child;
}

static struct nested_protocol_hw_step *nested_protocol_hw_step_locked(
    pid_t pid)
{
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        struct nested_protocol_hw_step *step =
            &nested_protocol_hw_steps[index];

        if (step->active &&
            (step->request_pid == pid || step->child_pid == pid))
            return step;
    }
    return NULL;
}

static bool nested_protocol_hw_step_write(pid_t pid, uintptr_t offset,
                                          uintptr_t value)
{
    const uintptr_t dr0_offset = offsetof(struct user, u_debugreg[0]);
    const uintptr_t dr6_offset = offsetof(struct user, u_debugreg[6]);
    const uintptr_t dr7_offset = offsetof(struct user, u_debugreg[7]);
    struct nested_protocol_hw_step *step;
    pid_t child = 0;
    uintptr_t target = 0;
    uintptr_t synthetic_address = 0;
    uintptr_t protocol_target = 0;
    size_t reg_index = 0;
    bool is_debug_reg = offset >= dr0_offset &&
                        offset <= dr7_offset &&
                        ((offset - dr0_offset) % sizeof(uintptr_t)) == 0;
    bool protocol = false;
    bool candidate = false;
    bool handled = false;

    bool dead = atomic_load_explicit(&nested_parent_kernel_exit_confirmed,
                                     memory_order_acquire) && pid == nested_server_outer_pid;
    pthread_mutex_lock(&nested_event_lock);
    const struct parent_owned_child_state *dead_state = parent_owned_child_locked(pid, false);
    dead = dead || (dead_state != NULL && dead_state->exit_event_queued);
    pthread_mutex_unlock(&nested_event_lock);
    if (parent_owned_mode && nested_server && is_debug_reg && dead) {
        /* The fixed identity's exit is kernel-confirmed. No DR bank remains
         * to restore; this is IDA breakpoint teardown, not an execution or
         * live-register operation. Root/child death can precede PROC_EXIT. */
        errno = 0;
        return true;
    }

    if (nested_direct_debug_register_rpc ||
        (pid == nested_server_outer_pid &&
         atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire)))
        return false;


    event_trace_log("[ida-vtdbg-shim] hardware-step POKEUSER enter request_pid=%d off=0x%llx value=0x%llx dr0=0x%llx dr6=0x%llx dr7=0x%llx\n",
                    pid, (unsigned long long)offset,
                    (unsigned long long)value,
                    (unsigned long long)dr0_offset,
                    (unsigned long long)dr6_offset,
                    (unsigned long long)dr7_offset);

    if (is_debug_reg) {
        reg_index = (size_t)((offset - dr0_offset) / sizeof(uintptr_t));
        child = nested_protocol_hw_step_child(pid);
        if (child > 0 && reg_index == 0 && value != 0 &&
            parent_owned_get_synthetic_step_stop(child,
                                                 &synthetic_address)) {
            /* A physical observer INT3 is debugger-owned. Only a trace-stop
             * before a genuine program INT3 can start another protocol F8. */
            if (parent_owned_synthetic_is_trace(child) &&
                nested_ida_step_intended(child, synthetic_address) &&
                value == synthetic_address + 1u &&
                nested_server_at_program_int3(child, &protocol_target)) {
                target = value;
                protocol = true;
                candidate = true;
            }
        } else if (child > 0 && reg_index == 0 && value != 0) {
            struct user_regs_struct regs;
            siginfo_t info;
            uint8_t original = 0;
            uintptr_t instruction_word = 0;
            memset(&regs, 0, sizeof(regs));
            memset(&info, 0, sizeof(info));
            if (nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL, &regs) == 0 &&
                nested_ida_step_intended(child, (uintptr_t)regs.rip) &&
                value == regs.rip + 1u &&
                nested_driver_forward_ptrace(PTRACE_GETSIGINFO, child, NULL, &info) == 0 &&
                info.si_signo == SIGTRAP && info.si_code == TRAP_TRACE &&
                (!nested_breakpoint_address_recorded((uintptr_t)regs.rip, &original) ||
                 original == 0xccu)) {
                errno = 0;
                long peek = nested_driver_forward_ptrace(
                    PTRACE_PEEKDATA, child, (void *)(uintptr_t)regs.rip, NULL);
                if (!(peek == -1 && errno != 0))
                    instruction_word = (uintptr_t)peek;
                if ((uint8_t)instruction_word == 0xccu) {
                    /* This is an IDA trace-stop BEFORE a program INT3, not
                     * the program's exception. Record a narrow step request
                     * whose real exception is produced only after CONT. */
                    target = value;
                    protocol = true;
                    candidate = true;
                    event_trace_log("[ida-vtdbg-shim] hardware step at trace-before-program-INT3 child=%d rip=0x%llx\n",
                                    child, (unsigned long long)regs.rip);
                }
            }
        }
        event_trace_log("[ida-vtdbg-shim] hardware-step POKEUSER probe request_pid=%d child=%d off=0x%llx value=0x%llx target=0x%llx candidate=%d\n",
                        pid, child, (unsigned long long)offset,
                        (unsigned long long)value,
                        (unsigned long long)target,
                        candidate ? 1 : 0);
    }

    pthread_mutex_lock(&nested_event_lock);
    step = nested_protocol_hw_step_locked(pid);
    if (candidate) {
        if (step == NULL) {
            for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
                if (!nested_protocol_hw_steps[index].active) {
                    step = &nested_protocol_hw_steps[index];
                    break;
                }
            }
        }
        if (step != NULL) {
            if (!step->active || step->completed) {
                memset(step, 0, sizeof(*step));
                step->request_pid = pid;
                step->child_pid = child;
                step->target = target;
                step->protocol = protocol;
                step->active = true;
            } else if (target != 0) {
                step->target = target;
                step->protocol = protocol;
            }
            step->debug_regs[reg_index] = value;
            handled = true;
        }
    } else if (step != NULL) {
        if (step->completed && is_debug_reg && reg_index < 4 && value != 0) {
            /* A new IDA hardware BP is not cleanup of the old protocol F8.
             * Let the ordinary register path install it on the real child. */
            memset(step, 0, sizeof(*step));
            step = NULL;
        }
        if (step != NULL) {
        if (is_debug_reg) {
            step->debug_regs[reg_index] = value;
            handled = true;
        }
        if (handled && step->resume_issued && step->debug_regs[0] == 0 &&
            step->debug_regs[7] == 0)
            memset(step, 0, sizeof(*step));
        }
    }
    pthread_mutex_unlock(&nested_event_lock);

    if (handled)
        event_trace_log("[ida-vtdbg-shim] virtual protocol hardware-step register pid=%d child=%d off=0x%llx value=0x%llx target=0x%llx candidate=%d\n",
                        pid, child, (unsigned long long)offset,
                        (unsigned long long)value,
                        (unsigned long long)target,
                        candidate ? 1 : 0);
    if (handled)
        handler_trace_log("[ida-vtdbg-shim] debugger-dr-write pid=%d off=0x%llx value=0x%llx candidate=%d\n",
                          pid, (unsigned long long)offset,
                          (unsigned long long)value, candidate ? 1 : 0);
    if (!handled && is_debug_reg && parent_owned_mode && nested_server &&
        pid == nested_server_outer_pid && child > 0) {
        nested_direct_debug_register_rpc = true;
        long result = nested_driver_forward_ptrace(PTRACE_POKEUSER, child,
                                      (void *)offset, (void *)value);
        nested_direct_debug_register_rpc = false;
        handler_trace_log("[ida-vtdbg-shim] debugger-hw-real-write root=%d child=%d off=0x%llx value=0x%llx result=%ld\n",
                          pid, child, (unsigned long long)offset,
                          (unsigned long long)value, result);
        return result == 0;
    }
    return handled;
}

static void nested_generic_hw_step_start(pid_t request_pid, pid_t child,
                                         uintptr_t target)
{
    if (child <= 0 || target == 0)
        return;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        struct nested_generic_hw_step *step = &nested_generic_hw_steps[n];
        if (step->active && step->child_pid == child) {
            step->request_pid = request_pid;
            step->target = target;
            pthread_mutex_unlock(&nested_event_lock);
            event_trace_log("[ida-vtdbg-shim] generic IDA hardware step refreshed child=%d target=0x%llx\n",
                            child, (unsigned long long)target);
            return;
        }
    }
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        struct nested_generic_hw_step *step = &nested_generic_hw_steps[n];
        if (!step->active) {
            step->request_pid = request_pid;
            step->child_pid = child;
            step->target = target;
            step->active = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] generic IDA hardware step armed child=%d target=0x%llx\n",
                    child, (unsigned long long)target);
}

static bool nested_ida_step_intended(pid_t child, uintptr_t ip)
{
    bool intended = false;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n)
        if (nested_ida_step_intents[n].active &&
            nested_ida_step_intents[n].child == child &&
            nested_ida_step_intents[n].ip == ip) {
            intended = true;
            break;
        }
    pthread_mutex_unlock(&nested_event_lock);
    return intended;
}

static bool nested_ida_call_return_request(pid_t child, uintptr_t target)
{
    struct user_regs_struct regs;
    uint8_t bytes[16] = {0};
    uintptr_t words[2] = {0, 0};
    size_t i = 0;
    bool address32 = false;

    if (!ida_bpt_request_context.active ||
        !ida_bpt_request_context.client_update ||
        (ida_bpt_request_context.type != 8 &&
         ida_bpt_request_context.type != 4) ||
        ida_bpt_request_context.address != target || child <= 0)
        return false;
    bool real_parent = child == nested_server_outer_pid &&
        atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire);
    if ((real_parent ? ptrace_internal(PTRACE_GETREGS, child, NULL, &regs)
                     : nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL, &regs)) < 0)
        return false;
    if (!nested_ida_step_intended(child, (uintptr_t)regs.rip))
        return false;
    for (size_t n = 0; n < 2; ++n) {
        errno = 0;
        unsigned long fetched = 0;
        long word = real_parent
            ? ptrace_internal(PTRACE_PEEKDATA, child,
                (void *)(uintptr_t)(regs.rip + n * 8), &fetched)
            : nested_driver_forward_ptrace(PTRACE_PEEKDATA, child,
                (void *)(uintptr_t)(regs.rip + n * 8), NULL);
        if (word == -1 && errno != 0)
            return false;
        words[n] = real_parent ? fetched : (uintptr_t)word;
    }
    memcpy(bytes, words, sizeof(bytes));
    uint8_t original = 0;
    if (bytes[0] == 0xcc &&
        nested_breakpoint_address_recorded((uintptr_t)regs.rip, &original))
        bytes[0] = original;
    while (i < 8 && (bytes[i] == 0x66 || bytes[i] == 0x67 ||
           bytes[i] == 0x2e || bytes[i] == 0x3e || bytes[i] == 0x64 ||
           bytes[i] == 0x65 || bytes[i] == 0xf2 || bytes[i] == 0xf3 ||
           (bytes[i] >= 0x40 && bytes[i] <= 0x4f))) {
        address32 |= bytes[i] == 0x67;
        ++i;
    }
    if (bytes[i] == 0xe8) {
        i += 5; /* x86-64 near CALL rel32 */
    } else if (bytes[i] == 0xff && ((bytes[i + 1] >> 3) & 7u) == 2u) {
        uint8_t modrm = bytes[i + 1];
        unsigned int mod = modrm >> 6;
        unsigned int rm = modrm & 7u;
        i += 2;
        if (mod != 3 && rm == 4) {
            uint8_t sib = bytes[i++];
            if (mod == 0 && (sib & 7u) == 5)
                i += 4;
        } else if (mod == 0 && rm == 5) {
            i += 4;
        }
        if (mod == 1)
            ++i;
        else if (mod == 2)
            i += 4;
        (void)address32; /* ModRM displacement size is unchanged in 32-bit EA */
    } else {
        return false;
    }
    return i <= 15 && target == (uintptr_t)regs.rip + i;
}

static bool nested_generic_hw_step_pending(pid_t pid, uintptr_t *target)
{
    bool found = false;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        struct nested_generic_hw_step *step = &nested_generic_hw_steps[n];
        if (step->active && (step->child_pid == pid || step->request_pid == pid)) {
            if (target != NULL)
                *target = step->target;
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    return found;
}

static void nested_generic_hw_step_complete(pid_t child)
{
    bool removed = false;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        if (nested_generic_hw_steps[n].active &&
            nested_generic_hw_steps[n].child_pid == child) {
            memset(&nested_generic_hw_steps[n], 0,
                   sizeof(nested_generic_hw_steps[n]));
            removed = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (removed)
        event_trace_log("[ida-vtdbg-shim] generic IDA hardware step completed child=%d\n", child);
}

static void nested_generic_hw_step_clear(pid_t pid)
{
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_QUEUE_MAX; ++n) {
        if (nested_generic_hw_steps[n].active &&
            (nested_generic_hw_steps[n].child_pid == pid ||
             nested_generic_hw_steps[n].request_pid == pid))
            memset(&nested_generic_hw_steps[n], 0,
                   sizeof(nested_generic_hw_steps[n]));
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static bool nested_protocol_hw_step_peek(pid_t pid, uintptr_t offset,
                                         uintptr_t *value)
{
    const uintptr_t dr0_offset = offsetof(struct user, u_debugreg[0]);
    const uintptr_t dr7_offset = offsetof(struct user, u_debugreg[7]);
    struct nested_protocol_hw_step *step;
    bool handled = false;
    size_t reg_index;

    if (value == NULL || offset < dr0_offset || offset > dr7_offset ||
        ((offset - dr0_offset) % sizeof(uintptr_t)) != 0)
        return false;
    bool dead = atomic_load_explicit(&nested_parent_kernel_exit_confirmed,
                                     memory_order_acquire) && pid == nested_server_outer_pid;
    pthread_mutex_lock(&nested_event_lock);
    const struct parent_owned_child_state *dead_state = parent_owned_child_locked(pid, false);
    dead = dead || (dead_state != NULL && dead_state->exit_event_queued);
    pthread_mutex_unlock(&nested_event_lock);
    if (parent_owned_mode && nested_server && dead) {
        *value = 0; /* terminal logical breakpoint bank, no live registers */
        errno = 0;
        return true;
    }
    if (pid == nested_server_outer_pid &&
        atomic_load_explicit(&nested_parent_real_stopped, memory_order_acquire))
        return false;
    reg_index = (size_t)((offset - dr0_offset) / sizeof(uintptr_t));

    pthread_mutex_lock(&nested_event_lock);
    step = nested_protocol_hw_step_locked(pid);
    if (step != NULL) {
        *value = step->debug_regs[reg_index];
        handled = true;
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (!handled && !nested_direct_debug_register_rpc && parent_owned_mode &&
        nested_server && pid == nested_server_outer_pid) {
        pid_t child = nested_protocol_hw_step_child(pid);
        if (child > 0) {
            nested_direct_debug_register_rpc = true;
            errno = 0;
            long fetched = nested_driver_forward_ptrace(PTRACE_PEEKUSER,
                                             child, (void *)offset, NULL);
            bool succeeded = !(fetched == -1 && errno != 0);
            nested_direct_debug_register_rpc = false;
            if (succeeded) {
                *value = (uintptr_t)fetched;
                handled = true;
            }
        }
    }
    return handled;
}

static bool nested_protocol_hw_step_pending(pid_t pid)
{
    struct nested_protocol_hw_step *step;
    bool pending = false;

    pthread_mutex_lock(&nested_event_lock);
    step = nested_protocol_hw_step_locked(pid);
    if (step != NULL)
        pending = !step->resume_issued && !step->completed;
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static bool nested_protocol_hw_step_take(pid_t pid, pid_t *child,
                                         bool *protocol)
{
    struct nested_protocol_hw_step *step;
    bool taken = false;

    pthread_mutex_lock(&nested_event_lock);
    step = nested_protocol_hw_step_locked(pid);
    if (step != NULL && !step->resume_issued && !step->completed) {
        step->resume_issued = true;
        if (child != NULL)
            *child = step->child_pid;
        if (protocol != NULL)
            *protocol = step->protocol;
        taken = true;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return taken;
}

static uintptr_t nested_protocol_hw_step_target(pid_t pid)
{
    uintptr_t target = 0;

    pthread_mutex_lock(&nested_event_lock);
    {
        struct nested_protocol_hw_step *step =
            nested_protocol_hw_step_locked(pid);
        if (step != NULL)
            target = step->target;
    }
    pthread_mutex_unlock(&nested_event_lock);
    return target;
}

static bool nested_protocol_hw_step_already_issued(pid_t pid)
{
    struct nested_protocol_hw_step *step;
    bool issued = false;

    pthread_mutex_lock(&nested_event_lock);
    step = nested_protocol_hw_step_locked(pid);
    if (step != NULL)
        issued = step->resume_issued && !step->completed;
    pthread_mutex_unlock(&nested_event_lock);
    return issued;
}

static void nested_protocol_hw_step_reset(pid_t child)
{
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        if (nested_protocol_hw_steps[index].active &&
            nested_protocol_hw_steps[index].child_pid == child) {
            /* Preserve DR cleanup acknowledgement until IDA clears DR0/7.
             * Destroying the record before those zero writes makes cleanup
             * look like a fresh step at the synthetic breakpoint. */
            nested_protocol_hw_steps[index].resume_issued = true;
            /* Completion ends duplicate-resume suppression.  IDA need not
             * clear DR0 (it may only disable DR7), so register cleanup must
             * never be a prerequisite for the next genuine CONT/STEP. */
            nested_protocol_hw_steps[index].completed = true;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    handler_trace_log("[ida-vtdbg-shim] debugger-dr-completed child=%d\n", child);
}

static void nested_target_request_protocol_step(pid_t child,
                                                uintptr_t stale_address)
{
    if (!nested_target || nested_target_launcher || child <= 0)
        return;
    if (stale_address == 0) {
        if (!parent_owned_get_synthetic_step_stop(child, &stale_address) ||
            stale_address == 0)
            stale_address = parent_owned_last_synthetic_step_address(child);
    }
    pthread_mutex_lock(&nested_event_lock);
    memset(&nested_target_protocol_step, 0,
           sizeof(nested_target_protocol_step));
    nested_target_protocol_step.child = child;
    nested_target_protocol_step.stale_address = stale_address;
    nested_target_protocol_step.requested = true;
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] target protocol-step observe requested child=%d stale=0x%llx\n",
                    child, (unsigned long long)stale_address);
}

static bool nested_target_capture_protocol_regs(
    pid_t child, const struct user_regs_struct *regs)
{
    bool captured = false;

    if (!nested_target || nested_target_launcher || child <= 0 || regs == NULL)
        return false;
    if (handler_trace_enabled)
        handler_trace_log("[ida-vtdbg-shim] handler-resume seq=%llu child=%d owner=%d rip=0x%llx rbp=0x%llx rsp=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx rdi=0x%llx\n",
                          atomic_load_explicit(&handler_trace_sequence, memory_order_relaxed),
                          child, current_tid(), (unsigned long long)regs->rip,
                          (unsigned long long)regs->rbp, (unsigned long long)regs->rsp,
                          (unsigned long long)regs->rax, (unsigned long long)regs->rbx,
                          (unsigned long long)regs->rcx, (unsigned long long)regs->rdx,
                          (unsigned long long)regs->rsi, (unsigned long long)regs->rdi);
    pthread_mutex_lock(&nested_event_lock);
    if (nested_target_protocol_step.requested &&
        !nested_target_protocol_step.armed &&
        (nested_target_protocol_step.child == 0 ||
         nested_target_protocol_step.child == child) &&
        regs->rip != 0) {
        nested_target_protocol_step.child = child;
        nested_target_protocol_step.address = (uintptr_t)regs->rip;
        nested_target_protocol_step.aligned =
            nested_target_protocol_step.address &
            ~(sizeof(uintptr_t) - 1u);
        captured = true;
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (captured)
        event_trace_log("[ida-vtdbg-shim] target protocol-step resume RIP captured child=%d rip=0x%llx\n",
                        child, (unsigned long long)regs->rip);
    if (nested_target && nested_target_protocol_step.requested == false &&
        parent_owned_get_program_exception(child, NULL, NULL, NULL)) {
        parent_owned_set_exception_resume(child, true,
                                          (uintptr_t)regs->rip);
        event_trace_log("[ida-vtdbg-shim] target program-exception SETREGS resume captured child=%d rip=0x%llx\n",
                        child, (unsigned long long)regs->rip);
    }
    return captured;
}

static bool nested_target_capture_protocol_regset(pid_t child, void *addr,
                                                  void *data)
{
    const struct iovec *iov = data;
    const struct user_regs_struct *regs;

    /* NT_PRSTATUS is 1 on Linux x86-64. */
    if (addr == NULL || (uintptr_t)addr != 1u || iov == NULL ||
        iov->iov_base == NULL || iov->iov_len < sizeof(*regs))
        return false;
    regs = iov->iov_base;
    event_trace_log("[ida-vtdbg-shim] target SETREGSET child=%d rip=0x%llx len=%zu\n",
                    child, (unsigned long long)regs->rip, iov->iov_len);
    return nested_target_capture_protocol_regs(child, regs);
}

static bool nested_target_arm_protocol_step(pid_t child)
{
    struct user_regs_struct regs;
    uintptr_t address;
    uintptr_t aligned;
    uintptr_t word;
    uint8_t original;
    uintptr_t stale_address = 0;
    long result;
    bool requested;

    if (!nested_target || nested_target_launcher || child <= 0)
        return false;
    pthread_mutex_lock(&nested_event_lock);
    requested = nested_target_protocol_step.requested &&
                !nested_target_protocol_step.armed &&
                (nested_target_protocol_step.child == 0 ||
                 nested_target_protocol_step.child == child);
    address = nested_target_protocol_step.address;
    aligned = nested_target_protocol_step.aligned;
    stale_address = nested_target_protocol_step.stale_address;
    pthread_mutex_unlock(&nested_event_lock);
    if (!requested)
        return false;

    if (address == 0) {
        memset(&regs, 0, sizeof(regs));
        result = ptrace_raw(PTRACE_GETREGS, child, NULL, &regs);
        if (result < 0 || regs.rip == 0)
            return false;
        address = (uintptr_t)regs.rip;
        aligned = address & ~(sizeof(uintptr_t) - 1u);
    }

    /* ptrace_raw() enters SYS_ptrace directly.  At the syscall ABI level a
     * PEEK request writes the fetched word through data and returns status 0;
     * only libc's ptrace() wrapper turns that word into its return value. */
    word = 0;
    errno = 0;
    result = ptrace_raw(PTRACE_PEEKDATA, child, (void *)aligned, &word);
    if (result != 0) {
        event_trace_log("[ida-vtdbg-shim] target protocol-step PEEKDATA failed child=%d addr=0x%llx result=%ld errno=%d\n",
                        child, (unsigned long long)aligned, result, errno);
        return false;
    }
    original = (uint8_t)(word >> ((address - aligned) * 8u));
    if (original == 0xccu) {
        pthread_mutex_lock(&nested_event_lock);
        nested_target_protocol_step.child = child;
        nested_target_protocol_step.address = address;
        nested_target_protocol_step.aligned = aligned;
        nested_target_protocol_step.original_byte = original;
        nested_target_protocol_step.requested = false;
        nested_target_protocol_step.armed = true;
        pthread_mutex_unlock(&nested_event_lock);
        event_trace_log("[ida-vtdbg-shim] target protocol-step resume RIP already has INT3 child=%d rip=0x%llx\n",
                        child, (unsigned long long)address);
        return true;
    }
    word &= ~((uintptr_t)0xffu << ((address - aligned) * 8u));
    word |= (uintptr_t)0xccu << ((address - aligned) * 8u);
    result = ptrace_raw(PTRACE_POKEDATA, child, (void *)aligned,
                        (void *)word);
    if (result < 0)
        return false;

    pthread_mutex_lock(&nested_event_lock);
    nested_target_protocol_step.child = child;
    nested_target_protocol_step.address = address;
    nested_target_protocol_step.aligned = aligned;
    nested_target_protocol_step.original_byte = original;
    nested_target_protocol_step.armed = true;
    pthread_mutex_unlock(&nested_event_lock);
    if (requested && parent_owned_mode) {
        /* The target's real parent has now consumed the protocol INT3,
         * selected the architectural resume RIP, and is about to issue its
         * own PTRACE_CONT.  The proxy stop that linux_server saw belongs to
         * the old protocol event; keep it from being reclassified as a new
         * stop while the child runs to the synthetic resume breakpoint. */
        (void)parent_owned_proxy_stop_held(child, true, false);
        if (stale_address != 0)
            parent_owned_set_resume_observation(child, true,
                                                stale_address + 1u,
                                                address + 1u);
        event_trace_log("[ida-vtdbg-shim] target parent released old proxy stop child=%d resume=0x%llx stale=0x%llx\n",
                        child, (unsigned long long)address,
                        (unsigned long long)stale_address);
    }
    event_trace_log("[ida-vtdbg-shim] target protocol-step synthetic breakpoint armed child=%d addr=0x%llx word=0x%llx original=0x%02x\n",
                    child, (unsigned long long)address,
                    (unsigned long long)word,
                    (unsigned int)original);
    return true;
}

static bool nested_target_restore_synthetic_step(pid_t child)
{
    uintptr_t address;
    uintptr_t aligned;
    uintptr_t word;
    uint8_t original;
    long result;
    bool armed;

    pthread_mutex_lock(&nested_event_lock);
    armed = nested_target_protocol_step.armed &&
            nested_target_protocol_step.child == child;
    address = nested_target_protocol_step.address;
    aligned = nested_target_protocol_step.aligned;
    original = nested_target_protocol_step.original_byte;
    pthread_mutex_unlock(&nested_event_lock);
    if (!armed)
        return false;

    word = 0;
    errno = 0;
    result = ptrace_raw(PTRACE_PEEKDATA, child, (void *)aligned, &word);
    if (result != 0) {
        event_trace_log("[ida-vtdbg-shim] target protocol-step restore PEEKDATA failed child=%d addr=0x%llx result=%ld errno=%d\n",
                        child, (unsigned long long)aligned, result, errno);
        return false;
    }
    word &= ~((uintptr_t)0xffu << ((address - aligned) * 8u));
    word |= (uintptr_t)original << ((address - aligned) * 8u);
    result = ptrace_raw(PTRACE_POKEDATA, child, (void *)aligned,
                        (void *)word);
    if (result < 0)
        return false;
    pthread_mutex_lock(&nested_event_lock);
    memset(&nested_target_protocol_step, 0,
           sizeof(nested_target_protocol_step));
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] target protocol-step synthetic breakpoint restored child=%d addr=0x%llx\n",
                    child, (unsigned long long)address);
    handler_trace_log("[ida-vtdbg-shim] debugger-synthetic-restored child=%d addr=0x%llx byte=0x%02x\n",
                      child, (unsigned long long)address, (unsigned int)original);
    return true;
}

static bool nested_target_protocol_step_pending(pid_t child)
{
    bool pending;

    pthread_mutex_lock(&nested_event_lock);
    pending = (nested_target_protocol_step.armed ||
               nested_target_protocol_step.trace_step_pending) &&
              nested_target_protocol_step.child == child;
    pthread_mutex_unlock(&nested_event_lock);
    return pending;
}

static bool nested_target_protocol_step_requested(pid_t child)
{
    bool requested = false;

    pthread_mutex_lock(&nested_event_lock);
    requested = nested_target_protocol_step.requested &&
                nested_target_protocol_step.child == child;
    pthread_mutex_unlock(&nested_event_lock);
    return requested;
}

/* The target's real parent tracer never sees debugger-only synthetic stops.
 * Once IDA resumes the synthetic event, rewind the x86 INT3 post-trap RIP,
 * restore the original instruction, and resume the child from inside the
 * parent's wait interposer.  A requested single-step is re-presented as a
 * synthetic TRAP_TRACE stop on the next pass through nested_target_wait_common. */
static bool nested_target_resume_synthetic_step(pid_t child,
                                               unsigned int resume)
{
    struct user_regs_struct regs;
    uintptr_t address = 0;
    bool armed;
    bool trace_step_pending;
    bool protocol_step_requested;
    uintptr_t stale_address = 0;
    enum __ptrace_request request;
    long result;

    memset(&regs, 0, sizeof(regs));
    pthread_mutex_lock(&nested_event_lock);
    armed = nested_target_protocol_step.armed &&
            nested_target_protocol_step.child == child;
    trace_step_pending =
        nested_target_protocol_step.trace_step_pending &&
        nested_target_protocol_step.child == child;
    protocol_step_requested = nested_target_protocol_step.requested &&
                              nested_target_protocol_step.child == child;
    address = nested_target_protocol_step.address;
    stale_address = nested_target_protocol_step.stale_address;
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] target synthetic resume entry process=%d child=%d resume=%u armed=%d trace=%d requested=%d addr=0x%llx stale=0x%llx\n",
                    getpid(), child, resume, armed ? 1 : 0,
                    trace_step_pending ? 1 : 0,
                    protocol_step_requested ? 1 : 0,
                    (unsigned long long)address,
                    (unsigned long long)stale_address);
    handler_trace_log("[ida-vtdbg-shim] debugger-synthetic-resume child=%d resume=%u armed=%d trace=%d requested=%d addr=0x%llx\n",
                      child, resume, armed ? 1 : 0, trace_step_pending ? 1 : 0,
                      protocol_step_requested ? 1 : 0, (unsigned long long)address);
    if (!armed && !trace_step_pending && !protocol_step_requested)
        return false;

    if (armed) {
        memset(&regs, 0, sizeof(regs));
        result = ptrace_raw(PTRACE_GETREGS, child, NULL, &regs);
        if (result < 0)
            return false;
        if (regs.rip == address + 1u) {
            regs.rip = address;
            result = ptrace_raw(PTRACE_SETREGS, child, NULL, &regs);
            if (result < 0)
                return false;
        }
        if (!nested_target_restore_synthetic_step(child))
            return false;
    }

    request = resume == PARENT_OWNED_RESUME_STEP
                  ? PTRACE_SINGLESTEP
                  : PTRACE_CONT;
    if (request == PTRACE_SINGLESTEP) {
        pthread_mutex_lock(&nested_event_lock);
        memset(&nested_target_protocol_step, 0,
               sizeof(nested_target_protocol_step));
        nested_target_protocol_step.child = child;
        nested_target_protocol_step.trace_step_pending = true;
        pthread_mutex_unlock(&nested_event_lock);
    } else if (protocol_step_requested && !armed && !trace_step_pending) {
        /* A pre-INT3 trace-stop still needs the real parent's SETREGS.
         * Conversely, reaching the armed resume breakpoint completes that
         * observation.  Re-arming 'requested' after restoring it would plant
         * another synthetic BP at every subsequent VM destination. */
        pthread_mutex_lock(&nested_event_lock);
        memset(&nested_target_protocol_step, 0,
               sizeof(nested_target_protocol_step));
        nested_target_protocol_step.child = child;
        /* Preserve the real protocol INT3 address while the target parent
         * handles the stop and later redirects the child.  The next kernel
         * event may still be the old post-INT3 wait record. */
        nested_target_protocol_step.stale_address = stale_address;
        nested_target_protocol_step.requested = true;
        pthread_mutex_unlock(&nested_event_lock);
    } else {
        pthread_mutex_lock(&nested_event_lock);
        memset(&nested_target_protocol_step, 0,
               sizeof(nested_target_protocol_step));
        pthread_mutex_unlock(&nested_event_lock);
    }

    result = ptrace_raw(request, child, NULL, NULL);
    if (result < 0) {
        pthread_mutex_lock(&nested_event_lock);
        if (nested_target_protocol_step.child == child &&
            nested_target_protocol_step.trace_step_pending)
            memset(&nested_target_protocol_step, 0,
                   sizeof(nested_target_protocol_step));
        pthread_mutex_unlock(&nested_event_lock);
        event_trace_log("[ida-vtdbg-shim] target protocol-step synthetic resume failed child=%d request=%d errno=%d\n",
                        child, request, errno);
        return false;
    }
    event_trace_log("[ida-vtdbg-shim] target protocol-step synthetic resumed child=%d request=%d rip=0x%llx\n",
                    child, request,
                    (unsigned long long)(regs.rip != 0 ? regs.rip : 0));
    return true;
}

static bool nested_target_is_synthetic_stop(
    pid_t child, int status, struct user_regs_struct *regs)
{
    struct user_regs_struct local_regs;
    siginfo_t info;
    uintptr_t address;
    bool armed;
    bool trace_step_pending;
    long result;

    if (!nested_target || nested_target_launcher || child <= 0 ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
        return false;
    if (regs == NULL)
        regs = &local_regs;
    result = ptrace_raw(PTRACE_GETREGS, child, NULL, regs);
    if (result < 0 || regs->rip == 0)
        return false;
    pthread_mutex_lock(&nested_event_lock);
    armed = nested_target_protocol_step.armed &&
            nested_target_protocol_step.child == child;
    trace_step_pending =
        nested_target_protocol_step.trace_step_pending &&
        nested_target_protocol_step.child == child;
    address = nested_target_protocol_step.address;
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] synthetic-stop classify child=%d rip=0x%llx armed=%d trace=%d addr=0x%llx status=0x%x\n",
                    child, (unsigned long long)regs->rip, armed ? 1 : 0,
                    trace_step_pending ? 1 : 0,
                    (unsigned long long)address, (unsigned int)status);
    if (armed && regs->rip == address + 1u)
        return true;
    if (!trace_step_pending)
        return false;
    memset(&info, 0, sizeof(info));
    result = ptrace_raw(PTRACE_GETSIGINFO, child, NULL, &info);
    if (result < 0)
        return false;
#ifdef TRAP_TRACE
    return info.si_code == TRAP_TRACE;
#else
    return info.si_code == 2;
#endif
}

static int nested_target_hold_synthetic_stop(pid_t child, int *status,
                                             struct rusage *usage,
                                             bool use_wait4)
{
    int local_status;

    if (status == NULL)
        return -1;
    local_status = *status;
    for (;;) {
        unsigned int resume;
        (void)parent_owned_proxy_stop_held(child, true, true);
        nested_parent_report_stop(child, local_status, false,
                                  IDA_VTDBG_EVENT_F_SYNTHETIC_STEP);
        for (;;) {
            int serviced = nested_driver_service_command(true, NULL);
            if (serviced < 0)
                return -1;
            resume = parent_owned_take_resume_request(child);
            event_trace_log("[ida-vtdbg-shim] synthetic hold poll process=%d child=%d serviced=%d resume=%u\n",
                            getpid(), child, serviced, resume);
            if (resume != PARENT_OWNED_RESUME_NONE)
                break;
            {
                struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
                (void)nanosleep(&delay, NULL);
            }
        }
        if (resume == PARENT_OWNED_RESUME_CONT ||
            resume == PARENT_OWNED_RESUME_STEP) {
            if (!nested_target_resume_synthetic_step(child, resume))
                return -1;
            (void)parent_owned_proxy_stop_held(child, true, false);
            if (resume == PARENT_OWNED_RESUME_CONT)
                return 1;

            /* Consume the single-step stop here so the target's VM cannot
             * mistake this debugger-only TRAP_TRACE for a protocol INT3. */
            for (;;) {
                struct rusage local_usage;
                pid_t waited = use_wait4
                                   ? real_wait4(child, &local_status,
                                                WNOHANG,
                                                usage != NULL ? &local_usage
                                                              : NULL)
                                   : real_waitpid(child, &local_status,
                                                  WNOHANG);
                if (waited < 0) {
                    if (errno == EINTR)
                        continue;
                    return -1;
                }
                if (waited == child) {
                    if (usage != NULL && use_wait4)
                        *usage = local_usage;
                    if (!WIFSTOPPED(local_status)) {
                        *status = local_status;
                        return 0;
                    }
                    if (WSTOPSIG(local_status) != SIGTRAP) {
                        *status = local_status;
                        return 0;
                    }
                    *status = local_status;
                    if (!nested_target_is_synthetic_stop(child, local_status, NULL)) {
                        /* A real INT3 executed during single-step belongs to
                         * the parent's VM, never this synthetic trace loop. */
                        pthread_mutex_lock(&nested_event_lock);
                        if (nested_target_protocol_step.child == child)
                            nested_target_protocol_step.trace_step_pending = false;
                        pthread_mutex_unlock(&nested_event_lock);
                        return 0;
                    }
                    break;
                }
                if (nested_driver_service_command(true, NULL) < 0)
                    return -1;
                {
                    struct timespec delay = {.tv_sec = 0,
                                             .tv_nsec = 1000000};
                    (void)nanosleep(&delay, NULL);
                }
            }
            continue;
        }
    }
}

static size_t nested_shadow_index_locked(pid_t child)
{
    for (size_t n = 0; n < nested_shadow_count; ++n)
        if (nested_shadow_pids[n] == child)
            return n;
    return NESTED_QUEUE_MAX;
}

static bool nested_breakpoint_restore_pending_locked(
    const struct nested_user_breakpoint *breakpoint, pid_t child)
{
    size_t slot = nested_shadow_index_locked(child);
    if (slot >= NESTED_QUEUE_MAX)
        return false;
    return (breakpoint->restore_pending_mask[slot / 64u] &
            (UINT64_C(1) << (slot % 64u))) != 0;
}

static void nested_breakpoint_restore_mark_locked(
    struct nested_user_breakpoint *breakpoint, pid_t source_pid)
{
    if (source_pid != nested_server_outer_pid || source_pid <= 0)
        return;
    for (size_t n = 0; n < nested_shadow_count; ++n)
        breakpoint->restore_pending_mask[n / 64u] |= UINT64_C(1) << (n % 64u);
}

static void nested_breakpoint_restore_ack_locked(
    struct nested_user_breakpoint *breakpoint, pid_t child)
{
    size_t slot = nested_shadow_index_locked(child);
    if (slot >= NESTED_QUEUE_MAX)
        return;
    breakpoint->restore_pending_mask[slot / 64u] &=
        ~(UINT64_C(1) << (slot % 64u));
}

static void nested_breakpoint_remove(pid_t source_pid, uintptr_t address,
                                     uint8_t original)
{
    bool clear_oneshot = parent_owned_mode && nested_server &&
                         oneshot_algorithm_enabled &&
                         address == oneshot_algorithm_address;

    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        if ((nested_user_breakpoints[index].active ||
             nested_user_breakpoints[index].suppressed) &&
            nested_user_breakpoints[index].address == address &&
            nested_user_breakpoints[index].original_byte == original) {
            nested_user_breakpoints[index].active = false;
            nested_user_breakpoints[index].suppressed = false;
            nested_breakpoint_restore_mark_locked(
                &nested_user_breakpoints[index], source_pid);
            atomic_fetch_add_explicit(&nested_breakpoint_revision, 1, memory_order_release);
            break;
        }
    }
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        if (nested_ida_software_steps[index].active &&
            nested_ida_software_steps[index].address == address &&
            nested_ida_software_steps[index].original == original)
            memset(&nested_ida_software_steps[index], 0,
                   sizeof(nested_ida_software_steps[index]));
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (clear_oneshot)
        shared_set_oneshot_control(false, address);
}

static void nested_breakpoint_record(uintptr_t address, uint8_t original);

/* Suppress exactly one explicitly configured algorithm breakpoint after its
 * first visible child stop.  The physical child byte is restored immediately
 * while the stop is held; nested_overlay_target_breakpoint_value() keeps the
 * parent's own anti-debug PEEKDATA check logically at 0xcc. */
static bool nested_auto_suppress_breakpoint(pid_t child, uintptr_t address)
{
    bool suppressed = false;
    uint8_t original = 0;
    uintptr_t aligned = address & ~(sizeof(uintptr_t) - 1u);

    if (repeat_handler_breakpoints || !oneshot_algorithm_enabled ||
        oneshot_algorithm_address == 0 ||
        child <= 0 || address != oneshot_algorithm_address)
        return false;

    pthread_mutex_lock(&nested_event_lock);
    if (!oneshot_algorithm_done) {
        for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
            struct nested_user_breakpoint *breakpoint =
                &nested_user_breakpoints[index];
            struct parent_owned_child_state *state;

            if (!breakpoint->active || breakpoint->suppressed ||
                breakpoint->address != address)
                continue;
            /* Keep active=true while the physical word is still 0xcc so
             * virtual PEEKDATA remains truthful during IDA's stop handling.
             * The suppressed bit prevents classification/replay on later
             * protocol stops. */
            breakpoint->suppressed = true;
            original = breakpoint->original_byte;
            state = parent_owned_child_locked(child, true);
            if (state != NULL)
                state->oneshot_visible = true;
            oneshot_algorithm_done = true;
            suppressed = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (suppressed) {
        uintptr_t word = 0;
        long peek_result;
        long poke_result;
        size_t offset = (size_t)(address - aligned);

        /* The server-side event poller is not the Linux ptrace owner.  Use the
         * driver mailbox for both operations; the POKE deliberately skips the
         * normal breakpoint-state commit so the suppressed entry remains
         * active for the logical parent-side PEEKDATA overlay. */
        peek_result = nested_driver_forward_ptrace(
            PTRACE_PEEKDATA, child, (void *)aligned, NULL);
        if (!(peek_result == -1 && errno != 0)) {
            word = (uintptr_t)peek_result;
            word &= ~((uintptr_t)0xffu << (offset * 8u));
            word |= (uintptr_t)original << (offset * 8u);
            nested_skip_breakpoint_commit = true;
            poke_result = nested_driver_forward_ptrace(
                PTRACE_POKEDATA, child, (void *)aligned, (void *)word);
            nested_skip_breakpoint_commit = false;
            event_trace_log("[ida-vtdbg-shim] one-shot physical restore child=%d addr=0x%llx original=0x%02x peek=%ld poke=%ld errno=%d\n",
                            child, (unsigned long long)address,
                            (unsigned int)original, peek_result,
                            poke_result, poke_result < 0 ? errno : 0);
        } else {
            event_trace_log("[ida-vtdbg-shim] one-shot physical restore child=%d addr=0x%llx original=0x%02x peek=%ld errno=%d\n",
                            child, (unsigned long long)address,
                            (unsigned int)original, peek_result,
                            peek_result < 0 ? errno : 0);
        }
        event_trace_log("[ida-vtdbg-shim] one-shot suppress breakpoint child=%d addr=0x%llx (logical parent overlay retained)\n",
                        child, (unsigned long long)address);
    }
    return suppressed;
}

static void nested_note_target_breakpoint_restore(pid_t pid, void *addr,
                                                   void *data)
{
    uintptr_t address = (uintptr_t)addr;
    uintptr_t value = (uintptr_t)data;

    if (!oneshot_algorithm_enabled || address == 0)
        return;
    for (size_t offset = 0; offset < sizeof(uintptr_t); ++offset) {
        uintptr_t byte_address = address + offset;
        uint8_t after = (uint8_t)(value >> (offset * 8u));
        bool restored = false;

        pthread_mutex_lock(&nested_event_lock);
        for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
            struct nested_user_breakpoint *breakpoint =
                &nested_user_breakpoints[index];
            if (!breakpoint->suppressed || !breakpoint->active ||
                breakpoint->address != byte_address ||
                breakpoint->original_byte != after)
                continue;
            /* The target's own parent VM has now restored the original byte;
             * keep the suppressed tombstone so a late IDA write remains
             * idempotent, but stop reporting/replaying the overlay. */
            breakpoint->active = false;
            restored = true;
            break;
        }
        pthread_mutex_unlock(&nested_event_lock);
        if (restored)
            event_trace_log("[ida-vtdbg-shim] target VM restored one-shot breakpoint pid=%d addr=0x%llx byte=0x%02x\n",
                            pid, (unsigned long long)byte_address,
                            (unsigned int)after);
    }
}

static bool nested_breakpoint_word_has_cc(void *data)
{
    uintptr_t value = (uintptr_t)data;

    for (size_t offset = 0; offset < sizeof(uintptr_t); ++offset)
        if (((value >> (offset * 8u)) & 0xffu) == 0xccu)
            return true;
    return false;
}

static bool nested_virtual_breakpoint_peek(pid_t pid, void *addr,
                                           long *value)
{
    uintptr_t address = (uintptr_t)addr;
    uintptr_t word = 0;
    bool found = false;
    uintptr_t actual_word = 0;
    long actual;

    if (!parent_owned_mode || (!nested_server && !nested_event_worker) ||
        value == NULL || address == 0)
        return false;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        if (nested_user_breakpoints[index].active &&
            nested_user_breakpoints[index].address >= address &&
            nested_user_breakpoints[index].address - address < sizeof(uintptr_t)) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    /* The real VM owner must remain runnable to service child RPCs. IDA
     * reads a new BP's original bytes before it records that BP, so root
     * PEEK must also work at an as-yet unregistered address. */
    if (!found && !(nested_server && pid == nested_server_outer_pid && pid > 0))
        return false;
    errno = 0;
    actual = ptrace_raw(PTRACE_PEEKDATA, pid, (void *)address,
                        &actual_word);
    if (actual == 0) {
        word = actual_word;
    } else {
        /* ptrace PEEK is unaligned and returns bytes starting at addr, not
         * at addr&~7. Returning an aligned word corrupts IDA's saved original
         * byte and makes del_bpt fail. The real parent can also be runnable
         * while holding its child; read its actual memory instead of filling
         * the non-breakpoint bytes with fabricated zeros. */
        struct iovec local = {.iov_base = &actual_word, .iov_len = sizeof(actual_word)};
        struct iovec remote = {.iov_base = (void *)address, .iov_len = sizeof(actual_word)};
        if (process_vm_readv(pid, &local, 1, &remote, 1, 0) != (ssize_t)sizeof(actual_word))
            return false;
        word = actual_word;
    }
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        uintptr_t bp_address;
        size_t offset;

        if (!nested_user_breakpoints[index].active)
            continue;
        bp_address = nested_user_breakpoints[index].address;
        if (bp_address < address || bp_address - address >= sizeof(uintptr_t))
            continue;
        offset = (size_t)(bp_address - address);
        word &= ~((uintptr_t)0xffu << (offset * 8u));
        word |= (uintptr_t)0xccu << (offset * 8u);
    }
    pthread_mutex_unlock(&nested_event_lock);
    *value = (long)word;
    /* linux_server checks errno rather than the returned PEEK word. The
     * ptrace attempt may have set ESRCH before process_vm_readv succeeded;
     * do not carry that stale error into the successful libc PEEK result. */
    errno = 0;
    trace_log("[ida-vtdbg-shim] virtual breakpoint peek pid=%d addr=0x%llx word=0x%llx\n",
              pid, (unsigned long long)address, (unsigned long long)word);
    return true;
}

/* Parent-side protocol reads are different from IDA's memory reads.  After a
 * one-shot child breakpoint is physically restored, the sample's own tracer
 * must still observe a logical 0xcc at the exact byte it is validating. */
static bool nested_overlay_target_breakpoint_value(pid_t pid, void *addr,
                                                    void *data)
{
    uintptr_t request_address = (uintptr_t)addr;
    uintptr_t word;
    bool found = false;

    if (!parent_owned_mode || !oneshot_algorithm_enabled ||
        repeat_handler_breakpoints || pid <= 0 ||
        addr == NULL || data == NULL)
        return false;
    word = *(uintptr_t *)data;
    /* The target process has its own shim address space, so it cannot see the
     * server worker's suppressed breakpoint table.  For the explicit
     * one-shot target path, the configured address is the cross-process
     * contract: the parent VM must observe 0xcc there even after the server
     * restored the physical instruction byte in the child. */
    if (nested_target && !nested_target_launcher &&
        (target_oneshot_overlay_enabled ||
         shared_get_oneshot_control(oneshot_algorithm_address)) &&
        oneshot_algorithm_address >= request_address &&
        oneshot_algorithm_address < request_address + sizeof(uintptr_t)) {
        size_t offset = (size_t)(oneshot_algorithm_address - request_address);
        word &= ~((uintptr_t)0xffu << (offset * 8u));
        word |= (uintptr_t)0xccu << (offset * 8u);
        *(uintptr_t *)data = word;
        event_trace_log("[ida-vtdbg-shim] target configured PEEKDATA pid=%d addr=0x%llx word=0x%llx\n",
                        pid, (unsigned long long)request_address,
                        (unsigned long long)word);
        return true;
    }
    pthread_mutex_lock(&nested_event_lock);
    {
        struct parent_owned_child_state *state =
            parent_owned_child_locked(pid, false);
        if (state != NULL && state->active) {
            for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
                uintptr_t bp_address;
                size_t offset;

                if (!nested_user_breakpoints[index].active ||
                    !nested_user_breakpoints[index].suppressed)
                    continue;
                bp_address = nested_user_breakpoints[index].address;
                if (bp_address < request_address ||
                    bp_address >= request_address + sizeof(uintptr_t))
                    continue;
                offset = (size_t)(bp_address - request_address);
                word &= ~((uintptr_t)0xffu << (offset * 8u));
                word |= (uintptr_t)0xccu << (offset * 8u);
                found = true;
            }
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (!found)
        return false;
    *(uintptr_t *)data = word;
    event_trace_log("[ida-vtdbg-shim] virtual target PEEKDATA pid=%d addr=0x%llx word=0x%llx\n",
                    pid, (unsigned long long)request_address,
                    (unsigned long long)word);
    return true;
}

/* A synthetic CLONE event is only half of IDA's child-creation protocol.
 * linux_server first obtains GETEVENTMSG, then applies ptrace options (or
 * attaches) to the reported child, and only then starts consuming that
 * child's initial stop.  Record that protocol edge explicitly instead of
 * guessing when its child_waiter thread has woken up. */
static void nested_virtual_child_attach_ack(pid_t child)
{
    if (!parent_owned_mode || child <= 0)
        return;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        struct nested_virtual_fork *fork_event = &nested_virtual_forks[index];

        if (!fork_event->active || fork_event->child_pid != child)
            continue;
        fork_event->child_attach_ready = true;
        /* Keep the queued record marked initial_stop.  nested_pop_event()
         * uses that marker to commit child_initial_delivered atomically when
         * it returns the stop after this attach acknowledgement. */
        event_trace_log("[ida-vtdbg-shim] initial child stop unblocked after attach parent=%d child=%d\n",
                        fork_event->parent_pid, child);
        trace_log("[ida-vtdbg-shim] virtual child attach ack parent=%d child=%d delivered=%d msg=%d\n",
                  fork_event->parent_pid, child,
                  fork_event->event_delivered ? 1 : 0,
                  fork_event->message_pending ? 1 : 0);
        break;
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static void nested_breakpoint_write_prepare_local(
    pid_t pid, void *addr, uintptr_t after,
    struct nested_breakpoint_write *write)
{
    uintptr_t address = (uintptr_t)addr;
    uintptr_t before = 0;
    bool before_valid = false;
    long result;

    memset(write, 0, sizeof(*write));
    if (!parent_owned_mode || (!nested_server && !nested_event_worker) ||
        pid <= 0 || address == 0 ||
        (!nested_breakpoint_word_has_cc((void *)after) &&
         !nested_breakpoint_word_registered(address)))
        return;
    errno = 0;
    result = ptrace_raw(PTRACE_PEEKDATA, pid, addr, &before);
    if (result == 0) {
        before_valid = true;
    } else {
        struct iovec local_iov = {.iov_base = &before,
                                  .iov_len = sizeof(before)};
        struct iovec remote_iov = {.iov_base = addr,
                                   .iov_len = sizeof(before)};
        ssize_t copied = process_vm_readv(pid, &local_iov, 1,
                                          &remote_iov, 1, 0);
        if (copied == (ssize_t)sizeof(before)) {
            before_valid = true;
        } else {
            /* The active overlay is the logical pre-write state even when the
             * actual outer process is running and ptrace cannot read it. */
            uintptr_t aligned = address & ~(sizeof(uintptr_t) - 1u);
            bool has_overlay = false;

            before = after;
            pthread_mutex_lock(&nested_event_lock);
            for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
                uintptr_t bp_address;
                size_t offset;

                if (!nested_user_breakpoints[index].active)
                    continue;
                bp_address = nested_user_breakpoints[index].address;
                if ((bp_address & ~(sizeof(uintptr_t) - 1u)) != aligned)
                    continue;
                offset = (size_t)(bp_address - aligned);
                before &= ~((uintptr_t)0xffu << (offset * 8u));
                before |= (uintptr_t)0xccu << (offset * 8u);
                has_overlay = true;
            }
            pthread_mutex_unlock(&nested_event_lock);
            before_valid = has_overlay;
            event_trace_log("[ida-vtdbg-shim] breakpoint prewrite fallback pid=%d addr=0x%llx peek_errno=%d vm_read=%lld overlay=%d\n",
                            pid, (unsigned long long)address, errno,
                            (long long)copied, has_overlay ? 1 : 0);
        }
    }
    if (before_valid) {
        uintptr_t aligned = address & ~(sizeof(uintptr_t) - 1u);

        pthread_mutex_lock(&nested_event_lock);
        for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
            uintptr_t bp_address;
            size_t offset;

            if (!nested_user_breakpoints[index].active)
                continue;
            bp_address = nested_user_breakpoints[index].address;
            if ((bp_address & ~(sizeof(uintptr_t) - 1u)) != aligned)
                continue;
            offset = (size_t)(bp_address - aligned);
            before &= ~((uintptr_t)0xffu << (offset * 8u));
            before |= (uintptr_t)0xccu << (offset * 8u);
        }
        pthread_mutex_unlock(&nested_event_lock);
    }
    if (!before_valid) {
        event_trace_log("[ida-vtdbg-shim] breakpoint prewrite unavailable pid=%d addr=0x%llx errno=%d\n",
                        pid, (unsigned long long)address, errno);
        return;
    }
    write->pid = pid;
    write->address = address;
    write->before = before;
    write->after = after;
    write->valid = true;
    event_trace_log("[ida-vtdbg-shim] breakpoint prewrite pid=%d addr=0x%llx before=0x%llx after=0x%llx\n",
                    pid, (unsigned long long)address,
                    (unsigned long long)write->before,
                    (unsigned long long)write->after);
}

static void nested_note_parent_breakpoint_write(
    pid_t pid, void *addr, void *data, long result,
    const struct nested_breakpoint_write *write)
{
    uintptr_t address = (uintptr_t)addr;
    uintptr_t value = (uintptr_t)data;
    uintptr_t peeked_word = 0;
    long peek_result;
    uintptr_t before_word = 0;
    bool before_valid = false;

    bool candidate = false;

    if (!parent_owned_mode || (!nested_server && !nested_event_worker) ||
        address == 0)
        return;
    for (size_t offset = 0; offset < sizeof(uintptr_t); ++offset) {
        if (((value >> (offset * 8u)) & 0xffu) == 0xccu) {
            candidate = true;
            break;
        }
    }
    if (result < 0 && !candidate &&
        !nested_breakpoint_address_known(address, NULL))
        return;
    trace_log("[ida-vtdbg-shim] breakpoint write pid=%d addr=0x%llx value=0x%llx req_result=%ld\n",
              pid, (unsigned long long)address,
              (unsigned long long)value, result);
    if (write != NULL && write->valid && write->pid == pid &&
        write->address == address) {
        before_word = write->before;
        before_valid = true;
    } else {
        errno = 0;
        peek_result = ptrace_raw(PTRACE_PEEKDATA, pid, addr, &peeked_word);
        if (peek_result == 0) {
            before_word = peeked_word;
            before_valid = true;
        }
    }
    event_trace_log("[ida-vtdbg-shim] breakpoint write-state pid=%d addr=0x%llx before=0x%llx after=0x%llx valid=%d result=%ld\n",
                    pid, (unsigned long long)address,
                    (unsigned long long)before_word,
                    (unsigned long long)value, before_valid ? 1 : 0, result);
    for (size_t offset = 0; offset < sizeof(uintptr_t); ++offset) {
        uintptr_t byte_address = address + offset;
        uint8_t after = (uint8_t)(value >> (offset * 8u));
        uint8_t before = before_valid
                             ? (uint8_t)(before_word >> (offset * 8u))
                             : 0;
        if (before_valid && after == 0xccu && before != 0xccu) {
            if (!nested_breakpoint_address_known(byte_address, NULL)) {
                nested_breakpoint_record(byte_address, before);
                trace_log("[ida-vtdbg-shim] record user breakpoint pid=%d addr=0x%llx original=0x%02x\n",
                          pid, (unsigned long long)byte_address,
                          (unsigned int)before);
            }
        } else if (before_valid && before == 0xccu && after != 0xccu) {
            nested_breakpoint_remove(pid, byte_address, after);
            trace_log("[ida-vtdbg-shim] remove user breakpoint pid=%d addr=0x%llx restore=0x%02x\n",
                      pid, (unsigned long long)byte_address,
                      (unsigned int)after);
        }
    }
    if ((nested_server || nested_event_worker) &&
        nested_server_outer_pid > 0 && pid == nested_server_outer_pid) {
        pid_t shadows[NESTED_QUEUE_MAX];
        size_t shadow_count = 0;

        pthread_mutex_lock(&nested_event_lock);
        for (size_t index = 0; index < nested_shadow_count &&
                                shadow_count < NESTED_QUEUE_MAX; ++index)
            shadows[shadow_count++] = nested_shadow_pids[index];
        pthread_mutex_unlock(&nested_event_lock);
        for (size_t index = 0; index < shadow_count; ++index) {
            nested_propagate_breakpoint_delta_to_child(
                pid, shadows[index], address, value, before_word, before_valid);
        }
    }
}

/* Parent and shadow child commonly share libc mappings, but their IDA
 * breakpoint transactions are not the same transaction.  Copying the raw
 * parent POKEDATA word to the child can therefore erase a neighboring child
 * breakpoint (or restore a byte that the child still owns).  Merge only the
 * byte transitions represented by this write, then overlay every breakpoint
 * that remains logically active in the shared table. */
static void nested_propagate_breakpoint_delta_to_child(
    pid_t parent, pid_t child, uintptr_t address, uintptr_t value,
    uintptr_t before_word, bool before_valid)
{
    uintptr_t merged;
    long peek;
    unsigned int changed_mask = 0;

    if (child <= 0 || address == 0 || !nested_is_shadow(child))
        return;
    errno = 0;
    peek = nested_driver_forward_ptrace(PTRACE_PEEKDATA, child,
                                        (void *)address, NULL);
    if (peek == -1 && errno != 0) {
        trace_log("[ida-vtdbg-shim] merged breakpoint read parent=%d child=%d addr=0x%llx errno=%d\n",
                  parent, child, (unsigned long long)address, errno);
        return;
    }
    merged = (uintptr_t)peek;
    for (size_t offset = 0; offset < sizeof(uintptr_t); ++offset) {
        uintptr_t byte_address = address + offset;
        uint8_t after = (uint8_t)(value >> (offset * 8u));
        uint8_t before = before_valid
                             ? (uint8_t)(before_word >> (offset * 8u))
                             : 0;
        uint8_t original = 0;
        bool active = nested_breakpoint_address_known(byte_address, &original);
        bool added = before_valid && before != 0xccu && after == 0xccu;
        bool removed = before_valid && before == 0xccu && after != 0xccu;
        uint8_t desired;

        if (active || added)
            desired = 0xccu;
        else if (removed)
            desired = after;
        else
            continue; /* Preserve unrelated bytes from the child word. */
        if ((uint8_t)(merged >> (offset * 8u)) == desired)
            continue;
        merged &= ~((uintptr_t)0xffu << (offset * 8u));
        merged |= (uintptr_t)desired << (offset * 8u);
        changed_mask |= 1u << offset;
    }
    if (changed_mask == 0)
        return;
    long forwarded = nested_driver_forward_ptrace(
        PTRACE_POKEDATA, child, (void *)address, (void *)merged);
    trace_log("[ida-vtdbg-shim] propagate merged breakpoint parent=%d child=%d addr=0x%llx before=0x%llx parent_after=0x%llx child_after=0x%llx changed=0x%x result=%ld errno=%d\n",
              parent, child, (unsigned long long)address,
              (unsigned long long)before_word,
              (unsigned long long)value, (unsigned long long)merged,
              changed_mask, forwarded, forwarded < 0 ? errno : 0);
}

static void nested_breakpoint_record(uintptr_t address, uint8_t original)
{
    bool arm_oneshot = parent_owned_mode && nested_server &&
                       oneshot_algorithm_enabled &&
                       !repeat_handler_breakpoints &&
                       address == oneshot_algorithm_address;

    event_trace_log("[ida-vtdbg-shim] logical breakpoint record request addr=0x%llx original=0x%02x\n",
                    (unsigned long long)address, (unsigned int)original);
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        if ((nested_user_breakpoints[index].active ||
             nested_user_breakpoints[index].suppressed ||
             nested_user_breakpoints[index].restore_pending_mask[0] != 0 ||
             nested_user_breakpoints[index].restore_pending_mask[1] != 0) &&
            nested_user_breakpoints[index].address == address) {
            if (!nested_user_breakpoints[index].active ||
                nested_user_breakpoints[index].suppressed ||
                nested_user_breakpoints[index].original_byte != original)
                atomic_fetch_add_explicit(&nested_breakpoint_revision, 1, memory_order_release);
            nested_user_breakpoints[index].active = true;
            nested_user_breakpoints[index].suppressed = false;
            memset(nested_user_breakpoints[index].restore_pending_mask, 0,
                   sizeof(nested_user_breakpoints[index].restore_pending_mask));
            nested_user_breakpoints[index].original_byte = original;
            event_trace_log("[ida-vtdbg-shim] logical breakpoint refreshed addr=0x%llx original=0x%02x slot=%zu\n",
                            (unsigned long long)address,
                            (unsigned int)original, index);
            pthread_mutex_unlock(&nested_event_lock);
            if (arm_oneshot)
                shared_set_oneshot_control(true, address);
            return;
        }
    }
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        if (!nested_user_breakpoints[index].active &&
            !nested_user_breakpoints[index].suppressed &&
            nested_user_breakpoints[index].restore_pending_mask[0] == 0 &&
            nested_user_breakpoints[index].restore_pending_mask[1] == 0) {
            atomic_fetch_add_explicit(&nested_breakpoint_revision, 1, memory_order_release);
            nested_user_breakpoints[index].active = true;
            nested_user_breakpoints[index].suppressed = false;
            memset(nested_user_breakpoints[index].restore_pending_mask, 0,
                   sizeof(nested_user_breakpoints[index].restore_pending_mask));
            nested_user_breakpoints[index].address = address;
            nested_user_breakpoints[index].original_byte = original;
            event_trace_log("[ida-vtdbg-shim] logical breakpoint stored addr=0x%llx original=0x%02x slot=%zu\n",
                            (unsigned long long)address,
                            (unsigned int)original, index);
            pthread_mutex_unlock(&nested_event_lock);
            if (arm_oneshot)
                shared_set_oneshot_control(true, address);
            return;
        }
    }
    pthread_mutex_unlock(&nested_event_lock);
}

static void nested_breakpoint_write_prepare(pid_t pid, void *addr,
                                            uintptr_t after,
                                            struct nested_breakpoint_write *write)
{
    uintptr_t address = (uintptr_t)addr;
    long value;

    memset(write, 0, sizeof(*write));
    if (address == 0 || (!nested_event_worker && !nested_server) ||
        !parent_owned_mode)
        return;
    errno = 0;
    value = nested_driver_forward_ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    /* The driver shim follows libc's PEEK convention: return the memory
     * word. It is not raw SYS_ptrace's return-status/data-out convention.
     * Negative instruction words are valid unless -1 carries errno. */
    if (value == -1 && errno != 0)
        return;
    write->pid = pid;
    write->address = address;
    write->before = (uintptr_t)value;
    write->after = after;
    write->valid = true;
}

static void nested_breakpoint_write_commit(
    const struct nested_breakpoint_write *write)
{
    if (write == NULL || !write->valid)
        return;
    for (size_t offset = 0; offset < sizeof(uintptr_t); ++offset) {
        uint8_t before = (uint8_t)(write->before >> (offset * 8u));
        uint8_t after = (uint8_t)(write->after >> (offset * 8u));
        uintptr_t address = write->address + offset;

        if (before != 0xcc && after == 0xcc) {
            nested_breakpoint_record(address, before);
        } else if (before == 0xcc && after != 0xcc) {
            pthread_mutex_lock(&nested_event_lock);
            for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
                if (nested_user_breakpoints[index].active &&
                    nested_user_breakpoints[index].address == address &&
                    nested_user_breakpoints[index].original_byte == after) {
                    nested_user_breakpoints[index].active = false;
                    nested_user_breakpoints[index].suppressed = false;
                    nested_breakpoint_restore_mark_locked(
                        &nested_user_breakpoints[index], write->pid);
                    atomic_fetch_add_explicit(&nested_breakpoint_revision, 1, memory_order_release);
                    break;
                }
            }
            pthread_mutex_unlock(&nested_event_lock);
        }
    }
}

static bool parent_owned_visible_child_stop(pid_t child)
{
    struct user_regs_struct regs;
    siginfo_t info;
    uintptr_t stale_rip = 0;
    uintptr_t expected_rip = 0;
    long result;
    bool breakpoint;
    uint8_t current_original = 0;

    if (!parent_owned_mode || (!nested_event_worker && !nested_server) ||
        child <= 0 ||
        !nested_is_shadow(child) ||
        !parent_owned_proxy_stop_held(child, false, false))
        return false;
    /* The first one-shot algorithm stop remains visible while IDA performs
     * its register/memory inspection and issues the resume acknowledgement.
     * The breakpoint record itself is already marked suppressed so later
     * protocol INT3s at the same address are hidden. */
    if (parent_owned_oneshot_visible(child))
        return true;
    if (parent_owned_initial_visible(child))
        return true;
    if (parent_owned_get_synthetic_step_stop(child, NULL))
        return true;
    if (parent_owned_debugger_owned_stop(child))
        return true;
    if (nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0)
        return false;

    if (parent_owned_get_resume_observation(child, &stale_rip,
                                             &expected_rip) &&
        stale_rip != 0 && regs.rip == stale_rip) {
        event_trace_log("[ida-vtdbg-shim] hide stale visible-child stop child=%d rip=0x%llx expected_resume=0x%llx\n",
                        child, (unsigned long long)regs.rip,
                        (unsigned long long)expected_rip);
        return false;
    }

    breakpoint = regs.rip > 0 &&
                 nested_breakpoint_address_known((uintptr_t)(regs.rip - 1),
                                                 NULL);
    /* For a pre-existing target INT3, IDA/Linux may already have rewound RIP
     * to the trap byte itself. Make that native protocol site visible when
     * it is explicitly registered with original byte 0xCC. */
    if (!breakpoint &&
        nested_breakpoint_address_known((uintptr_t)regs.rip,
                                        &current_original) &&
        current_original == 0xccu)
        breakpoint = true;
    memset(&info, 0, sizeof(info));
    result = nested_driver_forward_ptrace(PTRACE_GETSIGINFO, child, NULL,
                                          &info);
    if (event_trace_enabled && regs.rip >= 0x400b20 && regs.rip <= 0x400b40) {
        uint8_t recorded_original = 0;
        bool recorded = nested_breakpoint_address_recorded(0x400b2b,
                                                           &recorded_original);
        bool known = nested_breakpoint_address_known(0x400b2b, NULL);
        event_trace_log("[ida-vtdbg-shim] visible-stop-diagnostic child=%d rip=0x%llx siginfo_result=%ld si_code=%d bp_recorded=%d bp_known=%d bp_original=0x%02x oneshot_done=%d\n",
                        child, (unsigned long long)regs.rip, result,
                        result == 0 ? info.si_code : -1, recorded ? 1 : 0,
                        known ? 1 : 0, (unsigned int)recorded_original,
                        oneshot_algorithm_done ? 1 : 0);
    }
    if (result == 0 &&
        (info.si_code == TRAP_TRACE || info.si_code == TRAP_HWBKPT))
        breakpoint = true;
    /* Capture before IDA can write/rewind regs or remove its trap byte.
     * An adjacent original CC is NOT the cause of a debugger-owned stop. */
    uint8_t hit_original = 0;
    bool debugger_owned = result == 0 && info.si_signo == SIGTRAP &&
        (info.si_code == TRAP_TRACE || info.si_code == TRAP_HWBKPT ||
         ((info.si_code == SI_KERNEL || info.si_code == TRAP_BRKPT ||
           info.si_code == SIGTRAP) && regs.rip != 0 &&
          nested_breakpoint_address_recorded((uintptr_t)regs.rip - 1u,
                                             &hit_original) && hit_original != 0xccu));
    if (result == 0)
        parent_owned_capture_stop_source(child, debugger_owned, (uintptr_t)regs.rip,
            debugger_owned && info.si_code != TRAP_TRACE && regs.rip != 0
                ? (uintptr_t)regs.rip - 1u : (uintptr_t)regs.rip, info.si_code);
    if (debugger_owned)
        breakpoint = true;
    if (!debugger_owned && result == 0 && regs.rip != 0 &&
        (info.si_code == SI_KERNEL || info.si_code == TRAP_BRKPT ||
         info.si_code == SIGTRAP)) {
        uintptr_t candidates[2] = {
            (uintptr_t)(regs.rip - 1u), (uintptr_t)regs.rip
        };
        for (size_t index = 0; index < 2; ++index) {
            uintptr_t candidate = candidates[index];
            uintptr_t aligned;
            uintptr_t word;
            uint8_t recorded_original = 0;
            long peek;
            uint8_t opcode;
            bool recorded;

            if (candidate == 0)
                continue;
            /* An IDA-owned ordinary software breakpoint has a recorded
             * non-0xCC original byte.  Do not reinterpret it as a target VM
             * protocol trap; every other target-owned 0xCC is a dynamic
             * protocol candidate. */
            recorded = nested_breakpoint_address_recorded(
                candidate, &recorded_original);
            if (recorded && recorded_original != 0xccu)
                continue;
            aligned = candidate & ~(sizeof(uintptr_t) - 1u);
            errno = 0;
            peek = nested_driver_forward_ptrace(PTRACE_PEEKDATA, child,
                                                (void *)aligned, NULL);
            if (peek == -1 && errno != 0)
                break;
            word = (uintptr_t)peek;
            opcode = (uint8_t)(word >> ((candidate - aligned) * 8u));
            if (opcode == 0xccu) {
                /* Automated full-trace mode consumes native protocol stops
                 * internally. Explicit IDA breakpoints and TRAP_TRACE/HW
                 * stops retain their normal visibility. */
                bool parent_call_over = nested_server &&
                    nested_generic_hw_step_pending(nested_server_outer_pid, NULL);
                breakpoint = (!auto_continue_protocol && !parent_call_over) || breakpoint;
                parent_owned_set_protocol_int3_stop(child, true, candidate);
                event_trace_log("[ida-vtdbg-shim] auto protocol INT3 visible child=%d trap=0x%llx rip=0x%llx recorded=%d\n",
                                child, (unsigned long long)candidate,
                                (unsigned long long)regs.rip,
                                recorded ? 1 : 0);
                if ((auto_continue_protocol || parent_call_over) && !breakpoint)
                    return false;
                break;
            }
        }
    }
    /* A user breakpoint may be presented with RIP at the trap byte rather
     * than one byte past it.  Preserve ordinary IDA breakpoint semantics
     * before classifying a non-CC SIGTRAP as a target exception. */
    if (!breakpoint && regs.rip != 0 &&
        nested_breakpoint_address_recorded((uintptr_t)regs.rip,
                                           &current_original) &&
        current_original != 0xccu)
        breakpoint = true;
    if (!breakpoint && result == 0 && info.si_signo != SIGSTOP &&
        info.si_signo != SIGCHLD &&
        info.si_code != TRAP_TRACE && info.si_code != TRAP_HWBKPT &&
        !(info.si_signo == SIGTRAP &&
          (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL ||
           info.si_code == SIGTRAP))) {
        /* This stop was not caused by an IDA software/hardware breakpoint,
         * synthetic single-step, or loader SIGSTOP.  Preserve it as a
         * program-owned exception so F8 can observe the parent VM's eventual
         * SETREGS destination even when the exception is SIGSEGV/SIGILL/
         * SIGFPE/SIGSYS (or a SIGTRAP without an INT3 byte). */
        parent_owned_set_program_exception(child, true, info.si_signo,
                                           info.si_code, (uintptr_t)regs.rip);
        breakpoint = true;
        event_trace_log("[ida-vtdbg-shim] program exception visible child=%d signal=%d si_code=%d rip=0x%llx\n",
                        child, info.si_signo, info.si_code,
                        (unsigned long long)regs.rip);
    }
    if (!breakpoint && result == 0 && info.si_signo == SIGTRAP &&
        info.si_code != TRAP_TRACE && info.si_code != TRAP_HWBKPT) {
        /* A SIGTRAP without an INT3 byte, without an IDA breakpoint, and
         * without single-step metadata is still target-owned. Preserve it
         * so the parent can either recognize an anti-debug check or redirect
         * control flow with SETREGS. */
        parent_owned_set_program_exception(child, true, info.si_signo,
                                           info.si_code,
                                           (uintptr_t)regs.rip);
        breakpoint = true;
        event_trace_log("[ida-vtdbg-shim] target SIGTRAP without INT3 classified as program exception child=%d si_code=%d rip=0x%llx\n",
                        child, info.si_code,
                        (unsigned long long)regs.rip);
    }
    if (breakpoint && regs.rip > 0) {
        /* Linux/IDA may expose an INT3 stop with RIP either immediately
         * after the opcode or rewound to the opcode itself.  One-shot
         * algorithm/user breakpoints must be restored in both forms; using
         * only RIP-1 leaves a rewound 0x400B2B byte armed and creates an
         * infinite repeated-stop loop with badbpt=true in IDA. */
        if (!nested_auto_suppress_breakpoint(child,
                                             (uintptr_t)(regs.rip - 1)))
            (void)nested_auto_suppress_breakpoint(child,
                                                   (uintptr_t)regs.rip);
    }
    event_trace_log("[ida-vtdbg-shim] classify child stop pid=%d rip=0x%llx si_code=%d visible=%d\n",
                    child, (unsigned long long)regs.rip,
                    result == 0 ? info.si_code : -1,
                    breakpoint ? 1 : 0);
    return breakpoint;
}

/* When IDA cannot plant a temporary breakpoint in a parent-owned child, its
 * step-over implementation falls back to PTRACE_SINGLESTEP. A real target
 * protocol INT3 is parent-controlled, so convert that request into an
 * observation of the parent's eventual resume RIP. */
static bool nested_server_should_observe_parent_resume(pid_t child,
                                                       uintptr_t *rip_out)
{
    struct user_regs_struct regs;
    siginfo_t info;
    uintptr_t candidates[2];
    long result;
    bool found = false;
    uintptr_t protocol_address = 0;

    if (!parent_owned_mode || !nested_server || child <= 0 ||
        !nested_is_shadow(child) ||
        !parent_owned_proxy_stop_held(child, false, false) ||
        parent_owned_get_synthetic_step_stop(child, NULL) ||
        parent_owned_debugger_owned_stop(child))
        return false;

    memset(&regs, 0, sizeof(regs));
    result = nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL,
                                          &regs);
    if (result < 0 || regs.rip == 0)
        return false;
    event_trace_log("[ida-vtdbg-shim] protocol observer probe child=%d rip=0x%llx\n",
                    child, (unsigned long long)regs.rip);
    memset(&info, 0, sizeof(info));
    result = nested_driver_forward_ptrace(PTRACE_GETSIGINFO, child, NULL,
                                          &info);
    /* Linux may report a native INT3 as SI_KERNEL, TRAP_BRKPT, or a
     * backend-normalized SIGTRAP code.  The byte and the recorded original
     * instruction are the authoritative protocol markers; rejecting the
     * stop solely because linux_server rewrote si_code causes F9 to fall
     * back to IDA's exception dialog. */
    if (result < 0 ||
        (info.si_code != SI_KERNEL &&
         info.si_code != TRAP_BRKPT &&
         info.si_code != SIGTRAP)) {
        event_trace_log("[ida-vtdbg-shim] protocol observer reject child=%d siginfo_result=%ld si_code=%d\n",
                        child, result, result < 0 ? -1 : info.si_code);
        return false;
    }

    /* linux_server may report an INT3 with RIP at the following byte or
     * rewind it to the trap byte. A registered ordinary software breakpoint
     * has a non-CC original byte and must retain normal step semantics. */
    candidates[0] = regs.rip > 0 ? (uintptr_t)(regs.rip - 1u) : 0;
    candidates[1] = (uintptr_t)regs.rip;
    for (size_t index = 0; index < 2; ++index) {
        uintptr_t candidate = candidates[index];
        uintptr_t aligned;
        uintptr_t word;
        uint8_t original = 0;
        uint8_t instruction;
        bool known;
        bool dynamic_protocol;
        uintptr_t configured_protocol_address = 0;
        dynamic_protocol =
            parent_owned_get_protocol_int3_stop(
                child, &configured_protocol_address) &&
            candidate == configured_protocol_address;
        bool configured_protocol = dynamic_protocol ||
            (nested_protocol_int3_address != 0 &&
             candidate == nested_protocol_int3_address);

        if (candidate == 0)
            continue;
        known = nested_breakpoint_address_recorded(candidate, &original);
        /* Ordinary IDA breakpoints retain their normal step semantics. Any
         * other target-owned 0xCC observed at a genuine parent-owned SIGTRAP
         * is a dynamically discovered VM protocol point; the explicit address
         * remains only an optional hint for older adapters. */
        if (!configured_protocol && known && original != 0xccu)
            continue;
        aligned = candidate & ~(sizeof(uintptr_t) - 1u);
        result = nested_driver_forward_ptrace(PTRACE_PEEKDATA, child,
                                              (void *)aligned, NULL);
        if (result == -1 && errno != 0)
            continue;
        word = (uintptr_t)result;
        instruction = (uint8_t)(word >>
                               ((candidate - aligned) * 8u));
        if (instruction == 0xccu) {
            protocol_address = candidate;
            found = true;
            parent_owned_set_protocol_int3_stop(child, true, candidate);
            break;
        }
    }
    if (!found) {
        event_trace_log("[ida-vtdbg-shim] protocol observer reject child=%d no-INT3-candidate rip=0x%llx\n",
                        child, (unsigned long long)regs.rip);
        return false;
    }
    /* Return the architectural post-INT3 address. This is the address that
     * an inherited resume breakpoint is expected to guard. */
    if (rip_out != NULL)
        *rip_out = protocol_address + 1u;
    handler_trace_log("[ida-vtdbg-shim] handler-observe child=%d trap=0x%llx resume=0x%llx rip=0x%llx\n",
                      child, (unsigned long long)protocol_address,
                      (unsigned long long)(protocol_address + 1u),
                      (unsigned long long)regs.rip);
    event_trace_log("[ida-vtdbg-shim] protocol observer accept child=%d trap=0x%llx resume=0x%llx\n",
                    child, (unsigned long long)protocol_address,
                    (unsigned long long)(protocol_address + 1u));
    if (state_trace_enabled) {
        uintptr_t stack_words[4] = {0, 0, 0, 0};
        uintptr_t table_020 = 0;
        uintptr_t table_120 = 0;
        uintptr_t table_a48 = 0;
        uintptr_t table_a40 = 0;
        uintptr_t local_1bc = 0;
        uintptr_t local_1c0 = 0;
        uintptr_t local_1c8 = 0;
        uintptr_t local_1d4 = 0;
        uintptr_t local_1e0 = 0;
        uintptr_t local_190 = 0;
        uintptr_t local_184 = 0;
        uintptr_t stack = (uintptr_t)regs.rsp & ~(uintptr_t)0x7;
        uintptr_t rbp = (uintptr_t)regs.rbp;
        long value;

        for (size_t index = 0; index < 4; ++index) {
            value = nested_driver_forward_ptrace(
                PTRACE_PEEKDATA, child,
                (void *)(stack + index * sizeof(uintptr_t)), NULL);
            if (!(value == -1 && errno != 0))
                stack_words[index] = (uintptr_t)value;
        }
        value = nested_driver_forward_ptrace(
            PTRACE_PEEKDATA, child, (void *)0x606020u, NULL);
        if (!(value == -1 && errno != 0))
            table_020 = (uintptr_t)value;
        value = nested_driver_forward_ptrace(
            PTRACE_PEEKDATA, child, (void *)0x606120u, NULL);
        if (!(value == -1 && errno != 0))
            table_120 = (uintptr_t)value;
        value = nested_driver_forward_ptrace(
            PTRACE_PEEKDATA, child, (void *)0x606A40u, NULL);
        if (!(value == -1 && errno != 0))
            table_a40 = (uintptr_t)value;
        value = nested_driver_forward_ptrace(
            PTRACE_PEEKDATA, child, (void *)0x606A48u, NULL);
        if (!(value == -1 && errno != 0))
            table_a48 = (uintptr_t)value;
        if (rbp != 0) {
            const uintptr_t local_addresses[] = {
                rbp - 0x1bcu, rbp - 0x1c0u, rbp - 0x1c8u,
                rbp - 0x1d4u, rbp - 0x1e0u, rbp - 0x190u,
                rbp - 0x184u,
            };
            uintptr_t *local_values[] = {
                &local_1bc, &local_1c0, &local_1c8, &local_1d4,
                &local_1e0, &local_190, &local_184,
            };
            for (size_t index = 0;
                 index < sizeof(local_addresses) / sizeof(local_addresses[0]);
                 ++index) {
                value = nested_driver_forward_ptrace(
                    PTRACE_PEEKDATA, child,
                    (void *)local_addresses[index], NULL);
                if (!(value == -1 && errno != 0))
                    *local_values[index] = (uintptr_t)value;
            }
        }
        handler_state_log(
            "[ida-vtdbg-shim] handler-state child=%d trap=0x%llx rip=0x%llx rbp=0x%llx rsp=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx rdi=0x%llx local1bc=0x%llx local1c0=0x%llx local1c8=0x%llx local1d4=0x%llx local1e0=0x%llx local190=0x%llx local184=0x%llx stack0=0x%llx stack1=0x%llx stack2=0x%llx stack3=0x%llx t020=0x%llx t120=0x%llx ta40=0x%llx ta48=0x%llx\n",
            child, (unsigned long long)protocol_address,
            (unsigned long long)regs.rip, (unsigned long long)regs.rbp,
            (unsigned long long)regs.rsp,
            (unsigned long long)regs.rax, (unsigned long long)regs.rbx,
            (unsigned long long)regs.rcx, (unsigned long long)regs.rdx,
            (unsigned long long)regs.rsi, (unsigned long long)regs.rdi,
            (unsigned long long)local_1bc,
            (unsigned long long)local_1c0,
            (unsigned long long)local_1c8,
            (unsigned long long)local_1d4,
            (unsigned long long)local_1e0,
            (unsigned long long)local_190,
            (unsigned long long)local_184,
            (unsigned long long)stack_words[0],
            (unsigned long long)stack_words[1],
            (unsigned long long)stack_words[2],
            (unsigned long long)stack_words[3],
            (unsigned long long)table_020,
            (unsigned long long)table_120,
            (unsigned long long)table_a40,
            (unsigned long long)table_a48);
    }
    return true;
}

/* A trace-stop BEFORE the program's INT3 is debugger-owned; actually execute
 * the INT3 and then observe the real parent's SETREGS destination for F7. */
static bool nested_server_at_program_int3(pid_t child, uintptr_t *rip_out)
{
    struct user_regs_struct regs;
    siginfo_t info;
    uint8_t original = 0;
    long word;

    if (!parent_owned_mode || !nested_server || child <= 0 ||
        !nested_is_shadow(child) ||
        !parent_owned_proxy_stop_held(child, false, false) ||
        (parent_owned_get_synthetic_step_stop(child, NULL) &&
         !parent_owned_synthetic_is_trace(child)))
        return false;
    if (nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0 ||
        nested_driver_forward_ptrace(PTRACE_GETSIGINFO, child, NULL, &info) < 0 ||
        info.si_signo != SIGTRAP || info.si_code != TRAP_TRACE ||
        (nested_breakpoint_address_recorded((uintptr_t)regs.rip, &original) &&
         original != 0xccu))
        return false;
    errno = 0;
    word = nested_driver_forward_ptrace(PTRACE_PEEKDATA, child,
                                        (void *)(uintptr_t)regs.rip, NULL);
    if ((word == -1 && errno != 0) || (uint8_t)word != 0xccu)
        return false;
    if (rip_out != NULL)
        *rip_out = (uintptr_t)regs.rip;
    return true;
}

static bool nested_server_should_observe_program_exception(pid_t child)
{
    uintptr_t rip = 0;
    int signal_number = 0;
    int si_code = 0;

    if (!parent_owned_mode || !nested_server || child <= 0 ||
        !nested_is_shadow(child) ||
        !parent_owned_proxy_stop_held(child, false, false))
        return false;
    if (!parent_owned_get_program_exception(child, &rip, &signal_number,
                                            &si_code))
        return false;
    event_trace_log("[ida-vtdbg-shim] program exception resume observation child=%d signal=%d si_code=%d source_rip=0x%llx\n",
                    child, signal_number, si_code,
                    (unsigned long long)rip);
    return true;
}

static void nested_propagate_breakpoints_to_child(pid_t parent, pid_t child)
{
    struct replay_word {
        uintptr_t address;
        uintptr_t expected;
        uintptr_t replacement;
        uintptr_t mask;
        uintptr_t restore_mask;
    } words[NESTED_BREAKPOINT_MAX] = {0};
    size_t word_count = 0;

    if (!parent_owned_mode || child <= 0 || parent <= 0 ||
        (!nested_server && !nested_event_worker))
        return;
    /* A replay snapshot taken before del_bpt must not replant that byte after
     * the delete returns. Blocking here would deadlock the native ptrace RPC
     * broker; a busy writer already owns the exact byte update instead. */
    if (nested_breakpoint_memory_depth != 0 ||
        pthread_mutex_trylock(&nested_breakpoint_memory_lock) != 0)
        return;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_BREAKPOINT_MAX; ++index) {
        const struct nested_user_breakpoint *bp = &nested_user_breakpoints[index];
        uintptr_t address;
        size_t slot = word_count;
        bool restore = !bp->active && !bp->suppressed &&
            nested_breakpoint_restore_pending_locked(bp, child);

        if ((!bp->active || bp->suppressed) && !restore)
            continue;
        address = bp->address & ~(sizeof(uintptr_t) - 1u);
        for (size_t windex = 0; windex < word_count; ++windex) {
            if (words[windex].address == address) {
                slot = windex;
                break;
            }
        }
        if (slot == word_count) {
            if (word_count == NESTED_BREAKPOINT_MAX) break;
            words[slot].address = address;
            ++word_count;
        }
        uintptr_t byte_mask = (uintptr_t)0xffu << ((bp->address - address) * 8u);
        words[slot].mask |= byte_mask;
        words[slot].expected |= (uintptr_t)(restore ? 0xccu : bp->original_byte) <<
                                ((bp->address - address) * 8u);
        words[slot].replacement |= (uintptr_t)(restore ? bp->original_byte : 0xccu) <<
                                   ((bp->address - address) * 8u);
        if (restore) words[slot].restore_mask |= byte_mask;
    }
    pthread_mutex_unlock(&nested_event_lock);

    for (size_t windex = 0; windex < word_count; ++windex) {
        uintptr_t address = words[windex].address;
        uintptr_t word = 0;
        bool valid = false;
        struct iovec local_iov;
        struct iovec remote_iov;
        ssize_t vm_result;

        local_iov.iov_base = &word;
        local_iov.iov_len = sizeof(word);
        remote_iov.iov_base = (void *)address;
        remote_iov.iov_len = sizeof(word);
        vm_result = process_vm_readv(child, &local_iov, 1, &remote_iov, 1, 0);
        valid = vm_result == (ssize_t)sizeof(word);
        if (vm_result != (ssize_t)sizeof(word)) {
            errno = 0;
            if (nested_target && !nested_target_launcher) {
                valid = ptrace_raw(PTRACE_PEEKDATA, child, (void *)address, &word) == 0;
            } else {
                long peek = nested_driver_forward_ptrace(
                    PTRACE_PEEKDATA, child, (void *)address, NULL);
                valid = !(peek == -1 && errno != 0);
                if (valid) word = (uintptr_t)peek;
            }
        }
        if (!valid) {
            event_trace_log("[ida-vtdbg-shim] replay read rejected child=%d addr=0x%llx errno=%d (no parent/zero fallback)\n",
                            child, (unsigned long long)address, errno);
            continue;
        }
        uintptr_t before = word;
        uintptr_t applied_restore = 0;
        /* Alter only acknowledged debugger byte transitions. Parent/child
         * may contain different target patches in the other seven bytes. */
        for (size_t n = 0; n < sizeof(word); ++n) {
            uintptr_t mask = (uintptr_t)0xffu << (n * 8u);
            if ((words[windex].mask & mask) == 0) continue;
            if ((word & mask) == (words[windex].replacement & mask)) {
                applied_restore |= words[windex].restore_mask & mask;
                continue;
            }
            if ((word & mask) != (words[windex].expected & mask)) continue;
            word = (word & ~mask) | (words[windex].replacement & mask);
            applied_restore |= words[windex].restore_mask & mask;
        }
        if (word == before) vm_result = sizeof(word);
        else {
        local_iov.iov_base = &word;
        local_iov.iov_len = sizeof(word);
        remote_iov.iov_base = (void *)address;
        remote_iov.iov_len = sizeof(word);
        vm_result = process_vm_writev(child, &local_iov, 1, &remote_iov, 1, 0);
        }
        if (vm_result == (ssize_t)sizeof(word)) {
            trace_log("[ida-vtdbg-shim] replay breakpoint vm parent=%d child=%d addr=0x%llx word=0x%llx\n",
                      parent, child, (unsigned long long)address,
                      (unsigned long long)word);
        } else {
            long result;
            if (nested_target && !nested_target_launcher)
                result = ptrace_raw(PTRACE_POKEDATA, child,
                                     (void *)address, (void *)word);
            else
                result = nested_driver_forward_ptrace(
                    PTRACE_POKEDATA, child, (void *)address, (void *)word);
            trace_log("[ida-vtdbg-shim] replay breakpoint fallback parent=%d child=%d addr=0x%llx word=0x%llx result=%ld errno=%d\n",
                      parent, child, (unsigned long long)address,
                      (unsigned long long)word, result,
                      result < 0 ? errno : 0);
            if (result < 0) continue;
        }
        if (applied_restore != 0) {
            pthread_mutex_lock(&nested_event_lock);
            for (size_t n = 0; n < NESTED_BREAKPOINT_MAX; ++n) {
                struct nested_user_breakpoint *bp = &nested_user_breakpoints[n];
                if (bp->active || bp->suppressed || bp->address < address ||
                    bp->address - address >= sizeof(word)) continue;
                uintptr_t mask = (uintptr_t)0xffu << ((bp->address - address) * 8u);
                if ((applied_restore & mask) &&
                    (words[windex].replacement & mask) ==
                        ((uintptr_t)bp->original_byte << ((bp->address - address) * 8u)))
                    nested_breakpoint_restore_ack_locked(bp, child);
            }
            pthread_mutex_unlock(&nested_event_lock);
        }
    }
    pthread_mutex_unlock(&nested_breakpoint_memory_lock);
}

static void nested_server_note_synthetic_step_stop(pid_t child)
{
    struct user_regs_struct regs;
    siginfo_t info;
    uintptr_t address = 0;
    bool trace_step = false;
    long result;
    long siginfo_result;

    /* A new synthetic stop completes the previous virtual DR step.  Retain
     * only its cleanup shadow; no subsequent resume may be suppressed by it. */
    (void)parent_owned_consume_synthetic_step_stop(child);
    nested_protocol_hw_step_reset(child);
    memset(&regs, 0, sizeof(regs));
    result = nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL,
                                          &regs);
    if (result == 0 && regs.rip > 0) {
        memset(&info, 0, sizeof(info));
        siginfo_result = nested_driver_forward_ptrace(
            PTRACE_GETSIGINFO, child, NULL, &info);
#ifdef TRAP_TRACE
        trace_step = siginfo_result == 0 && info.si_signo == SIGTRAP &&
                     info.si_code == TRAP_TRACE;
#else
        trace_step = siginfo_result == 0 && info.si_signo == SIGTRAP &&
                     info.si_code == 2;
#endif
        /* A real x86 INT3 reports RIP one byte past the opcode, so IDA must
         * display RIP-1.  TRAP_TRACE is different: the kernel already
         * reports the post-instruction RIP.  Rewinding that stop as if it
         * were an INT3 makes the next F8 resume from the wrong address. */
        address = trace_step ? (uintptr_t)regs.rip
                             : (uintptr_t)(regs.rip - 1u);
    }
    parent_owned_set_synthetic_step_stop(child, true, address, trace_step);
    event_trace_log("[ida-vtdbg-shim] server recorded synthetic step stop child=%d trace=%d trap_rip=0x%llx display=0x%llx result=%ld\n",
                    child, trace_step ? 1 : 0,
                    (unsigned long long)regs.rip,
                    (unsigned long long)address, result);
}

static void nested_server_note_exception_resume(pid_t child)
{
    struct user_regs_struct regs;
    long result;
    uintptr_t rip = 0;

    memset(&regs, 0, sizeof(regs));
    result = nested_driver_forward_ptrace(PTRACE_GETREGS, child, NULL,
                                          &regs);
    if (result == 0)
        rip = (uintptr_t)regs.rip;
    parent_owned_set_exception_resume(child, true, rip);
    event_trace_log("[ida-vtdbg-shim] server recorded program-exception resume child=%d rip=0x%llx result=%ld\n",
                    child, (unsigned long long)rip, result);
}

/* The target parent consumes a protocol INT3 through its own wait/ptrace
 * loop.  The kernel event ring can deliver the already-consumed stop to the
 * linux_server reader after the parent has issued SETREGS+CONT.  Do not turn
 * that stale post-INT3 status into another proxy stop; wait for the explicit
 * synthetic resume event generated at the selected address instead. */
static bool parent_owned_drop_stale_resume_stop(
    const struct ida_vtdbg_policy_event *event)
{
    struct user_regs_struct regs;
    uintptr_t stale_rip = 0;
    uintptr_t expected_rip = 0;
    long result;

    if (!parent_owned_mode || event == NULL ||
        event->type != IDA_VTDBG_EVENT_STOP || event->pid == 0 ||
        (event->flags & (IDA_VTDBG_EVENT_F_INITIAL_STOP |
                         IDA_VTDBG_EVENT_F_SYNTHETIC_STEP |
                         IDA_VTDBG_EVENT_F_EXCEPTION_RESUME)) != 0 ||
        !WIFSTOPPED((int)event->status) ||
        WSTOPSIG((int)event->status) != SIGTRAP ||
        !parent_owned_get_resume_observation((pid_t)event->pid,
                                             &stale_rip, &expected_rip) ||
        stale_rip == 0)
        return false;

    memset(&regs, 0, sizeof(regs));
    result = nested_driver_forward_ptrace(PTRACE_GETREGS,
                                           (pid_t)event->pid, NULL, &regs);
    if (result < 0 || regs.rip != stale_rip)
        return false;
    event_trace_log("[ida-vtdbg-shim] drop stale protocol stop child=%u rip=0x%llx expected_resume=0x%llx seq=%llu\n",
                    event->pid, (unsigned long long)regs.rip,
                    (unsigned long long)expected_rip,
                    (unsigned long long)event->sequence);
    return true;
}

static void nested_poll_kernel_events(void)
{
    pid_t target_pids[SHIM_MAX_TARGETS];
    size_t target_count = 0;
    int fd;

    if (!nested_event_worker && !nested_server)
        return;
    nested_async_resume_pump();
    pthread_mutex_lock(&nested_kernel_poll_lock);
    /* Both linux_server itself and the optional event worker need an
     * independent reader on the actual debuggee's tracer session.  In the
     * normal linux_server path there is no event-worker process, so limiting
     * subscription to nested_event_worker leaves fork/initial-stop events in
     * the target-owned ring while the target parent is correctly parked at
     * its real child stop. */
    if (parent_owned_mode && (nested_server || nested_event_worker))
        nested_server_subscribe_events(nested_server_outer_pid);
    if (parent_owned_mode && nested_server && nested_server_session_end_pending &&
        nested_server_outer_pid > 0) {
        pid_t old_root = nested_server_session_end_root;

        if (old_root > 0 && old_root != nested_server_outer_pid) {
            event_trace_log("[ida-vtdbg-shim] finalize deferred session old_root=%d new_subscription_target=%d\n",
                            old_root, nested_server_outer_pid);
            nested_server_reset_parent_owned_session_from_poll();
            nested_server_subscribe_events(nested_server_outer_pid);
        }
    }
    if (nested_event_worker) {
        /* Do not drain the driver's global queue while linux_server is still
         * running its private trace-fork capability probes.  In parent-owned
         * mode the real parent TGID becomes known when IDA first registers a
         * stopped debuggee.  Until then there is no safe event scope. */
        if (parent_owned_mode && nested_server_outer_pid <= 0) {
            pthread_mutex_unlock(&nested_kernel_poll_lock);
            return;
        }
        if (nested_worker_event_fd < 0)
            nested_worker_event_fd =
                open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
        if (nested_worker_event_fd < 0) {
            trace_log("[ida-vtdbg-shim] worker event device open failed errno=%d (%s)\n",
                      errno, strerror(errno));
        } else if (trace_enabled && nested_worker_event_fd >= 0) {
            static bool worker_fd_logged;
            if (!worker_fd_logged) {
                trace_log("[ida-vtdbg-shim] worker event device fd=%d parent_outer=%d\n",
                          nested_worker_event_fd, nested_server_outer_pid);
                worker_fd_logged = true;
            }
        }
        if (nested_worker_event_fd >= 0 && !parent_owned_mode)
            shared_map_attach(&worker_shared, nested_worker_event_fd);
        if (nested_worker_event_fd >= 0) {
            for (unsigned int pass = 0; pass < 8; ++pass) {
                struct ida_vtdbg_policy_event event;
                struct nested_packet packet;
                struct shim_shared_map *event_map = NULL;

                memset(&event, 0, sizeof(event));
                if (parent_owned_mode &&
                    nested_event_subscription_pid ==
                        nested_server_outer_pid &&
                    policy_shared.ring != NULL)
                    event_map = &policy_shared;
                else if (worker_shared.ring != NULL && !parent_owned_mode)
                    event_map = &worker_shared;
                if (event_map != NULL) {
                    if (!shared_map_next(event_map, &event))
                        break;
                } else {
                    event.abi = IDA_VTDBG_POLICY_ABI;
                    event.flags = IDA_VTDBG_EVENT_F_NONBLOCK;
                    if (parent_owned_mode)
                        event.target_pid =
                            (uint32_t)nested_server_outer_pid;
                    else
                        event.flags |= IDA_VTDBG_EVENT_F_ANY_TARGET;
                    if (ioctl(nested_worker_event_fd,
                              IDA_VTDBG_IOC_NEXT_EVENT, &event) == 0)
                        goto worker_event_ready;
                    if (errno != EAGAIN && errno != ENOENT)
                        trace_log("[ida-vtdbg-shim] worker kernel event poll failed errno=%d (%s)\n",
                                  errno, strerror(errno));
                    break;
                }
worker_event_ready:
                event_trace_log("[ida-vtdbg-shim] worker event ready type=%u pid=%u parent=%u owner=%u status=0x%x flags=0x%x seq=%llu outer=%d process=%d tid=%d\n",
                                event.type, event.pid, event.parent_tgid,
                                event.parent_pid,
                                event.status, event.flags,
                                (unsigned long long)event.sequence,
                                nested_server_outer_pid, getpid(),
                                current_tid());
                if (event.pid == 0)
                    continue;
                if (event.type == IDA_VTDBG_EVENT_TRACEME_METADATA) {
                    event_trace_log("[ida-vtdbg-shim] consume TRACEME syscall metadata child=%u (no wait stop, no ptrace query)\n",
                                    event.pid);
                    continue;
                }
                if (parent_owned_mode) {
                    if (event.parent_tgid !=
                        (uint32_t)nested_server_outer_pid) {
                        trace_log("[ida-vtdbg-shim] worker ignored event type=%u target=%u pid=%u parent_tgid=%u outer=%d\n",
                                  event.type, event.target_pid, event.pid,
                                  event.parent_tgid, nested_server_outer_pid);
                        continue;
                    }
                }
                memset(&packet, 0, sizeof(packet));
                packet.magic = NESTED_MAGIC;
                packet.type = NESTED_EVENT;
                packet.owner_tid = event.parent_pid;
                packet.value = event.sequence;
                if (event.type == IDA_VTDBG_EVENT_FORK) {
                    if (parent_owned_mode) {
                        /* Do not publish the synthetic fork before its child
                         * has reached the real parent-owned SIGSTOP.  The
                         * Linux backend immediately performs a second wait
                         * for the new task after GETEVENTMSG; queueing the
                         * fork and child-stop together avoids an ECHILD race. */
                        event_trace_log("[ida-vtdbg-shim] defer parent-owned fork process=%d tid=%d parent=%u child=%u until initial stop\n",
                                        getpid(), current_tid(),
                                        event.parent_tgid, event.pid);
                        parent_owned_mark_initial_proxy((pid_t)event.pid);
                        continue;
                    }
                    packet.request = NESTED_EVENT_FORK;
                    packet.pid = (int32_t)event.parent_tgid;
                    packet.aux_pid = (int32_t)event.pid;
                    packet.owner_tid = event.parent_pid;
                } else if (parent_owned_mode &&
                           event.type == IDA_VTDBG_EVENT_STOP) {
                    if (event.flags & IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED) {
                        event_trace_log("[ida-vtdbg-shim] audit-only consumed protocol event child=%u seq=%llu\n",
                                        event.pid, (unsigned long long)event.sequence);
                        continue;
                    }
                    if (parent_owned_drop_stale_resume_stop(&event))
                        continue;
                    if ((event.flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) == 0 &&
                        parent_owned_take_traceme_pending(
                            (pid_t)event.pid) &&
                        !parent_owned_traceme_stop_has_user_breakpoint(
                            (pid_t)event.pid)) {
                        event_trace_log("[ida-vtdbg-shim] consume target-reported TRACEME stop child=%u status=0x%x\n",
                                        event.pid, event.status);
                        (void)parent_owned_proxy_stop_held(
                            (pid_t)event.pid, true, true);
                        if (nested_driver_protocol_ack((pid_t)event.pid) < 0)
                            trace_log("[ida-vtdbg-shim] target TRACEME ack failed child=%u errno=%d (%s)\n",
                                      event.pid, errno, strerror(errno));
                        else
                            (void)parent_owned_proxy_stop_held(
                                (pid_t)event.pid, true, false);
                        continue;
                    }
                    if ((event.flags & IDA_VTDBG_EVENT_F_TRACEME_STOP) != 0) {
                        /* Legacy kernels encode syscall metadata as STOP.
                         * It is never a real stop and must not query ptrace. */
                        event_trace_log("[ida-vtdbg-shim] consume PTRACE_TRACEME metadata child=%u status=0x%x\n",
                                        event.pid, event.status);
                        continue;
                    }
                    (void)parent_owned_proxy_stop_held((pid_t)event.pid,
                                                       true, true);
                    parent_owned_begin_physical_stop((pid_t)event.pid, event.sequence);
                    /* A synthetic protocol-step stop is already being held at
                     * the child breakpoint created by the target-side
                     * observer.  Replaying ordinary IDA breakpoints here can
                     * issue a blocking PEEK/POKE while the target parent is
                     * waiting for IDA's resume request, deadlocking the event
                     * poller before it queues the synthetic stop. */
                    if ((event.flags & (IDA_VTDBG_EVENT_F_SYNTHETIC_STEP |
                                       IDA_VTDBG_EVENT_F_INITIAL_STOP)) == 0)
                        nested_propagate_breakpoints_to_child(
                            (pid_t)event.parent_tgid, (pid_t)event.pid);
                    if ((event.flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) != 0) {
                        (void)parent_owned_take_initial_proxy(
                            (pid_t)event.pid);
                        parent_owned_set_initial_visible((pid_t)event.pid,
                                                         true);
                        /* Stage both records atomically.  nested_pop_event()
                         * keeps the child stop queued until IDA has completed
                         * GETEVENTMSG and its child attach/options handshake;
                         * no waiter-startup delay is needed. */
                        packet.request = NESTED_EVENT_FORK;
                        packet.pid = (int32_t)event.parent_tgid;
                        packet.aux_pid = (int32_t)event.pid;
                        packet.flags = IDA_VTDBG_EVENT_F_INITIAL_STOP;
                        packet.status = (int32_t)event.status;
                        packet.owner_tid = event.parent_pid;
                        nested_queue_event(&packet);
                        event_trace_log("[ida-vtdbg-shim] publish parent-owned child process=%d tid=%d parent=%u child=%u status=0x%x after real stop\n",
                                        getpid(), current_tid(),
                                        event.parent_tgid, event.pid,
                                        event.status);
                        continue;
                    }
                    if ((event.flags & IDA_VTDBG_EVENT_F_SYNTHETIC_STEP) != 0) {
                        (void)parent_owned_consume_resume_observation(
                            (pid_t)event.pid);
                        nested_server_note_synthetic_step_stop(
                            (pid_t)event.pid);
                        (void)parent_owned_proxy_stop_held(
                            (pid_t)event.pid, true, true);
                        packet.request = NESTED_EVENT_WAIT;
                        packet.pid = (int32_t)event.pid;
                        packet.status = (int32_t)event.status;
                        packet.owner_tid = event.parent_pid;
                        nested_queue_event(&packet);
                        event_trace_log("[ida-vtdbg-shim] publish synthetic protocol-step stop child=%u status=0x%x\n",
                                        event.pid, event.status);
                        continue;
                    }
                    if ((event.flags & IDA_VTDBG_EVENT_F_EXCEPTION_RESUME) != 0) {
                        uintptr_t resume_rip = 0;
                        (void)parent_owned_get_exception_resume(
                            (pid_t)event.pid, &resume_rip);
                        packet.request = NESTED_EVENT_WAIT;
                        packet.pid = (int32_t)event.pid;
                        packet.status = (int32_t)event.status;
                        packet.owner_tid = event.parent_pid;
                        nested_queue_event(&packet);
                        event_trace_log("[ida-vtdbg-shim] publish synthetic exception-resume stop child=%u rip=0x%llx status=0x%x\n",
                                        event.pid,
                                        (unsigned long long)resume_rip,
                                        event.status);
                        continue;
                    }
                    if (parent_owned_visible_child_stop((pid_t)event.pid)) {
                        packet.request = NESTED_EVENT_WAIT;
                        packet.pid = (int32_t)event.pid;
                        packet.status = (int32_t)event.status;
                        packet.owner_tid = event.parent_pid;
                    } else {
                        event_trace_log("[ida-vtdbg-shim] hide parent-owned protocol stop child=%u status=0x%x\n",
                                        event.pid, event.status);
                        if (nested_driver_protocol_ack((pid_t)event.pid) < 0) {
                            trace_log("[ida-vtdbg-shim] protocol stop resume failed child=%u errno=%d (%s)\n",
                                      event.pid, errno, strerror(errno));
                        } else {
                            (void)parent_owned_proxy_stop_held(
                                (pid_t)event.pid, true, false);
                        }
                        continue;
                    }
                } else {
                    continue;
                }
                nested_queue_event(&packet);
                event_trace_log("[ida-vtdbg-shim] worker kernel event type=%u parent=%d child=%d seq=%llu\n",
                                event.type, event.parent_tgid, event.pid,
                                (unsigned long long)event.sequence);
            }
        }
        pthread_mutex_unlock(&nested_kernel_poll_lock);
        return;
    }
    fd = ensure_policy_fd();
    if (fd < 0) {
        pthread_mutex_unlock(&nested_kernel_poll_lock);
        return;
    }

    if (policy_shared.ring != NULL) {
        bool consumed_shared = false;

        for (unsigned int pass = 0; pass < IDA_VTDBG_SHARED_RING_SLOTS;
             ++pass) {
            struct ida_vtdbg_policy_event event;
            struct nested_packet packet;

            if (!shared_map_next(&policy_shared, &event))
                break;
            consumed_shared = true;
            event_trace_log("[ida-vtdbg-shim] server shared event type=%u flags=0x%x pid=%u parent=%u status=0x%x seq=%llu\n",
                            event.type, event.flags, event.pid,
                            event.parent_tgid, event.status,
                            (unsigned long long)event.sequence);
            if (event.pid == 0)
                continue;
            if (event.type == IDA_VTDBG_EVENT_TRACEME_METADATA) {
                event_trace_log("[ida-vtdbg-shim] consume TRACEME syscall metadata child=%u (no wait stop, no ptrace query)\n",
                                event.pid);
                continue;
            }
            if (parent_owned_mode && nested_server &&
                nested_server_outer_pid <= 0 && event.parent_tgid > 0)
                nested_server_outer_pid = (pid_t)event.parent_tgid;
            memset(&packet, 0, sizeof(packet));
            packet.magic = NESTED_MAGIC;
            packet.type = NESTED_EVENT;
            packet.owner_tid = event.parent_pid;
            packet.value = event.sequence;
            if (parent_owned_mode && event.type == IDA_VTDBG_EVENT_FORK) {
                trace_log("[ida-vtdbg-shim] server defer shared fork parent=%u child=%u seq=%llu until initial stop\n",
                          event.parent_tgid, event.pid,
                          (unsigned long long)event.sequence);
                parent_owned_mark_initial_proxy((pid_t)event.pid);
                continue;
            }
            if (parent_owned_mode && event.type == IDA_VTDBG_EVENT_STOP) {
                if (event.flags & IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED) {
                    event_trace_log("[ida-vtdbg-shim] audit-only consumed protocol event child=%u seq=%llu\n",
                                    event.pid, (unsigned long long)event.sequence);
                    continue;
                }
                if (parent_owned_drop_stale_resume_stop(&event))
                    continue;
                if ((event.flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) == 0 &&
                    parent_owned_take_traceme_pending((pid_t)event.pid) &&
                    !parent_owned_traceme_stop_has_user_breakpoint(
                        (pid_t)event.pid)) {
                    event_trace_log("[ida-vtdbg-shim] consume target-reported TRACEME stop child=%u status=0x%x\n",
                                    event.pid, event.status);
                    (void)parent_owned_proxy_stop_held(
                        (pid_t)event.pid, true, true);
                    if (nested_driver_protocol_ack((pid_t)event.pid) < 0)
                        trace_log("[ida-vtdbg-shim] target TRACEME ack failed child=%u errno=%d (%s)\n",
                                  event.pid, errno, strerror(errno));
                    else
                        (void)parent_owned_proxy_stop_held(
                            (pid_t)event.pid, true, false);
                    continue;
                }
                if ((event.flags & IDA_VTDBG_EVENT_F_TRACEME_STOP) != 0) {
                    event_trace_log("[ida-vtdbg-shim] consume PTRACE_TRACEME metadata child=%u status=0x%x\n",
                                    event.pid, event.status);
                    continue;
                }
                (void)parent_owned_proxy_stop_held((pid_t)event.pid,
                                                   true, true);
                parent_owned_begin_physical_stop((pid_t)event.pid, event.sequence);
                if ((event.flags & (IDA_VTDBG_EVENT_F_SYNTHETIC_STEP |
                                   IDA_VTDBG_EVENT_F_INITIAL_STOP)) == 0)
                    nested_propagate_breakpoints_to_child(
                        (pid_t)event.parent_tgid, (pid_t)event.pid);
                if ((event.flags & IDA_VTDBG_EVENT_F_INITIAL_STOP) != 0) {
                    (void)parent_owned_take_initial_proxy((pid_t)event.pid);
                    parent_owned_set_initial_visible((pid_t)event.pid, true);
                    packet.request = NESTED_EVENT_FORK;
                    packet.pid = (int32_t)event.parent_tgid;
                    packet.aux_pid = (int32_t)event.pid;
                    packet.flags = IDA_VTDBG_EVENT_F_INITIAL_STOP;
                    packet.status = (int32_t)event.status;
                    nested_queue_event(&packet);
                    trace_log("[ida-vtdbg-shim] server publish shared child parent=%u child=%u status=0x%x seq=%llu\n",
                              event.parent_tgid, event.pid, event.status,
                              (unsigned long long)event.sequence);
                    continue;
                }
                if ((event.flags & IDA_VTDBG_EVENT_F_SYNTHETIC_STEP) != 0) {
                    (void)parent_owned_consume_resume_observation(
                        (pid_t)event.pid);
                    nested_server_note_synthetic_step_stop(
                        (pid_t)event.pid);
                    (void)parent_owned_proxy_stop_held(
                        (pid_t)event.pid, true, true);
                    packet.request = NESTED_EVENT_WAIT;
                    packet.pid = (int32_t)event.pid;
                    packet.status = (int32_t)event.status;
                    packet.owner_tid = event.parent_pid;
                    nested_queue_event(&packet);
                    event_trace_log("[ida-vtdbg-shim] server publish synthetic protocol-step stop child=%u status=0x%x\n",
                                    event.pid, event.status);
                    continue;
                }
                if ((event.flags & IDA_VTDBG_EVENT_F_EXCEPTION_RESUME) != 0) {
                    uintptr_t resume_rip = 0;
                    (void)parent_owned_get_exception_resume(
                        (pid_t)event.pid, &resume_rip);
                    packet.request = NESTED_EVENT_WAIT;
                    packet.pid = (int32_t)event.pid;
                    packet.status = (int32_t)event.status;
                    packet.owner_tid = event.parent_pid;
                    nested_queue_event(&packet);
                    event_trace_log("[ida-vtdbg-shim] server publish synthetic exception-resume stop child=%u rip=0x%llx status=0x%x\n",
                                    event.pid,
                                    (unsigned long long)resume_rip,
                                    event.status);
                    continue;
                }
                if (parent_owned_mode &&
                    parent_owned_drop_stale_resume_stop(&event))
                    continue;
                if (parent_owned_get_exception_resume((pid_t)event.pid, NULL)) {
                    nested_server_note_exception_resume((pid_t)event.pid);
                    packet.request = NESTED_EVENT_WAIT;
                    packet.pid = (int32_t)event.pid;
                    packet.status = (int32_t)event.status;
                    packet.owner_tid = event.parent_pid;
                    nested_queue_event(&packet);
                    event_trace_log("[ida-vtdbg-shim] server publish program-exception resume stop child=%u status=0x%x\n",
                                    event.pid, event.status);
                    continue;
                }
                if (!parent_owned_visible_child_stop((pid_t)event.pid)) {
                    trace_log("[ida-vtdbg-shim] server hide shared protocol stop child=%u status=0x%x\n",
                              event.pid, event.status);
                    if (nested_driver_protocol_ack((pid_t)event.pid) < 0)
                        trace_log("[ida-vtdbg-shim] server protocol stop resume failed child=%u errno=%d (%s)\n",
                                  event.pid, errno, strerror(errno));
                    else
                        (void)parent_owned_proxy_stop_held(
                            (pid_t)event.pid, true, false);
                    continue;
                }
                packet.request = NESTED_EVENT_WAIT;
                packet.pid = (int32_t)event.pid;
                packet.status = (int32_t)event.status;
                nested_queue_event(&packet);
                trace_log("[ida-vtdbg-shim] server queue shared child stop child=%u status=0x%x seq=%llu\n",
                          event.pid, event.status,
                          (unsigned long long)event.sequence);
                continue;
            }
            if (parent_owned_mode && event.type == IDA_VTDBG_EVENT_EXIT) {
                if (event.flags & IDA_VTDBG_EVENT_F_KERNEL_LIFECYCLE) {
                    bool publish = false;
                    if (event.pid == (uint32_t)nested_server_outer_pid)
                        atomic_store_explicit(&nested_parent_kernel_exit_confirmed,
                                              true, memory_order_release);
                    /* Native wait owns the root's exit status. The pinned
                     * lifecycle channel owns shadow child exits even after
                     * their real tracer exits/reparents them. No duplicate
                     * root status and no invented child exit code. */
                    if (!nested_is_shadow((pid_t)event.pid))
                        continue;
                    pthread_mutex_lock(&nested_event_lock);
                    struct parent_owned_child_state *state =
                        parent_owned_child_locked((pid_t)event.pid, false);
                    if (state != NULL && !state->exit_event_queued) {
                        state->exit_event_queued = true;
                        state->proxy_stop_held = false;
                        state->synthetic_step_stop = false;
                        publish = true;
                    }
                    pthread_mutex_unlock(&nested_event_lock);
                    if (!publish)
                        continue;
                    handler_trace_log("[ida-vtdbg-shim] debugger-child-exit child=%u status=0x%x seq=%llu\n",
                                      event.pid, event.status,
                                      (unsigned long long)event.sequence);
                }
                packet.request = NESTED_EVENT_WAIT;
                packet.pid = (int32_t)event.pid;
                packet.status = (int32_t)event.status;
                nested_queue_event(&packet);
                continue;
            }
            if (event.type != IDA_VTDBG_EVENT_FORK)
                continue;
            packet.request = NESTED_EVENT_FORK;
            packet.pid = (int32_t)event.parent_tgid;
            packet.aux_pid = (int32_t)event.pid;
            nested_queue_event(&packet);
            trace_log("[ida-vtdbg-shim] shared kernel fork parent=%d child=%d seq=%llu\n",
                      event.parent_tgid, event.pid,
                      (unsigned long long)event.sequence);
        }
        /* The shared reader is authoritative once the server has subscribed;
         * returning here prevents the same event from being consumed a second
         * time through NEXT_EVENT during linux_server's startup handshake. */
        (void)consumed_shared;
        pthread_mutex_unlock(&nested_kernel_poll_lock);
        return;
    }

    pthread_mutex_lock(&state_lock);
    for (size_t index = 0; index < SHIM_MAX_TARGETS; ++index) {
        if (!targets[index].active || targets[index].pid <= 0 ||
            target_count >= SHIM_MAX_TARGETS)
            continue;
        target_pids[target_count++] = targets[index].pid;
    }
    pthread_mutex_unlock(&state_lock);

    for (size_t index = 0; index < target_count; ++index) {
        for (unsigned int pass = 0; pass < 8; ++pass) {
            struct ida_vtdbg_policy_event event;
            struct nested_packet packet;

            memset(&event, 0, sizeof(event));
            event.abi = IDA_VTDBG_POLICY_ABI;
            event.target_pid = (uint32_t)target_pids[index];
            event.flags = IDA_VTDBG_EVENT_F_NONBLOCK;
            if (ioctl(fd, IDA_VTDBG_IOC_NEXT_EVENT, &event) < 0) {
                if (errno != EAGAIN && errno != ENOENT)
                    trace_log("[ida-vtdbg-shim] kernel event poll pid=%d failed errno=%d (%s)\n",
                              target_pids[index], errno, strerror(errno));
                break;
            }
            if (event.type != IDA_VTDBG_EVENT_FORK || event.pid == 0)
                continue;
            memset(&packet, 0, sizeof(packet));
            packet.magic = NESTED_MAGIC;
            packet.type = NESTED_EVENT;
            packet.request = NESTED_EVENT_FORK;
            packet.pid = (int32_t)event.parent_tgid;
            packet.aux_pid = (int32_t)event.pid;
            packet.owner_tid = event.parent_pid;
            nested_queue_event(&packet);
            trace_log("[ida-vtdbg-shim] kernel fork event parent=%d child=%d seq=%llu\n",
                      event.parent_tgid, event.pid,
                      (unsigned long long)event.sequence);
        }
    }
    pthread_mutex_unlock(&nested_kernel_poll_lock);
}

static void *nested_kernel_poller(void *unused)
{
    (void)unused;
    trace_log("[ida-vtdbg-shim] event-worker started listen=%d conn=%d\n",
              nested_listen_fd, nested_conn_fd);
    while (nested_kernel_poller_running) {
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
        /* Parent-owned fork/initial-stop notifications are published through
         * the kernel shared event ring, not the legacy nested socket.  The
         * linux_server wait hook must drain that ring before checking its
         * virtual event queue; otherwise IDA can freeze the outer task while
         * the child event remains invisible until the session times out. */
        if (nested_server_outer_pid > 0 &&
            nested_event_subscription_pid == nested_server_outer_pid)
            nested_poll_kernel_events();
        nested_poll_messages();
        nested_poll_kernel_events();
        (void)nanosleep(&delay, NULL);
    }
    return NULL;
}

static pid_t nested_worker_wait_event(pid_t requested, int *status,
                                     int options)
{
    pid_t event_pid = 0;

    if (!nested_event_worker || parent_owned_mode)
        return -2;
    nested_poll_messages();
    nested_poll_kernel_events();
    if (nested_pop_event(requested, status, &event_pid)) {
        trace_log("[ida-vtdbg-shim] worker wait event process=%d caller=%d requested=%d options=0x%x returned=%d status=0x%x\n",
                  getpid(), current_tid(), requested, options, event_pid,
                  status != NULL ? (unsigned int)*status : 0);
        return event_pid;
    }
    return -2;
}

static bool nested_virtual_ptrace(enum __ptrace_request request, pid_t pid,
                                  void *data, long *result)
{
    bool handled = false;
    bool resume_real_outer = false;
    pid_t real_outer_pid = 0;
    enum __ptrace_request real_outer_request = request;

    if (result == NULL)
        return false;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t index = 0; index < NESTED_QUEUE_MAX; ++index) {
        struct nested_virtual_fork *fork_event = &nested_virtual_forks[index];
        if (!fork_event->active || !fork_event->event_delivered ||
            fork_event->parent_pid != pid)
            continue;
        trace_log("[ida-vtdbg-shim] virtual ptrace candidate req=%d parent=%d child=%d msg=%d resume=%d owned=%d\n",
                  request, pid, fork_event->child_pid,
                  fork_event->message_pending ? 1 : 0,
                  fork_event->resume_requested ? 1 : 0,
                   parent_owned_mode ? 1 : 0);
        event_trace_log("[ida-vtdbg-shim] virtual ptrace candidate req=%d parent=%d child=%d event_delivered=%d msg=%d attach_ready=%d initial_delivered=%d outer_held=%d\n",
                        request, pid, fork_event->child_pid,
                        fork_event->event_delivered ? 1 : 0,
                        fork_event->message_pending ? 1 : 0,
                        fork_event->child_attach_ready ? 1 : 0,
                        fork_event->child_initial_delivered ? 1 : 0,
                        fork_event->outer_stop_held ? 1 : 0);
        if (request == PTRACE_GETEVENTMSG) {
            if (fork_event->message_pending && data != NULL) {
                pid_t child = fork_event->child_pid;
                *(unsigned long *)data = (unsigned long)fork_event->child_pid;
                fork_event->message_pending = false;
                for (size_t event_index = 0;
                     event_index < nested_event_count; ++event_index) {
                    if (!nested_events[event_index].virtual_fork ||
                        nested_events[event_index].pid != pid ||
                        nested_events[event_index].aux_pid != child)
                        continue;
                    for (size_t move = event_index + 1;
                         move < nested_event_count; ++move)
                        nested_events[move - 1] = nested_events[move];
                    --nested_event_count;
                    event_trace_log("[ida-vtdbg-shim] virtual fork GETEVENTMSG ack parent=%d child=%d remaining=%zu\n",
                                    pid, child, nested_event_count);
                    break;
                }
                if (fork_event->resume_requested &&
                    fork_event->child_initial_delivered)
                    fork_event->active = false;
                *result = 0;
                handled = true;
                event_trace_log("[ida-vtdbg-shim] virtual GETEVENTMSG handled parent=%d child=%d result=0 attach_ready=%d\n",
                                pid, child,
                                fork_event->child_attach_ready ? 1 : 0);
            }
        } else if (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                   request == PTRACE_SINGLESTEP ||
                   request == PTRACE_SETOPTIONS) {
            /* Most virtual fork notifications do not correspond to a kernel
             * stop of the outer parent.  The initial parent-owned bootstrap
             * is different: broker_wait deliberately held a real outer
             * SIGSTOP while presenting this clone-shaped event.  Release that
             * stop on the actual ptrace owner when IDA acknowledges it. */
            fork_event->resume_requested = true;
            event_trace_log("[ida-vtdbg-shim] synthetic fork lifecycle request=%d parent=%d child=%d msg=%d attach_ready=%d initial_delivered=%d\n",
                            request, pid, fork_event->child_pid,
                            fork_event->message_pending ? 1 : 0,
                            fork_event->child_attach_ready ? 1 : 0,
                            fork_event->child_initial_delivered ? 1 : 0);
            if (parent_owned_mode && fork_event->outer_stop_held &&
                (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                 request == PTRACE_SINGLESTEP)) {
                fork_event->outer_stop_held = false;
                resume_real_outer = true;
                real_outer_pid = pid;
                real_outer_request = request;
            } else if (parent_owned_mode &&
                (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                 request == PTRACE_SINGLESTEP)) {
                struct parent_owned_child_state *child_state =
                    parent_owned_child_locked(fork_event->child_pid, true);
                if (child_state != NULL) {
                    child_state->resume_request =
                        request == PTRACE_SINGLESTEP
                            ? PARENT_OWNED_RESUME_STEP
                            : PARENT_OWNED_RESUME_CONT;
                }
                event_trace_log("[ida-vtdbg-shim] synthetic fork resume req=%d parent=%d child=%d\n",
                                request, pid, fork_event->child_pid);
            }
            if (!fork_event->message_pending &&
                fork_event->child_initial_delivered)
                fork_event->active = false;
            *result = 0;
            handled = true;
        }
        break;
    }
    pthread_mutex_unlock(&nested_event_lock);
    if (handled && resume_real_outer) {
        long resumed = ptrace_internal(real_outer_request, real_outer_pid,
                                       NULL, data);
        if (resumed < 0) {
            *result = -1;
            return true;
        }
        *result = resumed;
    }
    if (handled)
        trace_log("[ida-vtdbg-shim] virtual ptrace handled req=%d pid=%d result=%ld\n",
                  request, pid, result != NULL ? *result : -1L);
    return handled;
}

static int nested_make_socket(void)
{
    struct sockaddr_un address;
    int fd;
    const char *configured = getenv("IDA_VTDBG_NESTED_SOCKET");

    if (configured != NULL && *configured != '\0')
        (void)snprintf(nested_socket_path, sizeof(nested_socket_path), "%s",
                       configured);
    else
        (void)snprintf(nested_socket_path, sizeof(nested_socket_path),
                       "/tmp/ida_vtdbg_nested_%d.sock", (int)getpid());
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (strlen(nested_socket_path) >= sizeof(address.sun_path)) {
        close(fd);
        return -1;
    }
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s",
                   nested_socket_path);
    (void)unlink(nested_socket_path);
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(fd, 1) < 0) {
        close(fd);
        return -1;
    }
    (void)fcntl(fd, F_SETFL, O_NONBLOCK);
    return fd;
}

static int nested_server_setup(void)
{
    nested_listen_fd = nested_make_socket();
    if (nested_listen_fd < 0)
        return -errno;
    (void)setenv("IDA_VTDBG_NESTED_SOCKET", nested_socket_path, 1);
    trace_log("[ida-vtdbg-shim] nested server socket=%s\n",
              nested_socket_path);
    return 0;
}

static bool nested_target_send_hello(void)
{
    struct nested_packet packet;

    memset(&packet, 0, sizeof(packet));
    packet.magic = NESTED_MAGIC;
    packet.type = NESTED_EVENT;
    packet.request = NESTED_EVENT_HELLO;
    packet.pid = getpid();
    packet.aux_pid = getppid();
    trace_log("[ida-vtdbg-shim] nested target hello pid=%d ppid=%d socket=%s\n",
              packet.pid, packet.aux_pid, nested_socket_path);
    return nested_send_packet(&packet);
}

static void nested_target_send_event(uint32_t request, pid_t pid, pid_t aux_pid,
                                     int status)
{
    struct nested_packet packet;

    if (!nested_target || nested_conn_fd < 0)
        return;
    memset(&packet, 0, sizeof(packet));
    packet.magic = NESTED_MAGIC;
    packet.type = NESTED_EVENT;
    packet.request = request;
    packet.pid = pid;
    packet.aux_pid = aux_pid;
    packet.status = status;
    packet.owner_tid = (uint32_t)current_tid();
    (void)nested_send_packet(&packet);
}

static int nested_target_connect(void)
{
    struct sockaddr_un address;
    const char *path = getenv("IDA_VTDBG_NESTED_SOCKET");
    int fd;

    if (path == NULL || *path == '\0')
        return -ENOENT;
    (void)snprintf(nested_socket_path, sizeof(nested_socket_path), "%s", path);
    fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    (void)snprintf(address.sun_path, sizeof(address.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        int saved = errno;
        close(fd);
        return -saved;
    }
    nested_conn_fd = fd;
    if (nested_kernel_events && nested_target_event_fd < 0)
        nested_target_event_fd =
            open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    (void)nested_target_send_hello();
    return 0;
}

static int nested_parent_driver_setup(void)
{
    struct ida_vtdbg_policy_session session;

    if (!parent_owned_mode || !nested_target || nested_target_launcher)
        return -EINVAL;
    if (nested_target_event_fd < 0)
        nested_target_event_fd =
            open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (nested_target_event_fd < 0)
        return -errno;
    memset(&session, 0, sizeof(session));
    session.abi = IDA_VTDBG_POLICY_ABI;
    session.target_pid = (uint32_t)getpid();
    session.flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS;
    if (ioctl(nested_target_event_fd, IDA_VTDBG_IOC_REGISTER_TRACER,
              &session) < 0)
        return -errno;
    trace_log("[ida-vtdbg-shim] parent-owned driver session pid=%d fd=%d\n",
              getpid(), nested_target_event_fd);
    return 0;
}

static void nested_server_subscribe_events(pid_t target)
{
    struct ida_vtdbg_policy_session request;
    int fd;

    if (!parent_owned_mode || (!nested_server && !nested_event_worker) ||
        target <= 0 ||
        nested_event_subscription_pid == target)
        return;
    fd = ensure_policy_fd();
    if (fd < 0)
        return;
    if (nested_event_subscription_pid != 0 &&
        nested_event_subscription_pid != target)
        (void)ioctl(fd, IDA_VTDBG_IOC_SHARED_RESET);
    memset(&request, 0, sizeof(request));
    request.abi = IDA_VTDBG_POLICY_ABI;
    request.target_pid = (uint32_t)target;
    request.flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS |
                    IDA_VTDBG_SUBSCRIBE_F_PERSISTENT_TREE;
    if (ioctl(fd, IDA_VTDBG_IOC_SUBSCRIBE_EVENTS, &request) == 0) {
        nested_event_subscription_pid = target;
        event_trace_log("[ida-vtdbg-shim] server subscribed shared event ring target=%d fd=%d server=%d worker=%d\n",
                        target, fd, nested_server ? 1 : 0,
                        nested_event_worker ? 1 : 0);
    } else if (errno != ENOENT && errno != ESRCH && errno != EAGAIN) {
        trace_log("[ida-vtdbg-shim] server event subscription failed target=%d fd=%d errno=%d (%s)\n",
                  target, fd, errno, strerror(errno));
    }
}

/* linux_server keeps its accepted IDA TCP endpoint in the same process as the
 * shim. After an explicit ProcessExit the peer can close first, leaving the
 * endpoint in CLOSE-WAIT while debugger state is already back at NOTASK.
 * Close only connected IPv4/IPv6 stream sockets for which a nonblocking peek
 * observes EOF; listeners, UNIX relay sockets, policy fds, and live IDA
 * connections are left untouched. */
static void nested_server_close_disconnected_clients(void)
{
    long limit = sysconf(_SC_OPEN_MAX);
    int closed = 0;

    if (limit <= 0 || limit > 4096)
        limit = 4096;
    for (int fd = 0; fd < (int)limit; ++fd) {
        struct stat info;
        struct sockaddr_storage peer;
        socklen_t peer_length = sizeof(peer);
        int type = 0;
        int accepting = 0;
        socklen_t option_length = sizeof(type);
        char probe;
        ssize_t received;

        if (fd == nested_listen_fd || fd == nested_conn_fd ||
            fd == policy_fd || fd == nested_worker_event_fd ||
            fd == nested_target_event_fd)
            continue;
        if (fstat(fd, &info) < 0 || !S_ISSOCK(info.st_mode))
            continue;
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &option_length) < 0 ||
            type != SOCK_STREAM)
            continue;
        option_length = sizeof(accepting);
        if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting,
                       &option_length) == 0 && accepting != 0)
            continue;
        if (getpeername(fd, (struct sockaddr *)&peer, &peer_length) < 0)
            continue;
        if (peer.ss_family != AF_INET && peer.ss_family != AF_INET6)
            continue;
        received = recv(fd, &probe, sizeof(probe),
                        MSG_PEEK | MSG_DONTWAIT | MSG_NOSIGNAL);
        if (received != 0 && !(received < 0 &&
                               (errno == ECONNRESET || errno == ENOTCONN)))
            continue;
        (void)shutdown(fd, SHUT_RDWR);
        close(fd);
        ++closed;
        event_trace_log("[ida-vtdbg-shim] closed disconnected IDA TCP fd=%d\n",
                        fd);
    }
    if (closed != 0)
        event_trace_log("[ida-vtdbg-shim] disconnected IDA TCP cleanup count=%d\n",
                        closed);
}

/* Caller may already hold nested_kernel_poll_lock (the shared-ring poller
 * invokes subscription while holding it). */
static void nested_server_reset_parent_owned_session_locked(bool poll_lock_held)
{
    int fd;
    pid_t root;

    if (!parent_owned_mode || !nested_server)
        return;
    if (!poll_lock_held)
        pthread_mutex_lock(&nested_kernel_poll_lock);
    pthread_mutex_lock(&nested_async_lock);
    for (size_t n = 0; n < nested_async_count; ++n)
        free(nested_async_resumes[n]);
    memset(nested_async_resumes, 0, sizeof(nested_async_resumes));
    nested_async_count = 0;
    pthread_mutex_unlock(&nested_async_lock);
    pthread_mutex_lock(&nested_event_lock);
    root = nested_server_session_end_root > 0
               ? nested_server_session_end_root
               : nested_server_outer_pid;
    if (!nested_server_session_end_pending && root <= 0) {
        pthread_mutex_unlock(&nested_event_lock);
        if (!poll_lock_held)
            pthread_mutex_unlock(&nested_kernel_poll_lock);
        return;
    }
    memset(nested_events, 0, sizeof(nested_events));
    memset(nested_virtual_forks, 0, sizeof(nested_virtual_forks));
    memset(parent_owned_children, 0, sizeof(parent_owned_children));
    memset(parent_owned_owners, 0, sizeof(parent_owned_owners));
    memset(nested_shadow_pids, 0, sizeof(nested_shadow_pids));
    memset(nested_user_breakpoints, 0, sizeof(nested_user_breakpoints));
    memset(nested_protocol_hw_steps, 0,
           sizeof(nested_protocol_hw_steps));
    memset(nested_generic_hw_steps, 0, sizeof(nested_generic_hw_steps));
    memset(nested_ida_step_intents, 0, sizeof(nested_ida_step_intents));
    memset(nested_ida_software_steps, 0, sizeof(nested_ida_software_steps));
    pthread_mutex_lock(&nested_native_stop_lock);
    memset(nested_native_stops, 0, sizeof(nested_native_stops));
    nested_native_stop_count = 0;
    pthread_mutex_unlock(&nested_native_stop_lock);
    atomic_store_explicit(&nested_parent_real_stopped, false, memory_order_release);
    atomic_store_explicit(&nested_parent_kernel_exit_confirmed, false, memory_order_release);
    atomic_store_explicit(&nested_parent_debug_event_presented, false, memory_order_release);
    atomic_store_explicit(&nested_parent_stop_unpresented, false, memory_order_release);
    atomic_store_explicit(&nested_parent_trace_requested, false, memory_order_release);
    memset(&nested_target_protocol_step, 0,
           sizeof(nested_target_protocol_step));
    nested_event_count = 0;
    nested_shadow_count = 0;
    nested_server_outer_pid = 0;
    nested_server_owner_tid = 0;
    nested_target_owner_tid = 0;
    nested_target_child_pid = 0;
    nested_event_subscription_pid = 0;
    nested_server_session_end_pending = false;
    nested_server_session_end_root = 0;
    oneshot_algorithm_done = false;
    shared_set_oneshot_control(false, 0);
    /* Keep any late-arriving deferred ProcessExit record across this reset.
     * parent_owned_execute_queued_process_exit() consumes it on the next
     * broker wait; clearing it here loses a shadow child when teardown races
     * the final PTRACE_KILL request. */
    pthread_mutex_unlock(&nested_event_lock);

    pthread_mutex_lock(&state_lock);
    memset(targets, 0, sizeof(targets));
    memset(tids, 0, sizeof(tids));
    pthread_mutex_unlock(&state_lock);

    fd = policy_fd;
    if (fd >= 0)
        (void)ioctl(fd, IDA_VTDBG_IOC_SHARED_RESET);
    if (!poll_lock_held)
        pthread_mutex_unlock(&nested_kernel_poll_lock);
    nested_server_close_disconnected_clients();
    event_trace_log("[ida-vtdbg-shim] parent-owned server session ended root=%d; event and breakpoint state reset\n",
                    root);
}

static void nested_server_reset_parent_owned_session(void)
{
    nested_server_reset_parent_owned_session_locked(false);
}

static void nested_server_reset_parent_owned_session_from_poll(void)
{
    nested_server_reset_parent_owned_session_locked(true);
}

static void nested_server_finalize_deferred_session(void)
{
    bool pending;

    pthread_mutex_lock(&nested_event_lock);
    pending = nested_server_session_end_pending;
    pthread_mutex_unlock(&nested_event_lock);
    if (pending)
        nested_server_reset_parent_owned_session();
}

static void nested_server_end_parent_owned_session(pid_t root)
{
    if (!parent_owned_mode || !nested_server || root <= 0)
        return;
    /* ProcessExit is issued while the real parent is still servicing the
     * child's proxy stop.  The ptrace kill is deliberately queued so it does
     * not race that wait.  Preserve all proxy/thread metadata until IDA has
     * received the final child THREAD_EXITED/PROCESS_EXITED events. */
    parent_owned_execute_queued_process_exit();
    pthread_mutex_lock(&nested_event_lock);
    if (nested_server_outer_pid != root || nested_server_session_end_pending) {
        pthread_mutex_unlock(&nested_event_lock);
        return;
    }
    nested_server_session_end_pending = true;
    nested_server_session_end_root = root;
    pthread_mutex_unlock(&nested_event_lock);
    event_trace_log("[ida-vtdbg-shim] parent-owned server session end deferred root=%d until next IDA connection\n",
                    root);
}

static void replay_target_stdin_after_fork(void)
{
    struct stat info;
    off_t result;

    if (!replay_stdin_enabled || !nested_target || nested_target_launcher ||
        !parent_owned_mode)
        return;
    if (fstat(STDIN_FILENO, &info) < 0 || !S_ISREG(info.st_mode))
        return;
    result = lseek(STDIN_FILENO, (off_t)0, SEEK_SET);
    event_trace_log("[ida-vtdbg-shim] replay target stdin after fork fd=%d result=%lld errno=%d\n",
                    STDIN_FILENO, (long long)result,
                    result < 0 ? errno : 0);
}

static void nested_target_report_child(pid_t child, int status)
{
    struct ida_vtdbg_policy_event event;
    pid_t owner_tid;

    if (!nested_target || nested_target_launcher || !nested_kernel_events ||
        child <= 0)
        return;
    if (nested_target_event_fd < 0)
        nested_target_event_fd =
            open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (nested_target_event_fd < 0) {
        trace_log("[ida-vtdbg-shim] target event device open failed errno=%d (%s)\n",
                  errno, strerror(errno));
        return;
    }
    owner_tid = parent_owned_get_owner_tid(child);
    if (owner_tid <= 0)
        owner_tid = current_tid();
    memset(&event, 0, sizeof(event));
    event.abi = IDA_VTDBG_POLICY_ABI;
    event.target_pid = (uint32_t)getpid();
    event.type = IDA_VTDBG_EVENT_FORK;
    event.pid = (uint32_t)child;
    event.tgid = (uint32_t)child;
    event.parent_pid = (uint32_t)owner_tid;
    event.parent_tgid = (uint32_t)getpid();
    event.status = (uint32_t)status;
    if (ioctl(nested_target_event_fd, IDA_VTDBG_IOC_REPORT_EVENT, &event) < 0)
        trace_log("[ida-vtdbg-shim] kernel child report pid=%d failed errno=%d (%s)\n",
                  child, errno, strerror(errno));
    else
        trace_log("[ida-vtdbg-shim] kernel child report parent=%d child=%d\n",
                  getpid(), child);
}

static void nested_parent_report_stop(pid_t child, int status,
                                     bool initial_stop, uint32_t extra_flags)
{
    struct ida_vtdbg_policy_event event;
    pid_t owner_tid;

    if (!parent_owned_mode || !nested_target || nested_target_launcher ||
        child <= 0)
        return;
    if (nested_target_event_fd < 0)
        nested_target_event_fd =
            open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (nested_target_event_fd < 0)
        return;
    owner_tid = parent_owned_get_owner_tid(child);
    if (owner_tid <= 0)
        owner_tid = current_tid();
    memset(&event, 0, sizeof(event));
    event.abi = IDA_VTDBG_POLICY_ABI;
    event.target_pid = (uint32_t)getpid();
    event.type = IDA_VTDBG_EVENT_STOP;
    event.flags = (initial_stop ? IDA_VTDBG_EVENT_F_INITIAL_STOP : 0) |
                  extra_flags;
    event.pid = (uint32_t)child;
    event.tgid = (uint32_t)child;
    event.parent_pid = (uint32_t)owner_tid;
    event.parent_tgid = (uint32_t)getpid();
    event.status = (uint32_t)status;
    {
        int report_result = ioctl(nested_target_event_fd,
                                  IDA_VTDBG_IOC_REPORT_EVENT, &event);
        event_trace_log("[ida-vtdbg-shim] parent-owned report proxy stop child=%d status=0x%x initial=%d flags=0x%x result=%d errno=%d\n",
                        child, (unsigned int)status,
                        initial_stop ? 1 : 0, event.flags, report_result,
                        report_result < 0 ? errno : 0);
    }
}

/* Parent-owned transport: all request/response state lives in the policy
 * driver.  Unlike the legacy SOCK_SEQPACKET relay, this survives linux_server
 * worker forks and never leaves a blocking endpoint in the target process. */
static int nested_driver_service_command(bool defer_resume, bool *release_wait)
{
    struct ida_vtdbg_ptrace_command command;
    struct nested_packet packet;
    struct nested_packet response;
    int fd;

    if (release_wait != NULL)
        *release_wait = false;
    if (!parent_owned_mode || !nested_target || nested_target_launcher)
        return 0;
    if (nested_target_event_fd < 0)
        nested_target_event_fd =
            open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    fd = nested_target_event_fd;
    if (fd < 0)
        return -errno;
    memset(&command, 0, sizeof(command));
    command.abi = IDA_VTDBG_POLICY_ABI;
    command.target_pid = (uint32_t)getpid();
    if (ioctl(fd, IDA_VTDBG_IOC_NEXT_COMMAND, &command) < 0) {
        if (errno == EAGAIN || errno == ENOENT)
            return 0;
        trace_log("[ida-vtdbg-shim] driver next command failed errno=%d (%s)\n",
                  errno, strerror(errno));
        return -errno;
    }
    memset(&packet, 0, sizeof(packet));
    packet.magic = NESTED_MAGIC;
    packet.type = NESTED_COMMAND;
    packet.request = command.request;
    packet.flags = command.flags;
    packet.pid = (int32_t)command.pid;
    packet.error = (int32_t)command.error;
    packet.addr = command.addr;
    packet.data = command.data;
    packet.length = command.length;
    packet.value = command.value;
    packet.payload_len = command.payload_len;
    memcpy(packet.payload, command.payload, packet.payload_len);
    event_trace_log("[ida-vtdbg-shim] owner mailbox claim seq=%llu req=%u child=%u flags=0x%x\n",
                    (unsigned long long)command.sequence, command.request,
                    command.pid, command.flags);
    (void)nested_execute_command(&packet, &response, defer_resume,
                                 release_wait);
    event_trace_log("[ida-vtdbg-shim] owner mailbox executed seq=%llu req=%u result=%d error=%d\n",
                    (unsigned long long)command.sequence, command.request,
                    response.status, response.error);
    if (parent_owned_mode && response.status == 0 &&
        !(command.flags & (PARENT_OWNED_COMMAND_F_PROTOCOL_ACK |
                           PARENT_OWNED_COMMAND_F_STEP_OBSERVE |
                           PARENT_OWNED_COMMAND_F_EXCEPTION_OBSERVE)) &&
        (command.request == PTRACE_CONT ||
         command.request == PTRACE_SYSCALL ||
         command.request == PTRACE_SINGLESTEP))
        parent_owned_set_resume_request((pid_t)command.pid, command.request);
    command.result = response.status;
    command.error = (uint32_t)response.error;
    command.value = response.value;
    command.payload_len = response.payload_len;
    if (command.payload_len > IDA_VTDBG_COMMAND_PAYLOAD_MAX)
        command.payload_len = IDA_VTDBG_COMMAND_PAYLOAD_MAX;
    memcpy(command.payload, response.payload, command.payload_len);
    if (ioctl(fd, IDA_VTDBG_IOC_COMPLETE_COMMAND, &command) < 0) {
        if (errno == EALREADY &&
            (command.flags & IDA_VTDBG_COMMAND_F_NATIVE_RESUME) != 0)
            return 1; /* real syscall return already completed this sequence */
        trace_log("[ida-vtdbg-shim] driver complete command failed errno=%d (%s)\n",
                  errno, strerror(errno));
        return -errno;
    }
    trace_log("[ida-vtdbg-shim] driver command serviced req=%u child=%u result=%lld\n",
              command.request, command.pid, (long long)command.result);
    return 1;
}

static bool nested_resume_request(enum __ptrace_request request)
{
    if (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
        request == PTRACE_SINGLESTEP)
        return true;
#ifdef PTRACE_SYSEMU
    if (request == PTRACE_SYSEMU)
        return true;
#endif
#ifdef PTRACE_SYSEMU_SINGLESTEP
    if (request == PTRACE_SYSEMU_SINGLESTEP)
        return true;
#endif
    return false;
}

static long nested_execute_command(const struct nested_packet *command,
                                   struct nested_packet *response,
                                   bool defer_resume, bool *release_wait)
{
    enum __ptrace_request request =
        (enum __ptrace_request)command->request;
    void *addr = (void *)(uintptr_t)command->addr;
    void *data = (void *)(uintptr_t)command->data;
    struct user_regs_struct regs;
    siginfo_t info;
    struct iovec local_iov;
    pid_t owner_tid = parent_owned_get_owner_tid((pid_t)command->pid);
    long peek_value = 0;
    long result;

    memset(response, 0, sizeof(*response));
    response->magic = NESTED_MAGIC;
    response->type = NESTED_RESPONSE;
    response->request = command->request;
    response->pid = command->pid;
    response->error = 0;
    if (release_wait != NULL)
        *release_wait = false;
    if (parent_owned_mode && nested_target &&
        (command->flags & PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS) != 0) {
        if (command->payload_len > NESTED_PAYLOAD_MAX ||
            command->payload_len % sizeof(struct nested_debugger_bp_metadata) != 0) {
            response->status = -1;
            response->error = EINVAL;
            return -1;
        }
        if ((command->flags & PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS_FIRST) != 0) {
            pthread_mutex_lock(&nested_event_lock);
            memset(nested_user_breakpoints, 0, sizeof(nested_user_breakpoints));
            pthread_mutex_unlock(&nested_event_lock);
        }
        for (size_t n = 0; n < command->payload_len;
             n += sizeof(struct nested_debugger_bp_metadata)) {
            struct nested_debugger_bp_metadata meta;
            memcpy(&meta, command->payload + n, sizeof(meta));
            if (meta.address != 0)
                nested_breakpoint_record(meta.address, meta.original);
        }
        if (command->request == PARENT_OWNED_COMMAND_SYNC_BREAKPOINTS) {
            /* Metadata has no native ptrace side effect. In particular do
             * not issue a gratuitous GETREGS through the parent's libc:
             * the user's parent BP may be at that syscall's return PC. */
            response->status = 0;
            return 0;
        }
    }
    if (parent_owned_mode && nested_target && nested_resume_request(request)) {
        if ((command->flags & PARENT_OWNED_COMMAND_F_GENERIC_HW_STEP) != 0 &&
            command->length != 0)
            nested_generic_hw_step_start(getpid(), command->pid,
                                         (uintptr_t)command->length);
        else if ((command->flags & PARENT_OWNED_COMMAND_F_CANCEL_CALL_OVER) != 0)
            nested_generic_hw_step_clear(command->pid);
    }
    if (parent_owned_mode &&
        (command->flags & PARENT_OWNED_COMMAND_F_PROTOCOL_ACK)) {
        /* F9 on an observed program INT3 releases the ORIGINAL wait status
         * to the real parent, rather than directly continuing the child past
         * the protocol. Restore only IDA's one-byte RIP rewind, if present. */
        uintptr_t post_int3 = (uintptr_t)command->value;
        if (post_int3 != 0) {
            result = ptrace_via_owner(owner_tid, PTRACE_GETREGS,
                                      command->pid, NULL, &regs);
            if (result == 0 && regs.rip == post_int3 - 1u) {
                regs.rip = post_int3;
                result = ptrace_via_owner(owner_tid, PTRACE_SETREGS,
                                          command->pid, NULL, &regs);
            }
            if (result < 0) {
                response->status = (int32_t)result;
                response->error = errno;
                return result;
            }
        }
        parent_owned_set_protocol_request(command->pid);
        event_trace_log("[ida-vtdbg-shim] F9 releases original program stop to parent child=%d post_int3=0x%llx\n",
                        command->pid, (unsigned long long)post_int3);
        response->status = 0;
        return 0;
    }
    if (parent_owned_mode && nested_target &&
        (command->flags & (PARENT_OWNED_COMMAND_F_STEP_OBSERVE |
                           PARENT_OWNED_COMMAND_F_EXCEPTION_OBSERVE))) {
        bool exception_observe =
            (command->flags & PARENT_OWNED_COMMAND_F_EXCEPTION_OBSERVE) != 0;
        uintptr_t resume_address = (uintptr_t)command->value;

        /* linux_server rewinds an INT3's RIP to the trap byte before
         * presenting the breakpoint to IDA.  The parent VM must receive the
         * architectural post-INT3 RIP, otherwise it handles a stop whose
         * register state IDA has already altered. */
        if (resume_address > 0) {
            memset(&regs, 0, sizeof(regs));
            result = ptrace_raw(PTRACE_GETREGS, command->pid, NULL, &regs);
            if (result < 0) {
                response->status = (int32_t)result;
                response->error = errno;
                event_trace_log("[ida-vtdbg-shim] target protocol-step RIP normalize GETREGS failed child=%d resume=0x%llx errno=%d\n",
                                command->pid,
                                (unsigned long long)resume_address, errno);
                return result;
            }
            if (regs.rip == resume_address - 1u) {
                uint64_t reported_rip = regs.rip;

                regs.rip = resume_address;
                result = ptrace_raw(PTRACE_SETREGS, command->pid, NULL,
                                    &regs);
                if (result < 0) {
                    response->status = (int32_t)result;
                    response->error = errno;
                    event_trace_log("[ida-vtdbg-shim] target protocol-step RIP normalize SETREGS failed child=%d from=0x%llx to=0x%llx errno=%d\n",
                                    command->pid,
                                    (unsigned long long)reported_rip,
                                    (unsigned long long)resume_address,
                                    errno);
                    return result;
                }
                event_trace_log("[ida-vtdbg-shim] target protocol-step normalized IDA-rewound RIP child=%d from=0x%llx to=0x%llx\n",
                                command->pid,
                                (unsigned long long)reported_rip,
                                (unsigned long long)resume_address);
            } else {
                event_trace_log("[ida-vtdbg-shim] target protocol-step preserved RIP child=%d rip=0x%llx expected=0x%llx\n",
                                command->pid,
                                (unsigned long long)regs.rip,
                                (unsigned long long)resume_address);
            }
        }
        bool hardware_step =
            (command->flags & PARENT_OWNED_COMMAND_F_HARDWARE_STEP) != 0;
        uintptr_t stale_protocol_address =
            (command->flags & PARENT_OWNED_COMMAND_F_STALE_PROTOCOL_RIP) != 0
                ? (uintptr_t)command->addr
                : 0;
        nested_target_request_protocol_step(command->pid,
                                             stale_protocol_address);
        /* The child is still stopped at the program's real protocol INT3.
         * Let the parent's VM receive and process that stop.  The optional
         * resume_address carries the post-INT3 PC that linux_server may have
         * hidden by rewinding RIP for IDA's breakpoint display. */
        if (hardware_step) {
            /* This command came from a synthetic TRAP_TRACE immediately
             * before the target's own INT3.  Resume the target child with
             * CONT so the real parent VM consumes that INT3. */
            if (defer_resume) {
                parent_owned_set_resume_request(command->pid, PTRACE_CONT);
            } else {
                result = ptrace_via_owner(owner_tid, PTRACE_CONT,
                                          command->pid, NULL, NULL);
                if (result < 0) {
                    response->status = (int32_t)result;
                    response->error = errno;
                    return result;
                }
                parent_owned_set_resume_request(command->pid, PTRACE_CONT);
            }
        } else {
            /* For a genuine protocol stop, release the parent's wait hook;
             * it owns the INT3 and chooses the next child RIP. */
            parent_owned_set_protocol_request(command->pid);
        }
        event_trace_log("[ida-vtdbg-shim] target observe command process=%d child=%d defer=%d release=%d exception=%d\n",
                        getpid(), command->pid, defer_resume ? 1 : 0,
                        release_wait != NULL ? 1 : 0,
                        exception_observe ? 1 : 0);
        if (exception_observe) {
            /* Consume the original program-owned exception before releasing
             * the real parent.  The first child stop after SETREGS is then
             * tagged as the resume observation instead of being classified as
             * the same SIGSEGV/SIGILL again. */
            parent_owned_clear_program_exception(command->pid);
            parent_owned_set_exception_resume(command->pid, true, 0);
        }
        response->status = 0;
        if (release_wait != NULL)
            *release_wait = true;
        event_trace_log("[ida-vtdbg-shim] target %s-observe command accepted child=%d\n",
                        exception_observe ? "exception" : "protocol",
                        command->pid);
        return 0;
    }
    if (parent_owned_mode && defer_resume &&
        request == PTRACE_SINGLESTEP &&
        !nested_target_protocol_step_pending(command->pid)) {
        parent_owned_request_step_after_protocol(command->pid);
        response->status = 0;
        if (release_wait != NULL)
            *release_wait = true;
        return 0;
    }
    if (defer_resume && nested_resume_request(request)) {
        /* The target's real tracer owns the child.  A resume request from
         * IDA is an acknowledgement that the target may leave its wait stop;
         * executing PTRACE_CONT here would race the target's own VM/tracer
         * state machine. */
        response->flags |= 1u;
        response->status = 0;
        if (parent_owned_mode &&
            (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
             request == PTRACE_SINGLESTEP))
            parent_owned_set_resume_request(command->pid, request);
        if (release_wait != NULL)
            *release_wait = true;
        return 0;
    }
    if (request == PTRACE_GETREGS) {
        result = ptrace_via_owner(owner_tid, request,
                                  command->pid, NULL, &regs);
        if (result == 0) {
            memcpy(response->payload, &regs, sizeof(regs));
            response->payload_len = sizeof(regs);
        }
    } else if (request == PTRACE_SETREGS) {
        if (command->payload_len != sizeof(regs)) {
            errno = EINVAL;
            result = -1;
        } else {
            memcpy(&regs, command->payload, sizeof(regs));
            if (parent_owned_mode &&
                parent_owned_get_program_exception(command->pid, NULL, NULL,
                                                   NULL)) {
                parent_owned_set_exception_resume(command->pid, true,
                                                  (uintptr_t)regs.rip);
                event_trace_log("[ida-vtdbg-shim] parent VM SETREGS exception resume child=%d rip=0x%llx\n",
                                command->pid,
                                (unsigned long long)regs.rip);
            }
            result = ptrace_via_owner(owner_tid, request,
                                      command->pid, NULL, &regs);
        }
    } else if (request == PTRACE_GETSIGINFO) {
        result = ptrace_via_owner(owner_tid, request,
                                  command->pid, NULL, &info);
        if (result == 0) {
            memcpy(response->payload, &info, sizeof(info));
            response->payload_len = sizeof(info);
        }
    } else if (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) {
        memset(&local_iov, 0, sizeof(local_iov));
        local_iov.iov_len = command->length > NESTED_PAYLOAD_MAX
                                ? NESTED_PAYLOAD_MAX
                                : (size_t)command->length;
        local_iov.iov_base = response->payload;
        if (request == PTRACE_SETREGSET) {
            if (command->payload_len > NESTED_PAYLOAD_MAX) {
                errno = EINVAL;
                result = -1;
            } else {
                memcpy(response->payload, command->payload,
                       command->payload_len);
                local_iov.iov_len = command->payload_len;
                result = ptrace_via_owner(owner_tid, request,
                                          command->pid, addr, &local_iov);
            }
        } else {
            result = ptrace_via_owner(owner_tid, request,
                                      command->pid, addr, &local_iov);
            if (result == 0)
                response->payload_len = (uint32_t)local_iov.iov_len;
        }
    } else if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT ||
               request == PTRACE_PEEKUSER) {
        errno = 0;
        result = ptrace_via_owner(owner_tid, request,
                                  command->pid, addr, &peek_value);
        if (result == 0)
            response->value = (uint64_t)peek_value;
    } else if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT ||
               request == PTRACE_POKEUSER) {
        const uintptr_t dr0_offset = offsetof(struct user, u_debugreg[0]);
        const uintptr_t dr7_offset = offsetof(struct user, u_debugreg[7]);
        struct nested_breakpoint_write target_write;
        uintptr_t before = 0;
        memset(&target_write, 0, sizeof(target_write));
        data = (void *)(uintptr_t)command->value;
        if (request == PTRACE_POKEUSER && command->value == 0 &&
            ((uintptr_t)addr == dr0_offset || (uintptr_t)addr == dr7_offset))
            nested_generic_hw_step_clear(command->pid);
        if (parent_owned_mode && nested_target &&
            (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
            ptrace_via_owner(owner_tid, PTRACE_PEEKDATA, command->pid,
                             addr, &before) == 0) {
            target_write.pid = command->pid;
            target_write.address = (uintptr_t)addr;
            target_write.before = before;
            target_write.after = (uintptr_t)command->value;
            target_write.valid = true;
        }
        result = ptrace_via_owner(owner_tid, request,
                                  command->pid, addr, data);
        if (result == 0 &&
            (command->flags & PARENT_OWNED_COMMAND_F_DEBUGGER_WRITE) != 0 &&
            command->payload_len == sizeof(struct nested_debugger_write_metadata)) {
            struct nested_debugger_write_metadata metadata;
            memcpy(&metadata, command->payload, sizeof(metadata));
            for (size_t n = 0; n < sizeof(uintptr_t); ++n)
                if ((metadata.recorded_mask & (1u << n)) != 0)
                    nested_breakpoint_record((uintptr_t)addr + n, metadata.original[n]);
        }
        /* This operation originated in the server mailbox, not the target's
         * own tracer. Mirror debugger provenance into that tracer's process
         * before recording its next physical stop. Fork/exec leaves the two
         * shims with separate tables; opcode CC alone is not provenance. */
        if (result == 0 && target_write.valid)
            nested_breakpoint_write_commit(&target_write);
        if (result == 0 && nested_target && !nested_target_launcher &&
            (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
            target_oneshot_restore_word(addr, data)) {
            target_oneshot_overlay_enabled = true;
            event_trace_log("[ida-vtdbg-shim] target one-shot overlay armed child=%d addr=0x%llx\n",
                            command->pid,
                            (unsigned long long)oneshot_algorithm_address);
        }
    } else if (request == PTRACE_GETEVENTMSG) {
        unsigned long message = 0;
        result = ptrace_via_owner(owner_tid, request,
                                  command->pid, NULL, &message);
        response->value = message;
    } else {
        result = ptrace_via_owner(owner_tid, request,
                                  command->pid, addr, data);
    }
    response->status = (int32_t)result;
    response->error = result < 0 ? errno : 0;
    return result;
}

static void nested_record_fork(pid_t child)
{
    if (!nested_target || child <= 0 || nested_conn_fd < 0)
        return;
    nested_target_child_pid = child;
    nested_target_owner_tid = current_tid();
    nested_target_send_event(NESTED_EVENT_FORK, getpid(), child, 0);
}

/* Service one command while the real tracer is stopped in wait().  Keeping
 * this on the tracer's owner thread is intentional: Linux associates the
 * ptrace relationship with the thread that performs the operation, and a
 * helper pthread would create an extra PTRACE_EVENT_CLONE stop visible to
 * linux_server. */
static int nested_target_service_command(bool defer_resume, bool *release_wait)
{
    struct nested_packet command;
    struct nested_packet response;
    ssize_t received;
    int saved_errno;
    bool release = false;

    if (release_wait != NULL)
        *release_wait = false;
    if (!nested_target || nested_conn_fd < 0)
        return -1;

    pthread_mutex_lock(&nested_io_lock);
    received = recv(nested_conn_fd, &command, sizeof(command), MSG_DONTWAIT);
    saved_errno = errno;
    pthread_mutex_unlock(&nested_io_lock);
    if (received < 0 && (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK))
        return 0;
    if (received == 0) {
        close(nested_conn_fd);
        nested_conn_fd = -1;
        return -1;
    }
    if (received < 0) {
        close(nested_conn_fd);
        nested_conn_fd = -1;
        errno = saved_errno;
        return -1;
    }
    if ((size_t)received != sizeof(command) ||
        command.magic != NESTED_MAGIC) {
        errno = EPROTO;
        return 1;
    }
    if (command.type != NESTED_COMMAND)
        return 1;

    (void)nested_execute_command(&command, &response, defer_resume, &release);
    if (!nested_send_packet(&response)) {
        close(nested_conn_fd);
        nested_conn_fd = -1;
        return -1;
    }
    if (release_wait != NULL)
        *release_wait = release;
    return 1;
}

static long nested_driver_sync_breakpoint_provenance(pid_t child)
{
    struct nested_debugger_bp_metadata metadata[NESTED_BREAKPOINT_MAX];
    size_t count = 0;
    if (nested_syncing_breakpoint_provenance || child <= 0)
        return 0;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_BREAKPOINT_MAX; ++n)
        if (nested_user_breakpoints[n].active &&
            !nested_user_breakpoints[n].suppressed) {
            memset(&metadata[count], 0, sizeof(metadata[count]));
            metadata[count].address = nested_user_breakpoints[n].address;
            metadata[count++].original = nested_user_breakpoints[n].original_byte;
        }
    pthread_mutex_unlock(&nested_event_lock);
    nested_syncing_breakpoint_provenance = true;
    for (size_t offset = 0; offset < count || offset == 0;) {
        size_t items = count - offset;
        const size_t capacity = sizeof(nested_sync_breakpoint_payload) / sizeof(metadata[0]);
        if (items > capacity) items = capacity;
        nested_sync_breakpoint_flags = PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS;
        if (offset == 0)
            nested_sync_breakpoint_flags |= PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS_FIRST;
        nested_sync_breakpoint_length = items * sizeof(metadata[0]);
        memcpy(nested_sync_breakpoint_payload, metadata + offset,
               nested_sync_breakpoint_length);
        long result = nested_driver_forward_ptrace(
            (enum __ptrace_request)PARENT_OWNED_COMMAND_SYNC_BREAKPOINTS,
            child, NULL, NULL);
        if (result < 0) {
            nested_syncing_breakpoint_provenance = false;
            return -1;
        }
        offset += items;
        if (items == 0) break;
    }
    nested_syncing_breakpoint_provenance = false;
    return 0;
}

static bool nested_kernel_child_stopped(pid_t child)
{
    if (!nested_server || !parent_owned_mode || nested_server_outer_pid <= 0 ||
        child <= 0)
        return false;
    int fd = ensure_policy_fd();
    struct ida_vtdbg_ptrace_command query = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)nested_server_outer_pid,
        .pid = (uint32_t)child,
        .request = IDA_VTDBG_NESTED_QUERY_STOP,
    };
    int saved_errno = errno;
    bool stopped = fd >= 0 &&
        ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &query) == 0 && query.result == 1;
    errno = saved_errno;
    return stopped;
}

/* The stock backend accepts a resume action and subsequently requests its
 * event. Keep those phases separate even when the real owner hits a user BP.
 * The driver still owns each mailbox sequence and actual syscall result;
 * this queue only adapts IDA's asynchronous action/event interface. */
static void nested_async_capture_metadata(struct nested_async_resume *pending)
{
    pending->metadata_count = pending->metadata_offset = 0;
    pthread_mutex_lock(&nested_event_lock);
    for (size_t n = 0; n < NESTED_BREAKPOINT_MAX; ++n)
        if (nested_user_breakpoints[n].active && !nested_user_breakpoints[n].suppressed) {
            struct nested_debugger_bp_metadata *meta =
                &pending->metadata[pending->metadata_count++];
            memset(meta, 0, sizeof(*meta));
            meta->address = nested_user_breakpoints[n].address;
            meta->original = nested_user_breakpoints[n].original_byte;
        }
    pending->metadata_revision = atomic_load_explicit(&nested_breakpoint_revision,
                                                     memory_order_acquire);
    pthread_mutex_unlock(&nested_event_lock);
    pending->captured = true;
}

static void nested_async_resume_pump(void)
{
    if (!nested_server || !parent_owned_mode ||
        pthread_mutex_trylock(&nested_driver_command_lock) != 0)
        return;
    pthread_mutex_lock(&nested_async_lock);
    int fd = ensure_policy_fd();
    /* Work is bounded by queue/table sizes, not elapsed-time guesses. An
     * incomplete kernel sequence immediately returns to native wait/events. */
    for (size_t work = 0; fd >= 0 && nested_async_count != 0 &&
                           work < NESTED_QUEUE_MAX; ++work) {
        struct nested_async_resume *pending = nested_async_resumes[0];
        struct ida_vtdbg_ptrace_command *wire = &pending->inflight;
        if (pending->submitted) {
            if (!pending->local_failure && ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, wire) < 0) {
                if (errno == EAGAIN) break;
                wire->result = -1;
                wire->error = (uint32_t)errno;
            }
            pending->submitted = false;
            event_trace_log("[ida-vtdbg-shim] async driver result seq=%llu req=%u child=%u result=%lld error=%u\n",
                (unsigned long long)wire->sequence, wire->request, wire->pid,
                (long long)wire->result, wire->error);
            if (wire->result < 0 || pending->action_submitted) {
                if (wire->result < 0) {
                    /* Never manufacture STEP or silently pass an execution
                     * error. Preserve the actual child stop for inspection. */
                    handler_trace_log("[ida-vtdbg-shim] debugger-resume-failed child=%u req=%u errno=%u\n",
                        pending->action.pid, pending->action.request, wire->error);
                    pthread_mutex_lock(&nested_event_lock);
                    if (nested_event_count < NESTED_QUEUE_MAX) {
                        nested_events[nested_event_count++] = (struct nested_queued_event){
                            .pid = (pid_t)pending->action.pid,
                            .status = (SIGSTOP << 8) | 0x7f,
                        };
                    }
                    pthread_mutex_unlock(&nested_event_lock);
                }
                free(pending);
                memmove(nested_async_resumes, nested_async_resumes + 1,
                        (--nested_async_count) * sizeof(nested_async_resumes[0]));
                continue;
            }
        }
        if (!pending->captured) nested_async_capture_metadata(pending);
        memset(wire, 0, sizeof(*wire));
        wire->abi = IDA_VTDBG_POLICY_ABI;
        wire->target_pid = pending->action.target_pid;
        wire->pid = pending->action.pid;
        if (pending->metadata_offset <= pending->metadata_count) {
            size_t remaining = pending->metadata_count - pending->metadata_offset;
            size_t capacity = sizeof(wire->payload) / sizeof(pending->metadata[0]);
            size_t count = remaining < capacity ? remaining : capacity;
            wire->request = PARENT_OWNED_COMMAND_SYNC_BREAKPOINTS;
            wire->flags = PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS |
                (pending->metadata_offset == 0 ? PARENT_OWNED_COMMAND_F_SYNC_BREAKPOINTS_FIRST : 0);
            wire->payload_len = (uint32_t)(count * sizeof(pending->metadata[0]));
            memcpy(wire->payload, pending->metadata + pending->metadata_offset, wire->payload_len);
        } else {
            if (pending->metadata_revision != atomic_load_explicit(&nested_breakpoint_revision,
                                                                   memory_order_acquire)) {
                nested_async_capture_metadata(pending);
                continue; /* F2 was changed while the owner was stopped */
            }
            *wire = pending->action;
        }
        if (ioctl(fd, IDA_VTDBG_IOC_SUBMIT_COMMAND, wire) < 0) {
            if (errno == EBUSY) break;
            wire->result = -1;
            wire->error = (uint32_t)errno;
            /* Handle it as a confirmed driver failure on the next pass. */
            pending->action_submitted = true;
            pending->submitted = true;
            pending->local_failure = true; /* no kernel sequence was created */
            break;
        }
        pending->submitted = true;
        pending->action_submitted = wire->request != PARENT_OWNED_COMMAND_SYNC_BREAKPOINTS;
        if (!pending->action_submitted) {
            size_t count = wire->payload_len / sizeof(pending->metadata[0]);
            pending->metadata_offset += count;
            if (pending->metadata_offset == pending->metadata_count)
                ++pending->metadata_offset; /* includes the empty-table ACK */
        }
        event_trace_log("[ida-vtdbg-shim] async driver submit seq=%llu req=%u child=%u flags=0x%x\n",
            (unsigned long long)wire->sequence, wire->request, wire->pid, wire->flags);
        break;
    }
    pthread_mutex_unlock(&nested_async_lock);
    pthread_mutex_unlock(&nested_driver_command_lock);
}

static long nested_async_resume_enqueue(const struct ida_vtdbg_ptrace_command *action)
{
    struct nested_async_resume *pending = calloc(1, sizeof(*pending));
    if (pending == NULL) { errno = ENOMEM; return -1; }
    pending->action = *action;
    pthread_mutex_lock(&nested_async_lock);
    if (nested_async_count == NESTED_QUEUE_MAX) {
        pthread_mutex_unlock(&nested_async_lock);
        free(pending);
        errno = EBUSY;
        return -1;
    }
    for (size_t n = 0; n < nested_async_count; ++n)
        if (nested_async_resumes[n]->action.pid == action->pid) {
            bool duplicate = nested_async_resumes[n]->action.request == action->request &&
                nested_async_resumes[n]->action.flags == action->flags;
            pthread_mutex_unlock(&nested_async_lock);
            free(pending);
            errno = duplicate ? 0 : EBUSY;
            return duplicate ? 0 : -1;
        }
    nested_async_resumes[nested_async_count++] = pending;
    pthread_mutex_lock(&nested_event_lock);
    struct parent_owned_child_state *state = parent_owned_child_locked((pid_t)action->pid, true);
    nested_event_audit_locked(5, (pid_t)action->pid, (int)action->request,
                              action->flags, 0, 0);
    if (state != NULL) {
        state->debugger_resume_accepted = true;
        /* Consume the OLD stop atomically with accepting its action. No
         * completion callback may erase the source of a newly arrived stop. */
        /* Keep immutable provenance until the next physical sequence. Native
         * thaw can repeat CONT for this already-accepted action before a new
         * STOP arrives; it must not reclassify the old, rewound RIP either. */
        state->initial_stop_visible = false;
        state->oneshot_visible = false;
        state->synthetic_step_stop = false;
        state->synthetic_trace_stop = false;
        state->synthetic_step_address = 0;
        state->protocol_int3_stop = false;
        state->protocol_int3_address = 0;
        state->program_exception_stop = false;
        state->program_exception_signal = state->program_exception_code = 0;
        state->program_exception_rip = 0;
    }
    pthread_mutex_unlock(&nested_event_lock);
    pthread_mutex_unlock(&nested_async_lock);
    /* Consume the previous presentation at action acceptance, before the
     * owner can generate the next event. Completion may arrive after that
     * new stop; clearing tags there would erase the NEW stop's provenance. */
    event_trace_log("[ida-vtdbg-shim] debugger resume queued child=%u req=%u flags=0x%x (execution completion remains kernel-owned)\n",
        action->pid, action->request, action->flags);
    nested_async_resume_pump();
    return 0;
}

static bool nested_kernel_bridge_request_allowed(enum __ptrace_request request)
{
    switch (request) {
    case PTRACE_GETREGS: case PTRACE_SETREGS:
    case PTRACE_GETFPREGS: case PTRACE_SETFPREGS:
    case PTRACE_GETREGSET: case PTRACE_SETREGSET:
    case PTRACE_GETSIGINFO: case PTRACE_SETSIGINFO:
    case PTRACE_GETEVENTMSG:
    case PTRACE_PEEKDATA: case PTRACE_PEEKTEXT: case PTRACE_PEEKUSER:
    case PTRACE_POKEDATA: case PTRACE_POKETEXT: case PTRACE_POKEUSER:
        return true;
    default:
        return false;
    }
}

/* Transport-independent presentation: the saved native state is unchanged
 * unless an explicitly tagged observer stop requires the IDA view. Both the
 * stopped-state ioctl and the owner mailbox must apply the same mapping. */
static void nested_present_stop(enum __ptrace_request request, pid_t child,
                                void *addr, void *data)
{
    uintptr_t synthetic_address = 0, protocol_address = 0;
    bool synthetic = parent_owned_get_synthetic_step_stop(child, &synthetic_address);
    bool protocol = parent_owned_get_protocol_int3_stop(child, &protocol_address);
    struct user_regs_struct *regs = NULL;
    if (data == NULL) return;
    if (request == PTRACE_GETREGS) regs = data;
    else if (request == PTRACE_GETREGSET && (uintptr_t)addr == 1u) {
        struct iovec *iov = data;
        if (iov->iov_base != NULL && iov->iov_len >= sizeof(*regs))
            regs = iov->iov_base;
    }
    if (regs != NULL && synthetic && synthetic_address != 0 &&
        !parent_owned_synthetic_is_trace(child) && regs->rip == synthetic_address + 1u)
        regs->rip = synthetic_address;
    if (request == PTRACE_GETSIGINFO && (synthetic || protocol)) {
        siginfo_t *info = data;
        info->si_signo = SIGTRAP;
        info->si_code = synthetic ? TRAP_TRACE : TRAP_BRKPT;
        if (synthetic_address != 0 || protocol)
            info->si_addr = (void *)(synthetic ? synthetic_address : protocol_address);
    }
}

static bool nested_kernel_stopped_ptrace(enum __ptrace_request request,
                                        pid_t child, void *addr, void *data,
                                        long *result)
{
    if (!nested_server || !parent_owned_mode || !nested_is_shadow(child) ||
        nested_syncing_breakpoint_provenance ||
        !nested_kernel_bridge_request_allowed(request))
        return false;
    struct ida_vtdbg_ptrace_command command = {
        .abi = IDA_VTDBG_POLICY_ABI,
        .target_pid = (uint32_t)nested_server_outer_pid,
        .pid = (uint32_t)child,
        .request = (uint32_t)request,
        .addr = (uint64_t)(uintptr_t)addr,
        .data = (uint64_t)(uintptr_t)data,
        .value = (uint64_t)(uintptr_t)data,
    };
    int fd = ensure_policy_fd();
    if (fd < 0) { *result = -1; return true; }
    if (ioctl(fd, IDA_VTDBG_IOC_NESTED_STOPPED_PTRACE, &command) < 0) {
        if (errno == ENOTTY)
            return false;
        *result = -1;
        return true;
    }
    if (command.result == -EOPNOTSUPP) {
        /* An unsupported synchronous query/write cannot be serviced by an
         * owner that IDA has stopped. Do not turn that rejection into an
         * unbounded WAIT_SUBMIT_COMMAND against the same stopped task. */
        if (atomic_load_explicit(&nested_parent_real_stopped,
                                 memory_order_acquire)) {
            *result = -1;
            errno = EBUSY;
            return true;
        }
        return false;
    }
    bool peek = request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT || request == PTRACE_PEEKUSER;
    *result = command.result < 0 ? -1 : peek ? (long)command.value : (long)command.result;
    errno = command.result < 0 ? (int)command.error : 0;
    event_trace_log("[ida-vtdbg-shim] kernel stopped-owner child query request=%d root=%d child=%d result=%ld\n",
                    request, nested_server_outer_pid, child, *result);
    return true;
}

static long nested_driver_forward_ptrace(enum __ptrace_request request,
                                         pid_t pid, void *addr, void *data)
{
    struct ida_vtdbg_ptrace_command command;
    struct iovec *server_iov = NULL;
    struct nested_breakpoint_write breakpoint_write;
    uintptr_t temporary_address = 0;
    pid_t command_pid = pid;
    bool synthetic_resume;
    bool protocol_hw_step = false;
    bool generic_hw_step = false;
    bool hardware_step_protocol = false;
    enum __ptrace_request wire_request = request;
    int fd;

    if (!parent_owned_mode || (!nested_event_worker && !nested_server)) {
        errno = ESRCH;
        return -1;
    }
    bool exited = false;
    bool resume_accepted = false;
    pthread_mutex_lock(&nested_event_lock);
    struct parent_owned_child_state *exit_state = parent_owned_child_locked(pid, false);
    exited = exit_state != NULL && exit_state->exit_event_queued;
    resume_accepted = exit_state != NULL && exit_state->debugger_resume_accepted;
    pthread_mutex_unlock(&nested_event_lock);
    if (nested_server && resume_accepted && nested_resume_request(request)) {
        /* Native thaw repeats the child's mode when a real parent BP is
         * resumed. Until IDA PRESENTS a new child STOP, that is the same
         * action, not a second F8. An arrived/queued native status is not
         * permission to step while the UI is still presenting its parent. */
        return 0;
    }
    if (exited) {
        /* A lifecycle tombstone is authoritative. Never submit a dead
         * child's GETREGS/PEEK/POKE into its stopped parent's mailbox. */
        if (request == PTRACE_CONT || request == PTRACE_KILL ||
            request == PTRACE_DETACH || request == PTRACE_POKEDATA ||
            request == PTRACE_POKETEXT || request == PTRACE_POKEUSER)
            return 0;
        errno = ESRCH;
        return -1;
    }
    if (nested_worker_event_fd < 0) {
        if (nested_server && policy_fd >= 0)
            nested_worker_event_fd = dup(policy_fd);
        else
            nested_worker_event_fd =
                open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    }
    fd = nested_worker_event_fd;
    if (fd < 0)
        return -1;
    if (request == PTRACE_POKEUSER &&
        nested_protocol_hw_step_write(pid, (uintptr_t)addr,
                                      (uintptr_t)data))
        return 0;
    /* IDA replays the root process's software breakpoints onto the synthetic
     * child immediately after the initial fork/stop event.  The real target
     * parent is still parked in its initial wait hook at that point, so a
     * physical POKEDATA would block the mailbox before the child is resumed.
     * The root logical breakpoint table is already authoritative; defer the
     * physical replay until the first post-handshake child stop. */
    if ((request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
        parent_owned_mode && parent_owned_initial_replay_pending(pid)) {
        event_trace_log("[ida-vtdbg-shim] defer initial-child breakpoint replay pid=%d addr=0x%llx\n",
                        pid, (unsigned long long)(uintptr_t)addr);
        return 0;
    }
    if (request == PTRACE_PEEKUSER &&
        nested_protocol_hw_step_peek(pid, (uintptr_t)addr,
                                     (uintptr_t *)&temporary_address))
        return (long)temporary_address;
    long direct_result = 0;
    memset(&breakpoint_write, 0, sizeof(breakpoint_write));
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT)
        nested_breakpoint_write_prepare(pid, addr, (uintptr_t)data, &breakpoint_write);
    if (nested_kernel_stopped_ptrace(request, pid, addr, data, &direct_result)) {
        if (direct_result == 0) {
            nested_present_stop(request, pid, addr, data);
            if (!nested_skip_breakpoint_commit)
                nested_breakpoint_write_commit(&breakpoint_write);
        }
        return direct_result;
    }
    if ((request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
        nested_protocol_hw_step_already_issued(pid)) {
        event_trace_log("[ida-vtdbg-shim] acknowledge duplicate hardware-step resume pid=%d process=%d\n",
                        pid, getpid());
        return 0;
    }
    if ((request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
        nested_protocol_hw_step_take(pid, &command_pid,
                                     &hardware_step_protocol)) {
        protocol_hw_step = hardware_step_protocol;
        generic_hw_step = !hardware_step_protocol;
        if (generic_hw_step && request == PTRACE_CONT)
            wire_request = PTRACE_SINGLESTEP;
    }
    {
        pid_t process_exit_root = nested_server_outer_pid;
        if (request == PTRACE_KILL && nested_server &&
            process_exit_root > 0 && nested_is_shadow(pid)) {
        event_trace_log("[ida-vtdbg-shim] defer shadow PTRACE_KILL child=%d to next server wait\n",
                        pid);
        parent_owned_queue_process_exit(process_exit_root, pid);
        return 0;
        }
    }
    if (request == PTRACE_KILL || request == PTRACE_DETACH)
        event_trace_log("[ida-vtdbg-shim] driver ProcessExit ptrace entry request=%d pid=%d outer=%d held=%d\n",
                        request, pid, nested_server_outer_pid,
                        parent_owned_proxy_stop_held(pid, false, false) ? 1 : 0);
    synthetic_resume =
        (request == PTRACE_SINGLESTEP || request == PTRACE_CONT) &&
        parent_owned_get_synthetic_step_stop(command_pid, NULL);
    /* The first post-exec child resume must acknowledge all debugger byte
     * provenance before it can produce any stop. No timing assumptions. */
    if (!nested_server && nested_is_shadow(command_pid) &&
        nested_resume_request(request) &&
        nested_driver_sync_breakpoint_provenance(command_pid) < 0)
        return -1;
    if (synthetic_resume)
        event_trace_log("[ida-vtdbg-shim] synthetic stop resume request=%d child=%d; route through driver mailbox, skip protocol observer\n",
                        request, command_pid);
    if (request == PTRACE_CONT || request == PTRACE_SINGLESTEP)
        event_trace_log("[ida-vtdbg-shim] driver child resume request=%d pid=%d shadow=%d held=%d\n",
                        request, command_pid,
                        nested_is_shadow(command_pid) ? 1 : 0,
                        parent_owned_proxy_stop_held(command_pid, false, false) ? 1 : 0);
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT ||
        request == PTRACE_POKEUSER)
        event_trace_log("[ida-vtdbg-shim] driver breakpoint write request=%d pid=%d addr=0x%llx value=0x%llx shadow=%d held=%d\n",
                        request, pid, (unsigned long long)(uintptr_t)addr,
                        (unsigned long long)(uintptr_t)data,
                        nested_is_shadow(pid) ? 1 : 0,
                        parent_owned_proxy_stop_held(pid, false, false) ? 1 : 0);
    memset(&command, 0, sizeof(command));
    command.abi = IDA_VTDBG_POLICY_ABI;
    command.target_pid = (uint32_t)nested_server_outer_pid;
    command.request = (uint32_t)wire_request;
    command.pid = (uint32_t)command_pid;
    command.addr = (uint64_t)(uintptr_t)addr;
    command.data = (uint64_t)(uintptr_t)data;
    if (nested_resume_request(request)) {
        uintptr_t generic_target = 0;
        if (nested_generic_hw_step_pending(command_pid, &generic_target)) {
            command.flags |= PARENT_OWNED_COMMAND_F_GENERIC_HW_STEP;
            command.length = generic_target;
        } else {
            command.flags |= PARENT_OWNED_COMMAND_F_CANCEL_CALL_OVER;
        }
        nested_ida_step_intent_clear(command_pid);
    }
    memset(&breakpoint_write, 0, sizeof(breakpoint_write));
    if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT ||
        request == PTRACE_PEEKUSER)
        command.addr = (uint64_t)(uintptr_t)addr;
    else if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT ||
             request == PTRACE_POKEUSER) {
        command.value = (uint64_t)(uintptr_t)data;
        if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT)
            nested_breakpoint_write_prepare(pid, addr, command.value,
                                            &breakpoint_write);
        if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) {
            struct nested_debugger_write_metadata metadata = {0};
            for (size_t n = 0; n < sizeof(uintptr_t); ++n)
                if (nested_breakpoint_address_recorded((uintptr_t)addr + n,
                                                       &metadata.original[n]))
                    metadata.recorded_mask |= (uint8_t)(1u << n);
            command.flags |= PARENT_OWNED_COMMAND_F_DEBUGGER_WRITE;
            command.payload_len = sizeof(metadata);
            memcpy(command.payload, &metadata, sizeof(metadata));
        }
    }
    /* Every mailbox POKE here originated in IDA. An unknown newly-inserted
     * CC is therefore debugger-owned, NOT evidence for a temporary protocol
     * observer. Install it and record its original byte; never acknowledge
     * an uninstalled F2/temporary software breakpoint. */
    if (protocol_hw_step) {
        uintptr_t protocol_target = nested_protocol_hw_step_target(pid);

        command.flags |= PARENT_OWNED_COMMAND_F_STEP_OBSERVE;
        command.flags |= PARENT_OWNED_COMMAND_F_HARDWARE_STEP;
        /* The child is stopped immediately before its real protocol INT3.
         * Do not apply linux_server's INT3-RIP rewind; let the target's parent
         * execute that opcode and capture the parent-selected resume RIP. */
        command.value = 0;
        if (protocol_target > 0) {
            /* Carry the synthetic stop's trap address to the target process.
             * The server and target have separate shim state, so the target
             * cannot recover this address from its local proxy table after
             * the server consumes the synthetic event. */
            command.flags |= PARENT_OWNED_COMMAND_F_STALE_PROTOCOL_RIP;
            command.addr = protocol_target - 1u;
            /* Keep the server-side event reader in the same state as the
             * target-side wait hook.  The event ring is read by this process,
             * so it must know to discard the already-consumed post-INT3 stop
             * while the target parent redirects the child. */
            parent_owned_set_resume_observation(command_pid, true,
                                                protocol_target,
                                                protocol_target);
        }
        event_trace_log("[ida-vtdbg-shim] virtual hardware step-over at protocol INT3 root_pid=%d child=%d\n",
                        pid, command_pid);
    } else if (generic_hw_step) {
        event_trace_log("[ida-vtdbg-shim] virtual generic hardware step pid=%d child=%d -> SINGLESTEP\n",
                        pid, command_pid);
    } else if ((!synthetic_resume || parent_owned_synthetic_is_trace(pid)) &&
               (request == PTRACE_SINGLESTEP || request == PTRACE_CONT) &&
               nested_server_at_program_int3(pid, &temporary_address)) {
        command.flags |= PARENT_OWNED_COMMAND_F_STEP_OBSERVE |
                         PARENT_OWNED_COMMAND_F_HARDWARE_STEP |
                         PARENT_OWNED_COMMAND_F_STALE_PROTOCOL_RIP;
        command.value = 0;
        command.addr = temporary_address;
        parent_owned_set_resume_observation(command_pid, true,
                                            temporary_address + 1u,
                                            temporary_address + 1u);
        handler_trace_log("[ida-vtdbg-shim] debugger-before-program-INT3 child=%d req=%u rip=0x%llx\n",
                          command_pid, request, (unsigned long long)temporary_address);
    } else if (!synthetic_resume && request == PTRACE_SINGLESTEP &&
        nested_server_should_observe_program_exception(pid)) {
        event_trace_log("[ida-vtdbg-shim] virtual program-exception single-step child=%d -> parent-resume observation\n",
                        pid);
        command.flags |= PARENT_OWNED_COMMAND_F_EXCEPTION_OBSERVE;
        command.value = 0;
    } else if (!synthetic_resume && request == PTRACE_SINGLESTEP &&
               nested_server_should_observe_parent_resume(pid,
                                                         &temporary_address)) {
        event_trace_log("[ida-vtdbg-shim] virtual protocol single-step pid=%d rip=0x%llx -> parent-resume observation\n",
                        pid, (unsigned long long)temporary_address);
        command.flags |= PARENT_OWNED_COMMAND_F_STEP_OBSERVE;
        command.value = temporary_address;
    } else if (!synthetic_resume && request == PTRACE_CONT &&
               nested_server_should_observe_parent_resume(
                    pid, &temporary_address)) {
        /* A program-owned INT3 is an input to the target parent's VM. F9
         * must release that stop to the parent; executing raw CONT here
         * skips the VM handler entirely and eventually uses uninitialized
         * locals at 0x400b2b. A logical breakpoint at the resume site retains
         * the existing step-observer behavior. */
        bool observe = nested_breakpoint_address_known(temporary_address, NULL);
        event_trace_log("[ida-vtdbg-shim] virtual protocol F9 pid=%d post_int3=0x%llx observe=%d -> real parent wait\n",
                        pid, (unsigned long long)temporary_address, observe ? 1 : 0);
        command.flags |= observe ? PARENT_OWNED_COMMAND_F_STEP_OBSERVE
                                 : PARENT_OWNED_COMMAND_F_PROTOCOL_ACK;
        command.value = temporary_address;
    }
    else if (request == PTRACE_GETREGS)
        command.length = sizeof(struct user_regs_struct);
    else if (request == PTRACE_SETREGS) {
        command.payload_len = sizeof(struct user_regs_struct);
        memcpy(command.payload, data, command.payload_len);
    } else if (request == PTRACE_GETSIGINFO) {
        command.length = sizeof(siginfo_t);
    } else if (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) {
        server_iov = (struct iovec *)data;
        if (server_iov == NULL || server_iov->iov_len > IDA_VTDBG_COMMAND_PAYLOAD_MAX) {
            errno = EINVAL;
            return -1;
        }
        command.length = server_iov->iov_len;
        if (request == PTRACE_SETREGSET) {
            command.payload_len = (uint32_t)server_iov->iov_len;
            memcpy(command.payload, server_iov->iov_base, command.payload_len);
        }
    }
    /* The driver mailbox is one-command-at-a-time per session.  Serialize all
     * IDA waiter/event-poller ptrace RPCs in this process so a concurrent
     * register read cannot collide with breakpoint replay (E_BUSY). */
    if (nested_syncing_breakpoint_provenance &&
        (uint32_t)request == PARENT_OWNED_COMMAND_SYNC_BREAKPOINTS) {
        command.flags |= nested_sync_breakpoint_flags;
        command.payload_len = (uint32_t)nested_sync_breakpoint_length;
        memcpy(command.payload, nested_sync_breakpoint_payload,
               nested_sync_breakpoint_length);
    }
    if ((wire_request == PTRACE_CONT || wire_request == PTRACE_SINGLESTEP ||
         wire_request == PTRACE_SYSCALL) &&
        (command.flags & (PARENT_OWNED_COMMAND_F_PROTOCOL_ACK |
                          PARENT_OWNED_COMMAND_F_STEP_OBSERVE |
                          PARENT_OWNED_COMMAND_F_EXCEPTION_OBSERVE)) == 0 &&
        !synthetic_resume)
        command.flags |= IDA_VTDBG_COMMAND_F_NATIVE_RESUME;
    if (nested_server && nested_resume_request(request) && !nested_syncing_breakpoint_provenance)
        return nested_async_resume_enqueue(&command);
    pthread_mutex_lock(&nested_driver_command_lock);
    if (ioctl(fd, IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND, &command) < 0) {
        trace_log("[ida-vtdbg-shim] driver submit failed target=%u child=%u req=%u fd=%d errno=%d (%s)\n",
                  command.target_pid, command.pid, command.request, fd,
                  errno, strerror(errno));
        pthread_mutex_unlock(&nested_driver_command_lock);
        return -1;
    }
    event_trace_log("[ida-vtdbg-shim] server mailbox submitted seq=%llu req=%u child=%u flags=0x%x\n",
                    (unsigned long long)command.sequence, command.request,
                    command.pid, command.flags);
    /* The mailbox parent is intentionally blocked in its own wait/ptrace
     * protocol and is not an outer ptrace-stop.  The legacy socket relay used
     * nested_server_wake_outer_target() to kick a stopped linux_server, but
     * doing that here issues PTRACE_CONT against a running parent and returns
     * ESRCH, which IDA reports as internal error 30060. */
    if (!parent_owned_mode)
        nested_server_wake_outer_target();
    bool got_response = false;
    for (unsigned int pass = 0; pass < 200000; ++pass) {
        if (ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, &command) == 0) {
            got_response = true;
            break;
        }
        if (errno != EAGAIN) {
            trace_log("[ida-vtdbg-shim] driver response failed target=%u child=%u req=%u fd=%d errno=%d (%s)\n",
                      command.target_pid, command.pid, command.request, fd,
                      errno, strerror(errno));
            pthread_mutex_unlock(&nested_driver_command_lock);
            return -1;
        }
        sched_yield();
    }
    if (!got_response) {
        event_trace_log("[ida-vtdbg-shim] server mailbox no response seq=%llu req=%u child=%u\n",
                        (unsigned long long)command.sequence, command.request, command.pid);
        errno = ETIMEDOUT;
        pthread_mutex_unlock(&nested_driver_command_lock);
        return -1;
    }
    event_trace_log("[ida-vtdbg-shim] server mailbox response seq=%llu req=%u child=%u result=%lld error=%u\n",
                    (unsigned long long)command.sequence, command.request,
                    command.pid, (long long)command.result, command.error);
    if (request == PTRACE_GETREGS &&
        command.payload_len == sizeof(struct user_regs_struct))
        memcpy(data, command.payload, command.payload_len);
    else if (request == PTRACE_GETSIGINFO &&
             command.payload_len == sizeof(siginfo_t))
        memcpy(data, command.payload, command.payload_len);
    else if (request == PTRACE_GETREGSET && server_iov != NULL) {
        size_t copy_len = command.payload_len < server_iov->iov_len
                              ? command.payload_len : server_iov->iov_len;
        memcpy(server_iov->iov_base, command.payload, copy_len);
        server_iov->iov_len = copy_len;
    }
    if (command.result < 0) {
        errno = command.error != 0 ? (int)command.error : EIO;
        if (request == PTRACE_KILL || request == PTRACE_DETACH)
            event_trace_log("[ida-vtdbg-shim] driver ProcessExit ptrace failed request=%d pid=%d result=%lld errno=%d\n",
                            request, pid, (long long)command.result, errno);
        pthread_mutex_unlock(&nested_driver_command_lock);
        return -1;
    }
    {
        uintptr_t synthetic_address = 0;
        bool synthetic_stop =
            parent_owned_get_synthetic_step_stop(pid,
                                                 &synthetic_address);
        uintptr_t protocol_address = 0;
        bool protocol_stop =
            parent_owned_get_protocol_int3_stop(pid, &protocol_address);

        if (synthetic_stop && synthetic_address != 0 &&
            request == PTRACE_GETREGS && data != NULL) {
            struct user_regs_struct *regs = data;

            if (!parent_owned_synthetic_is_trace(pid) &&
                regs->rip == synthetic_address + 1u) {
                regs->rip = synthetic_address;
                event_trace_log("[ida-vtdbg-shim] present synthetic stop RIP child=%d rip=0x%llx\n",
                                pid,
                                (unsigned long long)synthetic_address);
            }
        } else if (synthetic_stop && request == PTRACE_GETSIGINFO &&
                   data != NULL) {
            siginfo_t *info = data;

            info->si_signo = SIGTRAP;
#ifdef TRAP_TRACE
            info->si_code = TRAP_TRACE;
#else
            info->si_code = 2;
#endif
            if (synthetic_address != 0)
                info->si_addr = (void *)synthetic_address;
            event_trace_log("[ida-vtdbg-shim] present synthetic stop as TRAP_TRACE child=%d addr=0x%llx\n",
                            pid,
                            (unsigned long long)synthetic_address);
        } else if (protocol_stop && request == PTRACE_GETSIGINFO &&
                   data != NULL) {
            siginfo_t *info = data;

            /* Present this explicitly configured native protocol INT3 as a
             * debugger breakpoint, without installing an IDA-owned 0xCC.
             * That keeps F8 from trying to delete the target's own opcode. */
            info->si_signo = SIGTRAP;
#ifdef TRAP_BRKPT
            info->si_code = TRAP_BRKPT;
#else
            info->si_code = 1;
#endif
            info->si_addr = (void *)protocol_address;
            event_trace_log("[ida-vtdbg-shim] present auto protocol stop as TRAP_BRKPT child=%d addr=0x%llx\n",
                            pid, (unsigned long long)protocol_address);
        } else if (synthetic_stop && synthetic_address != 0 &&
                   request == PTRACE_GETREGSET && server_iov != NULL &&
                   (uintptr_t)addr == 1u &&
                   server_iov->iov_base != NULL &&
                   server_iov->iov_len >= sizeof(struct user_regs_struct)) {
            struct user_regs_struct *regs = server_iov->iov_base;

            if (!parent_owned_synthetic_is_trace(pid) &&
                regs->rip == synthetic_address + 1u) {
                regs->rip = synthetic_address;
                event_trace_log("[ida-vtdbg-shim] present synthetic regset RIP child=%d rip=0x%llx\n",
                                pid,
                                (unsigned long long)synthetic_address);
            }
        }
    }
    if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT ||
        request == PTRACE_PEEKUSER) {
        long peek_result = (long)command.value;
        pthread_mutex_unlock(&nested_driver_command_lock);
        errno = 0; /* successful mailbox poll must not leak earlier EAGAIN */
        return peek_result;
    }
    if (command.result == 0 && !nested_skip_breakpoint_commit)
        nested_breakpoint_write_commit(&breakpoint_write);
    if (command.result == 0 &&
        (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
         request == PTRACE_SINGLESTEP)) {
        parent_owned_set_initial_visible(command_pid, false);
        parent_owned_set_oneshot_visible(command_pid, false);
        (void)parent_owned_consume_synthetic_step_stop(command_pid);
        parent_owned_set_protocol_int3_stop(command_pid, false, 0);
        parent_owned_clear_program_exception(command_pid);
    }
    pthread_mutex_unlock(&nested_driver_command_lock);
    if (request == PTRACE_KILL || request == PTRACE_DETACH)
        event_trace_log("[ida-vtdbg-shim] driver ProcessExit ptrace complete request=%d pid=%d result=%lld\n",
                        request, pid, (long long)command.result);
    errno = 0;
    return (long)command.result;
}

static int nested_driver_protocol_ack(pid_t child)
{
    struct ida_vtdbg_ptrace_command command;
    int fd;
    bool got_response = false;

    if (!parent_owned_mode || child <= 0) {
        errno = EINVAL;
        return -1;
    }
    if (nested_worker_event_fd < 0) {
        if (nested_server && policy_fd >= 0)
            nested_worker_event_fd = dup(policy_fd);
        else
            nested_worker_event_fd =
                open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    }
    fd = nested_worker_event_fd;
    if (fd < 0)
        return -1;
    memset(&command, 0, sizeof(command));
    command.abi = IDA_VTDBG_POLICY_ABI;
    command.target_pid = (uint32_t)nested_server_outer_pid;
    command.request = PTRACE_CONT;
    command.flags = PARENT_OWNED_COMMAND_F_PROTOCOL_ACK;
    command.pid = (uint32_t)child;
    if (nested_server)
        return (int)nested_async_resume_enqueue(&command);
    pthread_mutex_lock(&nested_driver_command_lock);
    if (ioctl(fd, IDA_VTDBG_IOC_WAIT_SUBMIT_COMMAND, &command) < 0) {
        pthread_mutex_unlock(&nested_driver_command_lock);
        return -1;
    }
    for (unsigned int pass = 0; pass < 200000; ++pass) {
        if (ioctl(fd, IDA_VTDBG_IOC_GET_RESPONSE, &command) == 0) {
            got_response = true;
            break;
        }
        if (errno != EAGAIN) {
            pthread_mutex_unlock(&nested_driver_command_lock);
            return -1;
        }
        sched_yield();
    }
    if (!got_response) {
        errno = ETIMEDOUT;
        pthread_mutex_unlock(&nested_driver_command_lock);
        return -1;
    }
    if (command.result < 0) {
        errno = command.error != 0 ? (int)command.error : EIO;
        pthread_mutex_unlock(&nested_driver_command_lock);
        return -1;
    }
    pthread_mutex_unlock(&nested_driver_command_lock);
    return 0;
}

static long nested_forward_ptrace(enum __ptrace_request request, pid_t pid,
                                  void *addr, void *data)
{
    struct nested_packet command;
    struct nested_packet response;
    struct iovec *server_iov = NULL;
    long result;

    if (!nested_event_worker || nested_conn_fd < 0) {
        errno = ESRCH;
        return -1;
    }
    if (request == PTRACE_SETOPTIONS) {
        /* linux_server applies its standard thread options immediately after
         * a clone event.  The real child is already owned/configured by the
         * target's tracer, and forwarding this synchronous setup request can
         * deadlock while that tracer is stopped at the outer fork breakpoint. */
        trace_log("[ida-vtdbg-shim] nested relay virtual SETOPTIONS pid=%d\n",
                  pid);
        return 0;
    }
    memset(&command, 0, sizeof(command));
    command.magic = NESTED_MAGIC;
    command.type = NESTED_COMMAND;
    command.request = request;
    command.pid = pid;
    command.addr = (uint64_t)(uintptr_t)addr;
    command.data = (uint64_t)(uintptr_t)data;
    if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT ||
        request == PTRACE_PEEKUSER)
        command.addr = (uint64_t)(uintptr_t)addr;
    else if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT ||
             request == PTRACE_POKEUSER)
        command.value = (uint64_t)(uintptr_t)data;
    else if (request == PTRACE_GETREGS) {
        command.length = sizeof(struct user_regs_struct);
    } else if (request == PTRACE_SETREGS) {
        command.payload_len = sizeof(struct user_regs_struct);
        memcpy(command.payload, data, command.payload_len);
    } else if (request == PTRACE_GETSIGINFO) {
        command.length = sizeof(siginfo_t);
    } else if (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) {
        server_iov = (struct iovec *)data;
        if (server_iov == NULL || server_iov->iov_len > NESTED_PAYLOAD_MAX) {
            errno = EINVAL;
            return -1;
        }
        command.addr = (uint64_t)(uintptr_t)addr;
        command.length = server_iov->iov_len;
        if (request == PTRACE_SETREGSET) {
            command.payload_len = (uint32_t)server_iov->iov_len;
            memcpy(command.payload, server_iov->iov_base,
                   server_iov->iov_len);
        }
    }
    nested_server_wake_outer_target();
    trace_log("[ida-vtdbg-shim] nested relay command request=%d pid=%d\n",
              request, pid);
    pthread_mutex_lock(&nested_io_lock);
    if (!nested_write_full(nested_conn_fd, &command, sizeof(command))) {
        pthread_mutex_unlock(&nested_io_lock);
        errno = EPIPE;
        return -1;
    }
    for (;;) {
        if (!nested_read_full(nested_conn_fd, &response, sizeof(response))) {
            pthread_mutex_unlock(&nested_io_lock);
            errno = EPIPE;
            return -1;
        }
        if (response.type == NESTED_EVENT) {
            nested_consume_packet(&response);
            continue;
        }
        break;
    }
    pthread_mutex_unlock(&nested_io_lock);
    if (request == PTRACE_GETREGS && response.payload_len == sizeof(struct user_regs_struct))
        memcpy(data, response.payload, response.payload_len);
    else if (request == PTRACE_GETSIGINFO && response.payload_len == sizeof(siginfo_t))
        memcpy(data, response.payload, response.payload_len);
    else if ((request == PTRACE_GETREGSET) && server_iov != NULL) {
        size_t copy_len = response.payload_len < server_iov->iov_len
                              ? response.payload_len
                              : server_iov->iov_len;
        memcpy(server_iov->iov_base, response.payload, copy_len);
        server_iov->iov_len = copy_len;
    }
    result = response.status;
    if (result < 0)
        errno = response.error != 0 ? response.error : EIO;
    else if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT ||
             request == PTRACE_PEEKUSER)
        result = (long)response.value;
    trace_log("[ida-vtdbg-shim] nested relay response request=%d pid=%d result=%ld flags=0x%x\n",
              request, pid, result, response.flags);
    return result;
}

static void trace_parent_owned_child_stop(pid_t child, int status,
                                           const char *where)
{
    struct user_regs_struct regs;
    siginfo_t info;
    long value = 0;
    long result;

    if ((!trace_enabled && !handler_trace_enabled) || child <= 0 ||
        !WIFSTOPPED(status))
        return;
    result = ptrace_via_owner(parent_owned_get_owner_tid(child),
                              PTRACE_GETREGS,
                              child, NULL, &regs);
    if (result < 0) {
        trace_log("[ida-vtdbg-shim] child stop where=%s pid=%d status=0x%x getregs errno=%d\n",
                  where, child, (unsigned int)status, errno);
        return;
    }
    result = ptrace_via_owner(parent_owned_get_owner_tid(child),
                              PTRACE_PEEKDATA,
                              child, (void *)(uintptr_t)(regs.rip - 1),
                              &value);
    trace_log("[ida-vtdbg-shim] child stop where=%s pid=%d status=0x%x rip=0x%llx before=0x%02x peek_result=%ld\n",
              where, child, (unsigned int)status,
              (unsigned long long)regs.rip, (unsigned int)((uint8_t)value),
              result);

    if (handler_trace_enabled && regs.rip >= handler_text_start &&
        regs.rip < handler_text_end) {
        struct iovec local;
        struct iovec remote;
        uint8_t opcode = 0;
        uintptr_t trap_address = regs.rip > 0 ? (uintptr_t)regs.rip - 1u
                                              : (uintptr_t)regs.rip;
        uint8_t original = 0;
        bool recorded = nested_breakpoint_address_recorded(
            trap_address, &original);
        bool debugger_bp = recorded && original != 0xccu;
        bool program_int3 = false;
        bool debugger_synthetic = false;
        const char *origin = "other";
        int si_code = -1;

        local.iov_base = &opcode;
        local.iov_len = sizeof(opcode);
        remote.iov_base = (void *)trap_address;
        remote.iov_len = sizeof(opcode);
        if (process_vm_readv(child, &local, 1, &remote, 1, 0) ==
            (ssize_t)sizeof(opcode))
            program_int3 = opcode == 0xccu;
        memset(&info, 0, sizeof(info));
        if (ptrace_via_owner(parent_owned_get_owner_tid(child),
                             PTRACE_GETSIGINFO, child, NULL, &info) == 0)
            si_code = info.si_code;
        pthread_mutex_lock(&nested_event_lock);
        debugger_synthetic = nested_target_protocol_step.child == child &&
            ((nested_target_protocol_step.armed &&
              regs.rip == nested_target_protocol_step.address + 1u) ||
             (nested_target_protocol_step.trace_step_pending &&
              si_code == TRAP_TRACE));
        pthread_mutex_unlock(&nested_event_lock);
        if (debugger_synthetic)
            origin = "ida_synthetic_step";
        else if (debugger_bp)
            origin = "ida_software_breakpoint";
        else if (si_code == TRAP_TRACE || si_code == TRAP_HWBKPT)
            origin = "ida_single_step_or_hw";
        else if (program_int3)
            origin = "program_int3";
        else if (si_code != -1 && info.si_signo != SIGTRAP &&
                 info.si_signo != SIGSTOP && info.si_signo != SIGCHLD)
            origin = "program_exception";

        unsigned long long sequence = atomic_fetch_add_explicit(
            &handler_trace_sequence, 1, memory_order_relaxed) + 1;
        handler_trace_log(
            "[ida-vtdbg-shim] handler-stop seq=%llu where=%s child=%d status=0x%x origin=%s si_code=%d rip=0x%llx trap=0x%llx rbp=0x%llx rsp=0x%llx rax=0x%llx rbx=0x%llx rcx=0x%llx rdx=0x%llx rsi=0x%llx rdi=0x%llx opcode=0x%02x recorded=%d original=0x%02x\n",
            sequence,
            where, child, (unsigned int)status,
            origin, si_code, (unsigned long long)regs.rip,
            (unsigned long long)trap_address,
            (unsigned long long)regs.rbp, (unsigned long long)regs.rsp,
            (unsigned long long)regs.rax, (unsigned long long)regs.rbx,
            (unsigned long long)regs.rcx, (unsigned long long)regs.rdx,
            (unsigned long long)regs.rsi, (unsigned long long)regs.rdi,
            (unsigned int)opcode, recorded ? 1 : 0, (unsigned int)original);
        /* Read the stopped child's state in its REAL ptrace owner's context.
         * This records one physical wait boundary, not duplicate IDA memory
         * probes, and avoids dozens of server->driver PEEK RPCs per stop. */
        if (state_trace_enabled) {
            unsigned char frame[0x280] = {0};
            char frame_hex[sizeof(frame) * 2 + 1];
            uintptr_t frame_rbp = (uintptr_t)regs.rbp;
            pthread_mutex_lock(&nested_event_lock);
            {
                struct parent_owned_child_state *state =
                    parent_owned_child_locked(child, true);
                if (state != NULL) {
                    if (state->trace_anchor_rbp == 0 && program_int3 && !debugger_bp)
                        state->trace_anchor_rbp = frame_rbp;
                    if (state->trace_anchor_rbp != 0)
                        frame_rbp = state->trace_anchor_rbp;
                }
            }
            pthread_mutex_unlock(&nested_event_lock);
            struct iovec frame_local = {.iov_base = frame, .iov_len = sizeof(frame)};
            struct iovec frame_remote = {
                .iov_base = (void *)(frame_rbp - 0x200u),
                .iov_len = sizeof(frame),
            };
            ssize_t frame_len = process_vm_readv(child, &frame_local, 1,
                                                  &frame_remote, 1, 0);
            if (frame_len < 0)
                frame_len = 0;
            for (size_t n = 0; n < (size_t)frame_len; ++n)
                (void)snprintf(frame_hex + n * 2, 3, "%02x", frame[n]);
            frame_hex[(size_t)frame_len * 2] = '\0';
            handler_trace_log("[ida-vtdbg-shim] handler-frame seq=%llu child=%d base=0x%llx length=%zd bytes=%s\n",
                              sequence, child, (unsigned long long)(frame_rbp - 0x200u),
                              frame_len, frame_hex);
            if (sequence == 1 || ((uintptr_t)regs.rip >= 0x4014d0u &&
                                  (uintptr_t)regs.rip <= 0x4014e0u)) {
                unsigned char tables[512];
                char table_hex[sizeof(tables) * 2 + 1];
                struct iovec table_local = {.iov_base = tables, .iov_len = sizeof(tables)};
                struct iovec table_remote = {.iov_base = (void *)0x606020u,
                                              .iov_len = sizeof(tables)};
                ssize_t table_len = process_vm_readv(child, &table_local, 1,
                                                     &table_remote, 1, 0);
                if (table_len < 0)
                    table_len = 0;
                for (size_t n = 0; n < (size_t)table_len; ++n)
                    (void)snprintf(table_hex + n * 2, 3, "%02x", tables[n]);
                table_hex[(size_t)table_len * 2] = '\0';
                handler_trace_log("[ida-vtdbg-shim] handler-tables seq=%llu child=%d base=0x606020 length=%zd bytes=%s\n",
                                  sequence, child, table_len, table_hex);
            }
        }
    }
}

/* In log mode, a proven target-owned INT3 needs no round-trip through IDA's
 * waiter/mailbox merely to confirm it should not pause. The real tracer has
 * authoritative registers, siginfo and mirrored debugger BP provenance. */
static bool nested_target_autorun_protocol(pid_t child, int status)
{
    struct user_regs_struct regs;
    siginfo_t info;
    uintptr_t word = 0;
    uint8_t original = 0;
    if (!auto_continue_protocol || !nested_target || nested_target_launcher ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        ((unsigned int)status >> 16) != 0 ||
        ptrace_raw(PTRACE_GETREGS, child, NULL, &regs) < 0 || regs.rip == 0 ||
        ptrace_raw(PTRACE_GETSIGINFO, child, NULL, &info) < 0 ||
        info.si_code == TRAP_TRACE || info.si_code == TRAP_HWBKPT ||
        nested_target_is_synthetic_stop(child, status, NULL) ||
        nested_breakpoint_address_known((uintptr_t)regs.rip - 1u, &original))
        return false;
    if (nested_breakpoint_address_recorded((uintptr_t)regs.rip - 1u, &original) &&
        original != 0xccu)
        return false;
    if (ptrace_raw(PTRACE_PEEKDATA, child,
                   (void *)(uintptr_t)(regs.rip - 1u), &word) != 0)
        return false;
    return (uint8_t)word == 0xccu;
}

static bool nested_target_is_program_int3_stop(pid_t child, int status)
{
    struct user_regs_struct regs;
    siginfo_t info;
    uintptr_t word = 0;
    uint8_t original = 0;

    if (!nested_target || nested_target_launcher || child <= 0 ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        ((unsigned int)status >> 16) != 0 ||
        ptrace_raw(PTRACE_GETREGS, child, NULL, &regs) < 0 || regs.rip == 0 ||
        ptrace_raw(PTRACE_GETSIGINFO, child, NULL, &info) < 0 ||
        info.si_code == TRAP_TRACE || info.si_code == TRAP_HWBKPT ||
        nested_target_is_synthetic_stop(child, status, NULL))
        return false;
    if (nested_breakpoint_address_recorded((uintptr_t)regs.rip - 1u,
                                           &original) && original != 0xccu)
        return false;
    /* An explicit IDA breakpoint, even on an original CC instruction,
     * interrupts F8. Its exception must not be auto-consumed by call-over. */
    if (nested_breakpoint_address_known((uintptr_t)regs.rip - 1u, NULL))
        return false;
    if (ptrace_raw(PTRACE_PEEKDATA, child,
                   (void *)(uintptr_t)(regs.rip - 1u), &word) != 0)
        return false;
    return (uint8_t)word == 0xccu;
}

/* Hide a debugger-requested non-protocol single-step stop from the target's
 * own VM dispatcher.  The parent remains the only real tracer; it will only
 * receive the next 0xCC protocol stop after IDA continues the proxy view. */
static int parent_owned_hold_proxy_stop(pid_t child, int *status,
                                        struct rusage *usage, bool use_wait4,
                                        bool report_stop, bool initial_stop)
{
    int local_status = *status;
    uintptr_t generic_step_target = 0;
    bool generic_step_protocol =
        nested_generic_hw_step_pending(child, &generic_step_target) &&
        nested_target_is_program_int3_stop(child, local_status);
    bool native_protocol_released =
                                   (nested_target_protocol_step_requested(child) ||
                                    nested_target_autorun_protocol(child, local_status) ||
                                    generic_step_protocol) &&
                                    WIFSTOPPED(local_status) &&
                                    WSTOPSIG(local_status) == SIGTRAP;

    (void)parent_owned_proxy_stop_held(child, true, true);
    if (report_stop)
        nested_parent_report_stop(child, local_status, initial_stop,
                                  native_protocol_released
                                    ? IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED
                                    : 0);
    if (native_protocol_released) {
        /* A synthetic protocol-step has just resumed the child with CONT;
         * this is now the target's real INT3 stop.  Release it to the real
         * parent VM instead of leaving the parent-owned proxy parked. */
        parent_owned_set_protocol_request(child);
        if (generic_step_protocol)
            event_trace_log("[ida-vtdbg-shim] suppress program protocol INT3 during IDA generic step child=%d target=0x%llx\n",
                            child, (unsigned long long)generic_step_target);
        event_trace_log("[ida-vtdbg-shim] auto-release resumed protocol stop child=%d\n",
                        child);
    }
    for (;;) {
        unsigned int resume;
        int serviced;

        serviced = nested_driver_service_command(false, NULL);
        if (serviced < 0)
            return -1;
        resume = parent_owned_take_resume_request(child);
        if (resume == PARENT_OWNED_RESUME_NONE) {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&delay, NULL);
            continue;
        }
        if (resume == PARENT_OWNED_RESUME_PROTOCOL) {
            *status = local_status;
            (void)parent_owned_proxy_stop_held(child, true, false);
            trace_log("[ida-vtdbg-shim] release child protocol stop to parent vm child=%d status=0x%x\n",
                      child, (unsigned int)local_status);
            return 1;
        }
        for (;;) {
            struct rusage local_usage;
            pid_t waited = use_wait4
                               ? real_wait4(child, &local_status, WNOHANG,
                                            usage != NULL ? &local_usage : NULL)
                               : real_waitpid(child, &local_status, WNOHANG);
            if (waited < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            if (waited == 0) {
                struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
                (void)nanosleep(&delay, NULL);
                continue;
            }
            if (usage != NULL && use_wait4)
                *usage = local_usage;
            if (!WIFSTOPPED(local_status)) {
                *status = local_status;
                (void)parent_owned_proxy_stop_held(child, true, false);
                return 1;
            }
            /* Every subsequent stop returns through the kernel event queue.
             * The linux_server worker classifies a debugger breakpoint or
             * TRAP_TRACE and either shows it to IDA or protocol-acks it back
             * to this real parent-owned wait hook. */
            uint32_t stop_flags = 0;
            trace_parent_owned_child_stop(child, local_status, "proxy-wait");
            if (WSTOPSIG(local_status) == SIGTRAP) {
                siginfo_t stop_info;
                memset(&stop_info, 0, sizeof(stop_info));
                if (ptrace_raw(PTRACE_GETSIGINFO, child, NULL, &stop_info) == 0 &&
                    stop_info.si_code == TRAP_HWBKPT)
                    nested_generic_hw_step_complete(child);
            }
            uintptr_t inner_target = 0;
            if (nested_generic_hw_step_pending(child, &inner_target) &&
                nested_target_is_program_int3_stop(child, local_status)) {
                parent_owned_set_protocol_request(child);
                stop_flags |= IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED;
                handler_trace_log("[ida-vtdbg-shim] debugger-call-over-protocol child=%d target=0x%llx\n",
                                  child, (unsigned long long)inner_target);
            }
            if (nested_target_protocol_step_requested(child) &&
                WSTOPSIG(local_status) == SIGTRAP) {
                siginfo_t real_info;
                memset(&real_info, 0, sizeof(real_info));
                if (ptrace_raw(PTRACE_GETSIGINFO, child, NULL, &real_info) == 0 &&
                    real_info.si_code != TRAP_TRACE && real_info.si_code != TRAP_HWBKPT) {
                    parent_owned_set_protocol_request(child);
                    stop_flags |= IDA_VTDBG_EVENT_F_PROTOCOL_CONSUMED;
                    event_trace_log("[ida-vtdbg-shim] release newly-executed real protocol INT3 child=%d\n", child);
                }
            }
            nested_parent_report_stop(child, local_status, false, stop_flags);
            (void)parent_owned_proxy_stop_held(child, true, true);
            break;
        }
    }
}

static pid_t nested_target_wait_common(pid_t pid, int *status, int options,
                                       struct rusage *usage, bool use_wait4)
{
    const bool nonblocking = (options & WNOHANG) != 0;
    const int wait_options = options | WNOHANG;

    for (;;) {
        int local_status = 0;
        struct rusage local_usage;
        pid_t result;

        if (use_wait4)
            result = real_wait4(pid, &local_status, wait_options,
                                usage != NULL ? &local_usage : NULL);
        else
            result = real_waitpid(pid, &local_status, wait_options);
        if (result < 0) {
            if (errno == EINTR && !nonblocking)
                continue;
            return result;
        }
        if (result == 0) {
            bool released = false;
            int serviced = nested_target_service_command(false, &released);
            (void)released;
            if (nonblocking)
                return 0;
            if (serviced <= 0) {
                struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
                if (nanosleep(&delay, NULL) < 0 && errno == EINTR)
                    return -1;
            }
            continue;
        }

        if (status != NULL)
            *status = local_status;
        if (usage != NULL && use_wait4)
            *usage = local_usage;
        trace_log("[ida-vtdbg-shim] nested target wait req=%d result=%d status=0x%x\n",
                  pid, result, (unsigned int)local_status);
        if (WIFSTOPPED(local_status)) {
            if (parent_owned_get_owner_tid(result) <= 0)
                parent_owned_set_owner_tid(result, current_tid());
            nested_target_owner_tid = parent_owned_get_owner_tid(result);
            nested_target_child_pid = result;
            trace_parent_owned_child_stop(result, local_status, "wait");
            if (parent_owned_mode && result != getpid() && result > 0 &&
                WSTOPSIG(local_status) == SIGTRAP)
                nested_propagate_breakpoints_to_child(getpid(), result);
        }
        if (parent_owned_mode && nested_target &&
            WIFSTOPPED(local_status) &&
            nested_target_is_synthetic_stop(result, local_status, NULL)) {
            /* This stop was created solely for IDA's protocol-step observer.
             * Hold it for the debugger, then resume the child internally and
             * continue this wait loop.  The real parent VM must never consume
             * the synthetic stop as one of its protocol INT3 transitions. */
            int synthetic = nested_target_hold_synthetic_stop(
                result, &local_status, usage, use_wait4);
            if (synthetic < 0)
                return -1;
            if (synthetic > 0)
                continue;
        }
        if (nested_conn_fd >= 0) {
            /* A SIGTRAP here is the target program's own child->parent
             * debugbreak protocol.  The parent is the only real ptrace
             * owner and must consume it without an IDA exception dialog or
             * a relay-induced wait deadlock.  Requests already queued by
             * IDA (GETREGS/PEEK/etc.) may be serviced while the child is
             * stopped, but the status is then returned immediately to the
             * parent protocol. */
            nested_target_report_child(result, local_status);
            if (WIFSTOPPED(local_status))
                (void)nested_target_service_command(true, NULL);
            if (!WIFSTOPPED(local_status) || WSTOPSIG(local_status) != SIGTRAP)
                nested_target_send_event(NESTED_EVENT_WAIT, result, 0,
                                         local_status);
        }
        if (parent_owned_mode && WIFSTOPPED(local_status)) {
            bool release = false;

            /* The parent owns this stopped child.  Service every command
             * already queued in the driver before yielding the original stop
             * to the parent's protocol state machine. */
            while (nested_driver_service_command(true, &release) > 0)
                ;
            if (parent_owned_get_exception_resume(result, NULL) &&
                WSTOPSIG(local_status) != SIGSTOP) {
                /* The real parent has consumed the original program-owned
                 * exception and redirected the child with SETREGS.  Do not
                 * feed the first resulting trap back into the parent's VM as
                 * another protocol stop; publish it as the debugger-visible
                 * exception-resume stop instead. */
                uintptr_t resume_rip = 0;
                (void)parent_owned_get_exception_resume(result, &resume_rip);
                event_trace_log("[ida-vtdbg-shim] target publish exception-resume stop child=%d rip=0x%llx status=0x%x\n",
                                result, (unsigned long long)resume_rip,
                                (unsigned int)local_status);
                nested_parent_report_stop(result, local_status, false,
                                          IDA_VTDBG_EVENT_F_EXCEPTION_RESUME);
                parent_owned_proxy_stop_held(result, true, true);
                parent_owned_consume_exception_resume(result, NULL);
                if (status != NULL)
                    *status = local_status;
                return result;
            } else if (WSTOPSIG(local_status) == SIGSTOP &&
                parent_owned_take_initial_proxy(result)) {
                event_trace_log("[ida-vtdbg-shim] parent-owned initial child stop child=%d status=0x%x owner=%d\n",
                                result, (unsigned int)local_status,
                                parent_owned_get_owner_tid(result));
                int held = parent_owned_hold_proxy_stop(
                    result, &local_status, usage, use_wait4, true, true);
                if (held < 0)
                    return -1;
                if (status != NULL)
                    *status = local_status;
            } else if (WSTOPSIG(local_status) == SIGTRAP) {
                bool initial = parent_owned_take_initial_proxy(result);

                event_trace_log("[ida-vtdbg-shim] parent-owned trap gate child=%d initial=%d status=0x%x\n",
                                result, initial ? 1 : 0,
                                (unsigned int)local_status);
                int held = parent_owned_hold_proxy_stop(result, &local_status,
                                                        usage, use_wait4,
                                                        true, false);
                if (held < 0)
                    return -1;
                if (status != NULL)
                    *status = local_status;
            } else if (parent_owned_proxy_step_pending(result, true)) {
                int held = parent_owned_hold_proxy_stop(result, &local_status,
                                                        usage, use_wait4, true,
                                                        false);
                if (held < 0)
                    return -1;
                if (status != NULL)
                    *status = local_status;
            }
        }
        return result;
    }
}

static pid_t nested_target_waitpid(pid_t pid, int *status, int options)
{
    return nested_target_wait_common(pid, status, options, NULL, false);
}

static pid_t nested_target_wait4(pid_t pid, int *status, int options,
                                 struct rusage *usage)
{
    return nested_target_wait_common(pid, status, options, usage, true);
}

static pid_t nested_target_wait(int *status)
{
    return nested_target_wait_common(-1, status, 0, NULL, false);
}

static pid_t nested_server_waitpid(pid_t requested, int *status, int options)
{
    bool shadow = requested > 0 && nested_is_shadow(requested);

    if (!nested_server || !nested_server_is_owner_thread() ||
        (!shadow && requested > 0))
        return -2;
    parent_owned_execute_queued_process_exit();
    for (;;) {
        int local_status = 0;
        pid_t result;

        if (nested_server_outer_pid > 0 &&
            nested_event_subscription_pid == nested_server_outer_pid)
            nested_poll_kernel_events();
        nested_poll_messages();
        {
            pid_t event_pid = 0;
            if (nested_pop_event(requested, status, &event_pid))
                return event_pid;
        }
        if (!shadow) {
            result = real_waitpid(requested, &local_status, options | WNOHANG);
            if (result > 0) {
                if (status != NULL)
                    *status = local_status;
                return result;
            }
            if (result < 0 && errno != EINTR && errno != ECHILD)
                return result;
            if (result < 0 && errno == ECHILD && options & WNOHANG)
                return result;
        }
        if (options & WNOHANG)
            return 0;
        {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&delay, NULL);
        }
    }
}

static pid_t nested_server_wait4(pid_t requested, int *status, int options,
                                 struct rusage *usage)
{
    bool shadow = requested > 0 && nested_is_shadow(requested);

    if (!nested_server || !nested_server_is_owner_thread() ||
        (!shadow && requested > 0))
        return -2;
    parent_owned_execute_queued_process_exit();
    for (;;) {
        int local_status = 0;
        struct rusage local_usage;
        pid_t result;

        if (nested_server_outer_pid > 0 &&
            nested_event_subscription_pid == nested_server_outer_pid)
            nested_poll_kernel_events();
        nested_poll_messages();
        {
            pid_t event_pid = 0;
            if (nested_pop_event(requested, status, &event_pid))
                return event_pid;
        }
        if (!shadow) {
            result = real_wait4(requested, &local_status, options | WNOHANG,
                                usage != NULL ? &local_usage : NULL);
            if (result > 0) {
                if (status != NULL)
                    *status = local_status;
                if (usage != NULL)
                    *usage = local_usage;
                return result;
            }
            if (result < 0 && errno != EINTR && errno != ECHILD)
                return result;
            if (result < 0 && errno == ECHILD && options & WNOHANG)
                return result;
        }
        if (options & WNOHANG)
            return 0;
        {
            struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
            (void)nanosleep(&delay, NULL);
        }
    }
}

static int ensure_policy_fd(void)
{
    int fd;
    pid_t restore_pids[SHIM_MAX_TARGETS];
    size_t restore_count = 0;
    size_t index;
    if (!compat_enabled || test_policy)
        return policy_fd;
    if (policy_fd >= 0) {
        struct stat fd_info;
        struct stat device_info;
        if (fstat(policy_fd, &fd_info) == 0 && S_ISCHR(fd_info.st_mode) &&
            stat("/dev/" IDA_VTDBG_POLICY_DEVICE, &device_info) == 0 &&
            fd_info.st_rdev == device_info.st_rdev) {
            if (policy_shared.ring == NULL || policy_shared.fd != policy_fd)
                shared_map_attach(&policy_shared, policy_fd);
            return policy_fd;
        }
        shared_map_detach(&policy_shared);
        policy_fd = -1;
        nested_event_subscription_pid = 0;
    }
    fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        policy_fd = fd;
        shared_map_attach(&policy_shared, fd);
        if (!nested_server && !nested_event_worker && !parent_owned_mode) {
            struct ida_vtdbg_policy_session tracer_request = {
                .abi = IDA_VTDBG_POLICY_ABI,
                .target_pid = (uint32_t)getpid(),
                .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS |
                         IDA_VTDBG_POLICY_F_DEFER_TREE_ARM,
            };
            if (ioctl(fd, IDA_VTDBG_IOC_REGISTER_TRACER,
                      &tracer_request) < 0)
                trace_log("[ida-vtdbg-shim] tracer registration pid=%d failed errno=%d (%s)\n",
                          getpid(), errno, strerror(errno));
            else
                trace_log("[ida-vtdbg-shim] tracer registration pid=%d fd=%d\n",
                          getpid(), fd);
        }
        pthread_mutex_lock(&state_lock);
        for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
            if (targets[index].active && restore_count < SHIM_MAX_TARGETS)
                restore_pids[restore_count++] = targets[index].pid;
        }
        pthread_mutex_unlock(&state_lock);
        for (index = 0; index < restore_count; ++index) {
            struct ida_vtdbg_policy_session request = {
                .abi = IDA_VTDBG_POLICY_ABI,
                .target_pid = (uint32_t)target_tgid(restore_pids[index]),
                .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
            };
            if (request.target_pid == 0)
                request.target_pid = (uint32_t)restore_pids[index];
            if (ioctl(fd, IDA_VTDBG_IOC_REGISTER, &request) < 0)
                trace_log("[ida-vtdbg-shim] restore pid=%d failed errno=%d (%s)\n",
                          restore_pids[index], errno, strerror(errno));
            else
                trace_log("[ida-vtdbg-shim] restore pid=%d tgid=%u fd=%d\n",
                          restore_pids[index], request.target_pid, fd);
        }
    } else
        trace_log("[ida-vtdbg-shim] ensure_policy_fd open failed errno=%d (%s)\n",
                  errno, strerror(errno));
    return policy_fd;
}

static void resolve_symbols(void)
{
    void *symbol;
    symbol = dlsym(RTLD_NEXT, "ptrace");
    memcpy(&real_ptrace, &symbol, sizeof(real_ptrace));
    symbol = dlsym(RTLD_NEXT, "syscall");
    memcpy(&real_syscall, &symbol, sizeof(real_syscall));
    symbol = dlsym(RTLD_NEXT, "waitpid");
    memcpy(&real_waitpid, &symbol, sizeof(real_waitpid));
    symbol = dlsym(RTLD_NEXT, "__waitpid");
    memcpy(&real___waitpid, &symbol, sizeof(real___waitpid));
    if (real___waitpid == NULL)
        real___waitpid = real_waitpid;
    symbol = dlsym(RTLD_NEXT, "wait4");
    memcpy(&real_wait4, &symbol, sizeof(real_wait4));
    symbol = dlsym(RTLD_NEXT, "wait");
    memcpy(&real_wait, &symbol, sizeof(real_wait));
    symbol = dlsym(RTLD_NEXT, "waitid");
    memcpy(&real_waitid, &symbol, sizeof(real_waitid));
    symbol = dlsym(RTLD_NEXT, "fork");
    memcpy(&real_fork, &symbol, sizeof(real_fork));
    symbol = dlsym(RTLD_NEXT, "fopen");
    memcpy(&real_fopen, &symbol, sizeof(real_fopen));
    symbol = dlsym(RTLD_NEXT, "fopen64");
    memcpy(&real_fopen64, &symbol, sizeof(real_fopen64));
    symbol = dlsym(RTLD_NEXT, "execve");
    memcpy(&real_execve, &symbol, sizeof(real_execve));
    symbol = dlsym(RTLD_NEXT, "execveat");
    memcpy(&real_execveat, &symbol, sizeof(real_execveat));
    symbol = dlsym(RTLD_NEXT, "fexecve");
    memcpy(&real_fexecve, &symbol, sizeof(real_fexecve));
    (void)snprintf(shim_path, sizeof(shim_path), "%s",
                   "libida_joint_shim.so");
    const char *enabled = getenv("IDA_VTDBG_COMPAT");
    const char *test = getenv("IDA_VTDBG_TEST_POLICY");
    const char *mediate = getenv("IDA_VTDBG_MEDIATE_SYSCALLS");
    const char *trace = getenv("IDA_VTDBG_TRACE");
    const char *event_trace = getenv("IDA_VTDBG_TRACE_EVENTS");
    const char *state_trace = getenv("IDA_VTDBG_TRACE_STATE");
    const char *handler_trace = getenv("IDA_VTDBG_HANDLER_TRACE");
    const char *record_handlers = getenv("IDA_VTDBG_RECORD_HANDLERS");
    const char *repeat_handlers = getenv("IDA_VTDBG_REPEAT_HANDLER_BREAKPOINTS");
    const char *autorun_protocol = getenv("IDA_VTDBG_AUTO_CONTINUE_PROTOCOL");
    const char *handler_log = getenv("IDA_VTDBG_HANDLER_LOG");
    const char *handler_start = getenv("IDA_VTDBG_HANDLER_TEXT_START");
    const char *handler_end = getenv("IDA_VTDBG_HANDLER_TEXT_END");
    const char *nested = getenv("IDA_VTDBG_NESTED");
    const char *nested_role = getenv("IDA_VTDBG_NESTED_ROLE");
    const char *nested_kernel = getenv("IDA_VTDBG_NESTED_KERNEL");
    const char *parent_owned = getenv("IDA_VTDBG_PARENT_OWNED");
    const char *replay_stdin = getenv("IDA_VTDBG_REPLAY_STDIN");
    const char *shared = getenv("IDA_VTDBG_SHM");
    const char *direct = getenv("IDA_VTDBG_DIRECT_TARGET");
    const char *oneshot = getenv("IDA_VTDBG_ONESHOT_ALGORITHM");
    const char *oneshot_addr =
        getenv("IDA_VTDBG_ONESHOT_ALGORITHM_ADDR");
    const char *protocol_int3_addr =
        getenv("IDA_VTDBG_PROTOCOL_INT3_ADDR");
    compat_enabled = enabled != NULL && strcmp(enabled, "1") == 0;
    test_policy = test != NULL && strcmp(test, "1") == 0;
    syscall_mediation = mediate != NULL && strcmp(mediate, "1") == 0;
    trace_enabled = trace != NULL && strcmp(trace, "1") == 0;
    event_trace_enabled = event_trace != NULL &&
                          strcmp(event_trace, "1") == 0;
    state_trace_enabled = state_trace != NULL &&
                          strcmp(state_trace, "1") == 0;
    handler_trace_enabled =
        (handler_trace != NULL && strcmp(handler_trace, "1") == 0) ||
        (record_handlers != NULL && strcmp(record_handlers, "1") == 0);
    repeat_handler_breakpoints =
        repeat_handlers != NULL && strcmp(repeat_handlers, "1") == 0;
    auto_continue_protocol = autorun_protocol != NULL &&
                             strcmp(autorun_protocol, "1") == 0;
    if (handler_log != NULL && *handler_log != '\0')
        (void)snprintf(handler_log_path, sizeof(handler_log_path), "%s",
                       handler_log);
    else
        handler_log_path[0] = '\0';
    /* Handler recording is also the request for the detailed VM state
     * records.  It does not implicitly enable the high-volume event stream;
     * handler-observe/handler-state/handler-stop use their own sink. */
    if (handler_trace_enabled)
        state_trace_enabled = true;
    if (handler_start != NULL && *handler_start != '\0') {
        char *end = NULL;
        unsigned long long value = strtoull(handler_start, &end, 0);
        if (end != handler_start && *end == '\0')
            handler_text_start = (uintptr_t)value;
    }
    if (handler_end != NULL && *handler_end != '\0') {
        char *end = NULL;
        unsigned long long value = strtoull(handler_end, &end, 0);
        if (end != handler_end && *end == '\0')
            handler_text_end = (uintptr_t)value;
    }
    nested_server = nested != NULL && strcmp(nested, "1") == 0 &&
                    (nested_role == NULL || strcmp(nested_role, "target") != 0);
    nested_target = nested != NULL && strcmp(nested, "1") == 0 &&
                    nested_role != NULL && strcmp(nested_role, "target") == 0;
    nested_kernel_events = nested_kernel != NULL &&
                           strcmp(nested_kernel, "1") == 0;
    parent_owned_mode = parent_owned != NULL &&
                         strcmp(parent_owned, "1") == 0;
    replay_stdin_enabled = parent_owned_mode &&
                           (replay_stdin == NULL ||
                            strcmp(replay_stdin, "0") != 0);
    shared_memory_enabled = shared == NULL || strcmp(shared, "0") != 0;
    direct_target_injection = direct != NULL && strcmp(direct, "1") == 0;
    oneshot_algorithm_enabled = oneshot != NULL &&
                                strcmp(oneshot, "1") == 0;
    nested_protocol_int3_address = 0;
    if (protocol_int3_addr != NULL && *protocol_int3_addr != '\0') {
        char *end = NULL;
        unsigned long long configured =
            strtoull(protocol_int3_addr, &end, 0);
        if (end != protocol_int3_addr && *end == '\0')
            nested_protocol_int3_address = (uintptr_t)configured;
    }
    oneshot_algorithm_address = 0;
    if (oneshot_algorithm_enabled) {
        char *end = NULL;
        unsigned long long configured =
            oneshot_addr != NULL ? strtoull(oneshot_addr, &end, 0) : 0;
        if (oneshot_addr != NULL && end != oneshot_addr && *end == '\0')
            oneshot_algorithm_address = (uintptr_t)configured;
        else
            /* The default is only for the checked-in tradre harness.  A
             * different target supplies an explicit address through the
             * environment and does not rely on this sample value. */
            oneshot_algorithm_address = (uintptr_t)0x400b2bULL;
    }
    nested_target_launcher = nested_target && shim_is_linux_server_image();
    direct_target = direct_target_injection && !shim_is_linux_server_image();
    nested_event_worker = nested_target_launcher && nested_kernel_events;
    event_trace_log("[ida-vtdbg-shim] event trace init pid=%d server=%d worker=%d parent_owned=%d compat=%d\n",
                    getpid(), nested_server ? 1 : 0,
                    nested_event_worker ? 1 : 0,
                    parent_owned_mode ? 1 : 0, compat_enabled ? 1 : 0);
    if (parent_owned_mode && nested_event_worker) {
        compat_enabled = true;
        syscall_mediation = true;
    } else if (nested_target) {
        syscall_mediation = false;
    }
    install_ptrace_rpc_handler();
    trace_log("[ida-vtdbg-shim] init compat=%d test=%d mediate=%d policy_fd=%d nested_server=%d nested_target=%d launcher=%d worker=%d kernel=%d shm=%d direct_target=%d parent_owned=%d replay_stdin=%d oneshot=%d addr=0x%llx protocol_int3=0x%llx handlers=%d repeat_handlers=%d handler_log=%s\n",
              compat_enabled, test_policy, syscall_mediation, policy_fd,
              nested_server, nested_target, nested_target_launcher,
              nested_event_worker, nested_kernel_events,
              shared_memory_enabled, direct_target, parent_owned_mode,
              replay_stdin_enabled ? 1 : 0,
              oneshot_algorithm_enabled ? 1 : 0,
              (unsigned long long)oneshot_algorithm_address,
              (unsigned long long)nested_protocol_int3_address,
              handler_trace_enabled ? 1 : 0,
              repeat_handler_breakpoints ? 1 : 0,
              handler_log_path[0] != '\0' ? handler_log_path : "stderr");
    if (direct_target) {
        /* Do not leave the control switch visible to the tracee after this
         * constructor has classified its role. */
        unsetenv("IDA_VTDBG_DIRECT_TARGET");
        unsetenv("IDA_VTDBG_COMPAT");
        unsetenv("LD_PRELOAD");
    }
    if (compat_enabled) {
        oneshot_shared_open();
        policy_fd = open("/dev/" IDA_VTDBG_POLICY_DEVICE, O_RDWR | O_CLOEXEC);
        shared_map_attach(&policy_shared, policy_fd);
        if (policy_fd >= 0 && !nested_server && !nested_event_worker &&
            !parent_owned_mode) {
            struct ida_vtdbg_policy_session tracer_request = {
                .abi = IDA_VTDBG_POLICY_ABI,
                .target_pid = (uint32_t)getpid(),
                .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS |
                         IDA_VTDBG_POLICY_F_DEFER_TREE_ARM,
            };
            if (ioctl(policy_fd, IDA_VTDBG_IOC_REGISTER_TRACER,
                      &tracer_request) < 0)
                trace_log("[ida-vtdbg-shim] initial tracer registration pid=%d failed errno=%d (%s)\n",
                          getpid(), errno, strerror(errno));
        }
        trace_log("[ida-vtdbg-shim] initial policy open fd=%d errno=%d\n",
                  policy_fd, policy_fd < 0 ? errno : 0);
        if (policy_fd < 0 && !test_policy) {
            dprintf(STDERR_FILENO,
                    "[ida-vtdbg-shim] compatibility disabled: open /dev/%s: %s\n",
                    IDA_VTDBG_POLICY_DEVICE, strerror(errno));
            compat_enabled = false;
        }
    }
    if (nested_server && !parent_owned_mode)
        (void)nested_server_setup();
    else if (nested_event_worker && !parent_owned_mode) {
        (void)unsetenv("IDA_VTDBG_NESTED_SOCKET");
        (void)nested_server_setup();
    } else if (nested_target && !nested_target_launcher) {
        if (parent_owned_mode)
            (void)nested_parent_driver_setup();
        else
            (void)nested_target_connect();
    }
    /* In parent-owned server mode the wait-owner thread must be the sole
     * consumer of the shared event ring.  A second poller can win the ring
     * CAS, consume a synthetic child stop, and leave the IDA wait side parked
     * in nested_target_hold_synthetic_stop.  The owner wait loop already
     * drains the ring on every pass, so keep the helper thread for the launch
     * worker and legacy non-parent-owned server only. */
    if ((nested_event_worker || (nested_server && !parent_owned_mode)) &&
        nested_kernel_events) {
        trace_log("[ida-vtdbg-shim] event-worker create listen=%d conn=%d server=%d\n",
                  nested_listen_fd, nested_conn_fd);
        nested_kernel_poller_running = true;
        if (pthread_create(&nested_kernel_poller_thread, NULL,
                           nested_kernel_poller, NULL) == 0)
            nested_kernel_poller_started = true;
        else {
            trace_log("[ida-vtdbg-shim] event-worker create failed errno=%d (%s)\n",
                      errno, strerror(errno));
            nested_kernel_poller_running = false;
        }
    }
}

#include "ida90_event_adapter.inc"

__attribute__((constructor)) static void shim_init(void)
{
    pthread_once(&resolve_once, resolve_symbols);
    if (nested_server) {
        (void)setvbuf(stdout, NULL, _IOLBF, 0);
        (void)ida90_install_event_adapter();
    }
}

__attribute__((destructor)) static void shim_fini(void)
{
    size_t index;
    if (nested_kernel_poller_started) {
        nested_kernel_poller_running = false;
        (void)pthread_join(nested_kernel_poller_thread, NULL);
        nested_kernel_poller_started = false;
    }
    if (nested_worker_event_fd >= 0) {
        shared_map_detach(&worker_shared);
        close(nested_worker_event_fd);
        nested_worker_event_fd = -1;
    }
    if (nested_target_event_fd >= 0) {
        close(nested_target_event_fd);
        nested_target_event_fd = -1;
    }
    if (policy_fd >= 0) {
        for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
            if (targets[index].active) {
                struct ida_vtdbg_policy_session request = {
                    .abi = IDA_VTDBG_POLICY_ABI,
                    .target_pid = (uint32_t)(targets[index].tgid > 0
                                                  ? targets[index].tgid
                                                  : targets[index].pid),
                    .flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS,
                };
                (void)ioctl(policy_fd, IDA_VTDBG_IOC_UNREGISTER, &request);
            }
        }
        close(policy_fd);
        policy_fd = -1;
    }
    shared_map_detach(&policy_shared);
    oneshot_shared_close();
}

static struct shim_tid *get_tid_state_locked(pid_t tid, bool create)
{
    size_t index;
    struct shim_tid *free_slot = NULL;

    for (index = 0; index < SHIM_MAX_TIDS; ++index) {
        if (tids[index].active && tids[index].tid == tid)
            return &tids[index];
        if (!tids[index].active && free_slot == NULL)
            free_slot = &tids[index];
    }
    if (!create || free_slot == NULL)
        return NULL;
    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->tid = tid;
    free_slot->active = true;
    return free_slot;
}

static pid_t target_tgid(pid_t tid)
{
    char path[64];
    char line[128];
    FILE *status;
    pid_t tgid = tid;

    if (tid <= 0)
        return tid;
    (void)snprintf(path, sizeof(path), "/proc/%d/status", tid);
    status = fopen(path, "r");
    if (status == NULL)
        return tid;
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "Tgid:\t%d", &tgid) == 1)
            break;
    }
    fclose(status);
    return tgid;
}

static bool group_is_registered(pid_t pid)
{
    pid_t tgid = target_tgid(pid);
    size_t index;
    bool found = false;

    pthread_mutex_lock(&state_lock);
    for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
        if (targets[index].active &&
            (targets[index].pid == pid ||
             (tgid > 0 && targets[index].tgid == tgid))) {
            found = true;
            break;
        }
    }
    pthread_mutex_unlock(&state_lock);
    return found;
}

static struct shim_target *find_target_locked(pid_t pid)
{
    pid_t tgid = target_tgid(pid);
    size_t index;

    for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
        if (targets[index].active &&
            (targets[index].pid == pid ||
             (tgid > 0 && targets[index].tgid == tgid)))
            return &targets[index];
    }
    return NULL;
}

static bool target_startup_ready(pid_t pid)
{
    bool ready = false;
    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        ready = target != NULL && target->startup_ready;
    }
    pthread_mutex_unlock(&state_lock);
    return ready;
}

static void mark_target_startup_ready(pid_t pid)
{
    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        if (target != NULL)
            target->startup_ready = true;
    }
    pthread_mutex_unlock(&state_lock);
}

static bool note_continue_and_should_mediate(pid_t pid)
{
    bool mediate = false;
    bool parent_owned_outer = false;

    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        if (target != NULL) {
            ++target->continue_count;
            if (target->continue_count >= 2) {
                target->startup_ready = true;
                /* Parent-owned mode keeps the application's parent as the
                 * real PTRACE_TRACEME owner.  Rewriting that parent's IDA
                 * PTRACE_CONT into PTRACE_SYSCALL generates an unrequested
                 * stop for every loader/application syscall.  Keep the wait
                 * broker enabled for tree events, but leave this process on
                 * IDA's native CONT path.  The child-side TRACEME policy is
                 * supplied by the kernel module. */
                parent_owned_outer = parent_owned_mode && nested_server &&
                    nested_server_outer_pid > 0 &&
                    target->tgid == nested_server_outer_pid;
                mediate = !parent_owned_outer;
            }
        }
    }
    pthread_mutex_unlock(&state_lock);
    if (parent_owned_outer)
        trace_log("[ida-vtdbg-shim] keep parent-owned outer CONT native pid=%d outer=%d\n",
                  pid, nested_server_outer_pid);
    return mediate;
}

/* A fork child can execute PTRACE_TRACEME immediately after its inherited
 * ptrace-stop.  Unlike an exec target it has no PTRACE_EVENT_EXEC boundary,
 * so make its very first IDA resume a syscall resume.  This is deliberately
 * limited to a child discovered from a real PTRACE_EVENT_FORK/VFORK event. */
static void prepare_fork_child(pid_t pid)
{
    pthread_mutex_lock(&state_lock);
    {
        struct shim_target *target = find_target_locked(pid);
        if (target != NULL) {
            target->startup_ready = true;
            target->continue_count = 2;
        }
    }
    pthread_mutex_unlock(&state_lock);
    trace_log("[ida-vtdbg-shim] prepared real fork child pid=%d for syscall mediation\n",
              pid);
}

static bool target_is_registered(pid_t pid)
{
    return group_is_registered(pid);
}

static int policy_query(pid_t pid, const struct ptrace_syscall_info *info,
                        struct ida_vtdbg_policy_syscall *reply)
{
    bool registered;
    int fd;

    memset(reply, 0, sizeof(*reply));
    reply->abi = IDA_VTDBG_POLICY_ABI;
    reply->target_pid = (uint32_t)pid;
    reply->syscall_nr = info->entry.nr;
    memcpy(reply->args, info->entry.args, sizeof(reply->args));
    fd = ensure_policy_fd();
    if (fd >= 0) {
        if (ioctl(fd, IDA_VTDBG_IOC_QUERY_SYSCALL, reply) < 0) {
            trace_log("[ida-vtdbg-shim] query tid=%d nr=%llu fd=%d failed errno=%d (%s)\n",
                      pid, (unsigned long long)info->entry.nr, fd, errno,
                      strerror(errno));
            return -errno;
        }
        trace_log("[ida-vtdbg-shim] query tid=%d nr=%llu fd=%d action=%u result=%lld\n",
                  pid, (unsigned long long)info->entry.nr, fd, reply->action,
                  (long long)reply->result);
        return 0;
    }

    if (!test_policy)
        return -ENODEV;
    registered = group_is_registered(pid);
    if (!registered)
        return 0;
    if (info->entry.nr == 101 && info->entry.args[0] == PTRACE_TRACEME) {
        reply->action = IDA_VTDBG_ACTION_EMULATE;
        reply->result = 0;
    } else if (info->entry.nr == 157 && info->entry.args[0] == 3) {
        reply->action = IDA_VTDBG_ACTION_EMULATE;
        reply->result = 1;
    }
    return 0;
}

static int filter_buffer(pid_t pid, void *buffer, size_t length)
{
    struct ida_vtdbg_policy_buffer request;
    struct iovec local, remote;
    ssize_t copied;
    size_t chunk;
    int changed = 0;
    int fd;

    if (!compat_enabled || !target_is_registered(pid) || length == 0)
        return 0;
    while (length != 0) {
        chunk = length > sizeof(request.data) ? sizeof(request.data) : length;
        local.iov_base = request.data;
        local.iov_len = chunk;
        remote.iov_base = buffer;
        remote.iov_len = chunk;
        copied = process_vm_readv(pid, &local, 1, &remote, 1, 0);
        if (copied <= 0)
            break;
        if ((size_t)copied > sizeof(request.data))
            copied = sizeof(request.data);
        request.abi = IDA_VTDBG_POLICY_ABI;
        request.target_pid = (uint32_t)pid;
        request.length = (uint32_t)copied;
        request.changed = 0;
        fd = ensure_policy_fd();
        if (fd >= 0) {
            if (ioctl(fd, IDA_VTDBG_IOC_FILTER_BUFFER, &request) < 0) {
                trace_log("[ida-vtdbg-shim] filter tid=%d fd=%d failed errno=%d (%s)\n",
                          pid, fd, errno, strerror(errno));
                return -errno;
            }
            trace_log("[ida-vtdbg-shim] filter tid=%d fd=%d len=%zd changed=%u\n",
                      pid, fd, copied, request.changed);
        } else if (test_policy) {
            char *field = NULL;
            char local[IDA_VTDBG_POLICY_MAX_BUFFER + 1];
            size_t index;
            memcpy(local, request.data, (size_t)copied);
            local[copied] = '\0';
            field = strstr(local, "TracerPid:");
            if (field != NULL) {
                char *digits = field + strlen("TracerPid:");
                while ((size_t)(digits - local) < (size_t)copied &&
                       (*digits == ' ' || *digits == '\t'))
                    ++digits;
                for (index = 0;
                     (size_t)(digits - local) + index < (size_t)copied &&
                     digits[index] >= '0' &&
                     digits[index] <= '9';
                     ++index)
                    digits[index] = local[(size_t)(digits - local) + index] = '0';
                memcpy(request.data, local, (size_t)copied);
                request.changed = index != 0;
            }
        }
        if (request.changed) {
            local.iov_base = request.data;
            local.iov_len = copied;
            remote.iov_base = buffer;
            remote.iov_len = copied;
            if (process_vm_writev(pid, &local, 1, &remote, 1, 0) != copied)
                return -errno;
            changed = 1;
        }
        buffer = (uint8_t *)buffer + copied;
        length -= (size_t)copied;
        if ((size_t)copied < chunk)
            break;
    }
    return changed;
}

static int handle_syscall_stop(pid_t tid, struct shim_tid *state,
                               const siginfo_t *stop_info)
{
    struct ptrace_syscall_info info;
    struct ida_vtdbg_policy_syscall policy;
    struct user_regs_struct regs;
    long count;
    bool have_info = false;
    bool is_entry = false;

    memset(&info, 0, sizeof(info));
    count = ptrace_internal(PTRACE_GET_SYSCALL_INFO, tid,
                            (void *)(uintptr_t)sizeof(info), &info);
    if (count >= 0 && (info.op == PTRACE_SYSCALL_INFO_ENTRY ||
                       info.op == PTRACE_SYSCALL_INFO_EXIT)) {
        have_info = true;
        is_entry = info.op == PTRACE_SYSCALL_INFO_ENTRY;
        trace_log("[ida-vtdbg-shim] syscall-stop tid=%d info_count=%ld op=%u nr=%llu rval=%lld\n",
                  tid, count, info.op,
                  info.op == PTRACE_SYSCALL_INFO_ENTRY
                      ? (unsigned long long)info.entry.nr
                      : 0ULL,
                  info.op == PTRACE_SYSCALL_INFO_EXIT
                      ? (long long)info.exit.rval
                      : 0LL);
    } else {
        int saved_errno = errno;

        if (ptrace_internal(PTRACE_GETREGS, tid, NULL, &regs) < 0) {
            trace_log("[ida-vtdbg-shim] syscall-stop tid=%d GET_SYSCALL_INFO failed errno=%d (%s); GETREGS failed errno=%d (%s)\n",
                      tid, saved_errno, strerror(saved_errno), errno,
                      strerror(errno));
            return -errno;
        }
        /*
         * Some ptrace implementations return ESRCH for
         * PTRACE_GET_SYSCALL_INFO when the stop was delivered to a
         * different tracer thread.  On x86-64 the syscall-entry stop
         * exposes rax=-ENOSYS, while the exit stop exposes the return
         * value.  Keep a per-tid phase bit after the first stop and use
         * GETREGS as a compatible fallback.
         */
        if (!state->syscall_phase_known)
            is_entry = regs.rax == (uint64_t)-ENOSYS;
        else
            is_entry = state->next_syscall_is_entry;
        memset(&info, 0, sizeof(info));
        info.op = is_entry ? PTRACE_SYSCALL_INFO_ENTRY
                           : PTRACE_SYSCALL_INFO_EXIT;
        info.instruction_pointer = regs.rip;
        info.stack_pointer = regs.rsp;
        if (is_entry) {
            info.entry.nr = regs.orig_rax;
            info.entry.args[0] = regs.rdi;
            info.entry.args[1] = regs.rsi;
            info.entry.args[2] = regs.rdx;
            info.entry.args[3] = regs.r10;
            info.entry.args[4] = regs.r8;
            info.entry.args[5] = regs.r9;
        } else {
            info.exit.rval = (int64_t)regs.rax;
            info.exit.is_error = (regs.rax >= (uint64_t)-4095);
        }
        trace_log("[ida-vtdbg-shim] syscall-stop tid=%d GET_SYSCALL_INFO failed errno=%d (%s); fallback regs op=%u nr=%llu rval=%lld rax=0x%llx orig=0x%llx\n",
                  tid, saved_errno, strerror(saved_errno), info.op,
                  is_entry ? (unsigned long long)info.entry.nr : 0ULL,
                  !is_entry ? (long long)info.exit.rval : 0LL,
                  (unsigned long long)regs.rax,
                  (unsigned long long)regs.orig_rax);
    }

    state->syscall_phase_known = true;
    state->next_syscall_is_entry = !is_entry;
    if (is_entry) {
        state->filter_read = false;
        state->read_iovec_count = 0;
        if (info.entry.nr == 101 && info.entry.args[0] == PTRACE_TRACEME)
            mark_anti_checks_started(tid);
        if ((info.entry.nr == 0 || info.entry.nr == 17) &&
            target_is_registered(tid)) {
            state->filter_read = true;
            state->read_buffer = info.entry.args[1];
            state->read_iovecs[0].base = info.entry.args[1];
            state->read_iovecs[0].length = info.entry.args[2];
            state->read_iovec_count = 1;
        } else if ((info.entry.nr == 19 || info.entry.nr == 295 ||
                    info.entry.nr == 327) &&
                   target_is_registered(tid)) {
            size_t requested = info.entry.args[2] > SHIM_MAX_IOVECS
                                   ? SHIM_MAX_IOVECS
                                   : (size_t)info.entry.args[2];
            size_t index;
            for (index = 0; index < requested; ++index) {
                struct iovec local = {
                    .iov_base = &state->read_iovecs[index],
                    .iov_len = sizeof(state->read_iovecs[index]),
                };
                struct iovec remote = {
                    .iov_base = (void *)(uintptr_t)(info.entry.args[1] +
                                                    index * sizeof(struct iovec)),
                    .iov_len = sizeof(struct iovec),
                };
                if (process_vm_readv(tid, &local, 1, &remote, 1, 0) !=
                    (ssize_t)sizeof(struct iovec))
                    break;
                ++state->read_iovec_count;
            }
            if (state->read_iovec_count != 0) {
                state->filter_read = true;
                state->read_buffer = state->read_iovecs[0].base;
            }
        }
        if (policy_query(tid, &info, &policy) == 0 &&
            policy.action == IDA_VTDBG_ACTION_EMULATE) {
            if (ptrace_internal(PTRACE_GETREGS, tid, NULL, &regs) < 0)
                return -errno;
            regs.orig_rax = (uint64_t)-1;
            if (ptrace_internal(PTRACE_SETREGS, tid, NULL, &regs) < 0)
                return -errno;
            state->emulate_result = true;
            state->emulated_result = policy.result;
        }
    } else if (!is_entry) {
        if (state->emulate_result) {
            if (ptrace_internal(PTRACE_GETREGS, tid, NULL, &regs) < 0)
                return -errno;
            regs.rax = (uint64_t)state->emulated_result;
            if (ptrace_internal(PTRACE_SETREGS, tid, NULL, &regs) < 0)
                return -errno;
            state->emulate_result = false;
        }
        if (state->filter_read && info.exit.rval > 0) {
            size_t remaining = (size_t)info.exit.rval;
            size_t index;
            for (index = 0; index < state->read_iovec_count && remaining != 0;
                 ++index) {
                size_t length = state->read_iovecs[index].length > remaining
                                    ? remaining
                                    : (size_t)state->read_iovecs[index].length;
                (void)filter_buffer(
                    tid, (void *)(uintptr_t)state->read_iovecs[index].base,
                    length);
                remaining -= length;
            }
        }
        state->filter_read = false;
        state->read_iovec_count = 0;
    }

    (void)have_info;
    (void)stop_info;
    return 0;
}

static bool is_shim_preload_entry(const char *entry)
{
    const char *base;
    const char *shim_base;

    if (shim_path[0] == '\0')
        return strstr(entry, "libida_joint_shim.so") != NULL ||
               strstr(entry, "libida_vtdbg_shim.so") != NULL;
    if (strcmp(entry, shim_path) == 0)
        return true;
    base = strrchr(entry, '/');
    shim_base = strrchr(shim_path, '/');
    base = base == NULL ? entry : base + 1;
    shim_base = shim_base == NULL ? shim_path : shim_base + 1;
    return strcmp(base, shim_base) == 0;
}

static char *remove_shim_preload(const char *current)
{
    size_t capacity;
    size_t used = 0;
    char *output;
    const char *cursor;

    if (current == NULL || *current == '\0')
        return NULL;
    capacity = strlen(current) + 1;
    output = calloc(1, capacity);
    if (output == NULL)
        return NULL;
    cursor = current;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ':');
        size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        char item[PATH_MAX];
        if (length != 0 && length < sizeof(item)) {
            memcpy(item, cursor, length);
            item[length] = '\0';
            if (!is_shim_preload_entry(item)) {
                if (used != 0)
                    output[used++] = ':';
                memcpy(output + used, item, length);
                used += length;
            }
        }
        if (end == NULL)
            break;
        cursor = end + 1;
    }
    output[used] = '\0';
    return output;
}

static bool drop_target_environment(const char *entry)
{
    if (direct_target_injection &&
        strncmp(entry, "IDA_VTDBG_DIRECT_TARGET=", 23) == 0)
        return false;
    if (direct_target_injection && strncmp(entry, "LD_PRELOAD=", 11) == 0)
        return false;
    if ((nested_server || nested_target) &&
        strncmp(entry, "LD_PRELOAD=", 11) == 0)
        return false;
    if (nested_server && strncmp(entry, "IDA_VTDBG_NESTED_ROLE=", 22) == 0)
        return true;
    return strncmp(entry, "IDA_VTDBG_COMPAT=", 17) == 0 ||
           strncmp(entry, "IDA_VTDBG_TEST_POLICY=", 22) == 0 ||
           strncmp(entry, "IDA_VTDBG_DIRECT_TARGET=", 23) == 0 ||
           strncmp(entry, "LD_PRELOAD=", 11) == 0;
}

static char **sanitized_environment(char *const envp[])
{
    size_t count = 0;
    size_t index;
    size_t output_index = 0;
    bool nested_role_added = false;
    char **output;

    while (envp != NULL && envp[count] != NULL) {
        ++count;
    }
    output = calloc(count + 4, sizeof(*output));
    if (output == NULL)
        return NULL;
    for (index = 0; index < count; ++index) {
        if (drop_target_environment(envp[index])) {
            if (strncmp(envp[index], "LD_PRELOAD=", 11) == 0) {
                char *preload = remove_shim_preload(envp[index] + 11);
                if (preload != NULL && *preload != '\0') {
                    size_t size = strlen(preload) + 12;
                    output[output_index] = malloc(size);
                    if (output[output_index] == NULL) {
                        free(preload);
                        goto fail;
                    }
                    (void)snprintf(output[output_index], size, "LD_PRELOAD=%s",
                                   preload);
                    ++output_index;
                }
                free(preload);
            }
            continue;
        }
        if (nested_server &&
            strncmp(envp[index], "IDA_VTDBG_NESTED_ROLE=", 22) == 0)
            continue;
        output[output_index] = strdup(envp[index]);
        if (output[output_index] == NULL)
            goto fail;
        ++output_index;
    }
    if (nested_server || nested_event_worker) {
        output[output_index] = strdup("IDA_VTDBG_NESTED_ROLE=target");
        if (output[output_index] == NULL)
            goto fail;
        ++output_index;
        nested_role_added = true;
    }
    (void)nested_role_added;
    return output;

fail:
    for (index = 0; index < output_index; ++index)
        free(output[index]);
    free(output);
    return NULL;
}

static void free_environment(char **envp)
{
    size_t index;
    if (envp == NULL)
        return;
    for (index = 0; envp[index] != NULL; ++index)
        free(envp[index]);
    free(envp);
}

int execve(const char *path, char *const argv[], char *const envp[])
{
    char **clean_env;
    int result;

    pthread_once(&resolve_once, resolve_symbols);
    if (real_execve == NULL) {
        errno = ENOSYS;
        return -1;
    }
    clean_env = sanitized_environment(envp);
    if (clean_env == NULL) {
        errno = ENOMEM;
        return -1;
    }
    child_exec_depth++;
    result = real_execve(path, argv, clean_env);
    child_exec_depth--;
    int saved_errno = errno;
    trace_log("[ida-vtdbg-shim] execve path=%s result=%d errno=%d (%s) nested_server=%d nested_target=%d\n",
              path, result, saved_errno,
              strerror(saved_errno), nested_server, nested_target);
    free_environment(clean_env);
    errno = saved_errno;
    return result;
}

int execveat(int dirfd, const char *path, char *const argv[],
             char *const envp[], int flags)
{
    char **clean_env;
    int result;
    int saved_errno;

    pthread_once(&resolve_once, resolve_symbols);
    clean_env = sanitized_environment(envp);
    if (clean_env == NULL) {
        errno = ENOMEM;
        return -1;
    }
    child_exec_depth++;
    if (real_execveat != NULL) {
        result = real_execveat(dirfd, path, argv, clean_env, flags);
    } else {
        result = (int)syscall(SYS_execveat, dirfd, path, argv, clean_env,
                               flags);
    }
    child_exec_depth--;
    saved_errno = errno;
    free_environment(clean_env);
    errno = saved_errno;
    return result;
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
    char **clean_env;
    int result;
    int saved_errno;

    pthread_once(&resolve_once, resolve_symbols);
    clean_env = sanitized_environment(envp);
    if (clean_env == NULL) {
        errno = ENOMEM;
        return -1;
    }
    child_exec_depth++;
    if (real_fexecve != NULL) {
        result = real_fexecve(fd, argv, clean_env);
    } else {
        result = (int)syscall(SYS_execveat, fd, "", argv, clean_env,
                               AT_EMPTY_PATH);
    }
    child_exec_depth--;
    saved_errno = errno;
    free_environment(clean_env);
    errno = saved_errno;
    return result;
}

static int exec_search(const char *file, char *const argv[])
{
    const char *path_value = getenv("PATH");
    char *path_copy;
    char *save = NULL;
    char *component;
    int saved_error = ENOENT;

    if (strchr(file, '/') != NULL) {
        char **clean_env = sanitized_environment(environ);
        if (clean_env == NULL) {
            errno = ENOMEM;
            return -1;
        }
        int result = real_execve(file, argv, clean_env);
        int saved_errno = errno;
        free_environment(clean_env);
        errno = saved_errno;
        return result;
    }
    path_copy = strdup(path_value != NULL ? path_value : "/bin:/usr/bin");
    if (path_copy == NULL) {
        errno = ENOMEM;
        return -1;
    }
    for (component = strtok_r(path_copy, ":", &save); component != NULL;
         component = strtok_r(NULL, ":", &save)) {
        size_t needed = strlen(component) + strlen(file) + 2;
        char *candidate = malloc(needed);
        char **clean_env;
        int saved_errno;
        int result;

        if (candidate == NULL) {
            saved_error = ENOMEM;
            break;
        }
        (void)snprintf(candidate, needed, "%s/%s",
                       component[0] == '\0' ? "." : component, file);
        clean_env = sanitized_environment(environ);
        if (clean_env == NULL) {
            free(candidate);
            saved_error = ENOMEM;
            break;
        }
        result = real_execve(candidate, argv, clean_env);
        saved_errno = errno;
        free_environment(clean_env);
        free(candidate);
        if (saved_errno == EACCES)
            saved_error = EACCES;
        else if (saved_errno != ENOENT && saved_errno != ENOTDIR) {
            saved_error = saved_errno;
            break;
        }
        (void)result;
    }
    free(path_copy);
    errno = saved_error;
    return -1;
}

int execv(const char *path, char *const argv[])
{
    return execve(path, argv, environ);
}

int execvp(const char *file, char *const argv[])
{
    pthread_once(&resolve_once, resolve_symbols);
    if (real_execve == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return exec_search(file, argv);
}

static void register_best_effort(pid_t pid)
{
    struct ida_vtdbg_policy_session request;
    size_t index;
    pid_t tgid;
    pid_t owner_tid = 0;
    bool stored = false;
    bool rotate_deferred_session = false;
    if (!compat_enabled || pid <= 0 || child_exec_depth != 0)
        return;
    tgid = target_tgid(pid);
    pid_t tracer = tracer_pid_of(pid);

    /* A ProcessExit can be deferred until IDA has consumed the old child
     * thread events.  The next connection can nevertheless create its new
     * debuggee before any internal relay HELLO is emitted.  Rotate the old
     * parent-owned session on this first concrete new TGID, otherwise the
     * server keeps routing PTRACE/driver commands to the dead root and its
     * shadow child. */
    if (parent_owned_mode && nested_server) {
        pthread_mutex_lock(&nested_event_lock);
        rotate_deferred_session =
            nested_server_session_end_pending &&
            nested_server_session_end_root > 0 &&
            tgid > 0 && tgid != nested_server_session_end_root;
        pthread_mutex_unlock(&nested_event_lock);
        if (rotate_deferred_session) {
            event_trace_log("[ida-vtdbg-shim] rotate deferred parent-owned session old_root=%d new_tgid=%d\n",
                            nested_server_session_end_root, tgid);
            nested_server_finalize_deferred_session();
        }
    }
    request.abi = IDA_VTDBG_POLICY_ABI;
    request.target_pid = (uint32_t)(tgid > 0 ? tgid : pid);
    request.flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS;
    request.reserved = 0;
    pthread_mutex_lock(&state_lock);
    for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
        if ((targets[index].active || targets[index].exit_pending) &&
            targets[index].pid == pid) {
            targets[index].tgid = tgid;
            if (targets[index].owner_tid <= 0)
                targets[index].owner_tid = current_tid();
            targets[index].exit_pending = false;
            targets[index].active = true;
            pthread_mutex_unlock(&state_lock);
            return;
        }
        if (targets[index].active && targets[index].tgid == tgid &&
            targets[index].owner_tid > 0) {
            owner_tid = targets[index].owner_tid;
        }
        if (!targets[index].active) {
            targets[index].pid = pid;
            targets[index].tgid = tgid;
            targets[index].owner_tid = tracer > 0
                                           ? tracer
                                           : (owner_tid > 0 ? owner_tid
                                                            : current_tid());
            targets[index].startup_ready = false;
            targets[index].anti_checks_started = false;
            targets[index].active = true;
            stored = true;
            break;
        }
    }
    pthread_mutex_unlock(&state_lock);
    if (!stored)
        return;
    if (parent_owned_mode && nested_server) {
        /* The server first waits on linux_server's launch helper, then on the
         * executable process created beneath it.  Bind event subscription to
         * the first actual debuggee TGID, not later child-waiter/bootstrap
         * helper processes created while IDA performs its synthetic fork
         * handshake.  broker_wait() establishes this root from the original
         * positive wait request; subsequent register_best_effort() calls are
         * per-helper bookkeeping and must not retarget the tree mailbox. */
        if (nested_server_outer_pid <= 0)
            nested_server_outer_pid = tgid > 0 ? tgid : pid;
        if (nested_server_owner_tid <= 0)
            nested_server_owner_tid = tracer > 0 ? tracer : current_tid();
        nested_server_subscribe_events(nested_server_outer_pid);
        trace_log("[ida-vtdbg-shim] parent-owned local target pid=%d tgid=%d outer=%d ptrace_owner=%d wait_tid=%d server=%d worker=%d\n",
                  pid, tgid, nested_server_outer_pid,
                  nested_server_owner_tid, current_tid(), nested_server ? 1 : 0,
                  nested_event_worker ? 1 : 0);
        return;
    }
    if (parent_owned_mode && nested_event_worker) {
        if (nested_server_outer_pid <= 0)
            nested_server_outer_pid = tgid > 0 ? tgid : pid;
        nested_server_subscribe_events(nested_server_outer_pid);
        trace_log("[ida-vtdbg-shim] parent-owned worker target pid=%d tgid=%d outer=%d ptrace_owner=%d wait_tid=%d\n",
                  pid, tgid, nested_server_outer_pid,
                  nested_server_owner_tid, current_tid());
        return;
    }
    {
        int fd = ensure_policy_fd();
        if (fd >= 0 && ioctl(fd, IDA_VTDBG_IOC_REGISTER, &request) < 0)
            dprintf(STDERR_FILENO,
                    "[ida-vtdbg-shim] register pid %d failed: %s\n", pid,
                    strerror(errno));
        trace_log("[ida-vtdbg-shim] register pid=%d tgid=%d fd=%d stored=%d\n",
                  pid, tgid, fd, stored);
    }
}

static void unregister_best_effort(pid_t pid)
{
    struct ida_vtdbg_policy_session request;
    size_t index;
    pid_t tgid = 0;
    bool last_in_group = false;
    bool removed = false;
    if (!compat_enabled || pid <= 0)
        return;
    pthread_mutex_lock(&state_lock);
    for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
        if (targets[index].active && targets[index].pid == pid) {
            tgid = targets[index].tgid;
            if (nested_server && parent_owned_mode) {
                targets[index].exit_pending = true;
                targets[index].startup_ready = false;
            } else {
                targets[index].active = false;
                targets[index].exit_pending = false;
            }
            removed = true;
            break;
        }
    }
    if (!removed) {
        pthread_mutex_unlock(&state_lock);
        return;
    }
    if (tgid <= 0)
        tgid = target_tgid(pid);
    last_in_group = true;
    if (tgid > 0) {
        for (index = 0; index < SHIM_MAX_TARGETS; ++index) {
            if ((targets[index].active || targets[index].exit_pending) &&
                targets[index].tgid == tgid) {
                last_in_group = false;
                break;
            }
        }
    }
    pthread_mutex_unlock(&state_lock);
    if (nested_server && parent_owned_mode) {
        trace_log("[ida-vtdbg-shim] retain exited target tombstone pid=%d tgid=%d until session finalize\n",
                  pid, tgid);
        return;
    }
    if (last_in_group) {
        request.abi = IDA_VTDBG_POLICY_ABI;
        request.target_pid = (uint32_t)(tgid > 0 ? tgid : pid);
        request.flags = IDA_VTDBG_POLICY_DEFAULT_FLAGS;
        request.reserved = 0;
        {
            int fd = ensure_policy_fd();
            if (fd >= 0)
                (void)ioctl(fd, IDA_VTDBG_IOC_UNREGISTER, &request);
            trace_log("[ida-vtdbg-shim] unregister pid=%d tgid=%d fd=%d\n",
                      pid, tgid, fd);
        }
    }
}

static void unregister_tid_best_effort(pid_t tid)
{
    unregister_best_effort(tid);
}

static bool tid_is_compat(pid_t tid)
{
    return group_is_registered(tid);
}

static bool traced_by_this_server(pid_t tid)
{
    char path[64];
    char line[128];
    FILE *status;
    int tracer = 0;

    (void)snprintf(path, sizeof(path), "/proc/%d/status", tid);
    status = fopen(path, "r");
    if (status == NULL)
        return false;
    while (fgets(line, sizeof(line), status) != NULL) {
        if (sscanf(line, "TracerPid:\t%d", &tracer) == 1)
            break;
    }
    fclose(status);
    return tracer == getpid();
}

static bool forward_target_trap(pid_t tid, int *status_out)
{
    unsigned int event;
    struct user_regs_struct regs;
    struct iovec local;
    struct iovec remote;
    uint8_t opcode = 0;

    if (tid <= 0 || status_out == NULL || !WIFSTOPPED(*status_out) ||
        WSTOPSIG(*status_out) != SIGTRAP)
        return false;
    event = (unsigned int)*status_out >> 16;
    if (event != 0 || !tid_is_compat(tid) || !target_startup_ready(tid) ||
        !anti_checks_started(tid))
        return false;
    if (ptrace_internal(PTRACE_GETREGS, tid, NULL, &regs) < 0 ||
        regs.rip == 0)
        return false;
    local.iov_base = &opcode;
    local.iov_len = sizeof(opcode);
    remote.iov_base = (void *)(uintptr_t)(regs.rip - 1);
    remote.iov_len = sizeof(opcode);
    if (process_vm_readv(tid, &local, 1, &remote, 1, 0) !=
        (ssize_t)sizeof(opcode) || opcode != 0xcc)
        return false;
    trace_log("[ida-vtdbg-shim] forward target INT3 tid=%d rip=0x%llx\n",
              tid, (unsigned long long)regs.rip);
    if (ptrace_internal(PTRACE_SYSCALL, tid, NULL,
                        (void *)(intptr_t)SIGTRAP) < 0)
        return false;
    return true;
}

static bool parent_owned_outer_trap_visible(pid_t tid, int status)
{
    struct user_regs_struct regs;

    if (!parent_owned_mode || (!nested_event_worker && !nested_server) ||
        tid <= 0 ||
        !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP ||
        ((unsigned int)status >> 16) != 0)
        return false;
    if (ptrace_internal(PTRACE_GETREGS, tid, NULL, &regs) < 0 ||
        regs.rip == 0)
        return false;
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    if (ptrace_internal(PTRACE_GETSIGINFO, tid, NULL, &info) == 0 &&
        (info.si_code == TRAP_HWBKPT ||
         (info.si_code == TRAP_TRACE &&
          atomic_load_explicit(&nested_parent_trace_requested, memory_order_acquire))))
        return true;
    return nested_breakpoint_address_known((uintptr_t)(regs.rip - 1), NULL);
}

static pid_t broker_wait(pid_t requested, int *status, int options,
                         struct rusage *usage, bool use_wait4)
{
    pid_t tid;
    int local_status;

    if (!compat_enabled || !syscall_mediation || inside_wait_broker)
        return use_wait4 ? real_wait4(requested, status, options, usage)
                         : real_waitpid(requested, status, options);
    if (parent_owned_mode && nested_server)
        parent_owned_execute_queued_process_exit();
    if (parent_owned_mode && nested_server && requested > 0 &&
        nested_server_outer_pid <= 0) {
        nested_server_outer_pid = requested;
        nested_server_owner_tid = tracer_pid_of(requested);
        if (nested_server_owner_tid <= 0)
            nested_server_owner_tid = current_tid();
        trace_log("[ida-vtdbg-shim] parent-owned server locked target outer=%d owner=%d\n",
                  nested_server_outer_pid, nested_server_owner_tid);
    }
    inside_wait_broker = true;
    for (;;) {
        int *status_out = status != NULL ? status : &local_status;
        int wait_options = options;

        /* In nested mode relay events are produced by the target's own
         * waitpid() and may arrive while linux_server has no ptrace stop.
         * Poll the real tracee with WNOHANG so the relay queue is serviced
         * without requiring a second user action in IDA. */
        if (nested_server || (parent_owned_mode && nested_event_worker))
            wait_options |= WNOHANG;
        if (nested_server || nested_event_worker) {
            pid_t nested_tid = 0;
            nested_poll_kernel_events();
            nested_poll_messages();
            if (nested_pop_event(requested, status_out, &nested_tid)) {
                trace_log("[ida-vtdbg-shim] nested broker pop requested=%d pid=%d status=0x%x\n",
                          requested, nested_tid,
                          status_out != NULL ? (unsigned int)*status_out : 0);
                inside_wait_broker = false;
                return nested_tid;
            }
        }
        if (!nested_native_stop_take(requested, status_out, &tid))
            tid = use_wait4 ? real_wait4(requested, status_out, wait_options, usage)
                            : real_waitpid(requested, status_out, wait_options);
        if (parent_owned_mode && nested_server && tid > 0 &&
            WIFSTOPPED(*status_out) && WSTOPSIG(*status_out) != SIGCHLD &&
            nested_native_stop_defer(tid, *status_out)) {
            /* A real task remains stopped. Metadata queries may use the
             * kernel stop bridge, but IDA's waiter sees the status only
             * after its current add/continue RPC commits. */
            if (tid == nested_server_outer_pid) {
                parent_owned_owner_real_stop(tid);
                atomic_store_explicit(&nested_parent_real_stopped, true, memory_order_release);
                parent_owned_note_unpresented_stop(tid, *status_out);
                atomic_store_explicit(&nested_parent_debug_event_presented, false, memory_order_release);
                if (event_trace_enabled) {
                    struct user_regs_struct held_regs = {0};
                    uintptr_t stack_words[4] = {0};
                    if (ptrace_internal(PTRACE_GETREGS, tid, NULL, &held_regs) == 0) {
                        for (size_t n = 0; n < 4; ++n)
                            (void)ptrace_internal(PTRACE_PEEKDATA, tid,
                                (void *)(uintptr_t)(held_regs.rsp + n * sizeof(uintptr_t)),
                                &stack_words[n]);
                        event_trace_log("[ida-vtdbg-shim] deferred owner native regs rip=0x%llx rsp=0x%llx syscall=%lld rax=0x%llx stack=%lx,%lx,%lx,%lx\n",
                            (unsigned long long)held_regs.rip, (unsigned long long)held_regs.rsp,
                            (long long)held_regs.orig_rax, (unsigned long long)held_regs.rax,
                            stack_words[0], stack_words[1], stack_words[2], stack_words[3]);
                    }
                }
            }
            event_trace_log("[ida-vtdbg-shim] defer native stop during IDA transaction tid=%d status=0x%x\n",
                            tid, *status_out);
            if (options & WNOHANG) {
                *status_out = 0;
                inside_wait_broker = false;
                return 0;
            }
            continue;
        }
        if (tid > 0) {
            unsigned int raw_status = (unsigned int)*status_out;
            if (WIFSTOPPED(*status_out))
                event_trace_log("[ida-vtdbg-shim] broker stop process=%d caller=%d request=%d tid=%d status=0x%x sig=%d event=%u outer=%d\n",
                                getpid(), current_tid(), requested, tid,
                                raw_status, WSTOPSIG(*status_out),
                                raw_status >> 16,
                                nested_server_outer_pid);
            trace_log("[ida-vtdbg-shim] wait requested=%d options=0x%x tid=%d status=0x%x stopped=%d sig=%d event=%u compat=%d ready=%d\n",
                      requested, options, tid, raw_status,
                      WIFSTOPPED(*status_out) ? 1 : 0,
                      WIFSTOPPED(*status_out) ? WSTOPSIG(*status_out) : 0,
                      raw_status >> 16, tid_is_compat(tid),
                      target_startup_ready(tid));
        } else {
            trace_log("[ida-vtdbg-shim] wait requested=%d options=0x%x result=%d errno=%d (%s)\n",
                      requested, options, tid, tid < 0 ? errno : 0,
                      tid < 0 ? strerror(errno) : "ok");
        }
        if (tid > 0 && WIFSTOPPED(*status_out) &&
            (((unsigned int)*status_out >> 16) == PTRACE_EVENT_EXEC))
            mark_target_startup_ready(tid);
        if (tid > 0 && WIFSTOPPED(*status_out) && !tid_is_compat(tid) &&
            traced_by_this_server(tid))
            register_best_effort(tid);
        if (tid > 0 && WIFSTOPPED(*status_out) && tid_is_compat(tid)) {
            pid_t tracer = tracer_pid_of(tid);
            if (tracer > 0)
                set_target_owner(tid, tracer);
        }
        /* In parent-owned mode a traced parent receives SIGCHLD whenever its
         * own child stops at a protocol INT3.  That SIGCHLD is not an IDA
         * exception: resume the parent with the signal so it can execute its
         * native waitpid/ptrace exchange.  The child SIGTRAP itself remains
         * exclusively visible to that real parent tracer. */
        if (parent_owned_mode && (nested_event_worker || nested_server) &&
            tid > 0 &&
            WIFSTOPPED(*status_out) && WSTOPSIG(*status_out) == SIGCHLD &&
            tid_is_compat(tid)) {
            struct user_regs_struct owner_regs;
            bool preserve_parent_step = tid == nested_server_outer_pid &&
                atomic_load_explicit(&nested_parent_trace_requested, memory_order_acquire);

            if (!preserve_parent_step &&
                ptrace_internal(PTRACE_GETREGS, tid, NULL, &owner_regs) == 0) {
                parent_owned_owner_capture_regs(tid, &owner_regs);
                event_trace_log("[ida-vtdbg-shim] captured parent owner regs tid=%d rip=0x%llx rsp=0x%llx\n",
                                tid, (unsigned long long)owner_regs.rip,
                                (unsigned long long)owner_regs.rsp);
            }
            event_trace_log("[ida-vtdbg-shim] parent-owned consume outer SIGCHLD tid=%d\n",
                            tid);
            /* The child stop is already pending for the tracee's waitpid().
             * Do not reinject SIGCHLD: that repeatedly redelivers the same
             * signal through the outer tracer and starves the parent VM. */
            /* A SIGCHLD delivery stop can precede execution of the user's
             * selected parent instruction. CONT would cancel that actual
             * SINGLESTEP and leave IDA waiting forever for its STEP. Keep
             * the explicitly requested native step; no synthetic stop and
             * no signal timing assumption is involved. */
            enum __ptrace_request owner_resume = preserve_parent_step
                ? PTRACE_SINGLESTEP : PTRACE_CONT;
            if (ptrace_internal(owner_resume, tid, NULL, NULL) < 0 &&
                errno != ESRCH) {
                inside_wait_broker = false;
                return -1;
            }
            if (options & WNOHANG) {
                if (status != NULL)
                    *status = 0;
                inside_wait_broker = false;
                return 0;
            }
            continue;
        }
        if (parent_owned_mode && (nested_event_worker || nested_server) &&
            tid > 0 &&
            tid == nested_server_outer_pid && WIFSTOPPED(*status_out) &&
            WSTOPSIG(*status_out) == SIGSTOP &&
            parent_owned_has_initial_child_pending()) {
            event_trace_log("[ida-vtdbg-shim] parent-owned hold outer SIGSTOP for child bootstrap tid=%d\n",
                            tid);
            for (unsigned int pass = 0; pass < 50; ++pass) {
                pid_t bootstrap_pid = 0;
                int *bootstrap_status = status != NULL ? status_out : NULL;

                nested_poll_kernel_events();
                nested_poll_messages();
                if (current_tid() == nested_server_owner_tid &&
                    nested_pop_event(requested, bootstrap_status,
                                     &bootstrap_pid)) {
                    parent_owned_mark_virtual_outer_stop_held(bootstrap_pid);
                    event_trace_log("[ida-vtdbg-shim] nested broker pop child bootstrap process=%d caller=%d owner=%d requested=%d pid=%d status=0x%x\n",
                                    getpid(), current_tid(),
                                    nested_server_owner_tid, requested,
                                    bootstrap_pid,
                                    bootstrap_status != NULL ?
                                        (unsigned int)*bootstrap_status : 0);
                    inside_wait_broker = false;
                    return bootstrap_pid;
                }
                {
                    struct timespec delay = {
                        .tv_sec = 0, .tv_nsec = 1000000
                    };
                    (void)nanosleep(&delay, NULL);
                }
            }
            if (ptrace_internal(PTRACE_CONT, tid, NULL, NULL) < 0 &&
                errno != ESRCH) {
                inside_wait_broker = false;
                return -1;
            }
            if (options & WNOHANG) {
                if (status != NULL)
                    *status = 0;
                inside_wait_broker = false;
                return 0;
            }
            continue;
        }
        if (parent_owned_mode && (nested_event_worker || nested_server) &&
            tid > 0 &&
            WIFSTOPPED(*status_out) && WSTOPSIG(*status_out) == SIGTRAP &&
            ((unsigned int)*status_out >> 16) == 0 &&
            target_startup_ready(tid) &&
            !parent_owned_outer_trap_visible(tid, *status_out)) {
            trace_log("[ida-vtdbg-shim] parent-owned swallow outer SIGTRAP tid=%d status=0x%x\n",
                      tid, (unsigned int)*status_out);
            if (ptrace_internal(PTRACE_CONT, tid, NULL, NULL) < 0 &&
                errno != ESRCH) {
                inside_wait_broker = false;
                return -1;
            }
            if (options & WNOHANG) {
                if (status != NULL)
                    *status = 0;
                inside_wait_broker = false;
                return 0;
            }
            continue;
        }
        if (!parent_owned_mode && tid > 0 && WIFSTOPPED(*status_out) &&
            WSTOPSIG(*status_out) == SIGTRAP) {
            unsigned int ptrace_event = (unsigned int)*status_out >> 16;
            if (ptrace_event == PTRACE_EVENT_FORK ||
                ptrace_event == PTRACE_EVENT_VFORK) {
                unsigned long child = 0;
                if (ptrace_internal(PTRACE_GETEVENTMSG, tid, NULL, &child) == 0 &&
                    child > 0 && child <= INT32_MAX) {
                    register_best_effort((pid_t)child);
                    prepare_fork_child((pid_t)child);
                    /* IDA's linux backend handles CLONE notifications but
                     * can otherwise discard FORK/VFORK.  The child is still
                     * a real ptrace child; only the presentation code changes. */
                    *status_out = (int)((SIGTRAP << 8) |
                                        (PTRACE_EVENT_CLONE << 16));
                    trace_log("[ida-vtdbg-shim] normalize fork parent=%d child=%lu as clone stop\n",
                              tid, child);
                }
            }
        }
        if (!parent_owned_mode && forward_target_trap(tid, status_out)) {
            if (options & WNOHANG) {
                if (status != NULL)
                    *status = 0;
                inside_wait_broker = false;
                return 0;
            }
            continue;
        }
        if (nested_server && tid == 0) {
            if (options & WNOHANG) {
                if (status != NULL)
                    *status = 0;
                inside_wait_broker = false;
                return 0;
            }
            {
                struct timespec delay = {.tv_sec = 0, .tv_nsec = 1000000};
                (void)nanosleep(&delay, NULL);
            }
            continue;
        }
        if (tid <= 0 || !WIFSTOPPED(*status_out) ||
            !target_startup_ready(tid) ||
            WSTOPSIG(*status_out) != (SIGTRAP | 0x80) ||
            !tid_is_compat(tid)) {
            if (tid > 0 && parent_owned_mode &&
                tid == nested_server_outer_pid && WIFSTOPPED(*status_out)) {
                parent_owned_owner_real_stop(tid);
                atomic_store_explicit(&nested_parent_real_stopped, true, memory_order_release);
                parent_owned_note_unpresented_stop(tid, *status_out);
                atomic_store_explicit(&nested_parent_debug_event_presented, false, memory_order_release);
                atomic_store_explicit(&nested_parent_trace_requested, false, memory_order_release);
            }
            trace_log("[ida-vtdbg-shim] forward tid=%d stopped=%d sig=%d event=%u ready=%d compat=%d\n",
                      tid, tid > 0 && WIFSTOPPED(*status_out),
                      tid > 0 && WIFSTOPPED(*status_out) ? WSTOPSIG(*status_out)
                                                         : 0,
                      tid > 0 ? ((unsigned int)*status_out >> 16) : 0,
                      tid > 0 ? target_startup_ready(tid) : 0,
                      tid > 0 ? tid_is_compat(tid) : 0);
            if (tid > 0 && WIFSTOPPED(*status_out) &&
                WSTOPSIG(*status_out) == SIGTRAP &&
                (((unsigned int)*status_out >> 16) == PTRACE_EVENT_CLONE)) {
                unsigned long new_tid = 0;
                if (ptrace_internal(PTRACE_GETEVENTMSG, tid, NULL, &new_tid) == 0) {
                    register_best_effort((pid_t)new_tid);
                    (void)ptrace_internal(PTRACE_SYSCALL, (pid_t)new_tid, NULL,
                                           NULL);
                }
            }
            if (tid > 0 &&
                (WIFEXITED(*status_out) || WIFSIGNALED(*status_out))) {
                unregister_tid_best_effort(tid);
                if (tid == nested_server_outer_pid)
                    nested_server_end_parent_owned_session(tid);
            }
            inside_wait_broker = false;
            return tid;
        }

        struct shim_tid *state;
        pthread_mutex_lock(&state_lock);
        state = get_tid_state_locked(tid, true);
        pthread_mutex_unlock(&state_lock);
        trace_log("[ida-vtdbg-shim] mediate syscall-stop tid=%d state=%p\n",
                  tid, (void *)state);
        if (state == NULL || handle_syscall_stop(tid, state, NULL) < 0) {
            trace_log("[ida-vtdbg-shim] swallow failed syscall-stop tid=%d errno=%d (%s)\n",
                      tid, errno, strerror(errno));
            (void)ptrace_internal(PTRACE_SYSCALL, tid, NULL, NULL);
            if (options & WNOHANG) {
                if (status != NULL)
                    *status = 0;
                inside_wait_broker = false;
                return 0;
            }
            continue;
        }
        if (ptrace_internal(PTRACE_SYSCALL, tid, NULL, NULL) < 0 &&
            errno != ESRCH) {
            trace_log("[ida-vtdbg-shim] resume syscall tid=%d failed errno=%d (%s)\n",
                      tid, errno, strerror(errno));
            inside_wait_broker = false;
            return -1;
        }
        trace_log("[ida-vtdbg-shim] resume syscall tid=%d ok options=0x%x\n",
                  tid, options);
        if (options & WNOHANG) {
            if (status != NULL)
                *status = 0;
            inside_wait_broker = false;
            return 0;
        }
    }
}

long ptrace(enum __ptrace_request request, ...)
{
    va_list ap;
    struct nested_breakpoint_write breakpoint_write;
    pid_t pid = 0;
    void *addr = NULL;
    void *data = NULL;
    long result;

    memset(&breakpoint_write, 0, sizeof(breakpoint_write));
    pthread_once(&resolve_once, resolve_symbols);
    va_start(ap, request);
    if (request != PTRACE_TRACEME) {
        pid = va_arg(ap, pid_t);
        addr = va_arg(ap, void *);
        data = va_arg(ap, void *);
    }
    va_end(ap);

    if (nested_target && !nested_target_launcher &&
        (request == PTRACE_SETREGS || request == PTRACE_SETREGSET ||
         request == PTRACE_CONT || request == PTRACE_SINGLESTEP)) {
        uint64_t requested_rip = 0;
        if (request == PTRACE_SETREGS && data != NULL)
            requested_rip = ((const struct user_regs_struct *)data)->rip;
        else if (request == PTRACE_SETREGSET && data != NULL &&
                 (uintptr_t)addr == 1u) {
            const struct iovec *iov = data;
            if (iov->iov_base != NULL &&
                iov->iov_len >= sizeof(struct user_regs_struct))
                requested_rip =
                    ((const struct user_regs_struct *)iov->iov_base)->rip;
        }
        event_trace_log("[ida-vtdbg-shim] target ptrace control request=%d child=%d requested_rip=0x%llx\n",
                        request, pid,
                        (unsigned long long)requested_rip);
    }

    if (parent_owned_mode && nested_server &&
        nested_server_outer_pid > 0 &&
        nested_resume_request(request))
        event_trace_log("[ida-vtdbg-shim] server ptrace resume entry request=%d pid=%d shadow=%d held=%d\n",
                        request, pid, nested_is_shadow(pid) ? 1 : 0,
                        parent_owned_proxy_stop_held(pid, false, false) ? 1 : 0);
    if (parent_owned_mode && nested_server && nested_server_outer_pid > 0 &&
        (request == PTRACE_GETEVENTMSG || request == PTRACE_SETOPTIONS ||
         request == PTRACE_ATTACH || request == PTRACE_SEIZE ||
         request == PTRACE_CONT || request == PTRACE_SINGLESTEP))
        event_trace_log("[ida-vtdbg-shim] server ptrace lifecycle request=%d pid=%d outer=%d shadow=%d\n",
                        request, pid, nested_server_outer_pid,
                        nested_is_shadow(pid) ? 1 : 0);
    if (parent_owned_mode && nested_server &&
        nested_server_outer_pid > 0 &&
        (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT ||
         request == PTRACE_POKEUSER))
        event_trace_log("[ida-vtdbg-shim] server breakpoint write entry req=%d pid=%d addr=0x%llx value=0x%llx shadow=%d held=%d\n",
                        request, pid, (unsigned long long)(uintptr_t)addr,
                        (unsigned long long)(uintptr_t)data,
                        nested_is_shadow(pid) ? 1 : 0,
                        parent_owned_proxy_stop_held(pid, false, false) ? 1 : 0);

    if (parent_owned_mode && nested_server && pid > 0 &&
        pid == nested_server_outer_pid && request == PTRACE_KILL)
        return server_ptrace_call(request, pid, addr, data);
    if (parent_owned_reject_wait_step(request, pid))
        return -1;

    /* IDA's libc ptrace path reaches the compat-preserving tail below rather
     * than server_ptrace_call().  Handle the parent-owned hardware-step
     * registers here as well, before the real libc ptrace call programs DR0. */
    if (parent_owned_mode && nested_server &&
        request == PTRACE_POKEUSER &&
        nested_protocol_hw_step_write(pid, (uintptr_t)addr,
                                      (uintptr_t)data))
        return 0;
    if (parent_owned_mode && nested_server &&
        request == PTRACE_PEEKUSER) {
        uintptr_t debug_value = 0;
        if (nested_protocol_hw_step_peek(pid, (uintptr_t)addr,
                                         &debug_value))
            return (long)debug_value;
    }
    if (parent_owned_mode && nested_server &&
        (request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
        nested_protocol_hw_step_pending(pid))
        return nested_driver_forward_ptrace(request, pid, addr, data);

    /* linux_server probes fork tracing by creating short-lived children
     * before it starts the requested application.  Those PTRACE_CONT calls
     * must remain on linux_server's own state machine; routing them through
     * the target-owned event queue can repeatedly feed unrelated protocol
     * traps back into startup and starve start_process(). */
    if (parent_owned_mode && nested_server && nested_server_outer_pid <= 0 &&
        request == PTRACE_CONT && !nested_is_shadow(pid)) {
        event_trace_log("[ida-vtdbg-shim] pre-session ptrace continue passthrough pid=%d\n",
                        pid);
        return server_ptrace_call(request, pid, addr, data);
    }

    if (parent_owned_mode && nested_target && !nested_target_launcher &&
        request == PTRACE_CONT && pid == nested_target_child_pid &&
        parent_owned_take_step_after_protocol(pid)) {
        trace_log("[ida-vtdbg-shim] parent-owned protocol CONT -> SINGLESTEP child=%d\n",
                  pid);
        request = PTRACE_SINGLESTEP;
    }

    if (nested_server || nested_event_worker) {
        long virtual_result;
        if (parent_owned_keep_unpresented_stop(request, pid, "libc")) {
            return 0;
        }
        if (nested_virtual_ptrace(request, pid, data, &virtual_result))
            return virtual_result;
        if (parent_owned_virtual_owner_ptrace(request, pid, data,
                                              &virtual_result)) {
            event_trace_log("[ida-vtdbg-shim] virtual owner ptrace req=%d tid=%d result=%ld\n",
                            request, pid, virtual_result);
            return virtual_result;
        }
        if (nested_is_shadow(pid) && parent_owned_mode) {
            if (request == PTRACE_KILL)
                return nested_driver_forward_ptrace(request, pid, addr, data);
            if (request == PTRACE_SETOPTIONS || request == PTRACE_ATTACH ||
                request == PTRACE_SEIZE) {
                nested_virtual_child_attach_ack(pid);
                return 0;
            }
            /* The real parent's wait hook is in another process. Held-child
             * CONT/SINGLESTEP must reach it through the driver mailbox;
             * setting a server-local resume bit and returning success loses
             * the request and also bypasses protocol-step observation. */
            if (request == PTRACE_CONT &&
                !parent_owned_visible_child_stop(pid))
                return 0;
            if ((request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                 request == PTRACE_DETACH || request == PTRACE_KILL) &&
                !parent_owned_proxy_stop_held(pid, false, false))
                return 0;
            return nested_driver_forward_ptrace(request, pid, addr, data);
        }
        if (nested_is_shadow(pid))
            return nested_forward_ptrace(request, pid, addr, data);
    }
    if (direct_target && request == PTRACE_TRACEME) {
        trace_log("[ida-vtdbg-shim] direct target virtualized PTRACE_TRACEME pid=%d\n",
                  getpid());
        return 0;
    }
    if (!compat_enabled || real_ptrace == NULL) {
        int peek_errno = 0;
        if ((request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) &&
            nested_virtual_breakpoint_peek(pid, addr, &result))
            return result;
        if (nested_target && !nested_target_launcher &&
            request == PTRACE_CONT)
            (void)nested_target_arm_protocol_step(pid);
        if (nested_target && !nested_target_launcher &&
            (request == PTRACE_SETREGS || request == PTRACE_SETREGSET ||
             request == PTRACE_CONT || request == PTRACE_SINGLESTEP))
            event_trace_log("[ida-vtdbg-shim] target direct ptrace dispatch request=%d child=%d\n",
                            request, pid);
        result = request == PTRACE_TRACEME
                     ? real_ptrace(request, 0, NULL, NULL)
                     : real_ptrace(request, pid, addr, data);
        if (nested_target && !nested_target_launcher &&
            (request == PTRACE_SETREGS || request == PTRACE_SETREGSET ||
             request == PTRACE_CONT || request == PTRACE_SINGLESTEP))
            event_trace_log("[ida-vtdbg-shim] target direct ptrace result request=%d child=%d result=%ld errno=%d\n",
                            request, pid, result, result < 0 ? errno : 0);
        if (nested_target && !nested_target_launcher && result == 0 &&
            request == PTRACE_SETREGS && pid > 0) {
            struct user_regs_struct verified_regs;
            long verify_result;

            memset(&verified_regs, 0, sizeof(verified_regs));
            verify_result = ptrace_raw(PTRACE_GETREGS, pid, NULL,
                                       &verified_regs);
            event_trace_log("[ida-vtdbg-shim] target direct SETREGS verify child=%d result=%ld errno=%d rip=0x%llx\n",
                            pid, verify_result,
                            verify_result < 0 ? errno : 0,
                            (unsigned long long)verified_regs.rip);
        }
        if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT)
            peek_errno = errno;
        if (nested_target && !nested_target_launcher &&
            (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) &&
            peek_errno == 0) {
            uintptr_t logical_word = (uintptr_t)result;
            bool overlaid = nested_overlay_target_breakpoint_value(
                pid, addr, &logical_word);
            if (overlaid) {
                result = (long)logical_word;
            }
            if (event_trace_enabled && oneshot_algorithm_done &&
                target_peek_diag_count++ < 64u)
                event_trace_log("[ida-vtdbg-shim] target PEEKDATA pid=%d addr=0x%llx raw=0x%llx overlaid=%d out=0x%llx\n",
                                pid, (unsigned long long)(uintptr_t)addr,
                                (unsigned long long)(uintptr_t)result,
                                overlaid ? 1 : 0,
                                (unsigned long long)logical_word);
            errno = peek_errno;
        }
        if (nested_target && !nested_target_launcher && result == 0 &&
            request == PTRACE_SETREGS && data != NULL)
            (void)nested_target_capture_protocol_regs(
                pid, (const struct user_regs_struct *)data);
        else if (nested_target && !nested_target_launcher && result == 0 &&
                 request == PTRACE_SETREGSET)
            (void)nested_target_capture_protocol_regset(pid, addr, data);
        trace_log("[ida-vtdbg-shim] ptrace request=%d pid=%d result=%ld errno=%d\n",
                  request, pid, result, result < 0 ? errno : 0);
        return result;
    }

    /* Preserve IDA's own ptrace thread/state machine.  Only broker-internal
     * operations in handle_syscall_stop() use ptrace_dispatch(), which may
     * route a request to the thread that owns the Linux ptrace relationship. */
    if (syscall_mediation && request == PTRACE_SETOPTIONS) {
        unsigned long options = (unsigned long)(uintptr_t)data;
        unsigned long requested_options = options;
        options |= PTRACE_O_TRACESYSGOOD;
        if (!parent_owned_mode)
            options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
        trace_log("[ida-vtdbg-shim] ptrace SETOPTIONS pid=%d requested=0x%lx effective=0x%lx parent_owned=%d\n",
                  pid, requested_options, options, parent_owned_mode ? 1 : 0);
        data = (void *)(uintptr_t)options;
    }
    if (syscall_mediation && request == PTRACE_SEIZE) {
        unsigned long options = (unsigned long)(uintptr_t)data;
        unsigned long requested_options = options;
        options |= PTRACE_O_TRACESYSGOOD;
        if (!parent_owned_mode)
            options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK;
        trace_log("[ida-vtdbg-shim] ptrace SEIZE pid=%d requested=0x%lx effective=0x%lx parent_owned=%d\n",
                  pid, requested_options, options, parent_owned_mode ? 1 : 0);
        data = (void *)(uintptr_t)options;
    }
    if ((request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) &&
        nested_virtual_breakpoint_peek(pid, addr, &result))
        return result;
    if (!parent_owned_mode && syscall_mediation && request == PTRACE_CONT &&
        tid_is_compat(pid)) {
        unsigned long tree_options = PTRACE_O_TRACESYSGOOD |
                                     PTRACE_O_TRACEFORK |
                                     PTRACE_O_TRACEVFORK;

        if (ptrace_raw(PTRACE_SETOPTIONS, pid, NULL,
                       (void *)(uintptr_t)tree_options) < 0)
            trace_log("[ida-vtdbg-shim] tree options pid=%d unavailable errno=%d (%s)\n",
                      pid, errno, strerror(errno));
        else
            trace_log("[ida-vtdbg-shim] tree options armed pid=%d flags=0x%lx\n",
                      pid, tree_options);
    }
    if (syscall_mediation && request == PTRACE_CONT &&
        tid_is_compat(pid) && note_continue_and_should_mediate(pid))
        request = PTRACE_SYSCALL;
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT)
        nested_breakpoint_write_prepare_local(
            pid, addr, (uintptr_t)data, &breakpoint_write);
    if (nested_target && !nested_target_launcher &&
        (request == PTRACE_SETREGS || request == PTRACE_SETREGSET ||
         request == PTRACE_CONT || request == PTRACE_SINGLESTEP))
        event_trace_log("[ida-vtdbg-shim] target libc ptrace dispatch request=%d child=%d\n",
                        request, pid);
    result = request == PTRACE_TRACEME
                 ? real_ptrace(request, 0, NULL, NULL)
                 : real_ptrace(request, pid, addr, data);
    parent_owned_note_real_resume(request, pid, result);
    if (request == PTRACE_SETREGS || request == PTRACE_CONT ||
        request == PTRACE_SINGLESTEP)
        event_trace_log("[ida-vtdbg-shim] target libc ptrace request=%d pid=%d result=%ld errno=%d\n",
                        request, pid, result, result < 0 ? errno : 0);
    if (nested_target && !nested_target_launcher && result == 0 &&
        request == PTRACE_SETREGS && pid > 0) {
        struct user_regs_struct verified_regs;
        long verify_result;

        memset(&verified_regs, 0, sizeof(verified_regs));
        verify_result = ptrace_raw(PTRACE_GETREGS, pid, NULL,
                                   &verified_regs);
        event_trace_log("[ida-vtdbg-shim] target SETREGS verify child=%d result=%ld errno=%d rip=0x%llx\n",
                        pid, verify_result,
                        verify_result < 0 ? errno : 0,
                        (unsigned long long)verified_regs.rip);
    }
    if (nested_target && !nested_target_launcher && result == 0 &&
        request == PTRACE_SETREGS && data != NULL) {
        const struct user_regs_struct *set_regs = data;
        if (parent_owned_get_program_exception(pid, NULL, NULL, NULL)) {
            parent_owned_set_exception_resume(pid, true,
                                              (uintptr_t)set_regs->rip);
            event_trace_log("[ida-vtdbg-shim] target libc SETREGS exception resume captured child=%d rip=0x%llx\n",
                            pid, (unsigned long long)set_regs->rip);
        }
        (void)nested_target_capture_protocol_regs(pid, set_regs);
    }
    else if (nested_target && !nested_target_launcher && result == 0 &&
             request == PTRACE_SETREGSET)
        (void)nested_target_capture_protocol_regset(pid, addr, data);
    if (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) {
        if (result < 0 && restore_running_parent_word(pid, addr, data))
            result = 0;
        if (result < 0 && parent_owned_mode &&
            (nested_breakpoint_word_has_cc(data) ||
             nested_breakpoint_word_registered((uintptr_t)addr)) &&
            (errno == ESRCH || errno == EIO || errno == EFAULT ||
             errno == EPERM)) {
            trace_log("[ida-vtdbg-shim] virtualize failed libc breakpoint write pid=%d addr=0x%llx errno=%d\n",
                      pid, (unsigned long long)(uintptr_t)addr, errno);
            nested_note_parent_breakpoint_write(pid, addr, data, 0,
                                                &breakpoint_write);
            result = 0;
        } else {
            nested_note_parent_breakpoint_write(pid, addr, data, result,
                                                &breakpoint_write);
        }
    }
    if (nested_target && !nested_target_launcher && result == 0 &&
        (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT))
        nested_note_target_breakpoint_restore(pid, addr, data);
    if (nested_server && result == 0 &&
        (request == PTRACE_SEIZE || request == PTRACE_ATTACH))
        nested_server_owner_tid = current_tid();
    if (nested_target && !nested_target_launcher && result == 0) {
        if (request == PTRACE_SEIZE || request == PTRACE_ATTACH) {
            nested_target_owner_tid = current_tid();
            nested_target_child_pid = pid;
            nested_target_send_event(NESTED_EVENT_PTRACE, pid, 0,
                                     (int)request);
        } else if (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                   request == PTRACE_DETACH || request == PTRACE_KILL) {
            nested_target_send_event(NESTED_EVENT_PTRACE, pid, 0,
                                     (int)request);
        }
    }
    if (nested_target && !nested_target_launcher &&
        request == PTRACE_SEIZE && result == 0) {
        nested_target_owner_tid = current_tid();
        nested_target_child_pid = pid;
        nested_target_send_event(NESTED_EVENT_PTRACE, pid, 0, request);
    }
    trace_log("[ida-vtdbg-shim] ptrace result request=%d pid=%d self=%d result=%ld errno=%d\n",
              request, pid, current_tid(), result, result < 0 ? errno : 0);
    if (result == 0) {
        if (request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
            set_target_owner(pid, current_tid());
            if (parent_owned_mode && nested_event_worker) {
                nested_server_outer_pid = pid;
                nested_server_owner_tid = current_tid();
            }
            register_best_effort(pid);
        } else if (request == PTRACE_TRACEME)
            register_best_effort(getpid());
        else if (request == PTRACE_DETACH || request == PTRACE_KILL)
            unregister_tid_best_effort(pid);
    }
    return result;
}

/* linux_server uses both libc ptrace() and syscall(SYS_ptrace, ...).  Keep the
 * latter on the same policy path; the target never sees this wrapper because
 * exec sanitization removes the preload from the tracee environment. */
long syscall(long number, ...)
{
    va_list ap;
    unsigned long args[6] = {0, 0, 0, 0, 0, 0};
    long result;
    bool trace_process_exit_signal = false;

    pthread_once(&resolve_once, resolve_symbols);
    va_start(ap, number);
    for (size_t index = 0; index < 6; ++index)
        args[index] = va_arg(ap, unsigned long);
    va_end(ap);
    if (parent_owned_mode && nested_server && nested_server_outer_pid > 0) {
        if (number == SYS_kill && (int)args[1] == SIGKILL &&
            ((pid_t)args[0] == nested_server_outer_pid ||
             nested_is_shadow((pid_t)args[0])))
            trace_process_exit_signal = true;
#ifdef SYS_tgkill
        if (number == SYS_tgkill && (int)args[2] == SIGKILL &&
            ((pid_t)args[0] == nested_server_outer_pid ||
             nested_is_shadow((pid_t)args[1])))
            trace_process_exit_signal = true;
#endif
#ifdef SYS_tkill
        if (number == SYS_tkill && (int)args[1] == SIGKILL &&
            ((pid_t)args[0] == nested_server_outer_pid ||
             nested_is_shadow((pid_t)args[0])))
            trace_process_exit_signal = true;
#endif
    }
    if (trace_process_exit_signal)
        event_trace_log("[ida-vtdbg-shim] raw ProcessExit signal syscall nr=%ld a0=%lu a1=%lu a2=%lu\n",
                        number, args[0], args[1], args[2]);
    if (compat_enabled && parent_owned_mode && nested_server &&
        nested_server_outer_pid > 0 &&
        ((number == SYS_kill &&
          ((pid_t)args[0] == nested_server_outer_pid ||
           nested_is_shadow((pid_t)args[0]))) ||
         (number == SYS_tgkill &&
          (pid_t)args[0] == nested_server_outer_pid)))
        event_trace_log("[ida-vtdbg-shim] server ProcessExit signal syscall nr=%ld a0=%lu a1=%lu a2=%lu\n",
                        number, args[0], args[1], args[2]);
#if defined(SYS_tkill)
    if (number == SYS_tkill && compat_enabled && parent_owned_mode &&
        (nested_event_worker || nested_server) &&
        (int)args[1] == SIGSTOP) {
        pid_t tid = (pid_t)args[0];
        bool owner_ack = parent_owned_frozen_owner_stop(tid);
        bool shadow = nested_is_shadow(tid);
        bool held = shadow &&
                    parent_owned_proxy_stop_held(tid, false, false);
        bool acknowledged = shadow &&
                            parent_owned_frozen_child_stop(tid);

        event_trace_log("[ida-vtdbg-shim] parent-owned tkill stop tid=%d owner_ack=%d shadow=%d held=%d child_ack=%d\n",
                        tid, owner_ack ? 1 : 0,
                        shadow ? 1 : 0, held ? 1 : 0,
                        acknowledged ? 1 : 0);
        if (owner_ack || acknowledged)
            return 0;
    }
#endif
    if (number == SYS_ptrace && compat_enabled) {
        enum __ptrace_request request = (enum __ptrace_request)args[0];
        pid_t pid = (pid_t)args[1];
        void *addr = (void *)(uintptr_t)args[2];
        void *data = (void *)(uintptr_t)args[3];
        if (parent_owned_reject_wait_step(request, pid))
            return -1;
        if (parent_owned_mode && nested_server &&
            nested_resume_request(request))
            event_trace_log("[ida-vtdbg-shim] server raw resume entry request=%d pid=%d shadow=%d held=%d\n",
                            request, pid, nested_is_shadow(pid) ? 1 : 0,
                            parent_owned_proxy_stop_held(pid, false, false) ? 1 : 0);
        if (parent_owned_mode && nested_server &&
            (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT ||
             request == PTRACE_POKEUSER))
            event_trace_log("[ida-vtdbg-shim] server raw breakpoint write entry pid=%d addr=0x%llx value=0x%llx shadow=%d held=%d\n",
                            pid, (unsigned long long)(uintptr_t)addr,
                            (unsigned long long)(uintptr_t)data,
                            nested_is_shadow(pid) ? 1 : 0,
                            parent_owned_proxy_stop_held(pid, false, false) ? 1 : 0);
        if (nested_server || nested_event_worker) {
            long virtual_result;
            uintptr_t debug_value;
            if (parent_owned_keep_unpresented_stop(request, pid, "syscall")) {
                return 0;
            }
            if (parent_owned_mode && nested_server &&
                request == PTRACE_POKEUSER &&
                nested_protocol_hw_step_write(pid, (uintptr_t)addr,
                                              (uintptr_t)data))
                return 0;
            if (parent_owned_mode && nested_server &&
                request == PTRACE_PEEKUSER &&
                nested_protocol_hw_step_peek(pid, (uintptr_t)addr,
                                             &debug_value))
                return (long)debug_value;
            if (parent_owned_mode && nested_server &&
                (request == PTRACE_CONT || request == PTRACE_SINGLESTEP) &&
                nested_protocol_hw_step_pending(pid))
                return nested_driver_forward_ptrace(request, pid, addr,
                                                    data);
            if (nested_virtual_ptrace(request, pid, (void *)(uintptr_t)args[3],
                                      &virtual_result))
                return virtual_result;
            if (parent_owned_virtual_owner_ptrace(
                    request, pid, data, &virtual_result)) {
                event_trace_log("[ida-vtdbg-shim] virtual owner raw-ptrace req=%d tid=%d result=%ld\n",
                                request, pid, virtual_result);
                return virtual_result;
            }
            if (nested_is_shadow(pid) && parent_owned_mode) {
                if (request == PTRACE_KILL)
                    return nested_driver_forward_ptrace(request, pid, addr, data);
                if (request == PTRACE_SETOPTIONS ||
                    request == PTRACE_ATTACH || request == PTRACE_SEIZE) {
                    nested_virtual_child_attach_ack(pid);
                    return 0;
                }
                if (request == PTRACE_CONT &&
                    !parent_owned_visible_child_stop(pid))
                    return 0;
                if ((request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                     request == PTRACE_DETACH || request == PTRACE_KILL) &&
                    !parent_owned_proxy_stop_held(pid, false, false))
                    return 0;
                return nested_driver_forward_ptrace(request, pid, addr, data);
            }
            if (nested_is_shadow(pid))
                return nested_forward_ptrace(request, pid, addr, data);
        }
        if (nested_target && !nested_target_launcher) {
            int peek_errno = 0;
            if (request == PTRACE_CONT)
                (void)nested_target_arm_protocol_step(pid);
            long local_result = ptrace_raw(request, pid, addr, data);
            if (request == PTRACE_SETREGS || request == PTRACE_CONT ||
                request == PTRACE_SINGLESTEP)
                event_trace_log("[ida-vtdbg-shim] target raw ptrace request=%d pid=%d result=%ld errno=%d\n",
                                request, pid, local_result,
                                local_result < 0 ? errno : 0);
            if (request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT)
                peek_errno = errno;
            if ((request == PTRACE_PEEKDATA || request == PTRACE_PEEKTEXT) &&
                peek_errno == 0) {
                uintptr_t logical_word = (uintptr_t)local_result;
                if (nested_overlay_target_breakpoint_value(
                        pid, addr, &logical_word))
                    local_result = (long)logical_word;
                errno = peek_errno;
            }
            /* These writes come from tradre's own parent VM, not IDA's
             * breakpoint manager.  The parent already writes the real child
             * through its kernel ptrace relationship; do not register or
             * replay its graph patches as debugger software breakpoints. */
            if ((request == PTRACE_POKEDATA || request == PTRACE_POKETEXT) &&
                nested_breakpoint_word_has_cc(data))
                event_trace_log("[ida-vtdbg-shim] parent VM POKE pid=%d addr=0x%llx value=0x%llx result=%ld (not an IDA breakpoint)\n",
                                pid, (unsigned long long)(uintptr_t)addr,
                                (unsigned long long)(uintptr_t)data,
                                local_result);
            if (local_result == 0 &&
                (request == PTRACE_POKEDATA || request == PTRACE_POKETEXT))
                nested_note_target_breakpoint_restore(pid, addr, data);
            if (local_result == 0 && request == PTRACE_SETREGS &&
                data != NULL)
                (void)nested_target_capture_protocol_regs(
                    pid, (const struct user_regs_struct *)data);
            else if (local_result == 0 && request == PTRACE_SETREGSET)
                (void)nested_target_capture_protocol_regset(pid, addr, data);
            if (local_result == 0 &&
                (request == PTRACE_SEIZE || request == PTRACE_ATTACH)) {
                nested_target_owner_tid = current_tid();
                nested_target_child_pid = pid;
                nested_target_send_event(NESTED_EVENT_PTRACE, pid, 0,
                                         (int)request);
            } else if (local_result == 0 &&
                       (request == PTRACE_CONT || request == PTRACE_SYSCALL ||
                        request == PTRACE_DETACH || request == PTRACE_KILL)) {
                nested_target_send_event(NESTED_EVENT_PTRACE, pid, 0,
                                         (int)request);
            }
            return local_result;
        }
        if (nested_server &&
            (request == PTRACE_SEIZE || request == PTRACE_ATTACH)) {
            long owner_result = server_ptrace_call(request, pid, addr, data);
            if (owner_result == 0)
                nested_server_owner_tid = current_tid();
            return owner_result;
        }
        return server_ptrace_call(request, pid, addr, data);
    }
    if (number == SYS_ptrace && parent_owned_mode && nested_target &&
        !nested_target_launcher) {
        enum __ptrace_request request = (enum __ptrace_request)args[0];
        pid_t pid = (pid_t)args[1];
        void *data = (void *)(uintptr_t)args[3];

        if (request == PTRACE_SETREGS && data != NULL)
            event_trace_log("[ida-vtdbg-shim] target raw SETREGS child=%d rip=0x%llx\n",
                            pid,
                            (unsigned long long)((const struct user_regs_struct *)data)->rip);
        else if (request == PTRACE_SETREGSET && data != NULL &&
                 (uintptr_t)args[2] == 1u) {
            const struct iovec *iov = data;
            if (iov->iov_base != NULL &&
                iov->iov_len >= sizeof(struct user_regs_struct))
                event_trace_log("[ida-vtdbg-shim] target raw SETREGSET child=%d rip=0x%llx\n",
                                pid,
                                (unsigned long long)((const struct user_regs_struct *)iov->iov_base)->rip);
        } else if (request == PTRACE_CONT || request == PTRACE_SINGLESTEP)
            event_trace_log("[ida-vtdbg-shim] target raw resume request=%d child=%d\n",
                            request, pid);

        if (nested_server_outer_pid <= 0 &&
            (request == PTRACE_DETACH || request == PTRACE_KILL ||
             request == PTRACE_CONT || request == PTRACE_SINGLESTEP ||
             request == PTRACE_SYSCALL || request == PTRACE_SETOPTIONS ||
             request == PTRACE_POKEDATA || request == PTRACE_POKETEXT)) {
            event_trace_log("[ida-vtdbg-shim] idempotent raw ProcessExit cleanup request=%d pid=%d\n",
                            request, pid);
            return 0;
        }
        if (request == PTRACE_CONT)
            (void)nested_target_arm_protocol_step(pid);
        result = real_syscall(number, args[0], args[1], args[2], args[3],
                              args[4], args[5]);
        if (result == 0 && request == PTRACE_SETREGS && data != NULL) {
            const struct user_regs_struct *set_regs = data;
            if (parent_owned_get_program_exception(pid, NULL, NULL, NULL)) {
                parent_owned_set_exception_resume(pid, true,
                                                  (uintptr_t)set_regs->rip);
                event_trace_log("[ida-vtdbg-shim] target raw SETREGS exception resume captured child=%d rip=0x%llx\n",
                                pid, (unsigned long long)set_regs->rip);
            }
            (void)nested_target_capture_protocol_regs(pid, set_regs);
        }
        else if (result == 0 && request == PTRACE_SETREGSET)
            (void)nested_target_capture_protocol_regset(
                pid, (void *)(uintptr_t)args[2], data);
        return result;
    }
    if (number == SYS_ptrace && parent_owned_mode && nested_target &&
        !nested_target_launcher &&
        (enum __ptrace_request)args[0] == PTRACE_CONT &&
        (pid_t)args[1] == nested_target_child_pid &&
        parent_owned_take_step_after_protocol((pid_t)args[1])) {
        trace_log("[ida-vtdbg-shim] parent-owned raw CONT -> SINGLESTEP child=%d\n",
                  (pid_t)args[1]);
        return ptrace_raw(PTRACE_SINGLESTEP, (pid_t)args[1],
                          (void *)(uintptr_t)args[2],
                          (void *)(uintptr_t)args[3]);
    }
    if (number == SYS_ptrace && direct_target &&
        (enum __ptrace_request)args[0] == PTRACE_TRACEME) {
        trace_log("[ida-vtdbg-shim] direct target virtualized raw PTRACE_TRACEME pid=%d\n",
                  getpid());
        return 0;
    }
    /* IDA's linux_server has launch paths that issue SYS_wait4 directly
     * instead of calling waitpid()/wait4() through the PLT.  Keep that one
     * wait entry on the same event normalization path; the kernel remains
     * the source of the real ptrace fork stop and ptrace ownership is never
     * transferred to this shim. */
    if (number == SYS_wait4 && compat_enabled && syscall_mediation &&
        !inside_wait_broker) {
        return broker_wait((pid_t)args[0], (int *)(uintptr_t)args[1],
                           (int)args[2],
                           (struct rusage *)(uintptr_t)args[3], true);
    }
    if (number == SYS_wait4 && parent_owned_mode && nested_target &&
        !nested_target_launcher && !inside_wait_broker) {
        return nested_target_wait4((pid_t)args[0],
                                   (int *)(uintptr_t)args[1], (int)args[2],
                                   (struct rusage *)(uintptr_t)args[3]);
    }
    result = real_syscall(number, args[0], args[1], args[2], args[3],
                          args[4], args[5]);
    if (trace_process_exit_signal)
        event_trace_log("[ida-vtdbg-shim] raw ProcessExit signal result nr=%ld result=%ld errno=%d\n",
                        number, result, result < 0 ? errno : 0);
    if (compat_enabled && parent_owned_mode && nested_server &&
        nested_server_outer_pid > 0 &&
        ((number == SYS_kill &&
          ((pid_t)args[0] == nested_server_outer_pid ||
           nested_is_shadow((pid_t)args[0]))) ||
         (number == SYS_tgkill &&
          (pid_t)args[0] == nested_server_outer_pid)))
        event_trace_log("[ida-vtdbg-shim] server ProcessExit signal result nr=%ld result=%ld errno=%d\n",
                        number, result, result < 0 ? errno : 0);
    return result;
}

/* The child is a separate process, only displayed as an IDA thread. Map
 * linux_server's read-only thread-name lookup to its real procfs identity.
 * Do not remap the target parent's own /proc reads or fabricate metadata. */
static const char *nested_proc_comm_path(const char *path, const char *mode,
                                        char *mapped, size_t capacity)
{
    int root = 0, child = 0, consumed = 0;
    if (path == NULL || mode == NULL || mode[0] != 'r' ||
        strchr(mode, '+') != NULL || !nested_server || !parent_owned_mode)
        return path;
    if (sscanf(path, "/proc/%d/task/%d/comm%n", &root, &child, &consumed) != 2 ||
        consumed <= 0 || path[consumed] != '\0' ||
        root != nested_server_outer_pid || !nested_is_shadow(child))
        return path;
    (void)snprintf(mapped, capacity, "/proc/%d/task/%d/comm", child, child);
    return mapped;
}

FILE *fopen(const char *path, const char *mode)
{
    char mapped[96];
    pthread_once(&resolve_once, resolve_symbols);
    if (real_fopen == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    return real_fopen(nested_proc_comm_path(path, mode, mapped, sizeof(mapped)), mode);
}

FILE *fopen64(const char *path, const char *mode)
{
    char mapped[96];
    pthread_once(&resolve_once, resolve_symbols);
    if (real_fopen64 == NULL) {
        errno = ENOSYS;
        return NULL;
    }
    return real_fopen64(nested_proc_comm_path(path, mode, mapped, sizeof(mapped)), mode);
}

int kill(pid_t pid, int signal_number)
{
    long result;

    pthread_once(&resolve_once, resolve_symbols);
    if (parent_owned_mode && nested_server && nested_server_outer_pid > 0 &&
        (pid == nested_server_outer_pid || nested_is_shadow(pid)))
        event_trace_log("[ida-vtdbg-shim] server libc kill ProcessExit pid=%d signal=%d\n",
                        pid, signal_number);
    result = real_syscall6(SYS_kill, (unsigned long)pid,
                           (unsigned long)signal_number, 0, 0, 0, 0);
    if (parent_owned_mode && nested_server && nested_server_outer_pid > 0 &&
        (pid == nested_server_outer_pid || nested_is_shadow(pid)))
        event_trace_log("[ida-vtdbg-shim] server libc kill result pid=%d signal=%d result=%ld errno=%d\n",
                        pid, signal_number, result,
                        result < 0 ? errno : 0);
    return (int)result;
}

pid_t fork(void)
{
    pid_t child;

    pthread_once(&resolve_once, resolve_symbols);
    child = real_fork != NULL ? real_fork() : (pid_t)real_syscall(SYS_fork);
    if (nested_target && !nested_target_launcher) {
        if (child > 0 && parent_owned_mode) {
            nested_target_child_pid = child;
            nested_target_owner_tid = current_tid();
            parent_owned_set_owner_tid(child, nested_target_owner_tid);
            parent_owned_mark_initial_proxy(child);
            if (nested_kernel_events)
                nested_target_report_child(child, 0);
            trace_log("[ida-vtdbg-shim] parent-owned mark initial proxy parent=%d child=%d\n",
                      getpid(), child);
        }
        if (child > 0 && !nested_kernel_events)
            nested_record_fork(child);
        else if (child == 0 && parent_owned_mode) {
            ssize_t ignored_write;

            replay_target_stdin_after_fork();

            /* Acquire the child through its real parent before it returns to
             * application code.  IDA may already have patched a software BP
             * at the child entry in the parent's address space; a plain fork
             * would inherit and execute that INT3 before the application's
             * own PTRACE_TRACEME call.  The initial SIGSTOP makes the real
             * parent-owned relationship observable before any app byte runs. */
            if (nested_target_event_fd >= 0) {
                close(nested_target_event_fd);
                nested_target_event_fd = -1;
            }
            nested_target = false;
            if (ptrace_raw(PTRACE_TRACEME, 0, NULL, NULL) == 0) {
                static const char pretrace_ok[] =
                    "[ida-vtdbg-shim] parent-owned fork child pretraced\n";
                ignored_write = write(STDERR_FILENO, pretrace_ok,
                                      sizeof(pretrace_ok) - 1);
                (void)ignored_write;
                if (real_syscall6(SYS_tgkill, (unsigned long)getpid(),
                                  (unsigned long)current_tid(), SIGSTOP,
                                  0, 0, 0) < 0) {
                    static const char stop_failed[] =
                        "[ida-vtdbg-shim] parent-owned initial SIGSTOP failed\n";
                    ignored_write = write(STDERR_FILENO, stop_failed,
                                          sizeof(stop_failed) - 1);
                    (void)ignored_write;
                }
            } else {
                static const char pretrace_failed[] =
                    "[ida-vtdbg-shim] parent-owned fork child PTRACE_TRACEME failed\n";
                ignored_write = write(STDERR_FILENO, pretrace_failed,
                                      sizeof(pretrace_failed) - 1);
                (void)ignored_write;
            }
        } else if (child == 0 && nested_conn_fd >= 0) {
            /* The tracee child must not keep the relay endpoint open.  It is
             * not the ptrace owner and has no relay work to perform. */
            close(nested_conn_fd);
            nested_conn_fd = -1;
            nested_target = false;
        }
    }
    return child;
}

static pid_t ida_vtdbg_waitpid_impl(pid_t pid, int *status, int options)
{
    pthread_once(&resolve_once, resolve_symbols);
    trace_log("[ida-vtdbg-shim] waitpid wrapper self=%d pid=%d options=0x%x nested_server=%d inside=%d\n",
              current_tid(), pid, options, nested_server, inside_wait_broker);
    if (nested_target && !nested_target_launcher)
        return nested_target_waitpid(pid, status, options);
    if (nested_event_worker && !parent_owned_mode) {
        pid_t event_pid = nested_worker_wait_event(pid, status, options);
        if (event_pid != -2)
            return event_pid;
    }
    if (nested_server && pid > 0 && nested_is_shadow(pid)) {
        pid_t relay = nested_server_waitpid(pid, status, options);
        if (relay != -2)
            return relay;
    }
    return broker_wait(pid, status, options, NULL, false);
}

/* linux_server's child_waiter_t may bind the glibc-internal __waitpid symbol
 * directly instead of going through the public PLT entry.  Keep it on the
 * same policy/event path so the kernel-assisted nested queue is visible to
 * every reaper thread. */
static pid_t ida_vtdbg___waitpid_impl(pid_t pid, int *status, int options)
{
    pthread_once(&resolve_once, resolve_symbols);
    trace_log("[ida-vtdbg-shim] __waitpid wrapper self=%d pid=%d options=0x%x nested_server=%d inside=%d\n",
              current_tid(), pid, options, nested_server, inside_wait_broker);
    if (nested_target && !nested_target_launcher)
        return nested_target_waitpid(pid, status, options);
    if (nested_event_worker && !parent_owned_mode) {
        pid_t event_pid = nested_worker_wait_event(pid, status, options);
        if (event_pid != -2)
            return event_pid;
    }
    if (nested_server) {
        nested_poll_kernel_events();
        nested_poll_messages();
    }
    if (nested_server && pid > 0 && nested_is_shadow(pid)) {
        pid_t relay = nested_server_waitpid(pid, status, options);
        if (relay != -2)
            return relay;
    }
    return broker_wait(pid, status, options, NULL, false);
}

static pid_t ida_vtdbg_wait4_impl(pid_t pid, int *status, int options, struct rusage *usage)
{
    pthread_once(&resolve_once, resolve_symbols);
    if (nested_target && !nested_target_launcher)
        return nested_target_wait4(pid, status, options, usage);
    if (nested_server && pid > 0 && nested_is_shadow(pid)) {
        pid_t relay = nested_server_wait4(pid, status, options, usage);
        if (relay != -2)
            return relay;
    }
    return broker_wait(pid, status, options, usage, true);
}

static pid_t ida_vtdbg_wait_impl(int *status)
{
    pthread_once(&resolve_once, resolve_symbols);
    if (nested_target && !nested_target_launcher)
        return nested_target_wait(status);
    return real_wait(status);
}

__attribute__((visibility("hidden")))
pid_t ida_vtdbg_wait_dispatch(struct user_regs_struct *regs, unsigned int kind)
{
    pthread_once(&resolve_once, resolve_symbols);
    int saved_errno = errno;
    uint64_t sequence = parent_owned_wait_enter(regs, kind);
    errno = saved_errno;
    pid_t result;
    switch (kind) {
    case 0:
        result = ida_vtdbg_waitpid_impl((pid_t)regs->rdi,
                                      (int *)(uintptr_t)regs->rsi, (int)regs->rdx);
        break;
    case 1:
        result = ida_vtdbg___waitpid_impl((pid_t)regs->rdi,
                                        (int *)(uintptr_t)regs->rsi, (int)regs->rdx);
        break;
    case 2:
        result = ida_vtdbg_wait4_impl((pid_t)regs->rdi,
                                    (int *)(uintptr_t)regs->rsi, (int)regs->rdx,
                                    (struct rusage *)(uintptr_t)regs->rcx);
        break;
    default:
        result = ida_vtdbg_wait_impl((int *)(uintptr_t)regs->rdi);
        break;
    }
    parent_owned_wait_leave(sequence);
    return result;
}

int waitid(idtype_t idtype, id_t id, siginfo_t *info, int options)
{
    pthread_once(&resolve_once, resolve_symbols);
    trace_log("[ida-vtdbg-shim] waitid wrapper self=%d idtype=%d id=%d options=0x%x nested_server=%d\n",
              current_tid(), (int)idtype, (int)id, options, nested_server);
    if (nested_server) {
        nested_poll_kernel_events();
        nested_poll_messages();
    }
    if (real_waitid == NULL) {
        errno = ENOSYS;
        return -1;
    }
    return real_waitid(idtype, id, info, options);
}
