#!/usr/bin/env bash
set -euo pipefail
project_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
server=${IDA_JOINT_SERVER:-${IDA_LINUX_SERVER:-}}
port=${IDA_JOINT_PORT:-${IDA_LINUX_SERVER_PORT:-23960}}
workdir=${IDA_JOINT_WORKDIR:-$PWD}
server_log=${IDA_JOINT_SERVER_LOG:-${IDA_SERVER_LOG:-/dev/stdout}}
handler_log=${IDA_JOINT_HANDLER_LOG:-${IDA_VTDBG_HANDLER_LOG:-}}
record_handlers=${IDA_VTDBG_RECORD_HANDLERS:-0}
protocol_mode=stop
reload_module=0
input_file=${IDA_JOINT_INPUT_FILE:-}
generated_input=

usage() {
    printf '%s\n' 'usage: start_joint_server.sh --server /path/to/linux_server [options]' \
        '  --port PORT                    listener port (default 23960)' \
        '  --workdir DIR                  existing server working directory' \
        '  --reload-module                reload own module; fails if in use' \
        '  --protocol-mode stop|log       preserve program pauses or auto-continue' \
        '  --record-handlers              include detailed program handler records' \
        '  --handler-log PATH             append handler records to this file' \
        '  --input-file PATH              provide target stdin from an existing file' \
        '  --help'
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server|--port|--workdir|--protocol-mode|--handler-log|--input-file)
            [[ $# -ge 2 ]] || { echo "missing value for $1" >&2; exit 2; }
            case "$1" in
                --server) server=$2 ;;
                --port) port=$2 ;;
                --workdir) workdir=$2 ;;
                --protocol-mode) protocol_mode=$2 ;;
                --handler-log) handler_log=$2 ;;
                --input-file) input_file=$2 ;;
            esac
            shift 2 ;;
        --protocol-mode=*) protocol_mode=${1#*=}; shift ;;
        --reload-module) reload_module=1; shift ;;
        --record-handlers) record_handlers=1; shift ;;
        --no-record-handlers) record_handlers=0; shift ;;
        --help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done
case "$protocol_mode" in
    stop) auto_protocol=0 ;;
    log) auto_protocol=1; record_handlers=1 ;;
    *) echo "invalid protocol mode: $protocol_mode" >&2; exit 2 ;;
esac
[[ $(id -u) -eq 0 ]] || { echo "run as Linux root" >&2; exit 2; }
[[ -n "$server" && -x "$server" ]] || { echo "set --server or IDA_JOINT_SERVER to the licensed Linux server" >&2; exit 2; }
[[ $port =~ ^[0-9]+$ && $port -gt 0 && $port -lt 65536 ]] || { echo "invalid port" >&2; exit 2; }
[[ -d "$workdir" ]] || { echo "workdir does not exist: $workdir" >&2; exit 2; }
shim=$project_dir/tools/libida_joint_shim.so
module=$project_dir/driver/ida_joint_policy.ko
[[ -r "$shim" && -r "$module" ]] || { echo "build the shim and kernel module first" >&2; exit 1; }
# The ABI device name is stable. Never unload another module or change a
# user's active debugging session merely to acquire the same device.
if grep -q '^ida_vtdbg_policy ' /proc/modules; then
    echo "a different policy module already owns the ABI device; stop its sessions and unload it explicitly" >&2
    exit 1
fi
module_release=$(/usr/sbin/modinfo -F vermagic "$module")
[[ ${module_release%% *} == "$(uname -r)" ]] || { echo "module does not match running kernel" >&2; exit 1; }
if [[ $reload_module == 1 ]] && grep -q '^ida_joint_policy ' /proc/modules; then
    /usr/sbin/rmmod ida_joint_policy
fi
if ! grep -q '^ida_joint_policy ' /proc/modules; then
    /usr/sbin/insmod "$module"
fi
test -e /dev/vtdbg_policy
if [[ -n "$input_file" ]]; then
    [[ -r "$input_file" ]] || { echo "input file is not readable" >&2; exit 2; }
    exec <"$input_file"
elif [[ ${IDA_TRADRE_STDIN+x} == x ]]; then
    # Compatibility for a caller that explicitly supplies stdin; no sample or
    # expected input is embedded in the launcher.
    generated_input=$(mktemp /tmp/ida-joint-input.XXXXXX)
    printf '%s\n' "$IDA_TRADRE_STDIN" > "$generated_input"
    exec <"$generated_input"
    rm -f -- "$generated_input" # open fd owns the exact temporary inode
fi
cd -- "$workdir"
printf 'IDA Joint Debug protocol-mode=%s port=%s\n' "$protocol_mode" "$port"
exec env \
    LD_PRELOAD="$shim" \
    IDA_VTDBG_NESTED=1 IDA_VTDBG_NESTED_KERNEL=1 IDA_VTDBG_PARENT_OWNED=1 \
    IDA_VTDBG_COMPAT=1 IDA_VTDBG_MEDIATE_SYSCALLS=1 IDA_VTDBG_SHM=1 \
    IDA_VTDBG_PROTOCOL_INT3_ADDR=0 IDA_VTDBG_ONESHOT_ALGORITHM=0 \
    IDA_VTDBG_AUTO_CONTINUE_PROTOCOL="$auto_protocol" \
    IDA_VTDBG_RECORD_HANDLERS="$record_handlers" IDA_VTDBG_HANDLER_TRACE="$record_handlers" \
    IDA_VTDBG_TRACE_STATE=${IDA_VTDBG_TRACE_STATE:-0} IDA_VTDBG_HANDLER_LOG="$handler_log" \
    IDA_VTDBG_REPLAY_STDIN=${IDA_VTDBG_REPLAY_STDIN:-1} \
    IDA_VTDBG_TRACE=${IDA_VTDBG_TRACE:-0} IDA_VTDBG_TRACE_EVENTS=${IDA_VTDBG_TRACE_EVENTS:-0} \
    "$server" -t -p "$port" -v >"$server_log" 2>&1
