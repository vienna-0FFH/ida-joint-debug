#!/usr/bin/env bash
set -euo pipefail
project_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $(id -u) -eq 0 ]] || { echo "run as Linux root" >&2; exit 2; }
if grep -q '^ida_vtdbg_policy ' /proc/modules; then
    echo "a different policy module is active; refusing to alter it" >&2
    exit 2
fi
module=$project_dir/driver/ida_joint_policy.ko
release=$(/usr/sbin/modinfo -F vermagic "$module")
[[ ${release%% *} == "$(uname -r)" ]] || { echo "module kernel mismatch" >&2; exit 2; }
if grep -q '^ida_joint_policy ' /proc/modules; then
    /usr/sbin/rmmod ida_joint_policy # an active session makes this fail
fi
/usr/sbin/insmod "$module"
boot=$(</proc/sys/kernel/random/boot_id)
for name in policy_ioctl_smoke policy_mmap_smoke policy_owner_wait_context_smoke \
            policy_command_mailbox_smoke policy_command_exit_smoke \
            policy_stopped_owner_smoke policy_stopped_debugregs_smoke \
            policy_native_resume_boundary_smoke policy_stopped_query_exit_race_smoke; do
    "$project_dir/tests/$name"
done
"$project_dir/tests/policy_stopped_query_exit_race_smoke" --debug-registers
test "$boot" = "$(</proc/sys/kernel/random/boot_id)"
echo JOINT_KERNEL_SMOKES_PASS
