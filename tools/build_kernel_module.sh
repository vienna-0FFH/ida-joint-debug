#!/usr/bin/env bash
set -euo pipefail
project_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
kernel_build=${1:-${KERNEL_BUILD:-/lib/modules/$(uname -r)/build}}
[[ -f "$kernel_build/Makefile" ]] || { echo "missing prepared kernel build: $kernel_build" >&2; exit 2; }
running_release=$(uname -r)
build_release=$(make -s -C "$kernel_build" kernelrelease)
[[ "$running_release" == "$build_release" ]] || {
    echo "refusing module build: kernel $running_release != build $build_release" >&2
    exit 2
}
make -C "$kernel_build" M="$project_dir/driver" modules
printf 'module=%s\n' "$project_dir/driver/ida_joint_policy.ko"
