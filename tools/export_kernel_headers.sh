#!/usr/bin/env bash
set -euo pipefail
project_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
[[ $(id -u) -eq 0 ]] || { echo "run as Linux root" >&2; exit 2; }
destination=${IDA_JOINT_KERNEL_HEADERS:-$project_dir/.kernel-build-$(uname -r)}
if [[ -e "$destination" ]]; then
    echo "refusing to overwrite existing headers: $destination" >&2
    exit 2
fi
/usr/sbin/modprobe kheaders
[[ -r /sys/kernel/kheaders.tar.xz ]] || { echo "running kernel does not export kheaders" >&2; exit 2; }
mkdir -p -- "$destination"
tar -xJf /sys/kernel/kheaders.tar.xz -C "$destination"
grep UTS_RELEASE "$destination/include/generated/utsrelease.h"
printf 'headers=%s\n' "$destination"
