#!/usr/bin/env bash
set -euo pipefail
project_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
source_tree=${IDA_JOINT_KBUILD_SOURCE:?set IDA_JOINT_KBUILD_SOURCE to a local kernel tree containing Kbuild scripts}
header_tree=${IDA_JOINT_KERNEL_HEADERS:-$project_dir/.kernel-build-$(uname -r)}
[[ -r /proc/config.gz && -f "$source_tree/Makefile" && -d "$source_tree/scripts" ]] || {
    echo "missing running config or local Kbuild source" >&2; exit 2;
}
release=$(uname -r)
[[ -f "$header_tree/include/generated/utsrelease.h" ]] || { echo "missing running-kernel headers" >&2; exit 2; }
grep -Fq "\"$release\"" "$header_tree/include/generated/utsrelease.h" || {
    echo "exported headers do not match the running kernel" >&2; exit 2;
}
# A fresh, explicit temporary overlay: never delete or overwrite another tree.
overlay=$(mktemp -d "$project_dir/.kernel-kbuild-overlay.XXXXXX")
mkdir -p "$overlay/arch/x86"
ln -s "$source_tree/Makefile" "$overlay/Makefile"
ln -s "$source_tree/scripts" "$overlay/scripts"
ln -s "$source_tree/tools" "$overlay/tools"
for item in "$source_tree/arch/x86"/*; do
    base=${item##*/}
    [[ $base == include ]] && continue
    ln -s "$item" "$overlay/arch/x86/$base"
done
cp -a "$header_tree/include" "$overlay/include"
cp -a "$header_tree/arch/x86/include" "$overlay/arch/x86/include"
zcat /proc/config.gz > "$overlay/.config"
mkdir -p "$overlay/include/config"
sed -E 's/^(CONFIG_[A-Za-z0-9_]+)="(.*)"$/\1=\2/' "$overlay/.config" > "$overlay/include/config/auto.conf"
printf '%s\n' "$release" > "$overlay/include/config/kernel.release"
printf '#define UTS_RELEASE "%s"\n' "$release" > "$overlay/include/generated/utsrelease.h"
: > "$overlay/Module.symvers"
echo "WARNING: exported-header fallback lacks a matching full Kbuild and symbol CRCs; loadability requires explicit verification." >&2
make -C "$overlay" M="$project_dir/driver" modules KBUILD_MODPOST_WARN=1 \
    SHELL=/bin/bash KCFLAGS=-fno-stack-protector CFLAGS_MODULE=-fno-stack-protector
printf 'overlay=%s\nmodule=%s\n' "$overlay" "$project_dir/driver/ida_joint_policy.ko"
