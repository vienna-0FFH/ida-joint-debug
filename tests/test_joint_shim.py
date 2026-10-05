#!/usr/bin/env python3
import os
import subprocess


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHIM = os.path.join(ROOT, "tools", "libida_joint_shim.so")
HARNESS = os.path.join(ROOT, "tests", "server_ptrace_harness")
TARGET = os.path.join(ROOT, "tests", "anti_debug_tracee")

environment = os.environ.copy()
environment["LD_PRELOAD"] = SHIM
environment["IDA_VTDBG_COMPAT"] = "1"
environment["IDA_VTDBG_TEST_POLICY"] = "1"
environment["IDA_VTDBG_MEDIATE_SYSCALLS"] = "1"

result = subprocess.run(
    [HARNESS, TARGET],
    env=environment,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=12,
)
print(result.stdout, end="")
if (result.returncode != 0 or "ANTI_DEBUG=passed" not in result.stdout or
        "shim-preload-leaked-into-target" in result.stdout or
        "shim-config-leaked-into-target" in result.stdout):
    raise SystemExit(f"IDA server shim test failed with status {result.returncode}")
print("ida-server-shim: syscall mediation and compat policy PASS")
