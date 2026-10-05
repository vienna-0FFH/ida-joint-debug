"""Bounded Windows/WSL IDA integration runner for source-generated fixtures.

No proprietary files, target samples or saved IDA databases are distributed.
The only external requirements are WSL, a licensed IDA with idalib, and the
kernel module/shim compiled for the running kernel. Server readiness comes
from its own listening event, never a guessed ptrace synchronization delay.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True, help="licensed linux_server path as seen from WSL")
    parser.add_argument("--distro", default="Ubuntu")
    parser.add_argument("--port", type=int, default=23961)
    parser.add_argument("--name", required=True, help="unique local result name")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--mode", choices=("over", "syscall", "multi_sw", "slot4"))
    args = parser.parse_args()
    if not args.name.replace("_", "").isalnum():
        parser.error("use letters, digits and underscores in --name")
    if os.name != "nt":
        parser.error("this runner controls WSL from Windows")
    base = ["wsl.exe", "-d", args.distro, "-u", "root", "-e"]

    def wsl(*parts, timeout=20):
        return subprocess.run(base + list(parts), capture_output=True, text=True,
                              errors="replace", timeout=timeout, check=True)

    def process_rows():
        reply = wsl("ps", "-eo", "pid=,ppid=,comm=,args=")
        return [(int(p[0]), int(p[1]), p[2], p[3]) for line in reply.stdout.splitlines()
                if len(p := line.strip().split(None, 3)) == 4 and p[0].isdigit() and p[1].isdigit()]

    linux_root = wsl("wslpath", "-a", "-u", str(ROOT)).stdout.strip()
    output = ROOT / "artifacts" / "joint_fixture" / args.name
    output.mkdir(parents=True, exist_ok=False)
    server_log = output / "server.log"
    linux_output = linux_root + "/artifacts/joint_fixture/" + args.name
    result = {"server_pid": None, "sessions": [], "errors": [], "cleanup_pids": []}
    result["boot_before"] = wsl("cat", "/proc/sys/kernel/random/boot_id").stdout.strip()
    before = process_rows()
    old_pids = {p[0] for p in before}
    if any(comm == "linux_server" and (f"-p {args.port}" in command or f"-p{args.port}" in command)
           for _, _, comm, command in before):
        raise RuntimeError("requested test port already has a server; no external process was stopped")
    target = linux_root + "/tests/parent_owned_call_tracee"
    handler_log = "/tmp/ida-joint-" + args.name + "-handlers.log"
    launcher = base + ["env", "IDA_JOINT_SERVER_LOG=" + linux_output + "/server.log",
        "bash", linux_root + "/tools/start_joint_server.sh", "--server", args.server,
        "--port", str(args.port), "--workdir", linux_root + "/tests",
        "--protocol-mode", "stop", "--record-handlers", "--handler-log", handler_log]
    server = subprocess.Popen(launcher, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server_pid = None
    try:
        deadline = time.monotonic() + 20
        while True:
            if server.poll() is not None:
                raise RuntimeError("server exited before readiness")
            if server_log.exists() and "Listening on" in server_log.read_text(errors="replace"):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("server did not publish readiness within the failure budget")
            time.sleep(0.05)
        owned = [pid for pid, _, comm, command in process_rows() if pid not in old_pids and
                 comm == "linux_server" and (f"-p {args.port}" in command or f"-p{args.port}" in command)]
        if len(owned) != 1:
            raise RuntimeError("cannot identify the unique server started by this test")
        server_pid = result["server_pid"] = owned[0]
        modes = [args.mode] if args.mode else ["over", "syscall", "multi_sw", "slot4"]
        for mode in modes:
            database_dir = output / mode
            database_dir.mkdir()
            database = database_dir / "fixture"
            shutil.copy2(ROOT / "tests/parent_owned_call_tracee", database)
            evidence = database_dir / "result.json"
            env = os.environ.copy()
            env.update(VTDBG_IDA_DB=str(database), VTDBG_IDA_EVIDENCE=str(evidence),
                VTDBG_IDA_REMOTE_PATH=target, VTDBG_IDA_REMOTE_CWD=linux_root + "/tests",
                VTDBG_IDA_REMOTE_PORT=str(args.port), VTDBG_IDA_STEP_MODE=mode,
                VTDBG_IDA_TEST_TIMEOUT_SECONDS=str(args.timeout - 10),
                VTDBG_IDA_SERVER_LOG=str(server_log), VTDBG_IDA_LINUX_HANDLER_LOG=handler_log,
                IDA_JOINT_TEST_DISTRO=args.distro)
            with (database_dir / "client.log").open("w", encoding="utf-8") as stream:
                client = subprocess.run([sys.executable, "-u", str(ROOT / "tests/ida_joint_fixture.py")],
                    env=env, stdout=stream, stderr=subprocess.STDOUT, timeout=args.timeout)
            item = json.loads(evidence.read_text(encoding="utf-8")) if evidence.exists() else {"errors": ["missing evidence"]}
            result["sessions"].append({"mode": mode, "returncode": client.returncode,
                                       "errors": item.get("errors"), "natural_exit": item.get("exit_code")})
            print("SESSION", json.dumps(result["sessions"][-1]), flush=True)
            if client.returncode or item.get("errors"):
                raise RuntimeError("IDA fixture assertion failed")
        log = server_log.read_text(errors="replace")
        if any(t in log for t in ("BPT_WRITE_ERROR", "BPT_READ_ERROR", "internal error", "Unknown signal -1")):
            raise RuntimeError("server reported a breakpoint or event error")
    except Exception as exc:
        result["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        result["boot_after"] = wsl("cat", "/proc/sys/kernel/random/boot_id").stdout.strip()
        if result["boot_before"] != result["boot_after"]:
            result["errors"].append("WSL boot changed during the test")
        if server_pid is not None:
            rows = process_rows()
            owned = {server_pid}
            changed = True
            while changed:
                changed = False
                for pid, ppid, _, command in rows:
                    if pid not in old_pids and pid not in owned and (ppid in owned or command == target):
                        owned.add(pid)
                        changed = True
            result["cleanup_pids"] = sorted(owned)
            order = sorted(owned - {server_pid}) + [server_pid]
            command = "kill -KILL " + " ".join(str(p) for p in order) + " 2>/dev/null || true"
            wsl("bash", "-lc", command)
        if server.poll() is None:
            server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
        result["all_pass"] = not result["errors"] and bool(result["sessions"])
        (output / "summary.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result["all_pass"] else 10


if __name__ == "__main__":
    raise SystemExit(main())
