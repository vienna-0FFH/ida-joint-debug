"""Actual IDA regression for a returning call with ptrace protocols/syscall.

The fixture parent checks it received EXACTLY the two real program INT3s.
IDA software/HW BPs, trace stops and temporary breakpoints must stay out.
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

import idapro
import ida_dbg
import ida_idd
import ida_nalt

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ["VTDBG_IDA_EVIDENCE"])
MODE = os.environ["VTDBG_IDA_STEP_MODE"]
REMOTE = os.environ["VTDBG_IDA_REMOTE_PATH"]
DISTRO = os.environ.get("IDA_JOINT_TEST_DISTRO", "Ubuntu")
reply = subprocess.run(["wsl.exe", "-d", DISTRO, "-u", "root", "-e", "nm", REMOTE],
                       capture_output=True, text=True, timeout=15, check=True)
symbols = {p[2]: int(p[0], 16) for line in reply.stdout.splitlines()
           if len(p := line.split()) == 3 and p[2].startswith("fixture_")}
CALL = symbols["fixture_callsite"]
RETURN = symbols["fixture_call_return"]
INSIDE = symbols["fixture_inside"]
SYSCALL = symbols["fixture_syscall"]
evidence = {"mode": MODE, "symbols": {k: hex(v) for k, v in symbols.items()},
            "events": [], "errors": [], "start_seen": False,
            "return_seen": False, "exit_seen": False}


def save():
    OUT.write_text(json.dumps(evidence, indent=2), encoding="utf-8")


def attr_int(obj, name):
    value = getattr(obj, name)
    return int(value() if callable(value) else value)


rc = idapro.open_database(os.environ["VTDBG_IDA_DB"], True)
if rc != 0:
    raise SystemExit(f"fixture database open failed: {rc}")
try:
    mod = sys.modules.get("ida_joint_client")
    if mod is None:
        spec = importlib.util.spec_from_file_location("ida_joint_client", ROOT / "tools/ida_joint_client.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["ida_joint_client"] = mod
        spec.loader.exec_module(mod)
    hook = mod.install()
    # Only this isolated self-test DB: linux_server checks the INPUT path,
    # not the application path, before launching. Use its actual Linux ELF
    # path and retain the real file CRC; never suppress the CRC check.
    ida_nalt.set_root_filename(REMOTE)
    assert ida_dbg.load_debugger("linux", True)
    ida_dbg.set_process_options(REMOTE, "", os.environ["VTDBG_IDA_REMOTE_CWD"], "127.0.0.1", "",
                                int(os.environ.get("VTDBG_IDA_REMOTE_PORT", "23960")))
    for n in range(ida_dbg.get_bpt_qty() - 1, -1, -1):
        bp = ida_dbg.bpt_t()
        assert ida_dbg.getn_bpt(n, bp) and ida_dbg.del_bpt(bp.ea)
    assert ida_dbg.add_bpt(CALL, 0, ida_idd.BPT_SOFT)
    assert ida_dbg.start_process(None, None, None)
    phase = "start"
    deadline = time.monotonic() + float(os.environ["VTDBG_IDA_TEST_TIMEOUT_SECONDS"])
    sw_targets = [INSIDE + n for n in range(4)]
    sw_index = 0
    while time.monotonic() < deadline:
        code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 1)
        if code <= 0: continue
        ev = ida_dbg.get_debug_event()
        item = {"eid": int(ev.eid()), "pid": int(ev.pid), "tid": int(ev.tid),
                "ea": hex(ev.ea), "phase": phase, "state": int(ida_dbg.get_process_state())}
        evidence["events"].append(item)
        save()
        if item["eid"] == 2:
            evidence["exit_seen"] = True
            evidence["exit_code"] = attr_int(ev, "exit_code")
            break
        if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP and item["eid"] in (16, 32, 64):
            rip = int(ida_dbg.get_reg_val("RIP"))
            item["rip"] = hex(rip)
            if phase == "start" and rip == CALL:
                assert item["eid"] == 16 and item["pid"] != item["tid"]
                evidence["start_seen"] = True
                disabled = bool(ida_dbg.enable_bpt(CALL, False))
                evidence["call_bpt_disable"] = disabled
                if not disabled:
                    evidence["call_bpt_delete_fallback"] = bool(ida_dbg.del_bpt(CALL))
                assert disabled or evidence["call_bpt_delete_fallback"], "cannot disable/delete initial call BP"
                if MODE == "slot4":
                    for n in range(4):
                        assert ida_dbg.add_bpt(symbols["fixture_hardware_unused"] + n, 1, ida_idd.BPT_EXEC)
                    phase = "over"
                    evidence["step_over_issued"] = bool(ida_dbg.step_over())
                    assert evidence["step_over_issued"], "F8 request failed"
                elif MODE == "syscall":
                    assert ida_dbg.add_bpt(SYSCALL, 0, ida_idd.BPT_SOFT)
                    phase = "syscall"
                    assert ida_dbg.step_over()
                elif MODE == "multi_sw":
                    for address in sw_targets:
                        assert ida_dbg.add_bpt(address, 0, ida_idd.BPT_SOFT)
                    phase = "multi_sw"
                    assert ida_dbg.step_over()
                else:
                    phase = "over"
                    assert ida_dbg.step_over()
            elif phase == "over":
                assert item["eid"] in (16, 32) and rip == RETURN, f"call-over stopped at {rip:#x} instead of return {RETURN:#x}"
                assert int(ida_dbg.get_reg_val("RAX")) == 0x123
                evidence["return_seen"] = True
                phase = "finish"
                assert ida_dbg.continue_process()
            elif phase == "syscall":
                assert item["eid"] == 16 and rip == SYSCALL, "user BP inside callee must interrupt F8"
                assert ida_dbg.enable_bpt(SYSCALL, False)
                evidence["syscall_tid"] = item["tid"]
                phase = "after_syscall"
                assert ida_dbg.step_into()
            elif phase == "after_syscall":
                assert rip == symbols["fixture_after_syscall"] and item["eid"] == 32
                evidence["syscall_rax"] = int(ida_dbg.get_reg_val("RAX"))
                assert evidence["syscall_rax"] == evidence["syscall_tid"], "raw getpid syscall did not really execute"
                evidence["syscall_step_ok"] = True
                phase = "finish"
                assert ida_dbg.continue_process()
            elif phase == "multi_sw":
                assert item["eid"] == 16 and rip == sw_targets[sw_index], "same-word software BPs were overwritten or misclassified"
                assert ida_dbg.del_bpt(rip)
                sw_index += 1
                evidence["same_word_bp_hits"] = sw_index
                phase = "finish" if sw_index == len(sw_targets) else "multi_sw"
                assert ida_dbg.continue_process()
            else:
                assert ida_dbg.continue_process()
        else:
            assert ida_dbg.continue_process()
        save()
    text = Path(os.environ["VTDBG_IDA_SERVER_LOG"]).read_text(errors="replace")
    evidence["parent_received_only_program_events"] = "CALL_FIXTURE_PASS child_exit=37 program_protocols=2" in text
    assert evidence["start_seen"], "fixture initial IDA BP was not hit"
    assert evidence["exit_seen"], "fixture failed to publish terminal PROCESS_EXITED"
    assert evidence["exit_code"] == 0, "fixture parent rejected the debugger path"
    assert evidence["parent_received_only_program_events"], "IDA-generated stop leaked into parent protocol"
    if MODE in ("over", "slot4"): assert evidence["return_seen"]
    if MODE == "slot4":
        audit = subprocess.run(["wsl.exe", "-d", DISTRO, "-u", "root", "-e",
                                "grep", "-F", "debugger-call-over-software-fallback",
                                os.environ["VTDBG_IDA_LINUX_HANDLER_LOG"]],
                               capture_output=True, text=True, timeout=10)
        evidence["actual_temporary_software_fallback"] = audit.returncode == 0
        assert evidence["actual_temporary_software_fallback"], "the actual soft temporary breakpoint was not audited"
        assert "BPT_WRITE_ERROR" not in text and "BPT_READ_ERROR" not in text, "hardware slots/temp/cleanup had breakpoint errors"
    if MODE == "syscall": assert evidence.get("syscall_step_ok")
    if MODE == "multi_sw": assert evidence.get("same_word_bp_hits") == 4
except Exception as exc:
    evidence["errors"].append(f"{type(exc).__name__}: {exc}")
    evidence["exception_traceback"] = traceback.format_exc()
finally:
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_NOTASK:
        try: ida_dbg.exit_process()
        except Exception: pass
    evidence["step_intents"] = getattr(locals().get("hook"), "notifications", [])
    save()
    idapro.close_database()
print(json.dumps({k: v for k, v in evidence.items() if k != "events"}, indent=2), flush=True)
if evidence["errors"]: raise SystemExit(10)
print("IDA_RETURNING_PROTOCOL_CALL_PASS", flush=True)
