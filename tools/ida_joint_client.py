"""Runtime-only IDA F8 provenance; no target execution/VM logic lives here.

The stock Linux RPC sends identical breakpoints for F8 and manual HW BPs.
Observe the actual processor step-over calculation, notify our linux_server
shim over IDA's existing debugger ioctl, and return 0 to leave IDA decoding,
temporary BP installation and UI handling unchanged.
"""

import ida_dbg
import ida_idd
import ida_idp
import ida_ua

ACTION_IOCTL = 0x5644


def pending_owner_wait(tid=None):
    """Kernel-authoritative logical wait state, not a timer or PC heuristic."""
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        return False
    dbg = ida_idd.get_dbg()
    if dbg is None or dbg.name != "linux" or not dbg.is_remote():
        return False
    if tid is None:
        tid = int(ida_dbg.get_current_thread())
    request = f"VTDBGWAIT/1 {int(tid)}".encode("ascii")
    return int(ida_dbg.internal_ioctl(ACTION_IOCTL, request, None, None)) == 1


_ui_hook = None
_qt_filter = None
_wrapped_calls = []
_blocked_calls = []


def _block_owner_step(name):
    if not pending_owner_wait():
        return False
    entry = {"name": name, "tid": int(ida_dbg.get_current_thread())}
    _blocked_calls.append(entry)
    del _blocked_calls[:-64]
    try:
        import ida_kernwin
        ida_kernwin.msg(
            "IDA Joint Debug: selected owner is waiting for a program child event; "
            "F7/F8 cannot execute the mailbox loop. Select a child, or "
            "resume until the wait call actually returns.\n")
    except (ImportError, RuntimeError):
        pass
    return True


def _wrap_call(module, name, factory):
    original = getattr(module, name)
    wrapper = factory(original)
    _wrapped_calls.append((module, name, original, wrapper))
    setattr(module, name, wrapper)


def _install_api_wait_guards():
    # IDAPython step_* and process_ui_action call straight into IDA; the
    # latter does not emit UI_Hooks.preprocess_action on this IDA version.
    # Guard these supported public APIs before they invalidate UI/debugger
    # state. Everything unrelated to an active owner wait remains unchanged.
    for name in ("step_into", "step_over", "request_step_into", "request_step_over"):
        def factory(original, label=name):
            def guarded(*args, **kwargs):
                if _block_owner_step(label):
                    return False
                return original(*args, **kwargs)
            return guarded
        _wrap_call(ida_dbg, name, factory)
    import ida_kernwin

    def ui_factory(original):
        def guarded(name, *args, **kwargs):
            if name in ("ThreadStepOver", "ThreadStepInto") and _block_owner_step(name):
                return False
            return original(name, *args, **kwargs)
        return guarded
    _wrap_call(ida_kernwin, "process_ui_action", ui_factory)


def _install_wait_action_guard():
    global _ui_hook, _qt_filter
    # idalib has no action dispatcher; the server still rejects physical
    # SINGLESTEP on a logical wait. Interactive IDA gets an explanatory
    # non-modal message and retains its suspended state/selected child.
    try:
        import ida_kernwin

        class WaitActionGuard(ida_kernwin.UI_Hooks):
            def __init__(self):
                super().__init__()
                self.blocked_actions = []

            def preprocess_action(self, name):
                if name not in ("ThreadStepOver", "ThreadStepInto"):
                    return 0
                if not _block_owner_step(name):
                    return 0
                self.blocked_actions.append({"name": name,
                                             "tid": int(ida_dbg.get_current_thread())})
                del self.blocked_actions[:-32]
                return 1

        _ui_hook = WaitActionGuard()
        if not _ui_hook.hook():
            _ui_hook = None
    except (AttributeError, RuntimeError):
        _ui_hook = None
    # Qt keystrokes can bypass action preprocessing in debugger widgets.
    # This is a runtime UI adapter only; no debugger event is fabricated.
    try:
        from PyQt5 import QtCore, QtWidgets

        class WaitKeyGuard(QtCore.QObject):
            def eventFilter(self, watched, event):
                if event.type() == QtCore.QEvent.KeyPress and event.key() in (
                        QtCore.Qt.Key_F7, QtCore.Qt.Key_F8) and not event.modifiers():
                    return _block_owner_step("F7" if event.key() == QtCore.Qt.Key_F7 else "F8")
                return False

        app = QtWidgets.QApplication.instance()
        if app is not None:
            _qt_filter = WaitKeyGuard(app)
            app.installEventFilter(_qt_filter)
    except (ImportError, AttributeError, RuntimeError):
        _qt_filter = None


class StepIntent(ida_idp.IDP_Hooks):
    def __init__(self):
        super().__init__()
        self.notifications = []

    def ev_calc_step_over(self, target, ip):
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            return 0
        dbg = ida_idd.get_dbg()
        if dbg is None or dbg.name != "linux" or not dbg.is_remote():
            return 0
        tid = int(ida_dbg.get_current_thread())
        try:
            hardware = 0
            insn = ida_ua.insn_t()
            is_call = ida_ua.decode_insn(insn, int(ip)) > 0 and ida_idp.is_call_insn(insn)
            if is_call:
                for n in range(ida_dbg.get_bpt_qty()):
                    bp = ida_dbg.bpt_t()
                    if ida_dbg.getn_bpt(n, bp) and bp.enabled() and bp.is_hwbpt():
                        hardware += 1
            prefer_soft = int(is_call and hardware >= 4)
            request = f"VTDBGSTEP/2 {tid} {int(ip):x} {prefer_soft}".encode("ascii")
            result = int(ida_dbg.internal_ioctl(ACTION_IOCTL, request, None, None))
            entry = {"tid": tid, "ip": hex(int(ip)), "result": result,
                     "full_hardware_slots": bool(prefer_soft)}
            self.notifications.append(entry)
            if len(self.notifications) > 32:
                del self.notifications[:-32]
        except Exception as exc:
            self.notifications.append({"tid": tid, "ip": hex(int(ip)), "error": str(exc)})
        return 0


_hook = None


def install():
    global _hook
    if _hook is None:
        _hook = StepIntent()
        if not _hook.hook():
            _hook = None
            raise RuntimeError("IDA Joint Debug processor step-over hook installation failed")
        _install_wait_action_guard()
        _install_api_wait_guards()
    return _hook


def uninstall():
    global _hook, _ui_hook, _qt_filter
    if _qt_filter is not None:
        from PyQt5 import QtWidgets
        QtWidgets.QApplication.instance().removeEventFilter(_qt_filter)
        _qt_filter = None
    for module, name, original, wrapper in reversed(_wrapped_calls):
        if getattr(module, name) is wrapper:
            setattr(module, name, original)
    _wrapped_calls.clear()
    if _ui_hook is not None:
        _ui_hook.unhook()
        _ui_hook = None
    if _hook is not None:
        _hook.unhook()
        _hook = None


if __name__ == "__main__":
    install()
    print("IDA Joint Debug request provenance adapter installed; IDA files unchanged")
