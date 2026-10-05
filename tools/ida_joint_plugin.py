"""IDA user-profile loader for the runtime joint-debugging client.

Copy this loader and ida_joint_client.py to the user plugin directory, or set
IDA_JOINT_CLIENT_PATH to the full client path in a source checkout.
"""
import importlib.util
import os
from pathlib import Path
import sys

import idaapi

SOURCE = Path(os.environ.get("IDA_JOINT_CLIENT_PATH",
                             str(Path(__file__).resolve().with_name("ida_joint_client.py"))))


class JointDebugPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "Parent-child joint debugging for the remote Linux debugger"
    help = ""
    wanted_name = "IDA Joint Debug"
    wanted_hotkey = ""

    def init(self):
        try:
            self.adapter = sys.modules.get("ida_joint_client")
            if self.adapter is None:
                spec = importlib.util.spec_from_file_location("ida_joint_client", SOURCE)
                self.adapter = importlib.util.module_from_spec(spec)
                sys.modules["ida_joint_client"] = self.adapter
                spec.loader.exec_module(self.adapter)
            self.adapter.install()
            print("IDA Joint Debug client loaded; commercial IDA files unchanged")
            return idaapi.PLUGIN_KEEP
        except Exception as exc:
            print("IDA Joint Debug client unavailable: " + str(exc))
            return idaapi.PLUGIN_SKIP

    def run(self, arg):
        self.adapter.install()

    def term(self):
        if getattr(self, "adapter", None) is not None:
            self.adapter.uninstall()


def PLUGIN_ENTRY():
    return JointDebugPlugin()
