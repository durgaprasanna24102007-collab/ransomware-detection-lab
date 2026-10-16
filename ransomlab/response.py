from pathlib import Path
import os
import signal
import psutil

def containment_preview(pid, config):
    """Safe default: preview only. Never terminate a process automatically."""
    return {"action": "preview_only", "pid": int(pid), "auto_terminate": False,
            "message": "No process was stopped. Review evidence and approve containment manually."}

def terminate_lab_process(pid, config, explicitly_approved=False):
    """Optional controlled termination. Only targets the current user's process in an isolated lab."""
    if not explicitly_approved:
        raise PermissionError("Explicit approval is required")
    if config.get("auto_terminate", False):
        raise PermissionError("Automatic termination is intentionally disabled in this lab build")
    p = psutil.Process(int(pid))
    if p.uids().real != os.getuid():
        raise PermissionError("Can only target a process owned by the current user")
    cwd = p.cwd()
    lab_root = Path(config["lab_root"]).resolve()
    if not cwd or not Path(cwd).resolve().is_relative_to(lab_root):
        raise PermissionError("Process working directory is outside the lab scope")
    p.terminate()
    return {"action": "terminate_requested", "pid": int(pid), "message": "Termination requested for approved lab-scoped process."}
