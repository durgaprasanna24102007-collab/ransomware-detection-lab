import os
import time
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

def process_metadata(pid=None):
    if pid is None:
        return {"pid": None, "ppid": None, "name": None, "cmdline": None, "cwd": None, "start_time": None}
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            return {"pid": p.pid, "ppid": p.ppid(), "name": p.name(),
                    "cmdline": " ".join(p.cmdline()), "cwd": p.cwd(),
                    "start_time": p.create_time()}
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {"pid": pid, "ppid": None, "name": None, "cmdline": None, "cwd": None, "start_time": None}

class Handler(FileSystemEventHandler):
    def __init__(self, engine, lab_root):
        self.engine = engine
        self.lab_root = Path(lab_root).resolve()

    def _safe_path(self, path):
        try:
            Path(path).resolve().relative_to(self.lab_root)
            return True
        except (ValueError, OSError):
            return False

    def on_created(self, event):
        if not event.is_directory and self._safe_path(event.src_path):
            self.engine.process_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory and self._safe_path(event.src_path):
            self.engine.process_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and self._safe_path(event.src_path):
            self.engine.process_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            for p in (event.src_path, event.dest_path):
                if self._safe_path(p):
                    self.engine.process_event("moved", p)

def start_monitoring(engine, lab_root):
    root = Path(lab_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    observer = Observer()
    observer.schedule(Handler(engine, root), str(root), recursive=True)
    observer.start()
    return observer
