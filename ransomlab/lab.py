from pathlib import Path
import os
import shutil
import time
import secrets

def initialize_lab(config):
    root = Path(config["lab_root"])
    root.mkdir(parents=True, exist_ok=True)
    (root / "README_LAB.txt").write_text(
        "Ransomware Detection Lab test directory. Only use harmless test files here.\\n",
        encoding="utf-8")
    canary = root / "CANARY_DO_NOT_EDIT.txt"
    if not canary.exists():
        canary.write_text("Harmless canary marker. Touching this file creates a detection signal.\\n", encoding="utf-8")
    return root

def create_demo_files(root, count=12):
    root = Path(root)
    made = []
    for i in range(count):
        p = root / f"demo_document_{i:02d}.txt"
        p.write_text(f"Harmless demonstration document {i}. " * 12, encoding="utf-8")
        made.append(p)
    return made

def safe_simulation(root, count=15, delay=0.03):
    """Creates/rewrites only benign text files in the configured lab directory."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    start = time.perf_counter()
    changed = []
    for i in range(count):
        p = root / f"SIMULATED_ACTIVITY_{i:03d}.txt"
        p.write_text(("Harmless simulated file activity. " * (10 + i)) + "\\n", encoding="utf-8")
        changed.append(p)
        time.sleep(max(0, delay))
    return {"files": [str(p) for p in changed], "elapsed_ms": (time.perf_counter()-start)*1000,
            "note": "No encryption, destructive actions, persistence, or real ransomware behavior was used."}

def create_snapshot(config):
    root = Path(config["lab_root"]).resolve()
    snap_root = Path(config["snapshot_root"]).resolve()
    if not root.exists():
        raise FileNotFoundError("Lab directory does not exist")
    snap_root.mkdir(parents=True, exist_ok=True)
    destination = snap_root / time.strftime("snapshot_%Y%m%d_%H%M%S")
    shutil.copytree(root, destination)
    return destination

def restore_file_from_snapshot(snapshot_dir, relative_path, config):
    root = Path(config["lab_root"]).resolve()
    snapshot = Path(snapshot_dir).resolve()
    source = (snapshot / relative_path).resolve()
    target = (root / relative_path).resolve()
    if snapshot.parent != Path(config["snapshot_root"]).resolve():
        raise ValueError("Snapshot must be inside the configured snapshot directory")
    if not source.is_relative_to(snapshot) or not target.is_relative_to(root):
        raise ValueError("Path escapes configured lab scope")
    if not source.is_file():
        raise FileNotFoundError(source)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    return target
