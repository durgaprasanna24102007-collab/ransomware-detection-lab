import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"

def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        cfg = json.load(f)
    for key in ("lab_root", "snapshot_root", "database", "baseline_file"):
        cfg[key] = str((PROJECT_ROOT / cfg[key]).resolve())
    return cfg
