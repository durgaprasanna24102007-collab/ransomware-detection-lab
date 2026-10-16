from collections import deque
from pathlib import Path
import hashlib
import json
import math
import os
import time
from datetime import datetime, timezone

ATTACK_MAPPINGS = {
    "rapid_file_changes": {"technique": "T1486", "name": "Data Encrypted for Impact", "note": "Behavioral similarity only; not proof of encryption."},
    "canary_touched": {"technique": "T1036", "name": "Masquerading", "note": "Canary interaction is a local detection signal; mapping is contextual, not definitive."},
    "high_entropy_change": {"technique": "T1486", "name": "Data Encrypted for Impact", "note": "High entropy can also occur in compressed or legitimate encrypted files."},
}

def sha256_file(path, max_bytes=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        remaining = max_bytes
        while True:
            chunk_size = 65536 if remaining is None else min(65536, remaining)
            if chunk_size <= 0:
                break
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
            if remaining is not None:
                remaining -= len(chunk)
    return h.hexdigest()

def shannon_entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts if c)

def file_entropy(path, max_bytes=1_048_576):
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return shannon_entropy(data)
    except (OSError, PermissionError):
        return None

class AdaptiveBaseline:
    """Small, transparent baseline; baseline is an aid, not a security boundary."""
    def __init__(self, path):
        self.path = Path(path)
        self.counts = {"created": 0, "modified": 0, "deleted": 0}
        self.ready = False
        self.load()

    def load(self):
        if self.path.exists():
            try:
                obj = json.loads(self.path.read_text(encoding="utf-8"))
                self.counts = obj.get("counts", self.counts)
                self.ready = bool(obj.get("ready", False))
            except (OSError, ValueError):
                pass

    def observe(self, kind):
        if kind in self.counts:
            self.counts[kind] += 1

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps({"counts": self.counts, "ready": self.ready}, indent=2), encoding="utf-8")

    def mark_ready(self):
        self.ready = True
        self.save()

class DetectionEngine:
    def __init__(self, store, config):
        self.store = store
        self.config = config
        self.events = deque()
        self.window = int(config.get("event_window_seconds", 10))
        self.rapid_threshold = int(config.get("rapid_change_threshold", 8))
        self.high_threshold = int(config.get("high_risk_threshold", 70))
        self.medium_threshold = int(config.get("medium_risk_threshold", 40))
        self.last_alert_at = {}
        self.baseline = AdaptiveBaseline(config["baseline_file"])
        self.baseline.load()

    def process_event(self, kind, path, simulated=False, process=None):
        now = time.monotonic()
        event = {"at": now, "kind": kind, "path": str(path), "simulated": simulated}
        if process:
            event.update(process)
        self.events.append(event)
        while self.events and now - self.events[0]["at"] > self.window:
            self.events.popleft()

        self.baseline.observe(kind)
        self.store.add_event(kind, str(path), (process or {}).get("name"),
                             (process or {}).get("pid"), (process or {}).get("ppid"),
                             {"simulated": simulated, "at_monotonic": now})

        evidence = []
        score = 0
        recent_changes = [e for e in self.events if e["kind"] in {"created", "modified", "deleted", "moved"}]
        if len(recent_changes) >= self.rapid_threshold:
            score += 45
            evidence.append({"signal": "rapid_file_changes", "observed": len(recent_changes),
                             "window_seconds": self.window, "points": 45})
        if kind == "canary_touched":
            score += 60
            evidence.append({"signal": "canary_touched", "points": 60})
        entropy = file_entropy(path, int(self.config.get("max_file_bytes_for_entropy", 1048576))) if Path(path).is_file() else None
        if entropy is not None and entropy >= 7.6 and kind in {"created", "modified", "moved"}:
            score += 20
            evidence.append({"signal": "high_entropy_change", "entropy": round(entropy, 3), "points": 20})

        # Baseline deviation is intentionally modest until enough observations exist.
        if self.baseline.ready and kind in {"created", "modified", "deleted"}:
            expected = max(1, self.baseline.counts.get(kind, 0))
            if len(recent_changes) > expected * 2:
                score += 10
                evidence.append({"signal": "baseline_deviation", "points": 10})

        score = min(100, score)
        if score >= self.high_threshold:
            severity = "HIGH"
        elif score >= self.medium_threshold:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        if score >= self.medium_threshold:
            # Avoid flooding the database for the same path in a short period.
            key = str(path)
            if now - self.last_alert_at.get(key, -999) > 5:
                mapped = []
                for item in evidence:
                    if item["signal"] in ATTACK_MAPPINGS:
                        mapped.append({"signal": item["signal"], **ATTACK_MAPPINGS[item["signal"]]})
                explanation = "; ".join(f'{x["signal"]} (+{x["points"]})' for x in evidence) or "Correlated behavior"
                self.store.add_alert(severity, score, "Suspicious file activity", explanation,
                                     {"signals": evidence, "process": process or {}, "attack_mapping": mapped,
                                      "simulated": simulated, "attribution_note": "PID attribution may be unavailable for filesystem events."})
                self.last_alert_at[key] = now
        return {"score": score, "severity": severity, "evidence": evidence, "entropy": entropy}
