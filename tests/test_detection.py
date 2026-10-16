from pathlib import Path
import tempfile
from ransomlab.db import EventStore
from ransomlab.detection import DetectionEngine, shannon_entropy
from ransomlab.metrics import confusion_metrics

def make_config(tmp):
    return {
        "database": str(Path(tmp)/"events.db"),
        "baseline_file": str(Path(tmp)/"baseline.json"),
        "event_window_seconds": 10,
        "rapid_change_threshold": 4,
        "high_risk_threshold": 70,
        "medium_risk_threshold": 40,
        "max_file_bytes_for_entropy": 1048576,
    }

def test_entropy_empty_and_repeated():
    assert shannon_entropy(b"") == 0
    assert shannon_entropy(b"aaaaaa") == 0

def test_rapid_changes_create_alert():
    with tempfile.TemporaryDirectory() as tmp:
        cfg = make_config(tmp)
        store = EventStore(cfg["database"])
        engine = DetectionEngine(store, cfg)
        for i in range(5):
            p = Path(tmp)/f"f{i}.txt"
            p.write_text("ordinary harmless text")
            engine.process_event("created", str(p), simulated=True)
        assert len(store.rows("alerts")) >= 1

def test_confusion_metrics():
    rows = [
        {"expected":"positive","detected":1},
        {"expected":"positive","detected":0},
        {"expected":"negative","detected":1},
        {"expected":"negative","detected":0},
    ]
    m = confusion_metrics(rows)
    assert m["TP"] == m["FP"] == m["TN"] == m["FN"] == 1
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
