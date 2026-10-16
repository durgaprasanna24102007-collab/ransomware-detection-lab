# Ransomware Detection Lab (Kali Linux)

A modular educational endpoint-monitoring lab. It detects suspicious patterns in a designated directory, records evidence, and demonstrates safe incident response and recovery workflows.

## Safety and scope
- The simulation creates or rewrites harmless `.txt` files only in `lab_data/monitored`.
- It does **not** implement real ransomware, encryption of victim files, persistence, evasion, or destructive behavior.
- Process termination is not automatic. The response module defaults to preview-only; the optional termination function requires explicit approval and checks process ownership and lab-scoped working directory.
- Run as a normal user, not with `sudo`, unless you understand the security implications.
- Use an isolated Kali VM and snapshots for experiments.

## Features
- Filesystem monitoring with Watchdog/inotify backend
- Lightweight behavior correlation and explainable risk scoring
- Adaptive baseline storage (simple transparent prototype)
- File entropy and SHA-256 helper functions
- Canary-file signal
- SQLite events, alerts, and experiment records
- Streamlit dashboard and event timeline
- Snapshot creation and safe single-file restoration
- Evaluation metrics: precision, recall, false-positive rate
- Contextual MITRE ATT&CK references
- Pytest tests

## Important limitations
1. Filesystem notifications generally do not provide the originating PID. Process lineage is available only when an attribution source is added; current event records honestly leave it unknown unless supplied by a simulation or integration.
2. The included baseline is a starter implementation, not a trained anomaly-detection model. Calibrate it using representative benign workloads before relying on it.
3. Entropy is an indicator only. Compressed and legitimately encrypted data may also have high entropy.
4. The current dashboard's safe simulation feeds its own generated events directly into the engine. Live filesystem events are collected when the watcher is run separately.
5. This is a teaching prototype, not a production endpoint protection product. It does not guarantee prevention, containment, or recovery.

## Kali Linux installation
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
cd ransomware_detection_lab
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

If the project folder is in Downloads, first `cd ~/Downloads/ransomware_detection_lab` (adjust to the actual location).

## Run the dashboard
```bash
source .venv/bin/activate
streamlit run app.py
```
Open the local URL printed by Streamlit, usually `http://localhost:8501`.

## Run tests
```bash
source .venv/bin/activate
pytest -q
```

## Start live filesystem monitoring (optional)
Create `run_monitor.py` in the project root with:
```python
from ransomlab.config import load_config
from ransomlab.db import EventStore
from ransomlab.detection import DetectionEngine
from ransomlab.monitor import start_monitoring

cfg = load_config()
store = EventStore(cfg["database"])
engine = DetectionEngine(store, cfg)
observer = start_monitoring(engine, cfg["lab_root"])
print("Monitoring configured lab directory. Press Ctrl+C to stop.")
try:
    import time
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
    observer.join()
```
Then run `python run_monitor.py` in a second terminal. Do not monitor system directories.

## Demo checklist
1. Start the dashboard.
2. Run the safe simulation.
3. Inspect the Events & Alerts page and open an alert's evidence.
4. Create a snapshot.
5. Change a generated demo file manually and restore it from the snapshot.
6. Run `pytest -q`.
7. Record CPU/memory use and explain the limitations listed above.

## Project layout
```text
ransomware_detection_lab/
├── app.py
├── config.json
├── requirements.txt
├── README.md
├── ransomlab/
│   ├── config.py
│   ├── db.py
│   ├── detection.py
│   ├── lab.py
│   ├── metrics.py
│   ├── monitor.py
│   └── response.py
└── tests/
    └── test_detection.py
```
