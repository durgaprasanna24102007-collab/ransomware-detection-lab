import json
from pathlib import Path
import pandas as pd
import streamlit as st
import psutil

from ransomlab.config import load_config
from ransomlab.db import EventStore
from ransomlab.detection import DetectionEngine
from ransomlab.lab import initialize_lab, safe_simulation, create_snapshot, restore_file_from_snapshot
from ransomlab.metrics import confusion_metrics
from ransomlab.response import containment_preview

st.set_page_config(page_title="Ransomware Detection Lab", page_icon="🛡️", layout="wide")
cfg = load_config()
store = EventStore(cfg["database"])
engine = DetectionEngine(store, cfg)
lab_root = initialize_lab(cfg)

st.title("🛡️ Ransomware Detection Lab")
st.caption("Kali Linux · Behavioral detection · Safe simulations only")
st.warning("Use only the configured lab directory. This prototype does not provide guaranteed prevention or complete process attribution.")

pages = ["Overview", "Events & Alerts", "Safe Simulation", "Snapshots & Recovery", "Evaluation", "MITRE ATT&CK"]
page = st.sidebar.radio("Navigation", pages)

events = store.rows("events", 5000)
alerts = store.rows("alerts", 1000)
experiments = store.rows("experiments", 1000)

if page == "Overview":
    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Events recorded", len(events))
    c2.metric("Open alerts", sum(a["status"] == "open" for a in alerts))
    c3.metric("Lab files", sum(1 for p in lab_root.rglob("*") if p.is_file()))
    c4.metric("CPU usage", f"{psutil.cpu_percent(interval=0.15):.1f}%")
    st.subheader("Detection pipeline")
    st.write("Filesystem monitoring → behavior correlation → explainable risk score → alert/evidence → controlled response.")
    st.subheader("Recent alerts")
    if alerts:
        st.dataframe(pd.DataFrame(alerts).drop(columns=["evidence"], errors="ignore"), use_container_width=True)
    else:
        st.info("No alerts yet. Run the harmless simulation to populate the lab.")
    st.subheader("Lab scope")
    st.code(str(lab_root))

elif page == "Events & Alerts":
    st.subheader("Alerts")
    if alerts:
        df = pd.DataFrame(alerts)
        st.dataframe(df.drop(columns=["evidence"], errors="ignore"), use_container_width=True)
        alert_id = st.number_input("Alert ID to inspect", min_value=1, step=1)
        chosen = next((a for a in alerts if a["id"] == alert_id), None)
        if chosen:
            st.json(json.loads(chosen["evidence"]))
            new_status = st.selectbox("Update alert status", ["open","investigating","contained","closed"])
            if st.button("Save status"):
                store.update_alert_status(alert_id, new_status)
                st.success("Alert status updated.")
    else:
        st.info("No alerts recorded.")
    st.subheader("Event timeline")
    if events:
        st.dataframe(pd.DataFrame(events), use_container_width=True)
    else:
        st.info("No events recorded yet.")

elif page == "Safe Simulation":
    st.subheader("Generate harmless test activity")
    st.write("This writes plain-text files only in the configured lab directory. It does not encrypt, delete, or damage files.")
    count = st.slider("Number of test files", 5, 40, 15)
    if st.button("Run safe simulation", type="primary"):
        result = safe_simulation(lab_root, count=count)
        # Also feed events directly so the demo works even if filesystem notifications are delayed.
        for p in result["files"]:
            engine.process_event("created", p, simulated=True, process={"name":"safe_simulation","pid":None,"ppid":None})
        store.add_experiment("safe_file_burst", "positive", True, result["elapsed_ms"],
                             "Harmless file-creation burst; detection engine evaluated generated events.")
        st.success(f"Created {len(result['files'])} harmless test files.")
        st.json(result)
        st.info("Inspect Events & Alerts for the resulting evidence. Filesystem watcher events may also appear.")

elif page == "Snapshots & Recovery":
    st.subheader("Recovery snapshots")
    st.write("Snapshots copy the lab directory only; store important backups outside the VM as well.")
    if st.button("Create snapshot"):
        dest = create_snapshot(cfg)
        st.success(f"Snapshot created: {dest}")
    snap_root = Path(cfg["snapshot_root"])
    snapshots = sorted([p for p in snap_root.glob("snapshot_*") if p.is_dir()], reverse=True)
    if snapshots:
        selected = st.selectbox("Choose snapshot", [str(p) for p in snapshots])
        snapshot = Path(selected)
        candidates = [str(p.relative_to(snapshot)) for p in snapshot.rglob("*") if p.is_file()]
        if candidates:
            rel = st.selectbox("File to restore", candidates)
            if st.button("Restore selected file"):
                try:
                    restored = restore_file_from_snapshot(snapshot, rel, cfg)
                    st.success(f"Restored {restored}")
                except Exception as e:
                    st.error(str(e))
    else:
        st.info("No snapshots yet.")

elif page == "Evaluation":
    st.subheader("Detection evaluation")
    if experiments:
        df = pd.DataFrame(experiments)
        st.dataframe(df, use_container_width=True)
        st.json(confusion_metrics(experiments))
    else:
        st.info("No experiments yet. Run the safe simulation first.")
    st.caption("Metrics are only meaningful when expected labels and detection outcomes are independently validated.")

elif page == "MITRE ATT&CK":
    st.subheader("Behavior-to-technique mapping")
    st.write("Mappings are contextual hypotheses, not proof that a technique occurred.")
    st.dataframe(pd.DataFrame([
        {"Observed signal":"Rapid file changes", "Technique":"T1486", "Name":"Data Encrypted for Impact", "Caveat":"Behavioral similarity only."},
        {"Observed signal":"Canary interaction", "Technique":"Context-dependent", "Name":"Investigate process and access context", "Caveat":"Canary touch alone does not establish an ATT&CK technique."},
        {"Observed signal":"High entropy content change", "Technique":"T1486 (contextual)", "Name":"Data Encrypted for Impact", "Caveat":"Compression and legitimate encryption can also produce high entropy."},
    ]), use_container_width=True)
