import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

def utc_now():
    return datetime.now(timezone.utc).isoformat()

class EventStore:
    def __init__(self, db_path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def connect(self):
        con = sqlite3.connect(self.db_path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def _init_db(self):
        with self.connect() as con:
            con.executescript("""
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL, event_type TEXT NOT NULL,
              path TEXT, process_name TEXT, pid INTEGER, ppid INTEGER,
              details TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS alerts(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL, severity TEXT NOT NULL,
              risk_score INTEGER NOT NULL, title TEXT NOT NULL,
              explanation TEXT NOT NULL, evidence TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'open'
            );
            CREATE TABLE IF NOT EXISTS experiments(
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              timestamp TEXT NOT NULL, scenario TEXT NOT NULL,
              expected TEXT NOT NULL, detected INTEGER NOT NULL,
              detection_latency_ms REAL, notes TEXT
            );
            """)

    def add_event(self, event_type, path=None, process_name=None, pid=None, ppid=None, details=None):
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO events(timestamp,event_type,path,process_name,pid,ppid,details) VALUES(?,?,?,?,?,?,?)",
                (utc_now(), event_type, path, process_name, pid, ppid, json.dumps(details or {}))
            )
            return cur.lastrowid

    def add_alert(self, severity, risk_score, title, explanation, evidence):
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO alerts(timestamp,severity,risk_score,title,explanation,evidence) VALUES(?,?,?,?,?,?)",
                (utc_now(), severity, int(risk_score), title, explanation, json.dumps(evidence))
            )
            return cur.lastrowid

    def add_experiment(self, scenario, expected, detected, latency_ms=None, notes=""):
        with self.connect() as con:
            con.execute(
                "INSERT INTO experiments(timestamp,scenario,expected,detected,detection_latency_ms,notes) VALUES(?,?,?,?,?,?)",
                (utc_now(), scenario, expected, int(bool(detected)), latency_ms, notes)
            )

    def rows(self, table, limit=1000):
        if table not in {"events", "alerts", "experiments"}:
            raise ValueError("Unsupported table")
        with self.connect() as con:
            return [dict(r) for r in con.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()]

    def update_alert_status(self, alert_id, status):
        if status not in {"open", "investigating", "contained", "closed"}:
            raise ValueError("Invalid alert status")
        with self.connect() as con:
            con.execute("UPDATE alerts SET status=? WHERE id=?", (status, int(alert_id)))
