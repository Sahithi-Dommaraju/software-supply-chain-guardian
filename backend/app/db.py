"""Scan storage: one row per scan, results kept as JSON.

ponytail: SQLite + JSON blob per scan. Move components/edges/findings into
PostgreSQL tables when cross-scan queries (e.g. "which repos use lodash@x") are needed.
"""
import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path

import os

# Cloned repos (workspaces/<scan>/repo), scan artifacts (scans/<scan>/) and the DB live here.
DATA = Path(os.environ.get("GUARDIAN_DATA_DIR") or Path(__file__).resolve().parents[1] / "data")
DATA.mkdir(parents=True, exist_ok=True)

# Agents in pipeline order. "planned" ones are later Day 1 tasks, shown as stubs.
AGENTS = [
    ("checkout", "Repository Intake"),
    ("discovery", "Discovery Agent"),
    ("sbom", "SBOM Generator"),
    ("graph", "Dependency Graph"),
    ("inspection", "Container & CI/CD Inspection"),
    ("vulnerability", "Vulnerability Detection"),
    ("change_detection", "Suspicious-Change Detection"),
    ("evidence", "Investigation & Evidence"),
]
PLANNED: set[str] = set()  # agents listed but not built yet show as "planned"

_lock = threading.Lock()  # ponytail: one global lock, fine for a single-process demo
_db = sqlite3.connect(DATA / "guardian.db", check_same_thread=False)
_db.execute(
    "CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, repo_url TEXT, status TEXT,"
    " commit_sha TEXT, created_at REAL, data TEXT)"
)
# Normalized findings (vulnerability + suspicious), one row each, for querying across scans.
_db.execute(
    "CREATE TABLE IF NOT EXISTS findings (scan_id TEXT, finding_id TEXT, type TEXT, severity TEXT,"
    " initial_risk TEXT, component TEXT, advisory_id TEXT, rule TEXT, title TEXT, data TEXT,"
    " PRIMARY KEY (scan_id, finding_id))"
)
# A scan left 'running' by a server restart will never finish: say so instead of hanging.
_db.execute("UPDATE scans SET status='failed' WHERE status IN ('queued','running')")
_db.commit()


def create(repo_url: str) -> str:
    scan_id = uuid.uuid4().hex[:12]
    data = {
        "id": scan_id,
        "repo_url": repo_url,
        "status": "queued",
        "created_at": time.time(),
        "commit_sha": None,
        "error": None,
        "agents": {
            key: {"name": name, "status": "planned" if key in PLANNED else "pending"}
            for key, name in AGENTS
        },
        "results": {},
    }
    with _lock:
        _db.execute(
            "INSERT INTO scans VALUES (?,?,?,?,?,?)",
            (scan_id, repo_url, "queued", None, data["created_at"], json.dumps(data)),
        )
        _db.commit()
    return scan_id


def get(scan_id: str) -> dict | None:
    with _lock:
        row = _db.execute("SELECT data FROM scans WHERE id=?", (scan_id,)).fetchone()
    return json.loads(row[0]) if row else None


def list_scans() -> list[dict]:
    with _lock:
        rows = _db.execute(
            "SELECT id, repo_url, status, commit_sha, created_at FROM scans ORDER BY created_at DESC LIMIT 50"
        ).fetchall()
    keys = ("id", "repo_url", "status", "commit_sha", "created_at")
    return [dict(zip(keys, r)) for r in rows]


def update(scan_id: str, fn) -> None:
    """Read-modify-write the scan record under the lock."""
    with _lock:
        data = json.loads(_db.execute("SELECT data FROM scans WHERE id=?", (scan_id,)).fetchone()[0])
        fn(data)
        _db.execute(
            "UPDATE scans SET status=?, commit_sha=?, data=? WHERE id=?",
            (data["status"], data["commit_sha"], json.dumps(data), scan_id),
        )
        _db.commit()


def save_findings(scan_id: str, bundles: list[dict]) -> None:
    rows = [(scan_id, b["finding_id"], b["type"], b["severity"], b["initial_risk"]["level"],
             b["component"]["purl"] if b["component"] else None, b.get("advisory_id"), b.get("rule"),
             b["title"], json.dumps(b)) for b in bundles]
    with _lock:
        _db.executemany("INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        _db.commit()


def delete(scan_id: str) -> None:
    with _lock:
        _db.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        _db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        _db.commit()
