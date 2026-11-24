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

# Agents in pipeline order (shown as cards). Validate and Report run after approval, outside the pipeline.
AGENTS = [
    ("checkout", "Repository Intake"),
    ("discovery", "Discovery Agent"),
    ("sbom", "SBOM Generator"),
    ("graph", "Dependency Graph"),
    ("inspection", "Container & CI/CD Inspection"),
    ("vulnerability", "Vulnerability Detection"),
    ("change_detection", "Suspicious-Change Detection"),
    ("evidence", "Investigation & Evidence"),
    ("investigate", "Investigate"),
    ("prioritize", "Prioritize"),
    ("remediate", "Recommend Fix"),
    ("approval", "Human Approval"),
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


def _fail_interrupted() -> None:
    """A scan left queued/running by a server restart will never finish: mark it failed in both the
    status column and the JSON record (the dashboard and the delete check read the JSON)."""
    rows = _db.execute("SELECT id, data FROM scans").fetchall()
    for sid, raw in rows:
        d = json.loads(raw)
        if d.get("status") in ("queued", "running", "cancelling"):
            d.update(status="failed", error="Interrupted: the server restarted while this scan was running")
            for a in d.get("agents", {}).values():
                if a.get("status") in ("pending", "running"):
                    a["status"] = "skipped"
            _db.execute("UPDATE scans SET status='failed', data=? WHERE id=?", (json.dumps(d), sid))
    _db.commit()


_fail_interrupted()


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
        _db.execute("DELETE FROM decisions WHERE scan_id=?", (scan_id,))
        _db.execute("DELETE FROM validations WHERE scan_id=?", (scan_id,))
        _db.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        _db.commit()


# ---------------------------------------------------------------- LLM cache, approval decisions
_db.execute("CREATE TABLE IF NOT EXISTS llm_cache (key TEXT PRIMARY KEY, value TEXT, created_at REAL)")
_db.execute(
    "CREATE TABLE IF NOT EXISTS decisions (scan_id TEXT, card_id TEXT, decision TEXT, decided_by TEXT,"
    " note TEXT, decided_at TEXT, PRIMARY KEY (scan_id, card_id))"
)
_db.commit()


def cache_get(key: str) -> dict | None:
    with _lock:
        row = _db.execute("SELECT value FROM llm_cache WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else None


def cache_put(key: str, value: dict) -> None:
    with _lock:
        _db.execute("INSERT OR REPLACE INTO llm_cache VALUES (?,?,?)", (key, json.dumps(value), time.time()))
        _db.commit()


def decide(scan_id: str, card_id: str, decision: str, by: str, note: str) -> dict:
    row = {"card_id": card_id, "decision": decision, "decided_by": by, "note": note,
           "decided_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    with _lock:
        _db.execute("INSERT OR REPLACE INTO decisions VALUES (?,?,?,?,?,?)",
                    (scan_id, card_id, decision, by, note, row["decided_at"]))
        _db.commit()
    return row


def decisions(scan_id: str) -> dict[str, dict]:
    with _lock:
        rows = _db.execute("SELECT card_id, decision, decided_by, note, decided_at FROM decisions WHERE scan_id=?",
                           (scan_id,)).fetchall()
    keys = ("card_id", "decision", "decided_by", "note", "decided_at")
    return {r[0]: dict(zip(keys, r)) for r in rows}


# ---------------------------------------------------------------- Validate: one row per approved fix card
_db.execute("CREATE TABLE IF NOT EXISTS validations (scan_id TEXT, card_id TEXT, status TEXT, data TEXT,"
            " updated_at REAL, PRIMARY KEY (scan_id, card_id))")
# a validation cut off by a restart will never finish
for _sid, _cid, _raw in _db.execute("SELECT scan_id, card_id, data FROM validations WHERE status IN ('queued','running')").fetchall():
    _d = json.loads(_raw)
    _d.update(status="error", reason="Interrupted: the server restarted during validation. Run it again.")
    _db.execute("UPDATE validations SET status='error', data=? WHERE scan_id=? AND card_id=?", (json.dumps(_d), _sid, _cid))
_db.commit()


def save_validation(scan_id: str, card_id: str, record: dict) -> None:
    with _lock:
        _db.execute("INSERT OR REPLACE INTO validations VALUES (?,?,?,?,?)",
                    (scan_id, card_id, record["status"], json.dumps(record), time.time()))
        _db.commit()


def validations(scan_id: str) -> dict[str, dict]:
    with _lock:
        rows = _db.execute("SELECT card_id, data FROM validations WHERE scan_id=?", (scan_id,)).fetchall()
    return {r[0]: json.loads(r[1]) for r in rows}
