import os
import re
import shutil
import stat
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, pipeline
from .agents.checkout import GITHUB_URL

app = FastAPI(title="Software Supply Chain Guardian")


class ScanRequest(BaseModel):
    repo_url: str


@app.post("/api/scans", status_code=202)
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    url = req.repo_url.strip()
    if not GITHUB_URL.match(url):
        raise HTTPException(400, "Enter a public GitHub URL like https://github.com/owner/repo")
    scan_id = db.create(url)
    bg.add_task(pipeline.run, scan_id, url)
    return {"id": scan_id}


@app.get("/api/scans")
def list_scans():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


def _force_remove(func, path, _exc):
    # git marks pack files read-only; Windows refuses to delete those until the flag is cleared
    os.chmod(path, stat.S_IWRITE)
    func(path)


@app.delete("/api/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str):
    """Remove a scan: its DB rows, its evidence folder and the cloned repo."""
    if not re.fullmatch(r"[0-9a-f]{12}", scan_id):  # ids are generated hex; also blocks path tricks
        raise HTTPException(404, "Scan not found")
    scan = db.get(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["status"] in ("queued", "running"):
        raise HTTPException(409, "Scan is still running; wait for it to finish before deleting it")
    db.delete(scan_id)
    for folder in (db.DATA / "workspaces" / scan_id, db.DATA / "scans" / scan_id):
        if folder.exists():
            shutil.rmtree(folder, onerror=_force_remove)


@app.get("/api/scans/{scan_id}/artifacts/{name}")
def get_artifact(scan_id: str, name: str):
    """Evidence files (SBOM, generated lockfiles, tool outputs) for download."""
    base = (db.DATA / "scans" / scan_id).resolve()
    path = (base / name).resolve()
    if path.parent != base or not path.is_file():
        raise HTTPException(404, "Artifact not found")
    return FileResponse(path, filename=f"{scan_id}-{name}")


# Serve the built dashboard (npm run build) from the same port when present.
_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="dashboard")
