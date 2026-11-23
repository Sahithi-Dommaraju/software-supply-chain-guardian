# Software Supply Chain Guardian

Agentic supply-chain analysis for a public GitHub repository (Bosch hackathon). Paste a repo URL in the
dashboard; a LangGraph pipeline clones it at a pinned commit and runs each agent in turn. Every agent's
output shows up on the dashboard.

| # | Agent | Status | What it does |
|---|-------|--------|--------------|
| 1 | Repository Intake | built | Shallow clone (`--depth 1`, `core.symlinks=false`), records commit SHA, branch, author |
| 2 | Discovery | built | Finds manifests/lockfiles; direct + transitive deps from `package-lock.json` (v2/v3). No lockfile → generates one with `npm install --package-lock-only --ignore-scripts` and records command, npm version, time and sha256 as evidence. `requirements*.txt` and `go.mod` give direct deps; other ecosystems are reported as coverage gaps |
| 3 | SBOM | built | Merged CycloneDX 1.5 JSON (purls, scopes, licenses, hashes, dependency tree), cross-checked against `npm sbom` |
| 4 | Dependency graph | built | Nodes/edges, shortest introduction path per component, depth histogram, most depended-on packages |
| 5 | Container & CI/CD inspection | built | Dockerfile base-image pinning and risky `RUN`s; GitHub Actions pinning, `pull_request_target`, `write-all`, script injection; all with file:line |
| 6 | Vulnerability detection | planned | OSV-Scanner / Trivy against the SBOM |
| 7 | Suspicious-change detection | planned | Non-CVE anomalies with diff evidence |
| 8 | Investigation & evidence | planned | Evidence bundles and the Day 1 report |

No repository code runs during a scan. Nothing is cloned until a URL is submitted.

Dashboard: React + TypeScript with light and dark themes (toggle in the top bar), live per-agent status,
an interactive dependency graph (hover tooltips, neighbour highlighting, labels on zoom, click for details
and the introduction path), a filterable SBOM table with download, and container/CI observations linked
to file:line.

Full explanation of every agent and every dashboard element: [docs/DASHBOARD_GUIDE.md](docs/DASHBOARD_GUIDE.md).

## Run

Needs Python 3.11+, Node 20+ (with npm 9.5+ for `npm sbom`), and git.

First time only:

```powershell
cd backend; uv venv .venv; uv pip install --python .venv -r requirements.txt; cd ..
cd frontend; npm install; cd ..
```

Then, in two terminals (backend first):

```powershell
cd backend; .venv\Scripts\python -m uvicorn app.main:app --port 8000
```

```powershell
cd frontend; npm run dev
```

Open http://localhost:5173 and paste e.g. `https://github.com/juice-shop/juice-shop` (takes about 3 minutes:
most of it is npm resolving Juice Shop's two lockfiles).

Alternatively `npm run build` in `frontend`, then the backend alone serves the dashboard on http://localhost:8000.

## Where data goes

`backend/data/` (gitignored): `workspaces/<scan>/repo` is the clone, `scans/<scan>/` holds the SBOM,
generated lockfiles and `npm sbom` outputs, `guardian.db` is the SQLite scan store. Set
`GUARDIAN_DATA_DIR` to put it elsewhere.

## Layout

```
backend/app/main.py          FastAPI: POST /api/scans, GET /api/scans[/id], artifact download
backend/app/pipeline.py      LangGraph orchestrator; add new agents to STEPS
backend/app/agents/*.py      one module per agent: run(state) -> (state_update, dashboard_result)
backend/app/db.py            SQLite scan store, agent list
frontend/src/                React + TypeScript dashboard (Vite)
```

Self-check: `cd backend; .venv\Scripts\python -m tests.test_discovery`
