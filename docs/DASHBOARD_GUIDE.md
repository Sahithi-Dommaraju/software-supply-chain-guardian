# Supply Chain Guardian: In-Depth Guide

This guide explains everything built so far (Day 1 tasks 1 to 4 from the architecture document), how each
part works internally, what evidence it records, where it stops, and what every element of the dashboard
means. The running example throughout is **OWASP Juice Shop** (`https://github.com/juice-shop/juice-shop`,
commit `c9f9922`), scanned on 2026-11-23.

Contents

1. [The problem this solves](#1-the-problem-this-solves)
2. [Big picture: from URL to dashboard](#2-big-picture-from-url-to-dashboard)
3. [The orchestrator (LangGraph)](#3-the-orchestrator-langgraph)
4. [Agent 1: Repository Intake](#4-agent-1-repository-intake)
5. [Agent 2: Discovery](#5-agent-2-discovery)
6. [Agent 3: SBOM Generator](#6-agent-3-sbom-generator)
7. [Agent 4: Dependency Graph](#7-agent-4-dependency-graph)
8. [Agent 5: Container & CI/CD Inspection](#8-agent-5-container--cicd-inspection)
9. [Planned agents 6 to 8](#9-planned-agents-6-to-8)
10. [Storage, artifacts and the API](#10-storage-artifacts-and-the-api)
11. [Dashboard walkthrough](#11-dashboard-walkthrough)
12. [Safety model](#12-safety-model)
13. [Limits and known gaps](#13-limits-and-known-gaps)
14. [Extending the system](#14-extending-the-system)
15. [Glossary](#15-glossary)

---

## 1. The problem this solves

Modern applications are mostly other people's code. Juice Shop's own `package.json` names 98 packages,
but installing them pulls in **1,108** distinct packages for the backend alone, and 1,656 across the
backend and the Angular frontend. Each one is a supply-chain risk: it can have a known vulnerability
(a CVE), be abandoned, be typosquatted, run code at install time, or be swapped for a malicious version.

Before any of that can be judged, you need an accurate answer to three questions:

1. **What is in the software?** Every package, exact version, where it was downloaded from. This is the
   *inventory*, written out in a standard format called an **SBOM** (Software Bill of Materials).
2. **How did each package get in?** Which direct dependency pulled in which transitive one. This is the
   **dependency graph**, and it is what lets you say "crypto-js is here because pdfkit needs it".
3. **How is the software built and shipped?** Container base images and CI/CD workflows are part of the
   supply chain too: an unpinned base image or GitHub Action can change underneath you.

Tasks 1 to 4 answer exactly these three questions, deterministically, with evidence. Later agents
(vulnerability matching, suspicious-change detection, investigation) build on this foundation.

**Design rule from the architecture doc:** deterministic tools establish facts; AI only reasons over them.
Nothing in tasks 1 to 4 uses an LLM. Every number on the dashboard comes from git, npm or a parser, and
can be reproduced.

---

## 2. Big picture: from URL to dashboard

```
 Browser (React dashboard, :5173)
   │  1. POST /api/scans {"repo_url": "https://github.com/juice-shop/juice-shop"}
   ▼
 FastAPI backend (:8000)
   │  2. validate URL → create scan row (status "queued") → return {"id": "..."} immediately
   │  3. start pipeline in a background thread
   ▼
 LangGraph orchestrator ── runs agents in order, records status + timing for each
   │
   ├─▶ 1 Repository Intake      git clone --depth 1 → pinned commit SHA
   ├─▶ 2 Discovery              manifests → lockfiles (generate if missing) → components + edges
   ├─▶ 3 SBOM Generator         CycloneDX 1.5 JSON + npm sbom cross-check
   ├─▶ 4 Dependency Graph       BFS from repo root → depth + introduction path per package
   ├─▶ 5 Container & CI/CD      Dockerfiles + GitHub Actions → pinning and risky patterns
   ├─ ─ 6 Vulnerability Detection      (planned)
   ├─ ─ 7 Suspicious-Change Detection  (planned)
   └─ ─ 8 Investigation & Evidence     (planned)
   │
   ▼  each agent writes its result into the scan record in SQLite as soon as it finishes
 Browser polls GET /api/scans/{id} every 2 seconds → cards and tabs fill in live
```

Step by step, what happens when you press **Start scan**:

1. The dashboard sends the URL to `POST /api/scans`.
2. The backend checks the URL matches `https://github.com/<owner>/<repo>` (optionally ending in `.git`
   or `/`). Anything else (`file://`, other hosts, SSH URLs) is rejected with a 400 error before anything
   runs. This is the trust boundary: only public GitHub repos come in.
3. A scan record is created with a random 12-character id, status `queued`, and all eight agents listed
   (five `pending`, three `planned`). The id is returned at once, so the browser does not wait for the
   scan.
4. FastAPI runs `pipeline.run(scan_id, url)` as a background task.
5. The browser navigates to `#/scan/<id>` and polls every 2 seconds until the status is `completed` or
   `failed`.
6. Each agent flips its card to `running`, then to `done`, `partial` or `failed`, with a one-line
   summary and duration. Tabs show data as soon as the agent that produces it has finished.

For Juice Shop the whole run takes about 3 to 3.5 minutes. Roughly 15 to 70 seconds is the clone
(network-dependent), about 2 minutes is npm resolving two lockfiles, and everything else takes seconds.

---

## 3. The orchestrator (LangGraph)

**File:** `backend/app/pipeline.py`

[LangGraph](https://langchain-ai.github.io/langgraph/) is a library for building stateful workflows as a
graph of nodes. The architecture doc picks it because later stages need conditional routing, checkpoints
and a human-approval interrupt (Day 2). Today the graph is a straight line:

```
START → checkout → discovery → sbom → graph → inspection → END
```

### Shared state

All agents read from and write to one typed dictionary, `ScanState`:

| Key | Set by | Used by |
|-----|--------|---------|
| `scan_id`, `repo_url`, `workdir`, `artifacts` | orchestrator | everyone |
| `commit_sha`, `repo_name` | Intake | SBOM, Graph |
| `projects`, `components`, `edges` | Discovery | SBOM, Graph |

`workdir` is where the repo is cloned; `artifacts` is where evidence files are written (see section 10).

### The agent contract

Every agent is one Python function:

```python
def run(state: dict) -> tuple[dict, dict]:
    ...
    return state_update, dashboard_result
```

* `state_update` goes back into `ScanState` for later agents (for example Discovery returns the component
  list so the SBOM agent can use it).
* `dashboard_result` is what the dashboard shows. It is stored under `results.<agent>` in the scan record.
  Two special keys are popped off it: `_summary` (the one-liner on the agent card) and `_status`
  (`done` or `partial`).

The orchestrator wraps every agent in the same `_node` wrapper, which:

1. marks the agent `running` and records the start time;
2. calls the agent;
3. on success saves `dashboard_result`, the summary, the status and the duration;
4. on an exception marks the agent `failed` with the error message and re-raises.

If any agent fails, `pipeline.run` catches the exception, marks the whole scan `failed` with the error,
and marks every agent that never started as `skipped`. **A failed or partial scan is never shown as
clean.** This is a requirement from the architecture doc ("Does not report clean status when scanning is
partial, unsupported or failed").

### Status values

| Status | Meaning |
|--------|---------|
| `pending` | Waiting for earlier agents |
| `running` | Working now |
| `done` | Finished with full coverage |
| `partial` | Finished, but something was not covered (for example an unsupported manifest). Read the warnings |
| `failed` | Threw an error; the scan stops here |
| `skipped` | Never ran because an earlier agent failed |
| `planned` | Not built yet (tasks 5 to 7) |

---

## 4. Agent 1: Repository Intake

**File:** `backend/app/agents/checkout.py` · **Dashboard:** card 1, scan header, Overview → Scan provenance

### What it does

Clones the repository and pins the exact commit being analysed, so every later fact refers to one
known snapshot of the code.

### How

```
git clone --depth 1 --no-tags --single-branch -c core.symlinks=false <url> <workdir>
git rev-parse HEAD                      → commit SHA
git rev-parse --abbrev-ref HEAD         → branch
git log -1 --format=%cI%n%an%n%s        → commit date, author, subject
git ls-files                            → number of tracked files
```

| Flag / setting | Why |
|----------------|-----|
| `--depth 1` | Only the latest commit, not the whole history. Juice Shop's full history is large; we only need the current files |
| `--no-tags --single-branch` | Fetch the default branch only |
| `core.symlinks=false` | Symlinks in the repo become plain text files. A malicious repo could otherwise point a symlink at a file outside the workspace that a later agent reads |
| `GIT_TERMINAL_PROMPT=0` | A private or missing repo fails immediately instead of hanging on a password prompt |
| `GIT_LFS_SKIP_SMUDGE=1` | Large-file (LFS) blobs are not downloaded |
| timeout 600 s | A huge repo cannot block the pipeline forever |

`git clone` never runs code from the repository (git hooks are not copied by a clone), so this step is
safe for untrusted repos.

### Evidence recorded

Owner, repo, URL, the full 40-character **commit SHA**, branch, commit date, author and subject, the
number of tracked files and the exact clone command. Juice Shop: `master` @
`c9f99228d9d56afb5f5ca7925376292f7fa44b13`, 1,498 files.

### Failure

Wrong URL, private repo, network failure or timeout → the agent fails with git's error text and the scan
is marked failed. Nothing else runs, so you never get an empty "all clear" report for a repo that was
never read.

---

## 5. Agent 2: Discovery

**File:** `backend/app/agents/discovery.py` · **Dashboard:** card 2, Overview KPIs, Discovered projects,
Coverage gaps, SBOM table

This is the core of Day 1. It finds every dependency manifest, gets exact resolved versions, and builds
a normalized list of components and dependency edges that every later agent uses.

### 5.1 Finding manifests

The agent walks the whole repository, skipping folders that hold installed or built code rather than
source: `node_modules`, `.git`, `vendor`, `dist`, `build`, `.venv`, `venv`, `__pycache__`. It then routes
each file by name:

| File | Ecosystem | Handling |
|------|-----------|----------|
| `package.json` | npm | **Full**: direct + transitive, with edges (section 5.2) |
| `requirements*.txt` | PyPI | Direct dependencies only (section 5.4) |
| `go.mod` | Go | Direct + indirect modules, no parent edges (section 5.4) |
| `pyproject.toml`, `Pipfile`, `poetry.lock`, `Pipfile.lock`, `pom.xml`, `build.gradle(.kts)`, `Cargo.toml`, `Gemfile`, `composer.json` | various | **Detected but not supported yet**: listed as a coverage gap, never silently ignored |

Juice Shop has two `package.json` files: the root (the Node.js backend, 98 declared dependencies) and
`frontend/package.json` (the Angular app, 63 declared). Each becomes a **project**. The repo is a small
monorepo, so both are scanned and merged into one inventory.

### 5.2 npm: getting a lockfile

A `package.json` says *what range* of versions is acceptable (`"express": "^4.17.1"`). Only a
**lockfile** (`package-lock.json`) says which exact version was chosen, and lists every transitive
package. So the agent needs a lockfile.

**Case A: the repo commits a lockfile** (`package-lock.json` or `npm-shrinkwrap.json`). It is used as-is
and its sha256 is recorded. Lock source: `committed`.

**Case B: no lockfile (Juice Shop).** Juice Shop deliberately ships without one: its `.npmrc` contains
`package-lock=false`. The agent then generates one:

```
npm install --package-lock-only --ignore-scripts --package-lock=true --no-audit --no-fund
```

| Flag | Why |
|------|-----|
| `--package-lock-only` | Resolve versions and write `package-lock.json` **without downloading or installing any package**. No `node_modules` is created |
| `--ignore-scripts` | Never run `preinstall` / `install` / `postinstall` scripts. Juice Shop's root `postinstall` runs a nested install and build; that must not run on our machine |
| `--package-lock=true` | Overrides the repo's `.npmrc` `package-lock=false`, otherwise npm would refuse to write a lockfile |
| `--no-audit --no-fund` | Skip unrelated network calls and output |

**Peer-dependency conflicts (`--legacy-peer-deps`).** npm 7+ enforces "peer dependencies" strictly; many
real projects (including Juice Shop's Angular frontend) have conflicts that make the plain command fail.
If the first attempt fails, the agent retries once with `--legacy-peer-deps`, which is npm's documented
compatibility mode (the npm 6 behaviour). The command that actually succeeded is what gets recorded, so
you can see which mode was used. Juice Shop: root resolved normally, `frontend/` needed
`--legacy-peer-deps`.

Lock source: `generated`. Recorded evidence per project:

| Evidence | Juice Shop root |
|----------|-----------------|
| exact command | `npm install --package-lock-only --ignore-scripts --package-lock=true --no-audit --no-fund` |
| npm version | 11.6.2 |
| resolved at (UTC) | e.g. `2026-11-23T09:45:46Z` |
| sha256 of the lockfile | `b03dff2a…` |
| saved copy | `generated-lock-0.json` (downloadable from the dashboard) |

**Why the timestamp matters.** A generated lockfile reflects the npm registry *at that moment*. Scan the
same commit next week and a newly published patch version may be picked instead. The dashboard says so
explicitly ("versions resolved from the registry at … (time-dependent)"). The architecture doc requires
this distinction between *pinned* and *resolved* versions.

Other lockfiles: if a `yarn.lock` or `pnpm-lock.yaml` is present but no npm lockfile, the agent notes that
those were not parsed and that versions come from npm's resolution, which can differ slightly.

**npm workspaces.** If a `package.json` declares `"workspaces"`, its lockfile already covers all member
packages, so member `package.json` files beneath it are not scanned again as separate projects.

### 5.3 npm: parsing the lockfile

Lockfile versions 2 and 3 (npm 7+) contain a flat `packages` map keyed by install path:

```json
"node_modules/pdfkit":                      { "version": "0.11.0", "dependencies": { "crypto-js": "^3.1.9-1", ... } },
"node_modules/crypto-js":                   { "version": "3.3.0", "resolved": "https://registry.npmjs.org/...", "integrity": "sha512-...", "license": "MIT" },
"node_modules/a/node_modules/b":            { "version": "2.0.0" }
```

**Components.** Each entry becomes a component identified by its **purl** (Package URL, the standard
cross-tool identifier), e.g. `pkg:npm/crypto-js@3.3.0`, or `pkg:npm/%40ai-sdk/gateway@3.0.241` for a
scoped package (the `@` of a scope is percent-encoded as `%40`, per the purl spec). The same name and
version installed at several paths counts as **one** component, with `install_paths` recording how many
copies exist. Different versions of the same package are different components.

Fields kept per component:

| Field | Source | Meaning |
|-------|--------|---------|
| `name`, `version`, `purl` | lockfile | Identity |
| `direct` | root's dependency lists | Declared by the project itself (vs pulled in transitively) |
| `scope` | lockfile `dev` / `optional` flags | `runtime`, `dev` (only needed to develop/test) or `optional`. If a package is runtime anywhere, runtime wins |
| `license` | lockfile | License as declared by the package |
| `resolved` | lockfile | Exact tarball URL it was downloaded from |
| `origin` | derived from `resolved` | Host (e.g. `registry.npmjs.org`), or `git`, `local`, `unknown`. This is the "component origin" the Bosch brief asks for |
| `integrity` | lockfile | Subresource-integrity hash (sha512) of the tarball |
| `install_script` | lockfile `hasInstallScript` | The package runs code when installed. Not a vulnerability, but a classic supply-chain attack vector |
| `projects` | | Which project(s) use it |

**Edges.** For every package and each name in its `dependencies`, `optionalDependencies` and
`peerDependencies` (plus `devDependencies` for the project root), the agent finds *which installed copy*
satisfies it using **Node's own module-resolution rule**: look for `node_modules/<dep>` inside the
requesting package's folder, then walk up one level at a time to the root. That is exactly how Node finds
modules at runtime, so the edges match what the application really loads. Example: if `a` needs `b@^2`
but the root has `b@3`, npm installs `node_modules/a/node_modules/b@2`, and the edge correctly goes
`a → b@2.0.0`, not `b@3.0.0`. (This case is in the self-check, `backend/tests/test_discovery.py`.)

Edge kinds: `runtime`, `dev`, `optional`, `peer` (and for Go, `indirect`). Optional or peer dependencies
that are not installed are skipped silently; a missing **runtime** dependency is counted and reported as
a warning.

Lockfile v1 (npm 6, nested `dependencies` tree) is not supported and is reported as a failure for that
project rather than guessed at.

### 5.4 Python and Go (basic)

* **`requirements*.txt`**: each line like `flask==2.3.2` becomes `pkg:pypi/flask@2.3.2`. Ranges such as
  `flask>=2` become an unversioned component marked `(unpinned)`. Only direct dependencies are known:
  there is no resolver, so the project is marked `partial` with a note.
* **`go.mod`**: every `require` line becomes `pkg:golang/<module>@<version>`. Modules marked
  `// indirect` are flagged transitive, but which module needs them is not known without running
  `go mod graph`, so they hang directly off the project. Marked `partial`.

### 5.5 Output and Juice Shop numbers

| Metric | Juice Shop |
|--------|-----------|
| Projects | 2 (root `juice-shop` 20.4.0-SNAPSHOT, `frontend`) |
| Components | 1,656 unique (1,108 in root, 814 in frontend, 266 shared) |
| Direct | 154 |
| Transitive | 1,502 |
| Dependency edges | 3,381 |
| Packages with install scripts | 14 |
| Agent status | `done` (no unsupported manifests) |

Why 154 direct when the manifests declare 98 + 63 = 161? A few packages are declared by both projects
(counted once), and declarations are ranges while components are resolved versions.

---

## 6. Agent 3: SBOM Generator

**File:** `backend/app/agents/sbom.py` · **Dashboard:** card 3, SBOM tab

### What an SBOM is

A Software Bill of Materials is a machine-readable list of every component in a piece of software. Two
standards dominate: **CycloneDX** (OWASP) and **SPDX** (Linux Foundation). The Bosch brief accepts either;
we produce **CycloneDX 1.5 JSON**, which vulnerability scanners such as OSV-Scanner, Trivy and Grype read
directly. That is how the planned Vulnerability agent will consume it.

### How it is built

One merged SBOM per repository, built from the Discovery inventory (so all ecosystems share one format):

* `metadata.component`: the repository itself (name, short SHA as version, VCS URL, full commit SHA as a
  property).
* `components`: one `application` entry per project, then one `library` entry per package with
  `bom-ref` and `purl`, `version`, `scope` (`required` for runtime, `optional`, `excluded` for dev-only),
  `licenses`, `hashes` (the lockfile's base64 sha512 integrity converted to hex), `externalReferences`
  (the distribution URL) and `properties` (`guardian:direct`, `guardian:origin`,
  `guardian:install_script`).
* `dependencies`: for every component, the list of components it depends on (the graph, in SBOM form).

Juice Shop: **1,658 components** (1,656 packages + 2 projects), **1,659 dependency entries** (one per
component plus the repo root), about 1.7 MB.

### Independent cross-check

To prove the inventory is not invented, the agent also runs npm's own built-in CycloneDX generator for
each npm project:

```
npm sbom --sbom-format cyclonedx --package-lock-only [--legacy-peer-deps]
```

(`--legacy-peer-deps` is added when that project's lockfile was generated with it, otherwise npm rejects
the tree as invalid.) It counts the unique name@version pairs in npm's output and compares them with ours:

| Project | Guardian | npm sbom | Result |
|---------|----------|----------|--------|
| root | 1,108 | 1,108 | match |
| frontend | 814 | 814 | match |

npm's raw SBOMs are kept as evidence (`npm-sbom-0.cdx.json`, `npm-sbom-1.cdx.json`). If npm's tool fails,
that is shown as "tool failed" with its error; it does not invalidate our SBOM.

**Why not Syft?** The architecture recommends Syft. It is not installed on this machine, and
`npm sbom` ships with npm, needs no download, and is authoritative for npm. Syft can be added as another
cross-check later (section 14).

### Evidence recorded

SBOM file name, sha256, size, serial number (`urn:uuid:…`, unique per SBOM), component and dependency
counts, and every cross-check with its own artifact.

---

## 7. Agent 4: Dependency Graph

**File:** `backend/app/agents/graph.py` · **Dashboard:** card 4, Dependency graph tab, Overview charts,
"Introduced via" column

### What it does

Turns the edges into a navigable graph and answers "how did this package get here?" for every package.

### How

1. Nodes: one `repo` node (`juice-shop/juice-shop`), one `project` node per project, one node per
   component. Edges: `repo → project` plus every Discovery edge.
2. **Breadth-first search (BFS)** from the repo node. BFS visits nodes in order of distance, so the first
   time it reaches a package is via a **shortest path**. Remembering the parent of each node gives that
   path for free.
3. For each component it stores the path (e.g. `repo → project:. → pdfkit@0.11.0 → crypto-js@3.3.0`) and
   its **depth** (1 = direct, 2 = dependency of a direct dependency, …).
4. Statistics: fan-in (how many packages depend on each one, giving the "most depended-on" list), fan-out,
   depth histogram, max depth, and any components that cannot be reached from the root (a sign of a broken
   lockfile; the agent goes `partial` if there are any).

The graph is a JSON node/edge list in the scan record. The architecture doc says not to add a graph
database on Day 1; Postgres or SQLite tables are enough until cross-repo queries are needed.

Note that npm graphs can contain cycles (package A needs B, B needs A). BFS handles that naturally because
each node is visited once.

### Juice Shop numbers

| Metric | Value |
|--------|-------|
| Nodes | 1,659 (1 repo + 2 projects + 1,656 packages) |
| Edges | 3,383 (3,381 + 2 repo→project) |
| Max depth | 10 |
| Depth histogram | 1: 154 · 2: 475 · 3: 543 · 4: 293 · 5: 138 · 6: 33 · 7: 8 · 8: 6 · 9: 4 · 10: 2 |
| Most depended-on | `tslib@2.9.1` (45 dependents), `@types/node@26.6.6` (40), `call-bound@1.0.4` (40), … |
| Unreachable | 0 |

Most packages sit 2 to 4 levels deep: they are invisible in `package.json` but still shipped.

Example path the Bosch brief asks for ("show one transitive dependency path"):
`juice-shop/juice-shop → juice-shop → pdfkit@0.11.0 → crypto-js@3.3.0`. Juice Shop never declares
crypto-js, yet it ships version 3.3.0 because pdfkit depends on it (and crypto-js 3.x has a known critical
weakness, which the planned Vulnerability agent will flag).

---

## 8. Agent 5: Container & CI/CD Inspection

**File:** `backend/app/agents/inspection.py` · **Dashboard:** card 5, Container & CI/CD tab

The Bosch brief requires inspecting at least one container image or CI/CD workflow. This agent reads
both, **statically**: it reads the files and never builds or pulls an image or runs a workflow.

### Dockerfiles

Found by name (`Dockerfile`, `Dockerfile.*`, `*.dockerfile`). For each `FROM` line it records the image,
stage alias and line number, and classifies the pinning:

| Pinning | Example | Level | Why |
|---------|---------|-------|-----|
| digest | `node@sha256:ab12…` | info | Immutable: always the same image bytes |
| tag | `node:24` | notice | Tags are mutable: `node:24` points to a different image after every rebuild upstream |
| none / latest | `alpine`, `x:latest` | warning | Whatever is newest at build time |
| build stage | `FROM builder` | info | Refers to an earlier stage of the same file |

Risky build steps (`RUN` lines) it flags:

| Pattern | Why it matters |
|---------|----------------|
| `curl … \| sh` / `wget … \| bash` | Runs a script straight off the internet, unverified |
| `npm install` (not `npm ci`, without `--ignore-scripts`) | Resolves versions at build time (no lockfile enforcement) and runs install scripts |
| `--unsafe-perm` | Install scripts run as root |
| `ADD https://…` | Remote download with no checksum |
| no `USER` instruction | Container runs as the base image's default user (often root) |

### GitHub Actions workflows

For every `.github/workflows/*.yml|yaml`, each `uses:` line is recorded with its line number and
classified:

* **Pinned** if the ref is a full 40-character commit SHA (`actions/checkout@8e5e7e5…`). A SHA cannot be
  moved.
* **Not pinned** if it is a tag or branch (`@v3`, `@main`). The action's owner (or an attacker who
  compromises them) can move that tag to new code, which then runs in your CI with your secrets. This is
  how the 2025 `tj-actions/changed-files` compromise spread. First-party (`actions/*`, `github/*`) unpinned
  refs are a `notice`; third-party ones are a `warning`.
* Local actions (`./…`) count as pinned; `docker://` actions are pinned only with a digest.

Workflow-wide patterns flagged as warnings:

| Pattern | Why it matters |
|---------|----------------|
| `pull_request_target` | Runs on pull requests from forks with a write token and secrets; dangerous if it checks out the PR's code |
| `permissions: write-all` | Every job gets full write access |
| `${{ github.event.issue.title }}` (and PR/comment body, title, head ref, …) | Attacker-controlled text pasted into a script: a script-injection risk |

Other CI systems (`.gitlab-ci.yml`, `Jenkinsfile`, `.travis.yml`, `azure-pipelines.yml`) are detected and
listed as "not inspected", and the agent goes `partial`.

### Juice Shop results

3 Dockerfiles, 6 base-image references, 16 workflows, 94 action references, **7 not SHA-pinned**,
**9 warnings**. Examples:

* `Dockerfile:22`: `FROM gcr.io/distroless/nodejs24-debian13` has no tag or digest (warning).
* `Dockerfile:5`: `RUN npm install --omit=dev` (warning: no lockfile in the image build either).
* `.github/workflows/ci.yml:198`: `coverallsapp/github-action@v2`, a third-party action on a mutable tag.
* `.github/workflows/codeql-analysis.yml:23`: `github/codeql-action/init@v3` (first-party, notice).

These are **observations**, not scored findings. Deciding which matter and with what severity is the
planned Suspicious-Change Detection agent's job.

---

## 9. Planned agents 6 to 8

Shown on the dashboard as dashed purple cards and "planned" tabs, so the pipeline is visible end to end.
None of them runs yet, and **a scan makes no claim about vulnerabilities or suspicious changes until they
do**.

| Agent | Will do | Input already available |
|-------|---------|-------------------------|
| 6 Vulnerability Detection | Run OSV-Scanner or Trivy on `sbom.cdx.json` (or query the OSV API by purl); record advisory ID, severity, affected range, fixed version, source | SBOM, purls |
| 7 Suspicious-Change Detection | Non-CVE risks: install scripts, typosquat-like names, unexpected origins, unpinned images/actions (from agent 5), lockfile/manifest changes | Components with `install_script`, `origin`; inspection observations; the clone |
| 8 Investigation & Evidence | Join both branches with the graph: dependency path, evidence references, verified fact vs inference vs unknown; Day 1 report. First agent that may use an LLM, for explanation only | Paths from agent 4, everything above |

---

## 10. Storage, artifacts and the API

### Where files go

Everything lives under `backend/data/` (gitignored; override with the `GUARDIAN_DATA_DIR` environment
variable):

```
backend/data/
├── guardian.db                     SQLite: one row per scan
├── workspaces/<scan-id>/repo/      the clone (kept for later agents)
└── scans/<scan-id>/                evidence artifacts
    ├── sbom.cdx.json               the CycloneDX SBOM
    ├── generated-lock-0.json       lockfile generated for project 0 (if none committed)
    ├── generated-lock-1.json
    ├── npm-sbom-0.cdx.json         npm's own SBOM, cross-check evidence
    └── npm-sbom-1.cdx.json
```

### The database

Table `scans(id, repo_url, status, commit_sha, created_at, data)`. `data` is the full scan record as
JSON:

```json
{
  "id": "096bbd373609", "repo_url": "...", "status": "completed", "commit_sha": "c9f9922...",
  "error": null,
  "agents":  { "checkout": {"name": "Repository Intake", "status": "done", "summary": "...", "duration": 15.3}, ... },
  "results": { "checkout": {...}, "discovery": {...}, "sbom": {...}, "graph": {...}, "inspection": {...} }
}
```

A global lock serializes writes (fine for one process). If the server restarts mid-scan, scans left
`queued` or `running` are marked `failed` at the next start instead of spinning forever. Moving to
PostgreSQL with separate component, edge and finding tables is the planned upgrade when cross-scan queries
are needed.

### API endpoints

| Method & path | Purpose | Response |
|---------------|---------|----------|
| `POST /api/scans` body `{"repo_url": "..."}` | Validate URL, create scan, start pipeline | `202 {"id": "..."}`; `400` for a non-GitHub URL |
| `GET /api/scans` | Last 50 scans (for the home page) | `[{id, repo_url, status, commit_sha, created_at}]` |
| `GET /api/scans/{id}` | Full scan record (what the dashboard polls) | the JSON above; `404` if unknown |
| `GET /api/scans/{id}/artifacts/{name}` | Download an evidence file | the file; `404` if missing. Path traversal (`../`) is blocked |

Interactive API docs: http://localhost:8000/docs (FastAPI's built-in Swagger page).

---

## 11. Dashboard walkthrough

**Files:** `frontend/src/` (React 19 + TypeScript, Vite). `App.tsx` (routing, home, scan page, tabs),
`Overview.tsx`, `GraphView.tsx`, `SbomTable.tsx`, `Inspection.tsx`, `types.ts` (the typed API
contract), `styles.css`.

### Top bar

* **Supply Chain Guardian**: click to return home.
* **☀ Light / ☾ Dark**: theme toggle. It starts from your OS setting and is remembered in this browser.

### Home page

* **Scan box**: paste a public GitHub URL (pre-filled with Juice Shop) and press **Start scan**. Invalid
  URLs show the backend's error under the box. If the backend is not running you see "Backend not
  reachable on port 8000".
* **Recent scans**: the last 50 scans with repository, short commit SHA, status badge and start time.
  Click a row to open it. The URL `#/scan/<id>` is shareable and bookmarkable.

### Scan header

Repository (links to GitHub), branch, short commit SHA, commit date and author, commit subject in quotes,
and a large status badge: `queued` / `running` (blue), `completed` (green), `failed` (red). If the scan
failed, a red banner states the error and that the results are incomplete, so nothing should be read as
"clean".

### Agent pipeline (the eight cards)

One card per agent, in pipeline order. Each shows a status icon, step number, agent name, the one-line
summary, and duration. The top border colour carries the status:

| Icon / colour | Status |
|---------------|--------|
| ✓ green | done |
| ! amber | partial: finished with a coverage gap, read the warnings |
| ◌ blue, spinning | running |
| ✕ red | failed (hover the card for the error) |
| ○ grey | pending |
| – faded | skipped |
| … purple, dashed | planned (not built) |

Click a card to jump to its tab. Juice Shop summaries:

| Card | Summary |
|------|---------|
| 1 Repository Intake | `juice-shop/juice-shop @ c9f99228d9d5 (1498 files)` |
| 2 Discovery Agent | `2 project(s), 1656 components (154 direct)` |
| 3 SBOM Generator | `CycloneDX 1.5, 1658 components` |
| 4 Dependency Graph | `1659 nodes, 3383 edges, max depth 10` |
| 5 Container & CI/CD | `3 Dockerfile(s), 16 workflow(s), 7 unpinned action ref(s)` |
| 6–8 | `planned` |

### Tab: Overview

**KPI tiles**

| Tile | Juice Shop | Meaning |
|------|-----------|---------|
| Components | 1656 | Unique package@version across all projects |
| Direct | 154 | Declared in a project's own manifest |
| Transitive | 1502 | Pulled in by other packages |
| Dependency edges | 3381 | "A depends on B" links between packages and projects |
| Max depth | 10 | Longest shortest-path from a project to a package |
| Install scripts | 14 | Packages that run code when installed |
| CI/container warnings | 9 | Warning-level inspection observations |
| SBOM | CDX 1.5 | Format and spec version of the generated SBOM |

**Discovered projects table**

| Column | Content |
|--------|---------|
| Manifest | Path to the manifest, with the package name and version under it |
| Ecosystem | npm / pypi / golang |
| Lockfile | Lockfile used, plus a chip: `committed` (green, from the repo) or `generated` (orange, made at scan time) |
| Components | Packages in this project, and how many the manifest declares directly |
| Status | `parsed` (full), `partial` (direct only, or with gaps), `failed` |
| Evidence | The exact npm command, npm version and resolution time, lockfile sha256, a **download lockfile** link, and notes in amber (e.g. "`.npmrc` disables lockfiles", "time-dependent") |

**Coverage gaps** (amber card, only when needed): every warning, such as unsupported manifests,
unresolvable dependencies, or "no supported manifests found: inventory is empty because coverage is zero,
not because the repo is clean". Juice Shop has none.

**Components by dependency depth**: a bar per depth level ("direct", "depth 2", …) with counts, showing
how much of the software is hidden below the surface.

**Most depended-on packages**: top 10 by number of dependents. A compromise of one of these reaches the
most of the tree.

**Scan provenance**: repo URL, full pinned commit SHA, the exact clone command, tracked file count, SBOM
sha256, and the execution policy (no repository scripts run). This is the reproducibility record.

### Tab: Dependency graph

An interactive force-directed graph (canvas-based, so 1,659 nodes stay smooth). Packages push apart and
links pull together, so tightly related packages cluster.

* **Search box**: type or pick a package (`crypto-js@3.3.0`). The graph zooms to frame its whole
  introduction path, which is highlighted in yellow (amber in light mode) with arrows, and the side panel
  opens.
* **View switch**: `All` (everything), `Hide dev` (drops dev-only packages and dev edges, i.e. what
  actually ships), `Direct only` (repo, projects and direct dependencies, for a clean overview). The counter
  shows nodes and edges in the current view.
* **Legend / colours**: white (dark mode) or black (light mode) = repo; purple = project; teal = direct;
  blue = transitive; grey = dev-only; orange ring = has an install script; yellow/amber = selected path.
* **Node size**: repo largest, projects next, packages grow with their number of dependents.
* **Mouse**: hover a node for its name; click to select; scroll to zoom; drag the background to pan; click
  empty space to clear the selection.

**Side panel (Component details)** for the selected package:

| Section | Content |
|---------|---------|
| Header | Direct or transitive dependency, name@version |
| Introduced via | The shortest path from the repo to this package, each step clickable |
| purl, Scope, License, Origin | As in section 5.3 |
| Resolved | Exact download URL |
| Integrity | Start of the sha512 hash |
| Install script | yes / no |
| Install paths | Number of installed copies of this exact version |
| Projects | Which projects use it |
| Required by (n) | Packages that depend on it, with edge kind (runtime/dev/optional/peer) |
| Depends on (n) | Packages it depends on |

Try `crypto-js@3.3.0`: path `juice-shop/juice-shop → juice-shop → pdfkit@0.11.0 → crypto-js@3.3.0`,
transitive, runtime, MIT, `registry.npmjs.org`, required by `pdfkit@0.11.0`.

### Tab: SBOM

* **Header**: format, component and dependency-entry counts, serial number, sha256 prefix, size, and a
  **Download SBOM (JSON)** button (the CycloneDX file, ready for any scanner).
* **Independent cross-check**: per npm project, Guardian count vs `npm sbom` count, a `match` / `differs`
  / `tool failed` badge, and a `raw` link to npm's own SBOM.
* **Component table**, with filters:
  * text filter on name, purl or license;
  * relationship: direct + transitive / direct only / transitive only / has install script;
  * scope: all / runtime / dev / optional;
  * a counter (e.g. `1656 of 1656`) and 100 rows per page.

  | Column | Content |
  |--------|---------|
  | Package | Name (hover for the full purl); an orange `script` chip if it has an install script |
  | Version | Exact resolved version |
  | Ecosystem | npm / pypi / golang |
  | Relationship | `direct` or `transitive` |
  | Introduced via | The package that pulled it in (last step before it on the shortest path), or "project root" for direct ones. Hover for the full path |
  | Scope | runtime / dev / optional |
  | License | Declared license, or "unknown" |
  | Origin | Registry host or git/local/unknown |

  Example: filter "Has install script" to see the 14 packages that would run code on `npm install`.

### Tab: Container & CI/CD

* **KPI tiles**: Dockerfiles (3), Base images (6), Workflows (16), Action references (94),
  Not SHA-pinned (7), Warnings (9).
* **Observations table**: level badge (`WARNING` amber, `NOTICE` blue, `INFO` green), what was observed,
  and the evidence: a `file:line` link that opens that exact line **at the scanned commit** on GitHub, plus
  the offending line in a code box.
* **Container base images**: per Dockerfile, each `FROM` image, its stage name and a pinning badge.
* **GitHub Actions**: every action reference with workflow file and line (linked) and whether it is
  SHA-pinned. The "only not SHA-pinned" checkbox (on by default) narrows it to the 7 that matter.
* If other CI systems exist, a red banner lists them as not inspected.

### Tabs: Vulnerabilities, Suspicious changes, Evidence report

Marked `PLANNED`. Each shows what the agent will do and states explicitly that, until it runs, the scan
makes no claim in that area.

---

## 12. Safety model

The repo being scanned is **untrusted input**. The rules, and where they are enforced:

| Rule | Enforcement |
|------|-------------|
| Only public GitHub repos | URL regex at the API (`main.py`) and again in the Intake agent |
| Nothing is cloned until a URL is submitted | Cloning only happens inside the pipeline started by `POST /api/scans` |
| No repository code runs | git clone runs no hooks; npm always runs with `--ignore-scripts` and `--package-lock-only` (no packages installed); Dockerfiles and workflows are only read |
| No escape via symlinks | `core.symlinks=false` |
| No hanging on credentials | `GIT_TERMINAL_PROMPT=0`, timeouts on every subprocess |
| Evidence downloads cannot read other files | Artifact endpoint resolves the path and requires it to be directly inside the scan's folder |
| Never report clean when coverage is incomplete | `partial` / `failed` statuses, coverage-gap warnings, explicit "planned" notices |
| Scanned code never enters our git repo | `backend/data/` is gitignored |

One residual note: npm reads the repo's `.npmrc` during lockfile generation, so a repo could point npm at
a different registry. The `origin` column exposes this (it would show a non-npmjs host), and the
Suspicious-Change agent should flag it.

---

## 13. Limits and known gaps

| Limit | Effect | Path forward |
|-------|--------|--------------|
| Full transitive support is npm-only | Python/Go show direct deps only (`partial`); Maven, Gradle, Cargo, Ruby, PHP are listed as gaps | Add adapters (`poetry.lock`, `go mod graph`, `mvn dependency:tree`) or run Syft |
| Generated lockfiles are time-dependent | Rescanning the same commit later can resolve newer patch versions | Shown with timestamp and hash; prefer repos with committed lockfiles for reproducible demos |
| `yarn.lock` / `pnpm-lock.yaml` not parsed | npm's resolution is used instead and may differ | Add parsers |
| npm lockfile v1 not supported | That project fails | Regenerate, or add a v1 parser |
| One shortest path per package | Packages reachable several ways show only one route | Side panel lists all "Required by" parents; an all-paths query can be added |
| Container images not pulled or scanned | Only the Dockerfile text is inspected | Trivy image scan in the Vulnerability agent |
| Only GitHub Actions inspected in depth | Other CI systems listed but not analysed | Add parsers |
| Shallow clone, no history | No commit diffs yet | Suspicious-Change agent will fetch a base commit for diffs |
| SQLite + one lock, single process | Fine for a demo, not for many parallel scans | PostgreSQL + a job queue (architecture doc section 7) |
| No authentication | Anyone who can reach port 8000 can start scans | Run locally; add auth before exposing it |

---

## 14. Extending the system

Adding an agent takes three steps:

1. Create `backend/app/agents/<name>.py` with `def run(state) -> tuple[dict, dict]`. Read what you need
   from `state` (e.g. `state["components"]`, the SBOM at `state["artifacts"]/sbom.cdx.json`, the clone at
   `state["workdir"]`), and return `(state_update, dashboard_result)` with `_summary` and optionally
   `_status`.
2. Add it to `STEPS` in `backend/app/pipeline.py`. For the three planned agents, also remove the key from
   `PLANNED` in `backend/app/db.py`, so new scans show them as `pending` rather than `planned`.
3. Add its result type to `frontend/src/types.ts` and replace the planned panel for its tab in `App.tsx`
   with a real component.

New ecosystems go into `discovery.py` as another adapter emitting the same component and edge shape;
SBOM, graph and dashboard then work unchanged.

---

## 15. Glossary

| Term | Meaning |
|------|---------|
| Supply chain | All third-party code, tools, images and services that go into building and running your software |
| Manifest | File declaring dependencies and allowed version ranges (`package.json`, `requirements.txt`, `go.mod`) |
| Lockfile | File pinning the exact resolved version of every direct and transitive dependency (`package-lock.json`) |
| Direct dependency | Declared in the project's own manifest |
| Transitive dependency | Required by another dependency, not declared by the project |
| Dev dependency | Needed only for development/testing, not shipped at runtime |
| Peer dependency | A package expects the host project to provide it (common with plugins and Angular/React libraries) |
| `--legacy-peer-deps` | npm's npm-6-style mode that does not fail on peer-dependency conflicts |
| Install script | `preinstall` / `install` / `postinstall` code a package runs when installed |
| purl | Package URL, a standard ID like `pkg:npm/crypto-js@3.3.0` that every SBOM and vulnerability tool understands |
| SBOM | Software Bill of Materials: a machine-readable inventory of components |
| CycloneDX | OWASP's SBOM standard (we emit version 1.5 JSON) |
| Integrity hash | sha512 of a package tarball, so a tampered download can be detected |
| Origin | Where a package was downloaded from (registry host, git, local) |
| BFS | Breadth-first search: explores a graph level by level, giving shortest paths |
| Fan-in | Number of packages that depend on a given package |
| Digest pinning | Referencing a container image by its content hash (`@sha256:…`), which cannot change |
| SHA pinning | Referencing a GitHub Action by full commit hash, which cannot be moved |
| `pull_request_target` | GitHub Actions trigger that runs with the base repo's secrets on fork PRs |
| LangGraph | Library for stateful agent workflows as graphs; our orchestrator |
| CVE / advisory | A publicly recorded vulnerability (handled by the planned Vulnerability agent) |
