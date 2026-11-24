# Supply Chain Guardian: In-Depth Guide

This guide explains everything built so far (all of Day 1: tasks 1 to 8 from the architecture document), how each
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
9. [Agents 6 to 8: vulnerabilities, suspicious patterns, evidence](#9-agents-6-to-8-vulnerabilities-suspicious-patterns-evidence)
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
   ├─▶ 6 Vulnerability Detection      osv-scanner per lockfile (+ Trivy cross-check) → advisories
   ├─▶ 7 Suspicious-Change Detection  rules over lockfile, origins, names, Dockerfiles, workflows
   └─▶ 8 Investigation & Evidence     evidence bundle + initial risk per finding → report.md/json
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
   (all `pending`). The id is returned at once, so the browser does not wait for the
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
| `planned` | Listed but not built (none at the moment; used when adding future agents) |

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
directly. (The Vulnerability agent scans the lockfiles the SBOM was built from.)

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
weakness, which the Vulnerability agent flags as critical: GHSA-xwcq-pm8m-c4vf, fixed in 4.2.0).

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
Suspicious-Change Detection agent's job (section 9.2).

---

## 9. Agents 6 to 8: vulnerabilities, suspicious patterns, evidence

The two detection agents answer different questions, as the architecture doc requires: *does a published
advisory affect this exact package version?* (agent 6) and *is there a risky supply-chain pattern even
without a CVE?* (agent 7). Agent 8 joins both with the graph into evidence bundles.

Juice Shop run (all eight agents, about 75 seconds with cached npm metadata): **57 advisories on 22
packages** (7 critical, 22 high, 26 medium, 2 low), **34 suspicious-pattern findings**, **91 evidence
bundles** (7 critical, 20 high, 44 medium, 20 low initial risk).

### 9.1 Agent 6: Vulnerability Detection

**File:** `backend/app/agents/vulnerability.py` · **Tools:** [OSV-Scanner](https://google.github.io/osv-scanner/)
2.7.1 (required), [Trivy](https://trivy.dev) 0.76.2 (optional cross-check). Install on Windows with
`scoop install osv-scanner trivy`.

**What OSV is.** [OSV.dev](https://osv.dev) is Google's open vulnerability database. It aggregates the
GitHub Advisory Database (GHSA ids), the National Vulnerability Database (CVE ids), PyPI, Go and others
into one format with exact affected version ranges. OSV-Scanner reads a lockfile, asks OSV which of its
exact package versions are affected, and prints JSON.

**How it runs.** For every project Discovery found, the agent picks what the scanner can read: the npm
lockfile (committed or the one Discovery generated), the `requirements.txt` file, or `go.mod`. Then:

```
osv-scanner scan --lockfile package-lock.json --format json
```

* **Online mode (default)** queries `api.osv.dev`, so results are as fresh as the database.
* **Offline mode**: set `GUARDIAN_OSV_OFFLINE=1` before starting the backend. It adds
  `--offline-vulnerabilities --download-offline-databases`, so OSV's database is downloaded once and
  matched locally. The mode used is recorded with each scan.
* Exit code 1 means "vulnerabilities found" and is treated as success. Any other non-zero code marks that
  project's scan **failed** with the error text, and the agent goes `partial`. A failed scan is never
  reported as zero vulnerabilities.
* The scanner's JSON is saved untouched as `osv-<n>.json`, downloadable from the dashboard.

**Normalization.** OSV groups advisories that describe the same issue (e.g. `GHSA-xwcq-pm8m-c4vf` and
`CVE-2023-46233`). Each group on each package becomes **one finding**:

| Field | Source / rule |
|-------|---------------|
| `advisory_id` | The GHSA id if the group has one (GitHub-reviewed), else the first id |
| `aliases`, `cves` | Every other id in the group (CVE ids listed separately) |
| `cvss_score` | OSV's `max_severity` for the group (CVSS base score, 0–10) |
| `cvss_vector` | The CVSS vector string from the advisory, e.g. `CVSS:3.1/AV:N/AC:L/...` |
| `severity` | From the score: ≥9 critical, ≥7 high, ≥4 medium, >0 low. **No score** → the advisory's own label (GHSA `CRITICAL/HIGH/MODERATE/LOW`), recorded as `severity_source: advisory label`. **Neither** → `unrated` |
| `fixed_versions`, `fix` | All `fixed` events in the advisory's ranges for this package; `fix` is the lowest one newer than the installed version, or none ("no fix published") |
| `cwe` | Weakness ids (e.g. CWE-78 command injection) |
| `path`, `direct`, `scope` | Joined from the dependency graph by purl (`pkg:npm/name@version`): the "introduced via" path |
| `url` | `https://osv.dev/vulnerability/<id>` |

If the same package@advisory appears in both projects it is kept once, with `also_in` listing the other.
Juice Shop's 6 findings without a CVSS score (e.g. the `jsonwebtoken` and `marsdb` advisories) use the
advisory label.

**Trivy cross-check.** If `trivy` is on PATH, `trivy fs --scanners vuln --format json` runs on the same
lockfile. Each OSV finding gets `trivy_confirmed: true` when Trivy reports one of its ids on the same
package version. Juice Shop root: Trivy reported 54 entries and 50 match OSV. The 4 left over use old
`NSWG-ECO-*` ids (Node Security Working Group), which OSV files under a different id for the same issue.
Raw Trivy output is saved as `trivy-<n>.json`. The first Trivy run downloads its database (about a minute).

**Evidence recorded per project:** the exact command, the OSV-Scanner version, mode, timestamp, the
scanned file and its sha256 (the same hash Discovery recorded for a generated lockfile), the raw output
file, finding counts, and the Trivy agreement.

Examples from Juice Shop:

| Severity | Advisory | Package | Introduced via | Fixed in |
|----------|----------|---------|----------------|----------|
| critical 9.2 | GHSA-23hp-3jrh-7fpw | tar@6.2.1 | juice-shop → sqlite3@5.1.7 → tar | 7.5.19 |
| critical 9.1 | GHSA-xwcq-pm8m-c4vf (CVE-2023-46233) | crypto-js@3.3.0 | juice-shop → pdfkit@0.11.0 → crypto-js | 4.2.0 |
| critical 9.1 | GHSA-jf85-cpcp-j695 (CVE-2019-10744) | lodash@2.4.2 | juice-shop → sanitize-html@1.4.2 → lodash | 4.17.12 |
| high 8.7 | GHSA-gjcw-v447-2w7q | jws@0.2.6 | juice-shop → jsonwebtoken@0.4.0 → jws | 3.0.0 |

### 9.2 Agent 7: Suspicious-Change Detection

**File:** `backend/app/agents/change_detection.py`. No external tool: rules over data the earlier agents
already collected. Every finding is labelled **fact** (read directly from a file or tool output) or
**indicator** (a heuristic that needs a human to look).

| Rule | What it checks | Severity | Basis | Juice Shop |
|------|----------------|----------|-------|-----------|
| `install-script` | Lockfile `hasInstallScript: true`: the package runs code when installed | medium if runtime, low if dev/optional | fact | 14 |
| `unexpected-origin` | Tarball not from `registry.npmjs.org` / PyPI / Go proxy (git URL, plain URL, other registry) | high (local workspace package: low) | fact | 0 |
| `typosquat` | Name within one character edit (insert, delete, substitute, swap) of a popular npm package, or equal once `-`, `_`, `.` are removed. Scoped and short names are skipped | low | indicator | 2 (`colord` vs color, `safer-buffer` vs safe-buffer: both legitimate, which is why it is only an indicator) |
| `no-lockfile` | Project has no committed lockfile (Discovery had to generate one) | medium | fact | 2 |
| `unpinned-action` | GitHub Action on a tag/branch, not a commit SHA | medium third-party, low first-party | fact | 7 |
| `base-image` | `FROM` without a digest | medium for none/latest, low for a version tag | fact | 5 |
| `workflow-risk` | `pull_request_target`, `permissions: write-all`, untrusted event text in scripts | medium / high | fact | 1 |
| `build-install` | Dockerfile `npm install` (no lockfile) | medium for app deps, low for `npm install -g <tool>` | fact | 3 |

**Not applicable on a baseline scan:** `modified-lockfile`, `unexpected-new-dependency` and
`suspicious-version-bump` need a *before* and *after* commit to compare. This scan analyses one pinned
commit, so they are listed on the dashboard as not applicable, with the reason, instead of being silently
skipped.

The popular-package list is a fixed set of about 170 well-known npm names in the source file. Swapping it
for npm's top-1000 by downloads would catch more lookalikes.

### 9.3 Agent 8: Investigation & Evidence

**File:** `backend/app/agents/evidence.py`. Turns every finding from agents 6 and 7 into an **evidence
bundle**, the contract the architecture doc calls `EvidenceBundle`:

| Part | Content |
|------|---------|
| Component | purl, name, version, direct/transitive, scope |
| Dependency path | Repo → project → … → package, as names |
| Evidence references | Advisory URL, raw scanner output, SBOM entry, lockfile tarball URL + integrity hash, or `file:line` for CI/container findings |
| **Verified facts** | Statements generated straight from tool output, e.g. "OSV advisory GHSA-… lists crypto-js@3.3.0 as affected", "CVSS base score 9.1 (vector)", "Fixed in 4.2.0", "Trivy independently reports the same advisory" |
| **Inference** | Reasoned, not proven: "Transitive: fixing it most likely means upgrading the direct dependency pdfkit@0.11.0, or overriding the version", "Dev-only: not shipped in the production app", the rule's rationale |
| **Unknowns** | What was not checked: reachability (is the vulnerable function called?), exploitability in this deployment, what an install script actually does, a lookalike's publisher |
| **Initial risk** | A transparent rule, with its rationale shown (below) |

**Initial risk rule**

* Vulnerability: the severity band. If the package is **dev-only**, one level lower ("not part of the
  running application"). No rating at all → `review`.
* Suspicious pattern: the rule's own severity.

It deliberately does not use reachability or exposure; those are Day 2 Risk Analysis inputs, and the
report lists them as unknown rather than guessing.

**Outputs**

* `report.md`: human-readable report (coverage table, risk counts, every bundle). This is the Day 1 report.
* `report.json`: the same, machine-readable.
* A row per finding in the SQLite `findings` table (scan id, finding id, type, severity, initial risk,
  purl, advisory id, rule, title, full bundle JSON) for querying across scans.
* The **Day 1 acceptance checklist**, computed from what actually ran (e.g. "Vulnerability scan with
  advisory evidence" is only ticked if every project's scan succeeded).
* **Coverage gaps**: unsupported manifests, failed scanner runs, not-applicable rules, and the standing
  note that reachability is not analysed. None of these are presented as "clean".

**No LLM.** Every sentence in the report is assembled from tool output, so it works offline, costs
nothing, and cannot invent a CVE or a reachability claim. An LLM can later write a plain-English summary
on top of these bundles (Day 2), with the bundles as its only source.

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
    ├── npm-sbom-1.cdx.json
    ├── osv-0.json, osv-1.json      raw OSV-Scanner output per project
    ├── trivy-0.json, trivy-1.json  raw Trivy output (if installed)
    ├── report.md                   the Day 1 evidence report
    └── report.json                 same, machine-readable
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

Table `findings(scan_id, finding_id, type, severity, initial_risk, component, advisory_id, rule, title,
data)` holds one normalized row per vulnerability or suspicious finding (written by agent 8). Scans are
never modified after they finish: rescanning creates a new scan id, so results from different times
can be compared.

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
`Overview.tsx`, `GraphView.tsx`, `SbomTable.tsx`, `Inspection.tsx`, `Vulnerabilities.tsx`,
`Suspicious.tsx`, `Report.tsx`, `types.ts` (the typed API
contract), `styles.css`.

### Top bar

* **Supply Chain Guardian**: click to return home.
* **☀ Light / ☾ Dark**: theme toggle. It starts from your OS setting and is remembered in this browser.

### Home page

* **Scan box**: paste a public GitHub URL (empty by default; the placeholder shows the format) and press **Start scan**. Invalid
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
| 6 Vulnerability Detection | `57 advisories on 22 packages (7 critical, 22 high)` |
| 7 Suspicious-Change Detection | `34 findings across 7 rules (14 install-script, 7 unpinned-action, 5 base-image)` |
| 8 Investigation & Evidence | `91 evidence bundles, 27 critical/high initial risk` |

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
| Critical / high advisories | 7 / 22 | From the Vulnerability agent (57 advisories on 22 packages) |
| Suspicious-pattern findings | 34 | From the Suspicious-Change agent (0 high, 18 medium) |

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
  blue = transitive; grey = dev-only; orange ring = has an install script; yellow/amber = selected path;
  pink = hovered node and its neighbours. Each theme has its own palette with edges strong enough to read
  on its background.
* **Node size**: repo largest, projects next, packages grow with their number of dependents.
* **Hover tooltip**: hovering any dot shows `name@version`, direct or transitive, scope, depth, number of
  dependents and whether it has an install script. The hovered node, its edges and its direct neighbours
  turn pink and get labels, so you can see what it connects to at a glance.
* **Labels**: the repo, projects and the selected path are always labelled. Direct dependencies are
  labelled once you zoom in slightly (hidden at full zoom-out, where Juice Shop's 154 labels would overlap).
  Beyond about 2.5x zoom every package is labelled. Labels have a halo in the background colour so they
  stay readable over edges in both themes.
* **Mouse**: hover for the tooltip; click a node to open its details; scroll to zoom; drag the background
  to pan; click empty space to clear the selection. Every node can be clicked within about 8 screen pixels,
  even when it is drawn smaller than that at low zoom.
* **Narrow windows** (under 1100 px): the details panel floats over the right side of the graph instead
  of dropping below it, with a × to close it.

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

### Tab: Vulnerabilities

* **Severity tiles**: Critical 7, High 22, Medium 26, Low 2, Unrated 0, Packages affected 22. Click a
  tile to filter the table to that severity (click again to clear).
* **Scan evidence**: one row per project: OSV-Scanner version, mode (online/offline), timestamp and exact
  command; the scanned file and its sha256; result (`ok` / `failed` / `not scanned` with the reason) and
  a **raw OSV JSON** link; Trivy agreement ("50 of 54 entries match OSV", hover the leftover count to see
  them) and a raw Trivy link.
* **Advisory table**, filterable by text (package, GHSA/CVE id, title), severity and relationship
  (direct, transitive, runtime scope only):

  | Column | Content |
  |--------|---------|
  | Severity | Band badge with the CVSS score (e.g. `CRITICAL 9.1`) |
  | Advisory | GHSA id linked to osv.dev, CVE ids under it |
  | Package | name@version, `direct`/`transitive` chip, scope chip if not runtime |
  | Introduced via | The path, e.g. `juice-shop → pdfkit@0.11.0 → crypto-js@3.3.0` |
  | Fixed in | Lowest fixed version above the installed one, or "no fix" |
  | Summary | The advisory's title |

  Click a row for details: severity source, CVSS vector, all ids, CWE, every fixed version, project(s),
  whether Trivy confirms it, and publish date.

### Tab: Suspicious changes

* **Severity tiles** (high / medium / low, clickable) and **Rules triggered**.
* **Patterns checked**: a chip per rule with its count (greyed if zero); click to filter. Below it, the
  rules that are **not applicable** to a baseline scan (hover for the reason).
* **Findings table**: severity; the finding with its category, rule and (for packages) introduction path;
  **basis** (`fact` = read from a file or tool, `indicator` = heuristic, needs review); evidence
  (`file:line` link to GitHub at the scanned commit with the line's text, or the lockfile field and
  tarball URL); and why it matters.

### Tab: Evidence report

* **Header**: repository and commit, generation time, counts, and **Report (Markdown)** / **JSON**
  download buttons.
* **Initial-risk tiles**: critical 7, high 20, medium 44, low 20, review 0 (clickable filters).
* **Day 1 acceptance checklist**: each item from the architecture doc with ✓ or ✕, computed from what
  actually ran in this scan.
* **Coverage and gaps**: what this scan did not check.
* **Evidence bundles**: one expandable row per finding, sorted by initial risk. Expanded, it shows the
  dependency path, the risk rationale, the fixed version, three columns (**Verified facts**,
  **Inference**, **Unknown / not checked**) and the evidence links.

Scans made before agents 6 to 8 existed show those tabs as "did not exist when this scan ran"; start a
new scan to fill them.

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
| Never report clean when coverage is incomplete | `partial` / `failed` statuses, coverage-gap warnings, not-applicable rules and "unknown" lists in every evidence bundle |
| Scanned code never enters our git repo | `backend/data/` is gitignored |

One residual note: npm reads the repo's `.npmrc` during lockfile generation, so a repo could point npm at
a different registry. The `origin` column exposes this, and the Suspicious-Change agent's
`unexpected-origin` rule flags any package not served by the public registry as high.

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
| Shallow clone, no history | Diff-based rules (modified lockfile, new dependency, version bump) are not applicable | Fetch a base commit and diff manifests/lockfiles |
| Reachability not analysed | A vulnerable package may never have its vulnerable code called; risk can be overstated | Day 2: static call analysis, exposure and production-usage inputs |
| Typosquat list is static (~170 names) | Lookalikes of less popular packages are missed; legitimate lookalikes are flagged (as indicators) | Use npm download counts and publisher data |
| OSV online mode needs network | No network → that project's scan fails (reported, not clean) | `GUARDIAN_OSV_OFFLINE=1` with a downloaded database |
| Install scripts not inspected | We know a script exists, not what it does | Download the tarball in a sandbox and read the script |
| SQLite + one lock, single process | Fine for a demo, not for many parallel scans | PostgreSQL + a job queue (architecture doc section 7) |
| No authentication | Anyone who can reach port 8000 can start scans | Run locally; add auth before exposing it |

---

## 14. Extending the system

Adding an agent takes three steps:

1. Create `backend/app/agents/<name>.py` with `def run(state) -> tuple[dict, dict]`. Read what you need
   from `state` (e.g. `state["components"]`, the SBOM at `state["artifacts"]/sbom.cdx.json`, the clone at
   `state["workdir"]`), and return `(state_update, dashboard_result)` with `_summary` and optionally
   `_status`.
2. Add it to `STEPS` in `backend/app/pipeline.py` and to `AGENTS` in `backend/app/db.py` (name shown on
   its card). To show an agent before it exists, put its key in `PLANNED`.
3. Add its result type to `frontend/src/types.ts`, a component for its tab, and the tab in `App.tsx`.

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
| CVE / advisory | A publicly recorded vulnerability with an id (CVE from MITRE/NVD, GHSA from GitHub) |
| OSV | Open Source Vulnerabilities: Google's database and format that merges GHSA, NVD and ecosystem advisories with exact affected versions |
| CVSS | Common Vulnerability Scoring System: a 0–10 base score plus a vector describing how the issue is exploited |
| Evidence bundle | One finding with its component, path, evidence links, verified facts, inference, unknowns and initial risk |
| Initial risk | Day 1 rating from a fixed rule (severity band, lowered for dev-only); Day 2 refines it with reachability and exposure |
