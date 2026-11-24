"""Day 2 · Investigate: "Is this flagged package really dangerous?"

Input: packages the Suspicious-Change agent flagged (install-script, typosquat,
unexpected-origin) plus any package with a known-malware advisory (OSV "MAL-" id).

Per package (facts, from tools):
  1. `npm pack <name>@<version> --ignore-scripts` downloads the published tarball. Nothing is
     installed or executed. Its integrity hash is compared with the lockfile's.
  2. The tarball is extracted (tarfile "data" filter: no absolute paths, links or device files).
  3. Install hooks (preinstall/install/postinstall) are read from package.json, and any local
     script file they invoke is read (first 150 lines).
  4. GuardDog's npm source-code rules (semgrep) run once over all packages together
     (semgrep's start-up is slow on Windows); results are cached per package@version.
  5. OSV "MAL-" advisories for the package come from the Vulnerability agent's results.
Then the LLM reads the scripts + GuardDog hits and answers malicious / risky / harmless with a
confidence and the file:line it relied on; the Validator checks those citations exist.

Rule verdict (used when the AI is unavailable or fails validation):
  MAL- advisory -> malicious (fact); GuardDog hits beyond "has install script" -> risky;
  otherwise -> unknown (needs human review).
"""
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

from .. import db, llm
from .discovery import NPM

FLAG_RULES = {"install-script", "typosquat", "unexpected-origin"}
HOOKS = ("preinstall", "install", "postinstall")
SCRIPTS_DIR = Path(sys.executable).parent  # venv Scripts/bin: semgrep + guarddog live here
# Locate GuardDog's rule files without importing it (its import reads YAML in the OS codepage
# and fails on Windows); we only need the rules, run by semgrep below.
_spec = importlib.util.find_spec("guarddog")
GUARDDOG_RULES = Path(_spec.origin).parent / "analyzer" / "sourcecode" if _spec else None
GUARDDOG_VERSION = importlib.metadata.version("guarddog") if _spec else None
SEMGREP = shutil.which("semgrep", path=str(SCRIPTS_DIR)) or shutil.which("semgrep")

SYSTEM = """You are a software supply-chain security analyst. You judge whether an npm package's
install-time behaviour is malicious, risky or harmless, using ONLY the evidence given.
- malicious: clear intent to harm (exfiltrating secrets/env, downloading and running remote code,
  obfuscated payloads, persistence, crypto-miners).
- risky: runs code at install time that could be abused or is hard to audit (downloads binaries,
  runs node-gyp/compilers, shells out), but no sign of malicious intent.
- harmless: install-time code is benign and expected for this kind of package, or nothing runs.
Cite the exact file and line numbers you relied on (files and line numbers are shown before each
line). Never invent advisory IDs. Reply as JSON:
{"verdict": "malicious|risky|harmless", "confidence": 0.0-1.0,
 "evidence": [{"file": "...", "line": 1, "quote": "exact text from that line"}],
 "reason": "2-3 sentences"}"""


def safe_name(pkg: str, ver: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", f"{pkg}@{ver}")


def pack(c: dict, dest: Path) -> tuple[Path | None, dict]:
    spec = f"{c['name']}@{c['version']}" if c["origin"] == "registry.npmjs.org" else (c["resolved"] or "")
    out = subprocess.run([NPM, "pack", spec, "--ignore-scripts", "--json", "--pack-destination", str(dest)],
                         cwd=dest, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300)
    try:
        info = json.loads(out.stdout)[0]
    except (json.JSONDecodeError, IndexError):
        return None, {"error": out.stderr.strip()[-300:] or "npm pack failed"}
    tgz = dest / info["filename"].replace("/", "-").lstrip("@")
    if not tgz.exists():  # npm names scoped tarballs scope-name-version.tgz
        tgz = next(dest.glob(f"*{info['name'].split('/')[-1]}-{info['version']}.tgz"), tgz)
    return tgz, {"file": tgz.name, "size": info.get("size"), "integrity": info.get("integrity"),
                 "integrity_match": bool(c.get("integrity")) and info.get("integrity") == c["integrity"],
                 "command": f"npm pack {spec} --ignore-scripts"}


def read_scripts(pkg_dir: Path) -> tuple[list, dict]:
    """Install hooks and the local files they run. Returns (hooks, {relative file: lines})."""
    files = {}
    pj = pkg_dir / "package.json"
    if not pj.exists():
        return [], files
    text = pj.read_text(encoding="utf-8", errors="replace")
    files["package.json"] = text.splitlines()
    scripts = (json.loads(text).get("scripts") or {}) if text.strip() else {}
    hooks = [{"hook": h, "command": scripts[h]} for h in HOOKS if h in scripts]
    for h in hooks:
        for token in re.findall(r"[\w./\\-]+\.(?:c?js|mjs|sh|py|ps1)", h["command"]):
            f = (pkg_dir / token).resolve()
            if f.is_file() and f.is_relative_to(pkg_dir.resolve()):
                files[f.relative_to(pkg_dir.resolve()).as_posix()] = \
                    f.read_text(encoding="utf-8", errors="replace").splitlines()[:150]
    return hooks, files


def trimmed_copy(pkg_dir: Path, dest: Path) -> None:
    """package.json + JS sources only, so semgrep scans what matters (C sources, docs, tests skipped)."""
    n = 0
    for f in sorted(pkg_dir.rglob("*")):
        rel = f.relative_to(pkg_dir)
        if not f.is_file() or any(p in ("node_modules", "test", "tests", "deps", "docs") for p in rel.parts):
            continue
        if f.name == "package.json" and rel.parent == Path(".") or (f.suffix in (".js", ".cjs", ".mjs")
                                                                     and f.stat().st_size < 300_000):
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(f, dest / rel)
            n += 1
            if n > 400:
                break


def run_guarddog(trim_root: Path, names: list[str]) -> tuple[dict, dict]:
    """One semgrep run with GuardDog's npm rules over every package dir under trim_root."""
    if not (GUARDDOG_RULES and SEMGREP):
        return {}, {"status": "unavailable", "reason": "GuardDog/semgrep not installed in the backend venv"}
    rules = trim_root.parent / "guarddog-rules"
    rules.mkdir(exist_ok=True)
    for f in GUARDDOG_RULES.glob("*.yml"):
        if f.name.startswith("npm-") or f.name == "shady-links.yml":
            shutil.copy(f, rules / f.name)
    started = time.time()
    env = {**os.environ, "PYTHONUTF8": "1", "PATH": f"{SCRIPTS_DIR}{os.pathsep}{os.environ.get('PATH', '')}"}
    try:
        out = subprocess.run([SEMGREP, "scan", "--config", str(rules), "--json", "--metrics=off",
                              "--disable-version-check", "--quiet", "--no-git-ignore", str(trim_root)],
                             capture_output=True, text=True, encoding="utf-8", errors="replace",
                             env=env, timeout=1200)
        data = json.loads(out.stdout)
    except subprocess.TimeoutExpired:
        return {}, {"status": "timeout", "reason": "semgrep did not finish in 20 minutes"}
    except json.JSONDecodeError:
        return {}, {"status": "failed", "reason": out.stderr.strip()[-300:]}
    hits: dict[str, list] = {n: [] for n in names}
    for r in data.get("results", []):
        parts = Path(r["path"]).relative_to(trim_root).parts
        hits.setdefault(parts[0], []).append({
            "rule": r["check_id"].split(".")[-1], "file": Path(*parts[1:]).as_posix(),
            "line": r["start"]["line"], "code": (r.get("extra", {}).get("lines") or "").strip()[:200],
            "message": (r.get("extra", {}).get("message") or "").strip()[:200]})
    return hits, {"status": "ok", "tool": f"GuardDog {GUARDDOG_VERSION} rules via semgrep",
                  "seconds": round(time.time() - started, 1), "rules": sorted(p.stem for p in rules.glob("*.yml"))}


def rule_verdict(mal: list, gd_hits: list) -> tuple[str, str]:
    if mal:
        return "malicious", f"OSV lists known-malware advisory {', '.join(mal)} for this exact version."
    serious = [h for h in gd_hits if h["rule"] != "npm-install-script"]
    if serious:
        return "risky", f"GuardDog matched {', '.join(sorted({h['rule'] for h in serious}))}."
    return "unknown", "No malware advisory and no GuardDog match beyond the install hook; needs human review."


def run(state: dict) -> tuple[dict, dict]:
    art = Path(state["artifacts"]) / "packages"
    art.mkdir(parents=True, exist_ok=True)
    comps = {c["id"]: c for c in state["components"]}
    flagged: dict[str, set] = {}
    for f in state.get("suspicious", []):
        if f["rule"] in FLAG_RULES and f.get("component"):
            flagged.setdefault(f["component"], set()).add(f["rule"])
    mal_by_comp: dict[str, list] = {}
    for v in state.get("vulnerabilities", []):
        mal = [i for i in [v["advisory_id"], *v["aliases"]] if i.startswith("MAL-")]
        if mal:
            mal_by_comp.setdefault(v["component"], []).extend(mal)
            flagged.setdefault(v["component"], set()).add("malware-advisory")
    flagged = {k: v for k, v in flagged.items() if k in comps and comps[k]["ecosystem"] == "npm"}

    # 1-3: download, extract, read scripts
    items, trim_root = [], art / "trimmed"
    for cid, rules in sorted(flagged.items()):
        c = comps[cid]
        item = {"id": hashlib.sha1(f"inv|{cid}".encode()).hexdigest()[:12], "component": cid,
                "package": c["name"], "version": c["version"], "flagged_by": sorted(rules),
                "scope": c["scope"], "direct": c["direct"], "path": state.get("paths", {}).get(cid),
                "mal_advisories": sorted(set(mal_by_comp.get(cid, [])))}
        tgz, item["tarball"] = pack(c, art)
        if tgz:
            ex = art / safe_name(c["name"], c["version"])
            shutil.rmtree(ex, ignore_errors=True)
            with tarfile.open(tgz) as t:
                t.extractall(ex, filter="data")
            pkg_dir = next((p for p in ex.iterdir() if p.is_dir()), ex)  # usually "package/"
            item["install_scripts"], files = read_scripts(pkg_dir)
            item["files"] = {k: v for k, v in files.items()}
            trimmed_copy(pkg_dir, trim_root / safe_name(c["name"], c["version"]))
        else:
            item["install_scripts"], item["files"] = [], {}
        items.append(item)

    # 4: GuardDog once for all uncached packages
    gd_cache = {i["id"]: db.cache_get(f"guarddog|{GUARDDOG_VERSION}|{i['component']}") for i in items}
    todo = [safe_name(i["package"], i["version"]) for i in items if gd_cache[i["id"]] is None and i["tarball"].get("file")]
    gd_run = {"status": "cached", "tool": f"GuardDog {GUARDDOG_VERSION} rules via semgrep"}
    fresh: dict = {}
    if todo:
        fresh, gd_run = run_guarddog(trim_root, todo)
    for i in items:
        sn = safe_name(i["package"], i["version"])
        if gd_cache[i["id"]] is not None:
            i["guarddog"] = gd_cache[i["id"]]
        elif gd_run["status"] == "ok" and sn in todo:
            i["guarddog"] = {"status": "ok", "hits": fresh.get(sn, [])}
            db.cache_put(f"guarddog|{GUARDDOG_VERSION}|{i['component']}", i["guarddog"])
        else:
            i["guarddog"] = {"status": gd_run["status"], "hits": [], "reason": gd_run.get("reason")}
    shutil.rmtree(trim_root, ignore_errors=True)

    # 5-6: rule verdict, then LLM
    known_ids = {x for v in state.get("vulnerabilities", []) for x in [v["advisory_id"], *v["aliases"]]}
    for i in items:
        i["rule_verdict"], i["rule_reason"] = rule_verdict(i["mal_advisories"], i["guarddog"]["hits"])
        files = i.pop("files")
        i["code"] = {f: lines[:80] for f, lines in files.items() if f != "package.json"}
        if files:
            hooks_pj = [n for n, l in enumerate(files.get("package.json", []), 1) if any(f'"{h}"' in l for h in HOOKS)]
            i["code"]["package.json"] = files["package.json"]
            i["hook_lines"] = hooks_pj
        i["ai"] = investigate_with_llm(i, files, known_ids) if files else {"ok": False, "reason": "tarball unavailable"}
        if i["ai"].get("ok"):
            a = i["ai"]["answer"]
            i.update(verdict=a["verdict"], confidence=round(float(a["confidence"]), 2), basis="AI inference",
                     reason=a["reason"], evidence=a.get("evidence", []))
        else:
            i.update(verdict=i["rule_verdict"], confidence=1.0 if i["rule_verdict"] == "malicious" else None,
                     basis="fact" if i["rule_verdict"] != "unknown" else "rule (needs human review)",
                     reason=i["rule_reason"], evidence=[])
        if i["mal_advisories"]:  # a malware advisory is a tool fact; the AI may not overrule it
            i.update(verdict="malicious", basis="fact")

    counts = {v: sum(i["verdict"] == v for i in items) for v in ("malicious", "risky", "harmless", "unknown")}
    ai_ok = sum(bool(i["ai"].get("ok")) for i in items)
    public = {
        "items": items, "counts": counts, "guarddog": gd_run, "llm": {**llm.status(), "answered": ai_ok,
                                                                        "tokens": sum(i["ai"].get("tokens", 0) for i in items if not i["ai"].get("cached"))},
        "_status": "done" if ai_ok == len(items) else "partial",
        "_summary": f"{len(items)} packages: {counts['malicious']} malicious, {counts['risky']} risky, "
                    f"{counts['harmless']} harmless, {counts['unknown']} need review"
                    + ("" if llm.API_KEY else " (AI unavailable: no API key)"),
    }
    return {"investigations": items}, public


def investigate_with_llm(i: dict, files: dict, known_ids: set) -> dict:
    gd = "\n".join(f"- {h['rule']} at {h['file']}:{h['line']}: {h['code']}" for h in i["guarddog"]["hits"]) or "none"
    shown = "\n\n".join(f"FILE {name}\n{llm.numbered(lines)}" for name, lines in files.items())
    user = (f"Package: {i['package']}@{i['version']} (scope: {i['scope']}, "
            f"{'direct' if i['direct'] else 'transitive'} dependency)\n"
            f"Flagged by rules: {', '.join(i['flagged_by'])}\n"
            f"Install hooks: {json.dumps(i['install_scripts'])}\n"
            f"Tarball integrity matches lockfile: {i['tarball'].get('integrity_match')}\n"
            f"Known malware advisories (OSV MAL-): {', '.join(i['mal_advisories']) or 'none'}\n"
            f"GuardDog matches:\n{gd}\n\n{shown}")

    def validate(a: dict) -> list:
        p = llm.check_enum(a, "verdict", {"malicious", "risky", "harmless"})
        p += llm.check_number(a, "confidence", 0, 1)
        p += llm.check_citations(a, "evidence", files, required=a.get("verdict") != "harmless")
        p += llm.check_ids(a.get("reason", ""), known_ids)
        if i["mal_advisories"] and a.get("verdict") != "malicious":
            p.append("contradicts tool facts: OSV lists a malware advisory, so the verdict must be malicious")
        if not isinstance(a.get("reason"), str) or not a["reason"].strip():
            p.append("'reason' must be a short explanation")
        return p

    return llm.ask("investigate", f"{i['package']}@{i['version']}", SYSTEM, user, validate)
