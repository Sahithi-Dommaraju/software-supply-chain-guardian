"""Day 2 · Recommend Fix: "What exactly do we change?"

For each top-ranked risk (critical/high band, at most 15):
  target   = the vulnerable package T; `need` = highest fixed version among its advisories
  control  = the package you actually list in package.json (T itself if direct, else the first
             package on its "introduced via" path)
  1. Upgrade: walk the controlled package's published versions (npm registry) from low to high
     and, emulating npm (highest version satisfying each range), resolve the chain down to T.
     The first version where T resolves to >= need (or is no longer pulled in) is the fix.
  2. Override: if no version of the controlled package brings a safe T, pin T with npm
     "overrides" (npm >= 8.3).
  3. Replace / mitigate: no fixed version of T exists at all.
Recorded per card: advisories and CVEs removed, what remains, version-jump type, rollback,
the package.json change, the resolution chain and registry evidence.

LLM: reads the changelog (GitHub releases between the two versions) plus where the app uses
the package, and explains what may break and why. The Validator checks cited file:line are among
the snippets shown. Without the LLM the card still has the rule-based jump type.
"""
import hashlib
import json
import re
import urllib.parse
from pathlib import Path

from semantic_version import NpmSpec, Version

from .. import llm
from .prioritize import band, fetch_json, find_usages

MAX_CARDS = 15
REGISTRY = "https://registry.npmjs.org/"

SYSTEM = """You review a proposed npm dependency upgrade for breaking changes. Use ONLY the changelog
excerpt and the application code snippets given (line numbers are shown before each line).
Explain concretely what in THIS application's code could break and why; if the changelog says
nothing relevant, say so and rate the risk low. Never invent advisory IDs or APIs. Reply as JSON:
{"breaking_risk": "low|medium|high", "summary": "2-3 sentences",
 "notes": [{"text": "...", "file": "path or null", "line": 1}]}"""

_packuments: dict[str, dict] = {}


def packument(name: str) -> dict:
    if name not in _packuments:
        _packuments[name] = fetch_json(REGISTRY + urllib.parse.quote(name, safe="@"), 60)
    return _packuments[name]


def ver(s: str) -> Version | None:
    try:
        return Version(s)
    except ValueError:
        try:
            return Version.coerce(s)
        except ValueError:
            return None


def stable_versions(name: str) -> list[Version]:
    vs = [v for v in (ver(x) for x in packument(name).get("versions", {})) if v and not v.prerelease]
    return sorted(vs)


def resolve(name: str, spec: str) -> Version | None:
    """npm picks the highest published version matching the range."""
    try:
        return NpmSpec(spec).select(stable_versions(name))
    except ValueError:
        return None


def deps_of(name: str, version: Version) -> dict:
    meta = packument(name)["versions"].get(str(version), {})
    return {**(meta.get("optionalDependencies") or {}), **(meta.get("dependencies") or {})}


def walk_chain(chain: list[str], top_version: Version) -> tuple[Version | None, list] | None:
    """Resolve chain[0]@top_version down to chain[-1]. Returns (T version or None if dropped, steps)."""
    steps, current = [{"package": chain[0], "version": str(top_version)}], top_version
    for parent, child in zip(chain, chain[1:]):
        spec = deps_of(parent, current).get(child)
        if spec is None:
            return None, steps  # child no longer pulled in through this route
        current = resolve(child, spec)
        if current is None:
            return False, steps  # unresolvable: treat as not fixed
        steps.append({"package": child, "version": str(current), "range": spec})
    return current, steps


def jump(a: Version, b: Version) -> str:
    return "major" if b.major != a.major else "minor" if b.minor != a.minor else "patch"


def manifest_spec(root: Path, project_path: str, name: str) -> tuple[str | None, str | None, str]:
    pj = root / project_path / "package.json"
    data = json.loads(pj.read_text(encoding="utf-8")) if pj.exists() else {}
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        if name in (data.get(field) or {}):
            return data[field][name], field, pj.relative_to(root).as_posix()
    return None, None, pj.relative_to(root).as_posix()


def changelog(name: str, frm: Version, to: Version) -> tuple[str, str]:
    repo = (packument(name).get("repository") or {})
    url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    m = re.search(r"github\.com[/:]([^/]+)/([^/#.]+)", url)
    if not m:
        return "", "no GitHub repository listed on the registry"
    api = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}/releases?per_page=100"
    try:
        rel = fetch_json(api, 30)
    except Exception as e:
        return "", f"GitHub releases unavailable ({str(e)[:80]})"
    picked = []
    for r in rel:
        v = ver(re.sub(r"^[^\d]*", "", r.get("tag_name", "")))
        if v and frm < v <= to and r.get("body"):
            picked.append(f"## {r['tag_name']}\n{r['body'].strip()[:1500]}")
    text = "\n\n".join(sorted(picked))[:5000]
    return text, f"https://github.com/{m.group(1)}/{m.group(2)}/releases" if text else "no release notes between these versions"


def plan_fix(r: dict, comps: dict, paths: dict, root: Path) -> dict:
    cid = r["component"]
    path = paths.get(cid) or []
    chain_ids = path[2:] if len(path) > 2 else [cid]
    chain = [comps[i]["name"] for i in chain_ids if i in comps]
    project_path = path[1].removeprefix("project:") if len(path) > 1 else "."
    T, current_t = r["package"], ver(r["version"])
    fixes = sorted({ver(a["fix"]) for a in r["advisories"] if a["fix"] and ver(a["fix"])})
    card = {"id": hashlib.sha1(f"fix|{cid}".encode()).hexdigest()[:12], "risk_id": r["id"], "rank": r["rank"],
            "package": T, "version": r["version"], "band": r["band"], "score_before": r["final_score"],
            "chain": chain, "project": project_path, "evidence": {"registry": [REGISTRY + n for n in chain]}}
    if not fixes:
        return {**card, "action": "replace", "title": f"No fixed version of {T} exists: replace or mitigate",
                "advisories_removed": [], "cves_removed": [], "remaining": [a["id"] for a in r["advisories"]],
                "score_after": r["final_score"], "change": None, "rollback": None, "patch": None}
    need = fixes[-1]
    D = chain[0]
    d_current = ver(comps[chain_ids[0]]["version"])
    spec_from, field, manifest = manifest_spec(root, project_path, D)
    candidate, steps = None, []
    for v in [v for v in stable_versions(D) if v >= d_current][:200]:
        if len(chain) == 1:
            ok, t_new, steps = v >= need, v, [{"package": D, "version": str(v)}]
        else:
            t_new, steps = walk_chain(chain, v)
            ok = t_new is None or (t_new is not False and t_new >= need)
        if ok:
            candidate = v
            break
    if candidate is not None:
        t_after = need if len(chain) == 1 else (t_new if t_new else None)
        spec_to = f"^{candidate}"
        change = {"package": D, "from": str(d_current), "to": str(candidate), "spec_from": spec_from, "spec_to": spec_to,
                  "field": field, "manifest": manifest, "jump": jump(d_current, candidate)}
        action = "upgrade" if D == T else "upgrade-parent"
        title = (f"Upgrade {D} {d_current} → {candidate}" + ("" if D == T else
                 f" (pulls {T} {'out of the tree' if t_after is None else str(t_after)})"))
        patch = f'--- {manifest}\n+++ {manifest}\n   "{field}": {{\n-    "{D}": "{spec_from}",\n+    "{D}": "{spec_to}",'
        rollback = {"version": str(d_current), "how": f'Set "{D}": "{spec_from}" back in {manifest} and reinstall.'}
    else:
        t_after = need
        change = {"package": T, "from": r["version"], "to": str(need), "spec_from": None, "spec_to": f"^{need}",
                  "field": "overrides", "manifest": manifest, "jump": jump(current_t, need) if current_t else "unknown"}
        action, title = "override", f"Pin {T} to ^{need} with npm overrides (no {D} release pulls in a fixed {T})"
        patch = f'--- {manifest}\n+++ {manifest}\n+  "overrides": {{\n+    "{T}": "^{need}"\n+  }},'
        rollback = {"version": r["version"], "how": f'Remove the "{T}" entry from "overrides" in {manifest} and reinstall.'}
    removed = [a for a in r["advisories"] if a["fix"] and (t_after is None or (ver(a["fix"]) and ver(a["fix"]) <= t_after))]
    remaining = [a for a in r["advisories"] if a not in removed]
    f = r["factors"]
    after = 0.0 if not remaining else round(min(10, max((a["cvss"] or 5.0) for a in remaining) * f["U"] * f["D"] * f["P"] * f["E"]), 1)
    return {**card, "action": action, "title": title, "change": change, "patch": patch, "rollback": rollback,
            "resolution": steps, "target_after": "removed from tree" if t_after is None else str(t_after),
            "advisories_removed": [a["id"] for a in removed], "cves_removed": sorted({c for a in removed for c in a["cves"]}),
            "remaining": [a["id"] for a in remaining], "score_after": after, "band_after": band(after)}


def run(state: dict) -> tuple[dict, dict]:
    comps = {c["id"]: c for c in state["components"]}
    paths, root = state.get("paths", {}), Path(state["workdir"])
    top = [r for r in state.get("risks", []) if r["band"] in ("critical", "high")
           and "known malware" not in r["labels"] and r.get("advisories")][:MAX_CARDS]
    known_ids = {x for v in state.get("vulnerabilities", []) for x in [v["advisory_id"], *v["aliases"]]}
    cards, errors = [], []
    for r in top:
        try:
            card = plan_fix(r, comps, paths, root)
        except Exception as e:  # registry down etc.: keep going, say which card is missing
            errors.append({"package": r["package"], "error": f"{type(e).__name__}: {str(e)[:200]}"})
            continue
        ch = card.get("change")
        if ch and card["action"] != "replace":
            notes, source = changelog(ch["package"], ver(ch["from"]), ver(ch["to"]))
            card["evidence"]["changelog"] = source
            snippets = find_usages(root, [ch["package"]])
            card["usage_snippets"] = snippets
            card["ai"] = review(card, notes, snippets, root, known_ids)
        else:
            card["ai"] = {"ok": False, "reason": "no change to review"}
        card["compatibility"] = {"jump": (ch or {}).get("jump"),
                                 "breaking_risk": card["ai"]["answer"]["breaking_risk"] if card["ai"].get("ok") else None}
        cards.append(card)
    # malware is never "upgraded": it gets its own card
    for r in state.get("risks", []):
        if "known malware" in r["labels"]:
            cards.insert(0, {"id": hashlib.sha1(f"fix|{r['component']}".encode()).hexdigest()[:12], "risk_id": r["id"],
                             "rank": r["rank"], "package": r["package"], "version": r["version"], "band": "critical",
                             "action": "remove", "title": f"Remove {r['package']}@{r['version']} (known malware)",
                             "score_before": 10.0, "score_after": 0.0, "advisories_removed": [a["id"] for a in r["advisories"]],
                             "cves_removed": [], "remaining": [], "change": None, "patch": None,
                             "rollback": None, "ai": {"ok": False, "reason": "no AI for malware removal"},
                             "compatibility": {"jump": None, "breaking_risk": None}, "evidence": {}})
    public = {
        "cards": cards, "errors": errors, "llm": {**llm.status(), "answered": sum(bool(c["ai"].get("ok")) for c in cards)},
        "_status": "partial" if errors else "done",
        "_summary": f"{len(cards)} fix cards for {len(top)} top risks"
                    + (f"; {len(errors)} could not be planned" if errors else ""),
    }
    return {"fixes": cards}, public


def review(card: dict, notes: str, snippets: list, root: Path, known_ids: set) -> dict:
    ch = card["change"]
    shown = "\n\n".join(f"FILE {s['file']}\n{llm.numbered(s['lines'], s['start'])}" for s in snippets) \
        or "The application source does not import this package directly."
    user = (f"Proposed change: {ch['package']} {ch['from']} → {ch['to']} ({ch['jump']} version jump) "
            f"to fix {', '.join(card['advisories_removed'])} in {card['package']}@{card['version']}.\n\n"
            f"Changelog between these versions:\n{notes or '(not available)'}\n\nWhere the app uses {ch['package']}:\n{shown}")
    files = {s["file"]: (root / s["file"]).read_text(encoding="utf-8", errors="replace").splitlines() for s in snippets}
    windows = {(s["file"], n) for s in snippets for n in range(s["start"], s["start"] + len(s["lines"]))}

    def validate(a: dict) -> list:
        p = llm.check_enum(a, "breaking_risk", {"low", "medium", "high"})
        if not isinstance(a.get("summary"), str) or not a["summary"].strip():
            p.append("'summary' must be a short explanation")
        notes_ = a.get("notes")
        if not isinstance(notes_, list):
            p.append("'notes' must be a list")
            notes_ = []
        for n in notes_:
            if not isinstance(n, dict) or not n.get("text"):
                p.append("each note needs 'text'")
            elif n.get("file") and (n["file"] not in files or (n["file"], n.get("line")) not in windows):
                p.append(f"note cites {n.get('file')}:{n.get('line')}, which is not in the snippets shown")
        p += llm.check_ids(a.get("summary", "") + " ".join(str(n.get("text")) for n in notes_ if isinstance(n, dict)), known_ids)
        return p

    return llm.ask("remediate", f"{ch['package']}@{ch['from']}->{ch['to']}", SYSTEM, user, validate)
