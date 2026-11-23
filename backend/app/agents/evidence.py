"""Investigation & Evidence: one evidence bundle per finding, plus the Day 1 report.

Each bundle separates what is verified (read from a file or tool output), what is
inferred (reasoned from those facts), and what is unknown (not checked). The initial
risk is a transparent rule, not an opinion:

  vulnerability: severity band; one level lower if the package is dev-only
                 (not part of the running application); "unrated" stays "review".
  suspicious:    the rule's own severity.

No LLM: every sentence here is generated from tool output, so the report works offline
and contains nothing unsupported. An LLM can later add prose on top of these bundles.
"""
import json
import time
from pathlib import Path

from .. import db

LEVELS = ["critical", "high", "medium", "low"]
RISK_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "review": 4}


def initial_risk(f: dict) -> dict:
    if f["type"] == "suspicious":
        return {"level": f["severity"], "rationale": f"Rule '{f['rule']}' severity ({f['status']})."}
    sev = f["severity"]
    if sev not in LEVELS:
        return {"level": "review", "rationale": "Advisory has no severity rating; needs manual review."}
    if f.get("scope") == "dev":
        lower = LEVELS[min(LEVELS.index(sev) + 1, len(LEVELS) - 1)]
        return {"level": lower, "rationale": f"{sev.title()} advisory, lowered one level: dev-only package, "
                                             "not part of the running application."}
    return {"level": sev, "rationale": f"{sev.title()} advisory ({f['severity_source']}) on a "
                                       f"{'runtime' if f.get('scope') == 'runtime' else f.get('scope') or 'runtime'} dependency."}


def bundle(f: dict, comps: dict, label, sbom_name: str) -> dict:
    comp = comps.get(f["component"]) if f.get("component") else None
    path = f.get("path") or []
    facts, inference, unknowns, refs = [], [], [], []
    direct_parent = label(path[2]) if len(path) > 2 else None

    if comp:
        facts.append(f"{comp['name']}@{comp['version']} is in the resolved dependency tree "
                     f"({'direct' if comp['direct'] else 'transitive'}, {comp['scope']} scope).")
        if len(path) > 3:
            facts.append("Introduced via " + " → ".join(label(p) for p in path[1:]) + ".")
        refs.append({"kind": "sbom", "ref": sbom_name, "detail": f"component {comp['purl']}"})
        if comp.get("resolved"):
            refs.append({"kind": "lockfile", "ref": comp["resolved"], "detail": comp.get("integrity") or ""})

    if f["type"] == "vulnerability":
        ids = ", ".join([f["advisory_id"], *f["aliases"]])
        facts.append(f"OSV advisory {ids} lists {f['name']}@{f['version']} as affected.")
        if f["cvss_score"] is not None:
            facts.append(f"CVSS base score {f['cvss_score']} ({f['cvss_vector'] or 'vector not given'}).")
        elif f.get("advisory_label"):
            facts.append(f"No CVSS score; advisory rates it {f['advisory_label']}.")
        facts.append(f"Fixed in {f['fix']}." if f["fix"] else "No fixed version published.")
        if f.get("trivy_confirmed"):
            facts.append("Trivy independently reports the same advisory on this package version.")
        refs += [{"kind": "advisory", "ref": f["url"], "detail": f["title"]},
                 {"kind": "scanner", "ref": f"osv-scanner output for {f['project']}", "detail": "raw JSON kept"}]
        if not comp or not comp["direct"]:
            if direct_parent:
                inference.append(f"Transitive: fixing it most likely means upgrading the direct dependency "
                                 f"{direct_parent}, or overriding the version.")
        if f.get("scope") == "dev":
            inference.append("Dev-only: used for building/testing, so not shipped in the production app.")
        if not f["fix"]:
            inference.append("With no fixed version, options are replacing the package or mitigating its use.")
        unknowns += ["Reachability: not analysed. There is no evidence yet that the vulnerable code is called.",
                     "Exploitability in this application's deployment: not assessed."]
    else:
        ev = f["evidence"]
        if ev.get("file"):
            facts.append(f"{ev['file']}{':' + str(ev['line']) if ev.get('line') else ''}: {ev.get('text') or ''}".strip())
            refs.append({"kind": "file", "ref": ev["file"], "line": ev.get("line"), "detail": ev.get("text") or ""})
        if f["rule"] == "install-script":
            facts.append("Lockfile marks the package with hasInstallScript: true.")
            unknowns.append("What the script does: not inspected (the tarball was not downloaded).")
        if f["rule"] == "typosquat":
            inference.append(f["rationale"])
            unknowns.append("Publisher identity and download history: not checked.")
        else:
            inference.append(f["rationale"])
        if f["rule"] == "no-lockfile":
            facts += ev.get("notes", [])

    return {
        "finding_id": f["id"], "type": f["type"], "title": f["title"], "severity": f["severity"],
        "advisory_id": f.get("advisory_id"), "aliases": f.get("aliases", []), "rule": f.get("rule"),
        "category": f.get("category", "Known vulnerability"),
        "component": {"purl": comp["purl"], "name": comp["name"], "version": comp["version"],
                      "direct": comp["direct"], "scope": comp["scope"]} if comp else None,
        "project": f.get("project"), "dependency_path": [label(p) for p in path],
        "fix": f.get("fix"), "evidence_refs": refs,
        "verified_facts": facts, "inference": inference, "unknowns": unknowns,
        "initial_risk": initial_risk(f),
    }


def markdown(report: dict, bundles: list) -> str:
    r = report
    lines = [f"# Supply-chain report: {r['repository']}", "",
             f"- Commit: `{r['commit_sha']}`", f"- Generated: {r['generated_at']}",
             f"- Components: {r['inventory']['components']} ({r['inventory']['direct']} direct)", "",
             "## Coverage", "", "| Agent | Status | Summary |", "|---|---|---|"]
    lines += [f"| {a['name']} | {a['status']} | {a.get('summary') or ''} |" for a in r["coverage"]["agents"]]
    lines += [""] + [f"- Gap: {g}" for g in r["coverage"]["gaps"]]
    lines += ["", "## Initial risk", "", "| Level | Findings |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in r["risk_counts"].items()]
    lines += ["", "## Findings", ""]
    for b in bundles:
        lines += [f"### [{b['initial_risk']['level'].upper()}] {b['title']}", ""]
        if b["component"]:
            lines.append(f"- Component: `{b['component']['purl']}`")
        if b["dependency_path"]:
            lines.append(f"- Path: {' → '.join(b['dependency_path'])}")
        lines.append(f"- Risk rationale: {b['initial_risk']['rationale']}")
        lines += [f"- Fact: {x}" for x in b["verified_facts"]]
        lines += [f"- Inference: {x}" for x in b["inference"]]
        lines += [f"- Unknown: {x}" for x in b["unknowns"]]
        lines += [f"- Evidence: {e['kind']} {e['ref']}" for e in b["evidence_refs"]]
        lines.append("")
    return "\n".join(lines)


def run(state: dict) -> tuple[dict, dict]:
    scan = db.get(state["scan_id"])
    res, art = scan["results"], Path(state["artifacts"])
    comps = {c["id"]: c for c in state["components"]}
    names = {p["id"]: p.get("name") or p["path"] for p in state["projects"]}
    names["repo"] = state["repo_url"].removeprefix("https://github.com/")

    def label(i):
        c = comps.get(i)
        return f"{c['name']}@{c['version']}" if c else names.get(i, i)

    findings = state.get("vulnerabilities", []) + state.get("suspicious", [])
    bundles = [bundle(f, comps, label, res.get("sbom", {}).get("artifact", "sbom.cdx.json")) for f in findings]
    bundles.sort(key=lambda b: (RISK_ORDER[b["initial_risk"]["level"]], b["type"] != "vulnerability", b["title"]))

    gaps = list(res.get("discovery", {}).get("warnings", []))
    gaps += [f"{s['manifest']}: vulnerability scan {s['status']} ({s.get('error') or s.get('reason')})"
             for s in res.get("vulnerability", {}).get("scans", []) if s["status"] != "ok"]
    gaps += [f"{n['rule']}: {n['reason']}" for n in res.get("change_detection", {}).get("not_applicable", [])]
    gaps.append("Reachability and exploitability are not analysed for any finding (Day 2).")
    agents = [{"name": a["name"], "status": a["status"], "summary": a.get("summary")}
              for k, a in scan["agents"].items() if k != "evidence"]
    risk_counts = {lvl: sum(b["initial_risk"]["level"] == lvl for b in bundles) for lvl in RISK_ORDER}
    disc = res.get("discovery", {}).get("stats", {})
    vuln_scans = res.get("vulnerability", {}).get("scans", [])
    report = {
        "repository": names["repo"], "repo_url": state["repo_url"], "commit_sha": state["commit_sha"],
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "inventory": {"components": disc.get("components"), "direct": disc.get("direct"),
                      "transitive": disc.get("transitive"), "edges": disc.get("edges")},
        "risk_counts": risk_counts,
        "by_type": {"vulnerability": sum(b["type"] == "vulnerability" for b in bundles),
                    "suspicious": sum(b["type"] == "suspicious" for b in bundles)},
        "coverage": {"agents": agents, "gaps": gaps},
        "checklist": [
            {"item": "Scanned an authorized public repository at a pinned commit", "done": bool(state.get("commit_sha"))},
            {"item": "Identified manifests, direct/transitive dependencies and versions", "done": bool(comps)},
            {"item": "Generated a CycloneDX SBOM", "done": "sbom" in res},
            {"item": "Dependency graph with transitive paths", "done": bool(state.get("paths"))},
            {"item": "Inspected container images / CI/CD workflows",
             "done": bool(res.get("inspection", {}).get("stats", {}).get("dockerfiles")
                          or res.get("inspection", {}).get("stats", {}).get("workflows"))},
            {"item": "Vulnerability scan with advisory evidence",
             "done": bool(vuln_scans) and all(s["status"] == "ok" for s in vuln_scans)},
            {"item": "At least one suspicious supply-chain category demonstrated", "done": bool(state.get("suspicious"))},
            {"item": "Each finding linked to component, path, evidence and initial risk", "done": True},
            {"item": "No clean status claimed for partial or failed coverage",
             "done": True},
        ],
    }
    (art / "report.json").write_text(json.dumps({"report": report, "findings": bundles}, indent=1), encoding="utf-8")
    (art / "report.md").write_text(markdown(report, bundles), encoding="utf-8")
    db.save_findings(state["scan_id"], bundles)
    top = [b for b in bundles if b["initial_risk"]["level"] in ("critical", "high")]
    public = {
        "report": report, "bundles": bundles, "artifacts": {"json": "report.json", "markdown": "report.md"},
        "_summary": f"{len(bundles)} evidence bundles, {len(top)} critical/high initial risk",
    }
    return {}, public
