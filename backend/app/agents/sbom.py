"""SBOM Generator: CycloneDX 1.5 JSON built from the Discovery inventory.

One merged SBOM per repo (all projects), so every ecosystem gets the same format.
For npm projects, `npm sbom` (npm's built-in CycloneDX generator) is also run as an
independent cross-check and its output kept as evidence.
"""
import base64
import hashlib
import json
import subprocess
import time
import uuid
from pathlib import Path

from .discovery import NPM

HASH_ALGS = {"sha512": "SHA-512", "sha384": "SHA-384", "sha256": "SHA-256", "sha1": "SHA-1"}
SCOPES = {"runtime": "required", "optional": "optional", "dev": "excluded"}


def hashes(integrity: str | None) -> list:
    out = []
    for part in (integrity or "").split():
        alg, _, b64 = part.partition("-")
        if alg in HASH_ALGS:
            out.append({"alg": HASH_ALGS[alg], "content": base64.b64decode(b64).hex()})
    return out


def build_bom(state: dict) -> dict:
    deps: dict[str, list] = {}
    for e in state["edges"]:
        deps.setdefault(e["source"], []).append(e["target"])
    components = [
        {"type": "application", "bom-ref": p["id"], "name": p.get("name") or p["path"],
         **({"version": p["version"]} if p.get("version") else {}),
         "properties": [{"name": "guardian:manifest", "value": p["manifest"]},
                        {"name": "guardian:lock_source", "value": p.get("lock_source") or "none"}]}
        for p in state["projects"]
    ]
    for c in state["components"]:
        comp = {"type": "library", "bom-ref": c["id"], "name": c["name"], "version": c["version"],
                "purl": c["purl"], "scope": SCOPES[c["scope"]],
                "properties": [{"name": "guardian:direct", "value": str(c["direct"]).lower()},
                               {"name": "guardian:origin", "value": c["origin"]},
                               {"name": "guardian:install_script", "value": str(c["install_script"]).lower()}]}
        if c["license"]:
            comp["licenses"] = [{"license": {"name": str(c["license"])}}]
        if h := hashes(c["integrity"]):
            comp["hashes"] = h
        if c["resolved"]:
            comp["externalReferences"] = [{"type": "distribution", "url": c["resolved"]}]
        components.append(comp)
    root = "repo"
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": {"components": [{"type": "application", "name": "supply-chain-guardian", "version": "0.1.0"}]},
            "component": {"type": "application", "bom-ref": root, "name": state["repo_name"],
                          "version": state["commit_sha"][:12],
                          "externalReferences": [{"type": "vcs", "url": state["repo_url"]}],
                          "properties": [{"name": "guardian:commit_sha", "value": state["commit_sha"]}]},
        },
        "components": components,
        "dependencies": [{"ref": root, "dependsOn": [p["id"] for p in state["projects"]]}]
                        + [{"ref": c["bom-ref"], "dependsOn": sorted(set(deps.get(c["bom-ref"], [])))}
                           for c in components],
    }


def npm_crosscheck(state: dict, artifacts: Path) -> list:
    checks = []
    for i, p in enumerate(state["projects"]):
        if p["ecosystem"] != "npm" or p["status"] != "parsed":
            continue
        pdir = Path(state["workdir"]) / p["path"]
        # same peer-dep mode the lockfile was generated with, or npm sbom rejects the tree
        legacy = ["--legacy-peer-deps"] if "legacy-peer-deps" in p["evidence"].get("command", "") else []
        out = subprocess.run([NPM, "sbom", "--sbom-format", "cyclonedx", "--package-lock-only", *legacy],
                             cwd=pdir, capture_output=True, text=True, encoding="utf-8", errors="replace",
                             timeout=300)
        check = {"project": p["id"], "tool": "npm sbom (CycloneDX)", "ours": p["component_count"]}
        try:
            bom = json.loads(out.stdout)
            name = f"npm-sbom-{i}.cdx.json"
            (artifacts / name).write_text(out.stdout, encoding="utf-8")
            check.update(status="ok", artifact=name, tool_count=len({
                (c.get("name"), c.get("version")) for c in bom.get("components", [])}),
                spec=bom.get("specVersion"))
        except json.JSONDecodeError:
            check.update(status="failed", error=out.stderr.strip()[-300:])
        checks.append(check)
    return checks


def run(state: dict) -> tuple[dict, dict]:
    artifacts = Path(state["artifacts"])
    bom = build_bom(state)
    path = artifacts / "sbom.cdx.json"
    path.write_text(json.dumps(bom, indent=1), encoding="utf-8")
    checks = npm_crosscheck(state, artifacts)
    public = {
        "format": "CycloneDX", "spec_version": "1.5", "artifact": path.name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size_bytes": path.stat().st_size,
        "components": len(bom["components"]), "dependency_entries": len(bom["dependencies"]),
        "serial_number": bom["serialNumber"], "crosschecks": checks,
        "_summary": f"CycloneDX 1.5, {len(bom['components'])} components",
    }
    return {}, public
