"""Container & CI/CD Inspection: static read of Dockerfiles and GitHub Actions workflows.

Records every base image and third-party action with its pinning, plus a few
well-known risky patterns, each with file:line evidence. These are observations;
turning them into scored findings is the Suspicious-Change Detection agent's job.
Images are not pulled or built.
"""
import re
from pathlib import Path

from .discovery import find_manifests

SHA = re.compile(r"^[0-9a-f]{40}$")
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", re.I)
USES = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)")
RISKY_RUN = [
    (re.compile(r"(curl|wget)[^|\n]*\|\s*(ba|z)?sh"), "Pipes a downloaded script into a shell"),
    (re.compile(r"\bnpm\s+(install|i)\b(?!.*--ignore-scripts)"), "npm install (not npm ci): resolves versions at build time and runs install scripts"),
    (re.compile(r"--unsafe-perm"), "npm --unsafe-perm runs install scripts as root"),
    (re.compile(r"^\s*ADD\s+https?://", re.I), "ADD from a remote URL (no checksum)"),
]
WORKFLOW_RISKS = [
    (re.compile(r"\bpull_request_target\b"), "pull_request_target trigger runs with write token and secrets on fork PRs"),
    (re.compile(r"permissions:\s*write-all"), "Workflow grants write-all permissions"),
    (re.compile(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit)\.[\w.]*(title|body|message|name|ref)"),
     "Untrusted event text interpolated into the workflow (script-injection risk)"),
]


def image_pinning(image: str) -> tuple[str, str]:
    if "@sha256:" in image:
        return "digest", "info"
    tag = image.rsplit("/", 1)[-1].partition(":")[2]
    if not tag or tag == "latest":
        return "none (latest)", "warning"
    return f"tag ({tag})", "notice"


def inspect_dockerfile(path: Path, rel: str) -> dict:
    images, observations, stages = [], [], set()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for no, line in enumerate(lines, 1):
        if m := FROM.match(line):
            image, alias = m.group(1), m.group(2)
            if image.lower() in stages or image.lower() == "scratch":
                pin, level = "build stage", "info"
            else:
                pin, level = image_pinning(image)
            images.append({"image": image, "stage": alias, "line": no, "pinning": pin, "level": level})
            if alias:
                stages.add(alias.lower())
        for rx, msg in RISKY_RUN:
            if rx.search(line) and not line.lstrip().startswith("#"):
                observations.append({"file": rel, "line": no, "text": line.strip()[:200], "level": "warning", "message": msg})
    if not any(re.match(r"^\s*USER\s+", l, re.I) for l in lines):
        observations.append({"file": rel, "line": None, "text": "", "level": "notice",
                             "message": "No USER instruction: container runs as the base image's default user"})
    for i in images:
        if i["level"] != "info":
            observations.append({"file": rel, "line": i["line"], "text": f"FROM {i['image']}", "level": i["level"],
                                 "message": f"Base image not pinned by digest (pinning: {i['pinning']})"})
    return {"file": rel, "images": images, "observations": observations}


def inspect_workflow(path: Path, rel: str) -> dict:
    actions, observations = [], []
    for no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        if m := USES.match(line):
            ref = m.group(1)
            if ref.startswith("./"):
                kind, pinned = "local", True
            elif ref.startswith("docker://"):
                kind, pinned = "docker", "@sha256:" in ref
            else:
                kind, pinned = "action", bool(SHA.match(ref.rpartition("@")[2]))
            first_party = ref.startswith(("actions/", "github/"))
            actions.append({"uses": ref, "line": no, "kind": kind, "pinned": pinned, "first_party": first_party})
            if not pinned:
                observations.append({"file": rel, "line": no, "text": line.strip()[:200],
                                     "level": "notice" if first_party else "warning",
                                     "message": "Action referenced by mutable tag/branch, not a commit SHA"})
        for rx, msg in WORKFLOW_RISKS:
            if rx.search(line):
                observations.append({"file": rel, "line": no, "text": line.strip()[:200], "level": "warning", "message": msg})
    return {"file": rel, "actions": actions, "observations": observations}


def run(state: dict) -> tuple[dict, dict]:
    root = Path(state["workdir"])
    dockerfiles, workflows, other_ci = [], [], []
    for f in find_manifests(root):
        rel = f.relative_to(root).as_posix()
        if f.name.startswith("Dockerfile") or f.suffix == ".dockerfile":
            dockerfiles.append(inspect_dockerfile(f, rel))
        elif rel.startswith(".github/workflows/") and f.suffix in (".yml", ".yaml"):
            workflows.append(inspect_workflow(f, rel))
        elif f.name in (".gitlab-ci.yml", "Jenkinsfile", ".travis.yml", "azure-pipelines.yml"):
            other_ci.append(rel)
    observations = [o for x in dockerfiles + workflows for o in x["observations"]]
    actions = [a for w in workflows for a in w["actions"]]
    stats = {"dockerfiles": len(dockerfiles), "workflows": len(workflows),
             "base_images": sum(len(d["images"]) for d in dockerfiles),
             "actions": len(actions), "unpinned_actions": sum(not a["pinned"] for a in actions),
             "warnings": sum(o["level"] == "warning" for o in observations)}
    inspected = dockerfiles or workflows
    public = {
        "dockerfiles": dockerfiles, "workflows": workflows, "observations": observations,
        "not_inspected": other_ci, "stats": stats,
        "_status": "done" if inspected and not other_ci else "partial",
        "_summary": (f"{len(dockerfiles)} Dockerfile(s), {len(workflows)} workflow(s), "
                     f"{stats['unpinned_actions']} unpinned action ref(s)") if inspected
                    else "No Dockerfile or GitHub Actions workflow found",
    }
    return {"inspection": {"observations": observations}}, public
