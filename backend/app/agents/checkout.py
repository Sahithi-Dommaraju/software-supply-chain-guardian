"""Repository Intake: shallow-clone a public GitHub repo at a pinned commit.

Nothing from the repository is executed: git hooks are not installed by clone,
symlinks are checked out as plain files, LFS blobs are not fetched.
"""
import os
import re
import subprocess

GITHUB_URL = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"}


def git(*args, cwd=None, timeout=60) -> str:
    out = subprocess.run(
        ["git", *args], cwd=cwd, env=GIT_ENV, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
    )
    if out.returncode:
        raise RuntimeError(f"git {args[0]} failed: {out.stderr.strip()[-500:]}")
    return out.stdout.strip()


def run(state: dict) -> tuple[dict, dict]:
    m = GITHUB_URL.match(state["repo_url"])
    if not m:
        raise ValueError("Only public https://github.com/<owner>/<repo> URLs are supported")
    repo_dir = state["workdir"]
    git("clone", "--depth", "1", "--no-tags", "--single-branch", "-c", "core.symlinks=false",
        state["repo_url"], repo_dir, timeout=600)
    sha = git("rev-parse", "HEAD", cwd=repo_dir)
    branch = git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo_dir)
    date, author, subject = git("log", "-1", "--format=%cI%n%an%n%s", cwd=repo_dir).split("\n", 2)
    files = git("ls-files", cwd=repo_dir).count("\n") + 1
    public = {
        "owner": m.group(1), "repo": m.group(2), "url": state["repo_url"],
        "commit_sha": sha, "branch": branch, "commit_date": date,
        "commit_author": author, "commit_subject": subject, "tracked_files": files,
        "clone": "git clone --depth 1 --no-tags --single-branch -c core.symlinks=false",
        "_summary": f"{m.group(1)}/{m.group(2)} @ {sha[:12]} ({files} files)",
    }
    return {"commit_sha": sha, "repo_name": m.group(2)}, public
