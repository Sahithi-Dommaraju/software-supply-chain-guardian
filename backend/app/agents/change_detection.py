"""Suspicious-Change Detection: non-CVE supply-chain risk patterns.

This is a baseline scan of one pinned commit, so rules that need a before/after diff
(modified lockfile, version bumps, new dependencies) are reported as not applicable
rather than silently skipped. The rules that apply to a single snapshot:

  install-script      package runs code on install (lockfile hasInstallScript)       fact
  typosquat           name one edit away from a popular npm package                   indicator
  unexpected-origin   tarball not from the public registry (git, URL, other host)     fact
  no-lockfile         versions resolved at scan/build time, not pinned in the repo    fact
  unpinned-action     GitHub Action on a mutable tag/branch                           fact
  base-image          container base image not pinned by digest                       fact
  workflow-risk       pull_request_target, write-all, event text injection            fact
  build-install       Dockerfile installs packages without a lockfile                 fact

"fact" = read directly from a file/tool output. "indicator" = heuristic, needs review.
"""
import hashlib

TRUSTED_ORIGINS = {"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "proxy.golang.org"}

# Popular npm package names that typosquatters imitate. ponytail: static list; swap for
# the npm download-count top 1000 if false negatives matter.
POPULAR = set("""
express react react-dom vue angular lodash underscore axios request chalk commander debug moment
dayjs async bluebird q uuid yargs minimist glob rimraf mkdirp semver colors color dotenv cors
body-parser cookie-parser jsonwebtoken bcrypt bcryptjs mongoose mongodb mysql mysql2 pg sequelize
redis ioredis socket.io ws webpack babel-core typescript eslint prettier jest mocha chai sinon
nodemon pm2 cross-env inquirer ora jquery bootstrap rxjs zone.js core-js tslib classnames
prop-types redux react-redux next nuxt vite rollup esbuild gulp grunt browserify node-fetch
cheerio puppeteer jsdom marked highlight.js handlebars ejs pug nunjucks mustache multer helmet
morgan winston pino bunyan validator joi yup ajv qs querystring superagent got needle
node-sass sass less postcss autoprefixer tailwindcss lodash.merge lodash.get event-stream
crypto-js js-yaml yaml xml2js fs-extra graceful-fs chokidar through2 readable-stream
safe-buffer inherits once minimatch micromatch braces picomatch ms sqlite3 sequelize-cli
coffee-script electron typeorm knex passport express-session connect serve-static http-proxy
http-errors on-finished finalhandler send mime mime-types accepts negotiator vary
pdfkit sanitize-html jsonpath file-type unzipper tar archiver adm-zip
""".split())


def within_one_edit(a: str, b: str) -> bool:
    """Levenshtein distance <= 1, plus adjacent transposition."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1
                                  and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    if len(a) > len(b):
        a, b = b, a
    return any(b[:i] + b[i + 1:] == a for i in range(len(b)))


def lookalike(name: str) -> str | None:
    if name.startswith("@") or name in POPULAR or len(name) < 5:
        return None
    squashed = name.replace("-", "").replace("_", "").replace(".", "")
    for p in POPULAR:
        if within_one_edit(name, p) or (squashed == p.replace("-", "").replace(".", "") and name != p):
            return p
    return None


def finding(rule, category, title, severity, status, rationale, evidence, comp=None, path=None, project=None):
    key = f"{rule}|{comp['id'] if comp else ''}|{evidence.get('file', '')}|{evidence.get('line', '')}"
    return {
        "id": hashlib.sha1(key.encode()).hexdigest()[:12], "type": "suspicious", "rule": rule,
        "category": category, "title": title, "severity": severity, "status": status,
        "rationale": rationale, "evidence": evidence,
        "component": comp["id"] if comp else None, "name": comp["name"] if comp else None,
        "version": comp["version"] if comp else None, "direct": comp["direct"] if comp else None,
        "scope": comp["scope"] if comp else None, "path": path,
        "project": project or (comp["projects"][0] if comp else None),
    }


def run(state: dict) -> tuple[dict, dict]:
    paths = state.get("paths", {})
    out = []

    for c in state["components"]:
        p = paths.get(c["id"])
        if c["install_script"]:
            out.append(finding(
                "install-script", "Package behaviour", f"{c['name']}@{c['version']} runs an install script",
                "medium" if c["scope"] == "runtime" else "low", "fact",
                "Install scripts execute arbitrary code on every machine that installs the package "
                "(developer laptops, CI, image builds). A hijacked release of this package would run there.",
                {"source": "lockfile", "field": "hasInstallScript: true", "resolved": c["resolved"]}, c, p))
        if c["origin"] not in TRUSTED_ORIGINS:
            sev = "low" if c["origin"] == "local" else "high"
            out.append(finding(
                "unexpected-origin", "Package source", f"{c['name']}@{c['version']} comes from {c['origin']}",
                sev, "fact",
                "Not downloaded from the public registry, so registry-side protections (immutability, "
                "malware takedowns, advisories) do not apply." if sev == "high" else
                "Local/workspace package bundled from the repository itself.",
                {"source": "lockfile", "field": "resolved", "resolved": c["resolved"]}, c, p))
        if c["ecosystem"] == "npm" and (target := lookalike(c["name"])):
            out.append(finding(
                "typosquat", "Package identity", f"{c['name']} looks like popular package '{target}'",
                "low", "indicator",
                f"The name is one character edit away from '{target}', a pattern used by typosquatting "
                "attacks. Many lookalikes are legitimate: check the publisher and download count.",
                {"source": "name comparison", "lookalike_of": target}, c, p))

    for proj in state["projects"]:
        if proj.get("lock_source") == "generated":
            out.append(finding(
                "no-lockfile", "Build reproducibility", f"{proj['manifest']} has no committed lockfile",
                "medium", "fact",
                "Every install resolves the newest versions allowed by package.json ranges, so a malicious "
                "or broken release published tomorrow is picked up automatically. The scanned versions are "
                "what the registry served at scan time.",
                {"file": proj["manifest"], "notes": proj["notes"], "command": proj["evidence"].get("command")},
                project=proj["id"]))

    ins = state.get("inspection") or {}
    for o in ins.get("observations", []):
        msg, ev = o["message"], {"file": o["file"], "line": o["line"], "text": o["text"]}
        if msg.startswith("Action referenced"):
            third = o["level"] == "warning"
            out.append(finding("unpinned-action", "CI/CD", f"{o['text'].split('uses:')[-1].strip()} not pinned to a commit",
                               "medium" if third else "low", "fact",
                               "A tag or branch can be moved to new code by the action's owner (or an attacker who "
                               "takes over the repo); that code then runs in CI with this repo's token and secrets.", ev))
        elif msg.startswith("Base image"):
            out.append(finding("base-image", "Container", f"{o['text']} not pinned by digest",
                               "medium" if o["level"] == "warning" else "low", "fact",
                               "The image behind a tag (or 'latest') changes over time; builds silently pick up "
                               "whatever was published last.", ev))
        elif msg.startswith(("pull_request_target", "Workflow grants", "Untrusted event")):
            out.append(finding("workflow-risk", "CI/CD", msg, "high" if "Untrusted" in msg else "medium", "fact",
                               msg + ".", ev))
        elif msg.startswith("npm install"):
            global_tool = " -g " in f" {o['text']} "
            out.append(finding("build-install", "Container",
                               f"Image build runs '{o['text'].removeprefix('RUN ')}'",
                               "low" if global_tool else "medium", "fact",
                               "Installs a pinned build tool globally." if global_tool else
                               "Installs app dependencies at image-build time without a lockfile, so the image can "
                               "contain different versions than were scanned, and install scripts run during the build.",
                               ev))
        elif "curl" in msg.lower() or "Pipes" in msg or "unsafe-perm" in msg or "ADD from" in msg:
            out.append(finding("build-install", "Container", msg, "high", "fact", msg + ".", ev))

    order = {"high": 0, "medium": 1, "low": 2}
    out.sort(key=lambda f: (order[f["severity"]], f["rule"], f["name"] or ""))
    by_rule = {}
    for f in out:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
    not_applicable = [
        {"rule": "modified-lockfile", "reason": "Baseline scan of a single commit: there is no earlier snapshot to diff against."},
        {"rule": "unexpected-new-dependency", "reason": "Needs a base commit to compare manifests."},
        {"rule": "suspicious-version-bump", "reason": "Needs a base commit to compare resolved versions."},
    ]
    public = {
        "findings": out, "by_rule": by_rule, "not_applicable": not_applicable,
        "counts": {s: sum(f["severity"] == s for f in out) for s in ("high", "medium", "low")},
        "_summary": f"{len(out)} findings across {len(by_rule)} rules ("
                    + ", ".join(f"{n} {r}" for r, n in sorted(by_rule.items(), key=lambda x: -x[1])[:3]) + ")",
    }
    return {"suspicious": out}, public
