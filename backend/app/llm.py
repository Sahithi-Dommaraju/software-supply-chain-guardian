"""LLM access for the Day 2 agents, plus the shared Validator.

Provider: any OpenAI-compatible API. Defaults to Groq + Llama 3.3 70B. Settings come from
environment variables or backend/.env (gitignored):

  GROQ_API_KEY         the key (GUARDIAN_LLM_API_KEY also accepted)
  GUARDIAN_LLM_BASE_URL  default https://api.groq.com/openai/v1
  GUARDIAN_LLM_MODEL     default llama-3.3-70b-versatile

Every call goes through `ask()`:
  1. cached answer for (task, model, package@version, prompt hash)? return it
  2. call the model, JSON mode, temperature 0
  3. run the caller's validator (plain code: cited files/lines exist, ids real, values in range,
     no contradiction of tool facts); on failure retry once with the problems listed
  4. still failing, no key, or API error -> {"ok": False, ...}; the agent then keeps its rule-based
     result and marks the item "needs human review" / "AI explanation unavailable".
The pipeline never depends on the LLM to finish.
"""
import hashlib
import json
import os
import time
from pathlib import Path

from . import db

ENV_FILE = Path(__file__).resolve().parents[1] / ".env"
if ENV_FILE.exists():  # tiny .env loader: KEY=VALUE lines, real env vars win
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and not k.startswith("#"):
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

API_KEY = os.environ.get("GUARDIAN_LLM_API_KEY") or os.environ.get("GROQ_API_KEY")
BASE_URL = os.environ.get("GUARDIAN_LLM_BASE_URL", "https://api.groq.com/openai/v1")
MODEL = os.environ.get("GUARDIAN_LLM_MODEL", "llama-3.3-70b-versatile")

_client = None


def status() -> dict:
    return {"enabled": bool(API_KEY), "model": MODEL, "base_url": BASE_URL}


def _chat(system: str, user: str) -> tuple[str, dict]:
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(api_key=API_KEY, base_url=BASE_URL, timeout=60, max_retries=2)
    r = _client.chat.completions.create(
        model=MODEL, temperature=0, response_format={"type": "json_object"},
        messages=[{"role": "system", "content": system}, {"role": "user", "content": user}])
    usage = {"prompt_tokens": r.usage.prompt_tokens, "completion_tokens": r.usage.completion_tokens} if r.usage else {}
    return r.choices[0].message.content or "", usage


def ask(task: str, subject: str, system: str, user: str, validate) -> dict:
    """validate(answer: dict) -> list of problems (empty = valid)."""
    key = f"{task}|{MODEL}|{subject}|{hashlib.sha1((system + user).encode()).hexdigest()[:16]}"
    cached = db.cache_get(key)
    if cached:
        return {**cached, "cached": True}
    if not API_KEY:
        return {"ok": False, "reason": "AI explanation unavailable: no API key configured"}
    problems, tokens = [], 0
    prompt = user
    for attempt in (1, 2):
        try:
            raw, usage = _chat(system, prompt)
            tokens += sum(usage.values())
            answer = json.loads(raw)
            problems = validate(answer) if isinstance(answer, dict) else ["answer is not a JSON object"]
        except json.JSONDecodeError:
            problems = ["answer is not valid JSON"]
        except Exception as e:  # network, auth, rate limit: keep rule result
            return {"ok": False, "reason": f"AI explanation unavailable: {type(e).__name__}: {str(e)[:200]}"}
        if not problems:
            result = {"ok": True, "answer": answer, "model": MODEL, "attempts": attempt, "tokens": tokens,
                      "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            db.cache_put(key, result)
            return result
        prompt = (user + "\n\nYour previous answer was rejected by the validator:\n- " + "\n- ".join(problems)
                  + "\nAnswer again, fixing these problems, as JSON only.")
    return {"ok": False, "reason": "needs human review: AI answer failed validation twice",
            "problems": problems, "tokens": tokens}


# ---------------------------------------------------------------- shared Validator checks

def check_enum(answer: dict, field: str, allowed: set) -> list:
    return [] if answer.get(field) in allowed else [f"'{field}' must be one of {sorted(allowed)}"]


def check_number(answer: dict, field: str, lo: float, hi: float) -> list:
    v = answer.get(field)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not lo <= v <= hi:
        return [f"'{field}' must be a number between {lo} and {hi}"]
    return []


def check_citations(answer: dict, field: str, files: dict[str, list[str]], required: bool = True) -> list:
    """files: {path: lines}. Every cited {"file", "line"} must exist; quotes must match that line."""
    cites = answer.get(field)
    if not isinstance(cites, list) or (required and not cites):
        return [f"'{field}' must be a non-empty list of {{file, line}} citations"] if required else []
    out = []
    for c in cites:
        if not isinstance(c, dict) or c.get("file") not in files:
            out.append(f"citation {c!r} refers to a file that was not provided")
            continue
        line, lines = c.get("line"), files[c["file"]]
        if not isinstance(line, int) or not 1 <= line <= len(lines):
            out.append(f"citation {c['file']}:{line} is outside the file (1-{len(lines)})")
        elif c.get("quote") and c["quote"].strip()[:40] not in lines[line - 1]:
            out.append(f"quote for {c['file']}:{line} does not appear on that line")
    return out


def check_ids(text: str, known_ids: set[str]) -> list:
    """Any advisory id mentioned in free text must be one the tools reported."""
    import re
    found = set(re.findall(r"\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}|MAL-\d{4}-\d+)\b", text or ""))
    unknown = found - known_ids
    return [f"mentions advisory ids not reported by the scanners: {sorted(unknown)}"] if unknown else []


def numbered(lines: list[str], start: int = 1) -> str:
    return "\n".join(f"{i:>4}| {l}" for i, l in enumerate(lines, start))
