"""
veridict.extract — turn an agent's tool-call trace into a veridict claim chain.

The biggest friction in using veridict is hand-building the chain. Most agents already
emit a trace of tool calls; this maps common ones to checkable claims so you can gate a
run with almost no wiring:

    from veridict.extract import extract, from_openai
    chain = extract(my_tool_calls)            # generic list of {name, arguments, ...}
    chain = from_openai(messages)             # OpenAI chat-completions message list

It is intentionally best-effort and transparent: unknown tools are skipped and reported
(they become coverage gaps, not silent passes), and you can extend or replace the mapping.
A tool call is NOT a verified claim — it's a *claim to verify*; veridict still checks reality.
"""
from __future__ import annotations

import json
import re

def _marker(text):
    """CRLF-robust content marker (longest non-blank line) so a write claim verifies the
    content landed, not just that the file exists. "" when there's nothing to anchor on."""
    if not isinstance(text, str) or not text.strip():
        return ""
    return max((ln.strip() for ln in text.splitlines() if ln.strip()), key=len, default="")


# name-pattern -> (action, builder(args) -> extra step fields). First match wins.
DEFAULT_MAP = [
    (r"write|save|create.*file|put.*file|fs[_.]?write", "file",
     lambda a: {"path": a.get("path") or a.get("file") or a.get("filename") or a.get("filepath"),
                "contains": _marker(a.get("content") or a.get("text") or a.get("contents") or a.get("data") or "")}),
    (r"read.*file|cat|open.*file|fs[_.]?read", "file",
     lambda a: {"path": a.get("path") or a.get("file") or a.get("filename")}),
    (r"\b(run|exec|shell|bash|sh|command|terminal|pytest|test)\b", "cmd",
     lambda a: {"cmd": a.get("command") or a.get("cmd") or a.get("script") or a.get("code")}),
    (r"commit", "commit", lambda a: {"message": a.get("message") or a.get("msg")}),
    (r"push", "push", lambda a: {}),
    (r"branch", "branch", lambda a: {"name": a.get("name") or a.get("branch")}),
    (r"http|fetch|request|curl|get_url|api", "http",
     lambda a: {"url": a.get("url") or a.get("endpoint"),
                **({"status": int(a["status"])} if str(a.get("status", "")).strip().isdigit() else {})}),
]


_FAIL_STATUS = {"error", "rejected", "abstained", "escalated", "failed", "failure", "false", "denied"}


def _failed(call):
    """A tool call whose own result says it FAILED is not a success to verify — skip it,
    don't turn it into a success claim (extraction otherwise can't tell attempted from done).
    Covers status strings, ok/success=False, is_error=True, and a present `error` field."""
    res = call.get("result") if isinstance(call.get("result"), dict) else {}
    st = call.get("status") or res.get("status")
    if isinstance(st, str) and st.lower() in _FAIL_STATUS:
        return True
    for src in (call, res):
        if src.get("is_error") is True:
            return True
        for k in ("ok", "success", "succeeded"):
            if src.get(k) is False:
                return True
        if src.get("error") not in (None, "", False, [], {}):   # a non-empty error field = failed
            return True
    return False


def _args(a):
    """Tool arguments may be a dict or a JSON string (OpenAI). Normalize to dict."""
    if isinstance(a, dict):
        return a
    if isinstance(a, str):
        try:
            return json.loads(a)
        except Exception:
            return {}
    return {}


def _step_for(name, args, mapping):
    raw = (name or "").lower()
    name = re.sub(r"[^a-z0-9]+", " ", raw)        # write_file / write-file -> "write file"
    for pat, action, build in mapping:
        if re.search(pat, name):
            extra = {k: v for k, v in build(args).items() if v not in (None, "")}
            if action in ("file", "commit", "http", "branch", "cmd") and not extra:
                continue                       # matched a name but no usable target -> not checkable
                                               # (e.g. 'get_run_status' matches 'run' but has no command)
            return {"actor": "agent", "action": action, "claim": f"{name}({', '.join(f'{k}={v}' for k,v in args.items())})"[:120], **extra}
    return None


def extract(calls, mapping=None, repo=None):
    """calls: iterable of {"name": str, "arguments": dict|json-str}. Returns a claim chain.
    Unknown/uncheckable tools are skipped (see extract_report for what was dropped)."""
    mapping = mapping or DEFAULT_MAP
    chain = []
    for c in calls:
        if _failed(c):
            continue                           # the call itself reports failure -> not a claim
        step = _step_for(c.get("name"), _args(c.get("arguments") or c.get("args") or {}), mapping)
        if step:
            if repo:
                step["repo"] = repo
            chain.append(step)
    return chain


def extract_report(calls, mapping=None):
    """Like extract(), but also returns the tool names that were NOT mappable — so a
    'covered N of M tool calls' line is honest about what wasn't checked."""
    mapping = mapping or DEFAULT_MAP
    chain, skipped = [], []
    for c in calls:
        if _failed(c):
            skipped.append(f"{c.get('name')} (reported failed)")
            continue
        step = _step_for(c.get("name"), _args(c.get("arguments") or c.get("args") or {}), mapping)
        (chain.append(step) if step else skipped.append(c.get("name")))
    return chain, skipped


def from_openai(messages, mapping=None, repo=None):
    """Adapter for OpenAI / OpenAI-compatible (DeepSeek, etc.) chat messages: pull
    assistant `tool_calls` into a veridict chain."""
    calls = []
    for m in messages:
        for tc in (m.get("tool_calls") or []):
            fn = tc.get("function") or {}
            calls.append({"name": fn.get("name"), "arguments": fn.get("arguments")})
    return extract(calls, mapping=mapping, repo=repo)
