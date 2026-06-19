"""
veridict.hook — a Claude Code PostToolUse hook that verifies Write/Edit/Notebook
claims against the real file on disk, using veridict's deterministic `file` checker.

The gap it closes: agent SDKs (Claude Agent SDK, OpenAI Agents SDK) report a Write/Edit
as success even when the file was never created or the content didn't land
(anthropics/claude-code #13890, #18995, #23801, #40227 — closed NOT_PLANNED). After every
file tool, this checks ground truth and, on a mismatch, feeds a loud REJECT back to the model.

Install (settings.json):
    {"hooks": {"PostToolUse": [
        {"matcher": "Write|Edit|MultiEdit|NotebookEdit",
         "hooks": [{"type": "command", "command": "veridict hook"}]}]}}

I/O contract (Claude Code):
    stdin  : PostToolUse JSON {"tool_name","tool_input","tool_response","cwd"}
    exit 0 : verified (ACCEPT) or nothing to check — quiet, not injected into the model
    exit 2 : ground-truth mismatch — stderr is fed back to the model
It is a DETECTOR (PostToolUse runs after the tool), not a hard gate. It never breaks the
session: any unexpected input -> exit 0.
"""
from __future__ import annotations

import json
import os
import sys
import time

from .core import confirm_step, ACCEPT

FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
# PostToolUse fires right after the tool, so a genuine write has an mtime of ~now. Require
# freshness so a lie about a PRE-EXISTING (old) file is caught, not ACCEPTed on existence.
# Generous window absorbs clock skew / slow hooks; 0 disables.
_FRESH_SECS = int(os.environ.get("VERIDICT_HOOK_FRESH_SECS", "300"))


def _probe(text):
    """A CRLF/LF-robust content marker: the longest non-blank stripped line. One stripped
    line is a substring of the file regardless of line-ending normalization, so it won't
    false-fail on CRLF<->LF. Empty/blank content -> None (existence-only check)."""
    if not text:
        return None
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    return max(lines, key=len) if lines else None


def _markers(tool_name, ti):
    """Content markers to verify are now in the file (CRLF-robust longest lines). One per
    edit for MultiEdit (so a partial multi-edit can't pass on one landed line); [] = nothing
    to check beyond existence."""
    if tool_name == "Write":
        m = _probe(ti.get("content", ""))
        return [m] if m else []
    edits = ti.get("edits") or [{"new_string": ti.get("new_string", ti.get("new_source", ""))}]
    return [m for e in edits if isinstance(e, dict)
            for m in [_probe(e.get("new_string", e.get("new_source", "")))] if m]


def _mismatch(claim, evidence):
    return (2, "[veridict] GROUND-TRUTH MISMATCH — the tool reported success but reality "
            f"disagrees.\nveridict: REJECT  {claim}  ->  {evidence}\n"
            "Verify the file before claiming this step is done.")


def evaluate(payload):
    """Pure core: payload dict -> (exit_code, message). Defensive — any odd shape returns
    (0, None) so the hook never breaks the session."""
    if not isinstance(payload, dict) or payload.get("tool_name") not in FILE_TOOLS:
        return 0, None
    ti = payload.get("tool_input", {})
    if not isinstance(ti, dict):
        return 0, None
    path = ti.get("file_path") or ti.get("path") or ti.get("notebook_path")
    if not path or not isinstance(path, str):
        return 0, None
    cwd = payload.get("cwd") or None
    claim = f"{payload['tool_name']} {os.path.basename(path)}"
    base = {"actor": "claude", "action": "file", "path": path, "claim": claim}
    if _FRESH_SECS:
        base["since"] = time.time() - _FRESH_SECS     # a real write is recent; a lie about an old file isn't
    r = confirm_step(base, cwd)                       # existence + freshness first
    if r["verdict"] != ACCEPT:
        return _mismatch(claim, r["evidence"])
    for m in _markers(payload["tool_name"], ti):      # then EVERY claimed marker must be present
        r = confirm_step({**base, "contains": m}, cwd)
        if r["verdict"] != ACCEPT:
            return _mismatch(claim, r["evidence"])
    return 0, f"veridict: ACCEPT  {claim}  ->  verified on disk"


def main(argv=None):
    try:
        payload = json.load(sys.stdin)
    except Exception as e:
        print(f"veridict hook: unreadable payload: {e}", file=sys.stderr)
        return 0  # never break the session on a malformed payload
    code, msg = evaluate(payload)
    if msg:
        print(msg, file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())
