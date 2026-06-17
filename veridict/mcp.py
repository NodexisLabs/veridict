"""
veridict.mcp — expose veridict as an MCP tool over stdio (newline-delimited JSON-RPC 2.0).

Lets any MCP-aware agent (Claude, Cursor, your own harness) verify its own claimed actions
mid-run: it calls the `verify` tool with a claim chain and gets back ACCEPT/REJECT/ESCALATE
against ground truth. Stdlib only — a minimal but conformant initialize / tools/list /
tools/call loop.

    veridict mcp            # run the server on stdio
"""
from __future__ import annotations

import json
import os
import sys

from .core import confirm_step, ACCEPT, REJECT, ESCALATE
from .output import to_json

# The MCP caller may be untrusted, so the verify tool is sandboxed by default. A blind
# DeepSeek audit surfaced the whole surface to lock down: exec (RCE), network (SSRF),
# arbitrary file reads (path escape), and caller-chosen repo. Each is default-DENY here,
# opt-in only on a trusted host. (Locally / in CI, use the library or CLI without limits.)
_EXEC_ACTIONS = {"cmd", "tests"}
_NET_ACTIONS = {"http", "port"}
_ALLOW_EXEC = os.environ.get("VERIDICT_MCP_ALLOW_EXEC") == "1"
_ALLOW_NET = os.environ.get("VERIDICT_MCP_ALLOW_NET") == "1"
# the only repo/dir the MCP server will touch — caller-supplied repo/paths can't escape it
_MCP_ROOT = os.path.realpath(os.environ.get("VERIDICT_MCP_REPO") or os.getcwd())


def _escapes_sandbox(p):
    """True if path p resolves outside _MCP_ROOT. Canonicalizes (realpath) so it catches
    absolute paths, '..' traversal, AND symlinks that point out — regardless of platform
    (os.path.isabs is platform-specific and e.g. misses '/etc/passwd' on Windows)."""
    try:
        full = os.path.realpath(os.path.join(_MCP_ROOT, p))
        return os.path.commonpath([_MCP_ROOT, full]) != _MCP_ROOT
    except (ValueError, OSError):
        return True                                   # different drive / invalid -> treat as outside


def _denied(step):
    """Return a refusal reason if this step is unsafe to run for an untrusted MCP caller."""
    a = step.get("action")
    if a in _EXEC_ACTIONS and not _ALLOW_EXEC:
        return "executable check (cmd/tests) disabled over MCP — RCE risk (VERIDICT_MCP_ALLOW_EXEC=1)"
    if a in _NET_ACTIONS and not _ALLOW_NET:
        return "network check (http/port) disabled over MCP — SSRF risk (VERIDICT_MCP_ALLOW_NET=1)"
    p = step.get("path")
    if isinstance(p, str) and p and _escapes_sandbox(p):
        return "path escapes the MCP sandbox (absolute/traversal/symlink) — arbitrary-read risk"
    return None


def _verify_chain(chain, repo_unused):
    """Confirm the chain under the MCP sandbox: deny unsafe steps, ignore caller-supplied
    `repo`, and confine everything to _MCP_ROOT."""
    results = []
    for s in chain:
        if not isinstance(s, dict):
            results.append({"action": "?", "claim": str(s)[:80], "verdict": ESCALATE,
                            "evidence": "malformed step"})
            continue
        reason = _denied(s)
        if reason:
            results.append({**s, "verdict": ESCALATE, "evidence": reason})
        else:
            safe = {k: v for k, v in s.items() if k != "repo"}     # caller can't redirect the repo
            results.append(confirm_step(safe, _MCP_ROOT))
    overall = (ACCEPT if all(r["verdict"] == ACCEPT for r in results)
               else REJECT if any(r["verdict"] == REJECT for r in results) else ESCALATE)
    return results, overall

PROTOCOL = "2024-11-05"

VERIFY_TOOL = {
    "name": "verify",
    "description": ("Verify an agent's claimed actions against ground truth (git, files, exit "
                    "codes, HTTP, ports). Returns ACCEPT / REJECT / ESCALATE per step. No LLM."),
    "inputSchema": {
        "type": "object",
        "properties": {
            "chain": {"type": "array", "description": "claimed steps, e.g. "
                      '[{"action":"file","claim":"wrote x","path":"x.txt"}]',
                      "items": {"type": "object"}},
            "repo": {"type": "string", "description": "repo/working dir for the checkers"},
        },
        "required": ["chain"],
    },
}


def _result(id, result):
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _error(id, code, msg):
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}}


def handle(msg):
    """Dispatch one JSON-RPC message. Returns a response dict, or None for notifications."""
    method, mid, params = msg.get("method"), msg.get("id"), msg.get("params") or {}
    if method == "initialize":
        return _result(mid, {
            "protocolVersion": params.get("protocolVersion", PROTOCOL),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "veridict", "version": "0.2.0"},
        })
    if method in ("notifications/initialized", "initialized"):
        return None
    if method == "ping":
        return _result(mid, {})
    if method == "tools/list":
        return _result(mid, {"tools": [VERIFY_TOOL]})
    if method == "tools/call":
        if params.get("name") != "verify":
            return _error(mid, -32602, f"unknown tool: {params.get('name')}")
        args = params.get("arguments") or {}
        chain = args.get("chain") or []
        try:
            results, overall = _verify_chain(chain, args.get("repo"))
        except Exception as e:
            return _result(mid, {"content": [{"type": "text", "text": f"verify error: {e}"}],
                                 "isError": True})
        return _result(mid, {
            "content": [{"type": "text", "text": to_json(results, overall)}],
            "isError": overall != ACCEPT,
        })
    if mid is not None:
        return _error(mid, -32601, f"method not found: {method}")
    return None


def serve(stdin=None, stdout=None):
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle(msg)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


if __name__ == "__main__":
    serve()
