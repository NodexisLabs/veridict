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

# `cmd`/`tests` re-run a command. Exposing that over MCP would let a client run arbitrary
# code on this host (RCE). Disabled by default; opt in only in a trusted setup.
_EXEC_ACTIONS = {"cmd", "tests"}
_ALLOW_EXEC = os.environ.get("VERIDICT_MCP_ALLOW_EXEC") == "1"


def _verify_chain(chain, repo):
    """confirm the chain, but refuse to RUN executable steps unless explicitly allowed."""
    results = []
    for s in chain:
        if not _ALLOW_EXEC and isinstance(s, dict) and s.get("action") in _EXEC_ACTIONS:
            results.append({**s, "verdict": ESCALATE,
                            "evidence": "executable check (cmd/tests) disabled over MCP; "
                                        "set VERIDICT_MCP_ALLOW_EXEC=1 on a trusted host to enable"})
        else:
            results.append(confirm_step(s, repo))
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
