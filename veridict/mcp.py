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
import sys

from .core import confirm_chain, ACCEPT
from .output import to_json

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
            results, overall = confirm_chain(chain, repo=args.get("repo"), verbose=False)
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
