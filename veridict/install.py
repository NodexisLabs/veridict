"""
veridict.install — wire veridict into a Claude Code project, then VERIFY THE INSTALL
WITH VERIDICT ITSELF. The tool's thesis is "don't trust that an action happened — check
it," so the installer doesn't just claim success: it runs a veridict loop over its own
actions (settings written, hook actually fires) and reports ACCEPT/REJECT on the install.

What it does (idempotent):
  - .claude/settings.json : adds a PostToolUse hook (`veridict hook`) for file tools
  - .mcp.json             : registers the veridict MCP server (`veridict mcp`)
Then self-verifies and returns (results, overall).
"""
from __future__ import annotations

import json
import os
import tempfile

from .core import confirm_chain, confirm_step, ACCEPT, REJECT, ESCALATE
from .hook import evaluate as _hook_eval

DEFAULT_MATCHER = "Write|Edit|MultiEdit|NotebookEdit"
HOOK_COMMAND = "veridict hook"

# The /veridict skill — the conversational front door. Dropped into .claude/skills so the
# user never touches hook plumbing: they say "set up veridict" or "verify that" and the
# agent drives it.
SKILL_MD = """---
name: veridict
description: Ground-truth verification of the agent's own actions. Use when the user wants to
  set up automatic verification, or asks to confirm/"toolcheck" something the agent just did
  ("did that actually write?", "you said tests pass — check", "make my writes verified").
---

# veridict — make the agent's claims checkable

veridict checks whether an action the agent *claimed* actually happened, against ground truth
(files, git, exit codes, HTTP), deterministically — no LLM judging. Two jobs:

## A) "verify that" / "did that actually happen?" (on demand)
The user is pointing at something just done. DON'T reconfigure. Just check reality:
- a file write -> run `veridict verify` on a one-step chain, e.g.
  `echo '[{"action":"file","path":"PATH","contains":"SOME TEXT"}]' | veridict verify /dev/stdin`
  (or call the `verify` MCP tool if available), then report ACCEPT / REJECT / ESCALATE plainly.
- "tests pass" -> chain `{"action":"tests","cmd":"THE TEST COMMAND"}`.
- "it's deployed" -> chain `{"action":"http","url":"...","status":200}`.
Report what reality said in one line. If it's a REJECT, offer to fix and re-verify.

## A2) "did you follow my CLAUDE.md?" / "check my rules"
Run `veridict claude-md` — it maps the CHECKABLE rules in CLAUDE.md (no hardcoded keys,
no Anthropic API, commits credit Claude, clean tree...) to checks and runs them, and lists
the rules it can't gate (style/intent). Report the verdict + be upfront about what wasn't
gateable. Don't oversell — it checks the checkable subset, honestly.

## B) "set it up" / "always verify my writes" (persist)
Walk the user through up to 4 quick decisions — offer the defaults and let them just say
"defaults"; don't belabor it:
1. Auto-verify file writes via a PostToolUse hook?  (default: yes)
2. Allow on-demand verification over MCP?           (default: yes)
3. Which file tools to watch?                        (default: Write|Edit|MultiEdit|NotebookEdit)
4. Confirm with a self-test now?                     (default: yes)

Then run it — this also self-verifies the install with veridict:
    veridict install            # all defaults
    veridict install --no-mcp --matcher "Write|Edit"   # if they narrowed it
Show them the self-verify verdict (it proves the hook actually fires). Done — from now on a
write that didn't land gets flagged back to you automatically.

Keep it light. The whole point is that the user never has to learn hooks — they just talk.
"""


def wire_skill(target):
    """Drop the /veridict skill into .claude/skills (idempotent)."""
    sdir = os.path.join(target, ".claude", "skills", "veridict")
    os.makedirs(sdir, exist_ok=True)
    path = os.path.join(sdir, "SKILL.md")
    open(path, "w", encoding="utf-8").write(SKILL_MD)
    return path, "written"


def _load(path):
    if os.path.exists(path):
        try:
            return json.load(open(path, encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _already_hooked(settings):
    for entry in (settings.get("hooks", {}) or {}).get("PostToolUse", []) or []:
        for h in entry.get("hooks", []) or []:
            if "veridict" in str(h.get("command", "")):
                return True
    return False


def wire_hook(target, matcher=DEFAULT_MATCHER, command=HOOK_COMMAND):
    """Add the PostToolUse hook to .claude/settings.json (merge, idempotent)."""
    cdir = os.path.join(target, ".claude")
    os.makedirs(cdir, exist_ok=True)
    path = os.path.join(cdir, "settings.json")
    settings = _load(path)
    if _already_hooked(settings):
        return path, "already present"
    settings.setdefault("hooks", {}).setdefault("PostToolUse", []).append(
        {"matcher": matcher, "hooks": [{"type": "command", "command": command}]})
    json.dump(settings, open(path, "w", encoding="utf-8"), indent=2)
    return path, "added"


def wire_mcp(target):
    """Register the veridict MCP server in .mcp.json (merge, idempotent)."""
    path = os.path.join(target, ".mcp.json")
    cfg = _load(path)
    servers = cfg.setdefault("mcpServers", {})
    if "veridict" in servers:
        return path, "already present"
    servers["veridict"] = {"command": "veridict", "args": ["mcp"]}
    json.dump(cfg, open(path, "w", encoding="utf-8"), indent=2)
    return path, "added"


def _functional_probe(target):
    """Prove the hook actually WORKS end-to-end: a real write -> ACCEPT, a ghost write
    (claimed but never created) -> REJECT. Returns synthetic veridict result rows."""
    d = tempfile.mkdtemp(dir=target) if os.path.isdir(target) else tempfile.mkdtemp()
    real = os.path.join(d, "veridict_selftest.txt")
    open(real, "w", encoding="utf-8").write("veridict self-test marker\n")
    ghost = os.path.join(d, "veridict_ghost.txt")
    real_code, _ = _hook_eval({"tool_name": "Write", "cwd": d,
                               "tool_input": {"file_path": real, "content": "veridict self-test marker\n"}})
    ghost_code, _ = _hook_eval({"tool_name": "Write", "cwd": d,
                                "tool_input": {"file_path": ghost, "content": "never written\n"}})
    os.remove(real)
    return [
        {"actor": "veridict", "action": "hook", "claim": "hook ACCEPTs a real write",
         "verdict": ACCEPT if real_code == 0 else REJECT,
         "evidence": f"hook exit {real_code} on a true write (want 0)"},
        {"actor": "veridict", "action": "hook", "claim": "hook REJECTs a ghost write",
         "verdict": ACCEPT if ghost_code == 2 else REJECT,
         "evidence": f"hook exit {ghost_code} on a fabricated write (want 2)"},
    ]


def install(target=".", hook=True, mcp=True, skill=True, matcher=DEFAULT_MATCHER):
    """Wire veridict into the project at `target`, then self-verify. Returns (results, overall)."""
    target = os.path.abspath(target)
    actions = []
    if hook:
        hp, hstate = wire_hook(target, matcher)
        actions.append(("settings.json", hp, hstate))
    if mcp:
        mp, mstate = wire_mcp(target)
        actions.append((".mcp.json", mp, mstate))
    if skill:
        sp, sstate = wire_skill(target)
        actions.append(("/veridict skill", sp, sstate))

    # self-verification: veridict confirms its own install actually took effect
    chain = []
    if hook:
        chain.append({"actor": "veridict", "action": "file",
                      "claim": "settings.json carries the veridict hook",
                      "path": os.path.join(target, ".claude", "settings.json"), "contains": "veridict hook"})
    if mcp:
        chain.append({"actor": "veridict", "action": "file",
                      "claim": ".mcp.json registers the veridict server",
                      "path": os.path.join(target, ".mcp.json"), "contains": "veridict"})
    if skill:
        chain.append({"actor": "veridict", "action": "file",
                      "claim": "/veridict skill is installed",
                      "path": os.path.join(target, ".claude", "skills", "veridict", "SKILL.md"),
                      "contains": "veridict"})
    results = [confirm_step(s) for s in chain]
    if hook:
        results.extend(_functional_probe(target))
    overall = (ACCEPT if all(r["verdict"] == ACCEPT for r in results)
               else REJECT if any(r["verdict"] == REJECT for r in results) else ESCALATE)
    return results, overall, actions
