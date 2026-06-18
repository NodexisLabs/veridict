"""
veridict.claude_md — turn the CHECKABLE rules in a CLAUDE.md into veridict claims.

The #1 daily complaint is "Claude didn't follow my CLAUDE.md." A CLAUDE.md mixes checkable
post-conditions ("no hardcoded keys", "commits credit Claude", "tests pass") with semantic
intent ("write clean code", "be concise"). This maps the former to veridict claims and is
HONEST about the latter — it lists what it can't gate rather than faking a verdict.

DETERMINISTIC and zero-dep: pattern -> checker, and it ABSTAINS on anything it can't map
with confidence (no guessing a regex from arbitrary prose). An LLM could *propose* mappings
for the abstained rules, but that's a generator; the gate here stays deterministic.

    from veridict.claude_md import from_file
    chain, unmapped = from_file("CLAUDE.md")
"""
from __future__ import annotations

import os
import re

SECRET_PATTERN = r"""(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-/+]{16,}['"]"""

# known "banned construct" -> regex to forbid in source. Deliberately conservative: only
# tokens that are unambiguously CODE (not English homographs like "print"/"eval", which
# appear as verbs in prose). Unknown/ambiguous constructs -> abstain, never guess.
BANNED = {
    "anthropic api": r"(api\.anthropic\.com|^\s*(from|import)\s+anthropic\b)",
    "anthropic": r"(api\.anthropic\.com|^\s*(from|import)\s+anthropic\b)",
    "console.log": r"console\.log", "console log": r"console\.log",
    "debugger": r"\bdebugger\b", "todo": r"\bTODO\b", "fixme": r"\bFIXME\b",
}

_NEG = r"\b(no|never|don'?t|do not|avoid|without)\b"


def parse_rules(md):
    """Pull candidate rule lines from a CLAUDE.md (bullets + directive-looking lines),
    skipping headers, prose, and fenced code."""
    rules, in_code = [], False
    for raw in md.splitlines():
        line = raw.strip()
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code or not line or line.startswith("#"):
            continue
        m = re.match(r"^(?:[-*+]|\d+\.)\s+(.*)", line)
        text = re.sub(r"[*_`]", "", (m.group(1) if m else line)).strip()
        if len(text) < 6:
            continue
        if m or re.search(r"\b(must|never|always|don'?t|do not|no|avoid|ensure|require|should)\b",
                          text.lower()):
            rules.append(text[:160])
    return rules


def _why(rule):
    if re.search(r"\b(test|build|lint|typecheck|ci|format)\b", rule.lower()):
        return "checkable, but needs the command — add a cmd step, e.g. {'action':'tests','cmd':'pytest -q'}"
    return "semantic/intent — not deterministically gateable"


def map_rule(rule):
    """Return (step | None, reason). A step if confidently checkable; else None + why."""
    low = rule.lower()
    # secrets/keys — require a real secret noun ('hardcoded' alone is not enough, or
    # "no hardcoded fallbacks" would false-map to a secret check)
    if re.search(_NEG + r".{0,30}(hardcod\w*\s+(?:\w+\s+)?(?:keys?|secrets?|credentials?|tokens?|passwords?)"
                 r"|secrets?|api[_-]?keys?|credentials?|passwords?|private[_-]?keys?|access[_-]?keys?)", low):
        return {"action": "no_match", "pattern": SECRET_PATTERN, "claim": rule}, None
    # banned constructs — a negation plus a known forbidden token, word-bounded so it matches
    # mid-sentence ("No Anthropic API in code — ...") and doesn't fire on "fingerprint"/"evaluate"
    if re.search(_NEG, low):
        for key, pat in BANNED.items():
            if re.search(r"\b" + re.escape(key) + r"\b", low):
                return {"action": "no_match", "pattern": pat, "claim": rule}, None
    if re.search(r"\bcommit", low):
        if re.search(r"co-?author|credit\w*\s+claude|claude.{0,20}(credit|trailer|co-?author)", low):
            return {"action": "commit_trailer", "pattern": r"Co-Authored-By:\s*Claude", "claim": rule}, None
        if re.search(r"\b(ticket|issue|jira)\b", low):
            return {"action": "commit_trailer", "pattern": r"[A-Z]{2,}-\d+", "claim": rule}, None
        if "conventional" in low:
            return {"action": "commit_trailer",
                    "pattern": r"^(feat|fix|chore|docs|refactor|test|perf|build|ci)(\(.+\))?!?:", "claim": rule}, None
    if re.search(r"(working tree|repo\w*|tree)\b.{0,20}\bclean\b|\bno uncommitted\b", low):
        return {"action": "clean", "claim": rule}, None
    return None, _why(rule)


def from_text(md, repo=None):
    """Parse CLAUDE.md text -> (chain, unmapped). chain = veridict claims for checkable rules;
    unmapped = [(rule, reason)] for rules it won't fake a verdict on."""
    chain, unmapped = [], []
    for rule in parse_rules(md):
        step, why = map_rule(rule)
        if step:
            step.setdefault("actor", "CLAUDE.md")
            if repo:
                step["repo"] = repo
            chain.append(step)
        else:
            unmapped.append((rule, why))
    return chain, unmapped


def from_file(path, repo=None):
    with open(path, encoding="utf-8", errors="ignore") as f:
        return from_text(f.read(), repo=repo)


def find_claude_md(start="."):
    """Locate a CLAUDE.md: ./CLAUDE.md, ./.claude/CLAUDE.md, then ~/.claude/CLAUDE.md."""
    for c in (os.path.join(start, "CLAUDE.md"), os.path.join(start, ".claude", "CLAUDE.md"),
              os.path.expanduser("~/.claude/CLAUDE.md")):
        if os.path.isfile(c):
            return c
    return None
