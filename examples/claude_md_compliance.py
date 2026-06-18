"""
Verify Claude actually followed your CLAUDE.md — the *checkable* rules.

The #1 daily complaint in the Claude community is "Claude didn't follow my CLAUDE.md."
A CLAUDE.md is a mix of two things:
  - CHECKABLE post-conditions ("no hardcoded keys", "commits credit Claude", "tests pass")
    -> veridict can enforce these against ground truth.
  - SEMANTIC intent ("write clean code", "be concise") -> AI-complete; veridict refuses to
    fake a verdict on these. That honesty is the point.

This encodes three real, checkable rules with custom checkers and runs them as a veridict
chain. Two custom checkers are added: `no_match` (a regex must be ABSENT from source) and
`commit_trailer` (the latest commit message must contain a pattern).

    python examples/claude_md_compliance.py            # demo: a repo with planted violations
    python examples/claude_md_compliance.py /path/repo  # check a real repo (your dogfood)
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

from veridict import confirm_chain, register, ACCEPT

SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build",
             ".mypy_cache", ".pytest_cache", ".egg-info"}
CODE_EXT = (".py", ".js", ".ts", ".tsx", ".rs", ".go", ".java", ".rb", ".sh",
            ".yaml", ".yml", ".toml", ".json", ".env", ".cfg", ".ini")


def no_match(step, repo):
    """A regex must NOT appear in any source file. ACCEPT if absent; REJECT with file:line."""
    pat = re.compile(step["pattern"])
    exts = tuple(step.get("ext", CODE_EXT))
    root = str(repo or ".")
    hits = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for f in files:
            if not f.endswith(exts):
                continue
            fp = os.path.join(dirpath, f)
            try:
                with open(fp, encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh, 1):
                        if pat.search(line):
                            hits.append(f"{os.path.relpath(fp, root)}:{i}")
                            if len(hits) >= 5:
                                break
            except OSError:
                continue
            if len(hits) >= 5:
                break
        if len(hits) >= 5:
            break
    ok = not hits
    return ok, (f"clean — /{step['pattern']}/ absent from source"
                if ok else f"VIOLATION — /{step['pattern']}/ found at: {', '.join(hits)}")


def commit_trailer(step, repo):
    """The latest commit's full message must match a pattern (e.g. a Co-Authored-By trailer)."""
    r = subprocess.run(["git", "-C", str(repo or "."), "log", "-1", "--format=%B"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        return None, "not a git repo -> cannot verify commit"
    found = bool(re.search(step["pattern"], r.stdout))
    return found, (f"latest commit matches /{step['pattern']}/" if found
                   else f"latest commit is MISSING /{step['pattern']}/")


register("no_match", no_match)
register("commit_trailer", commit_trailer)

# Three real CLAUDE.md rules, encoded. Edit these to mirror your own md.
RULES = [
    {"actor": "CLAUDE.md", "action": "no_match", "claim": "No hardcoded keys in any file",
     "pattern": r"""(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-/+]{16,}['"]"""},
    {"actor": "CLAUDE.md", "action": "no_match", "claim": "No Anthropic API in code",
     "pattern": r"(api\.anthropic\.com|^\s*(from|import)\s+anthropic\b)", "ext": (".py", ".js", ".ts")},
    {"actor": "CLAUDE.md", "action": "commit_trailer", "claim": "Commits credit Claude",
     "pattern": r"Co-Authored-By:\s*Claude"},
]

# Rules veridict deliberately can NOT gate — printed so the honesty is explicit.
NOT_GATEABLE = ["Fail loud, no silent fallback", "Drop signal-free words / be concise",
                "Money is one level more specific than the grand framing"]


def _planted_demo_repo():
    import tempfile
    d = tempfile.mkdtemp(prefix="cmd_demo_")
    g = lambda *a: subprocess.run(["git", "-C", d, *a], capture_output=True, text=True)
    g("init", "-q")
    # a planted hardcoded secret (violates rule 1). The trigger word is split here so this
    # example's OWN source never self-matches when you scan a repo that contains it.
    open(os.path.join(d, "config.py"), "w").write("api" + '_key = "sk-live-AbCd1234EfGh5678XyZ"\n')
    # ... and a commit with NO Claude trailer (violates rule 3)
    g("add", "config.py")
    g("-c", "user.email=a@b.c", "-c", "user.name=ac", "commit", "-q", "-m", "add config")
    return d


def main():
    if len(sys.argv) > 1:
        repo, where = sys.argv[1], f"real repo: {sys.argv[1]}"
    else:
        repo, where = _planted_demo_repo(), "DEMO repo (planted violations)"
    print(f"Checking CLAUDE.md compliance against {where}\n")
    _, overall = confirm_chain(RULES, repo=repo)
    print("\n  not gateable by veridict (semantic intent — and it says so):")
    for r in NOT_GATEABLE:
        print(f"    · {r}")
    return 0 if overall == ACCEPT else 1


if __name__ == "__main__":
    sys.exit(main())
