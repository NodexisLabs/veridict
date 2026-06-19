"""
Adversarial/edge stress of the Claude Code hook (veridict.hook). Prints CONFIRMED-fixed
(OK), DOC (inherent heuristic limit), or a real issue. Run: python stress_hook.py
"""
from __future__ import annotations
import json, os, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from veridict.hook import evaluate

F = []
def finding(sev, what): F.append((sev, what)); print(f"  [{sev:8}] {what}")

d = tempfile.mkdtemp(prefix="hookstress_")
real = os.path.join(d, "f.txt")
open(real, "w", encoding="utf-8").write("alpha line one\nthe quick brown fox jumps\ngamma\n")
ghost = os.path.join(d, "ghost.txt")


def ev(tool, ti, cwd=d):
    return evaluate({"tool_name": tool, "tool_input": ti, "cwd": cwd})[0]


# --- robustness: the hook must NEVER break the session (always 0 on weird input) ---
print("\n[robustness] never break the session")
try:
    finding("OK" if ev("Write", []) == 0 else "HIGH", "non-dict tool_input -> 0 (was a crash before)")
except Exception as e:
    finding("HIGH", f"non-dict tool_input raised: {e}")
try:
    finding("OK" if ev("Write", {"file_path": 123, "content": "x"}) == 0 else "HIGH", "non-string path -> 0")
except Exception as e:
    finding("HIGH", f"non-string path raised: {e}")
p = subprocess.run([sys.executable, "-m", "veridict.hook"], input="}{ not json", capture_output=True, text=True)
finding("OK" if p.returncode == 0 else "HIGH", f"malformed stdin -> exit {p.returncode} (want 0)")

# --- correctness: partial MultiEdit must be caught (the fix) ---
print("\n[correctness] partial MultiEdit")
code = ev("MultiEdit", {"file_path": real, "edits": [
    {"new_string": "the quick brown fox jumps"},     # present
    {"new_string": "this line was never written"}]})  # absent
finding("OK" if code == 2 else "HIGH", f"partial MultiEdit (1 landed, 1 missing) -> exit {code} (want 2)")
code = ev("MultiEdit", {"file_path": real, "edits": [
    {"new_string": "alpha line one"}, {"new_string": "the quick brown fox jumps"}]})
finding("OK" if code == 0 else "HIGH", f"all edits present -> exit {code} (want 0)")

# --- inherent heuristic limits (documented, not bugs) ---
print("\n[heuristic limits] the single-longest-line content probe")
# (a) partial WRITE false-accept: the longest claimed line is present, but other claimed
#     content is not — Write only probes the single longest line, so it passes.
code = ev("Write", {"file_path": real,
                    "content": "the quick brown fox jumps\nBUT_THIS_NEVER_LANDED=true\n"})
finding("DOC" if code == 0 else "OK",
        "partial WRITE where only the longest line landed -> ACCEPT (probe is one line, not full content; "
        "use a sha256 step for exact)" if code == 0 else "partial write caught")
# (b) formatter-reflow false-reject: content's long line gets reflowed/split by a formatter
#     after the write, so the claimed line is no longer a contiguous substring.
reflowed = os.path.join(d, "reflowed.txt")
open(reflowed, "w", encoding="utf-8").write("the quick brown\nfox jumps\n")   # same words, line split
code = ev("Write", {"file_path": reflowed, "content": "the quick brown fox jumps\n"})
finding("DOC" if code == 2 else "OK",
        "a formatter reflowing the line AFTER the write -> false REJECT (probe needs a contiguous line)"
        if code == 2 else "reflow tolerated")

print("\n================ HOOK STRESS ================")
real_issues = [x for x in F if x[0] in ("HIGH", "MEDIUM", "ERROR")]
print(f"  real issues: {len(real_issues)} | documented heuristic limits: {sum(1 for x in F if x[0]=='DOC')} "
      f"| held up: {sum(1 for x in F if x[0]=='OK')}")
for sev, what in real_issues:
    print(f"  {sev} {what}")
