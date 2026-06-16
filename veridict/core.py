"""
veridict.core — confirm an agent's claimed action chain against ground truth.

An agent emits a chain of claimed steps, e.g.
    {"actor": "opifex", "action": "commit", "claim": "committed the fix", "message": "fix login"}
Each step's checker verifies the claim against reality; the step gets ACCEPT / REJECT / ESCALATE.
The chain is narrated, flagging exactly where reality diverged from the claim.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone

from .checkers import CHECKERS

ACCEPT, REJECT, ESCALATE = "ACCEPT", "REJECT", "ESCALATE"
_MARK = {ACCEPT: "[OK]", REJECT: "[!!]", ESCALATE: "[??]"}
_ANSI = {ACCEPT: "32", REJECT: "31", ESCALATE: "33"}  # green / red / yellow


def _enable_windows_vt():
    """Turn on ANSI/VT processing for the current console on Windows. Returns True if color
    is safe to emit. Classic conhost has VT off by default — without this, escape codes print
    as literal `←[32m` garbage, so if we can't enable it we must NOT emit color."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)                       # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not k.GetConsoleMode(h, ctypes.byref(mode)):
            return False                              # not a real console (redirected) -> caller's isatty handles it
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        if mode.value & ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        return bool(k.SetConsoleMode(h, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
    except Exception:
        return False


def _use_color(stream):
    return (stream.isatty() and not os.environ.get("NO_COLOR")
            and os.environ.get("TERM") != "dumb"
            and _enable_windows_vt())


def _c(s, code, on):
    return f"\033[{code}m{s}\033[0m" if on else s


def confirm_step(step, repo=None):
    chk = CHECKERS.get(step.get("action"))
    t0 = time.perf_counter()
    if chk is None:
        ok, ev = None, f"no checker for action '{step.get('action')}'"
    else:
        try:
            ok, ev = chk(step, step.get("repo", repo))
        except Exception as e:                                  # a broken checker -> escalate, never crash the gate
            ok, ev = None, f"checker error: {e}"
    verdict = ACCEPT if ok is True else (REJECT if ok is False else ESCALATE)
    return {**step, "verdict": verdict, "evidence": ev,
            "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 1)}


def confirm_chain(steps, repo=None, verbose=True, on_narrate=None):
    """Verify a list of claimed steps. Returns (results, overall_verdict).
    overall = ACCEPT only if every step ACCEPTs; REJECT if any REJECTs; else ESCALATE."""
    results = [confirm_step(s, repo) for s in steps]
    overall = (ACCEPT if all(r["verdict"] == ACCEPT for r in results)
               else REJECT if any(r["verdict"] == REJECT for r in results) else ESCALATE)
    if verbose:
        narrate(results, overall, on_narrate)
    return results, overall


def narrate(results, overall, on_narrate=None):
    """Print the confirmed chain. `on_narrate(summary, overall, results)` is an optional sink
    (wire TTS, a dashboard, Slack...) — keeps core dependency-free.

    Color/alignment only when writing to a real terminal; piped or redirected output stays
    plain so CI logs and `> file` capture clean text (respects NO_COLOR / TERM=dumb)."""
    color = _use_color(sys.stdout)
    dim = lambda s: _c(s, "2", color)
    bold = lambda s: _c(s, "1", color)
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in (ACCEPT, REJECT, ESCALATE)}

    print(bold(f"veridict  {len(results)} claims vs. ground truth"))
    print(dim("─" * 52))
    wact = max((len(f"{r.get('actor','agent')}/{r['action']}") for r in results), default=0)
    for r in results:
        v = r["verdict"]
        tag = _c(f"{v:<8}", _ANSI[v], color)               # ACCEPT / REJECT / ESCALATE, padded
        who = f"{r.get('actor','agent')}/{r['action']}".ljust(wact)
        print(f"  {tag} {who}  {dim('“')}{r.get('claim','')}{dim('”')}")
        print(f"  {'':8} {' '*wact}  {dim('└─ ' + str(r['evidence']))}")

    parts = [f"{counts[ACCEPT]} accepted"]
    if counts[REJECT]:
        parts.append(_c(f"{counts[REJECT]} rejected", _ANSI[REJECT], color))
    if counts[ESCALATE]:
        parts.append(_c(f"{counts[ESCALATE]} escalated", _ANSI[ESCALATE], color))
    print(dim("─" * 52))
    print(f"  => {_c(overall, _ANSI[overall], color)}  ·  " + "  ·  ".join(parts))

    bad = [r for r in results if r["verdict"] != ACCEPT]
    summary = (f"all {len(results)} steps confirmed against ground truth" if overall == ACCEPT
               else f"{overall}: " + "; ".join(f"{r.get('actor','agent')} {r['action']} {r['evidence']}" for r in bad))
    if on_narrate:
        on_narrate(summary, overall, results)
    return summary
