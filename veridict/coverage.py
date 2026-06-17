"""
veridict.coverage — does the agent's prose claim things no verified step covers?

This is the principled successor to regex "honesty detection" (which a stress test proved
is a dead end — it fails in any language). Instead of guessing whether prose is a lie, it
does something deterministic and modest: it extracts concrete artifacts the *answer* claims
success about (file paths, URLs) and flags any that do NOT appear in a verified (ACCEPTed)
step. Those are *unverified mentions* — the agent talked about doing something the gate
never confirmed.

It is ADVISORY, not a verdict: a mention with no matching step might be a lie, or might just
be an action you didn't emit a claim for. The fix for a real gate is still to emit a step.
Use this to find coverage holes ("you said X, nothing checked X"), not to judge honesty.
"""
from __future__ import annotations

import os
import re

from .core import ACCEPT

_SUCCESS = re.compile(r"\b(saved|wrote|written|created|stored|committed|pushed|deployed|"
                      r"updated|generated|added|done|complete|completed|success\w*)\b", re.I)
_ARTIFACT = re.compile(r"https?://[^\s)\"'>]+|\b[\w./\\-]+\.[A-Za-z0-9]{1,8}\b")


def _verified_tokens(results):
    toks = set()
    for r in results:
        if r["verdict"] != ACCEPT:
            continue
        for k in ("path", "url", "name", "message", "sha", "host"):
            v = r.get(k)
            if isinstance(v, str) and v:
                toks.add(v.lower())
                toks.add(os.path.basename(v).lower())          # match bare filename mentions too
    return toks


def mention_coverage(answer, results):
    """Return {advisory, verified_tokens, unverified_mentions:[{artifact, sentence}]}.
    unverified = an artifact the prose asserts success about that no ACCEPTed step covers."""
    verified = _verified_tokens(results)
    flagged, seen = [], set()
    for sentence in re.split(r"(?<=[.!?\n])\s+", answer or ""):
        if not _SUCCESS.search(sentence):
            continue
        for m in _ARTIFACT.findall(sentence):
            tok = m.lower()
            base = os.path.basename(tok)
            if tok in verified or base in verified or tok in seen:
                continue
            seen.add(tok)
            flagged.append({"artifact": m, "sentence": sentence.strip()[:160]})
    return {"advisory": True, "verified_tokens": sorted(verified),
            "unverified_mentions": flagged,
            "note": ("prose mentions success for artifact(s) no verified step covers — "
                     "emit a step to actually gate them" if flagged
                     else "every success-mention maps to a verified step")}
