"""veridict.recorder — accumulate claimed steps in code, then confirm them."""
from __future__ import annotations

from .core import confirm_chain


class Recorder:
    """Let an agent record what it claims to do, then verify the whole chain at the end.

        rec = Recorder(actor="git-driver", repo=".")
        rec.claim("commit", "committed the fix", message="fix login")
        rec.claim("tests",  "tests pass",        cmd="pytest -q")
        rec.claim("push",   "pushed to origin")
        results, verdict = rec.confirm()
    """
    def __init__(self, actor="agent", repo=None):
        self.actor, self.repo, self.steps = actor, repo, []

    def claim(self, action, claim, **params):
        self.steps.append({"actor": self.actor, "action": action, "claim": claim, **params})
        return self

    def confirm(self, **kw):
        return confirm_chain(self.steps, repo=self.repo, **kw)
