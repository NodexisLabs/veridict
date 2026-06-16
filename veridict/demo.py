"""veridict.demo — run against a throwaway real git repo; catch an agent's false claims."""
from __future__ import annotations
import os
import shutil
import subprocess
import tempfile

from .core import confirm_chain, REJECT, ESCALATE


def _git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


def demo(html_path=None):
    print("veridict demo — verifying an agent's claimed chain against real git\n")
    repo = tempfile.mkdtemp(prefix="veridict_")
    try:
        _git(repo, "init", "-q")
        open(os.path.join(repo, "app.py"), "w").write("print('hi')\n")
        _git(repo, "add", "app.py")
        _git(repo, "-c", "user.email=a@b.c", "-c", "user.name=ac", "commit", "-q", "-m", "add app")
        branch = _git(repo, "branch", "--show-current").stdout.strip() or "master"

        # an agent that OVER-REPORTS: some claims are true, some are lies
        chain = [
            {"actor": "agent", "action": "branch", "claim": "on the right branch", "name": branch},
            {"actor": "agent", "action": "file", "claim": "wrote app.py", "path": "app.py"},
            {"actor": "agent", "action": "commit", "claim": "committed 'add app'", "message": "add app"},
            {"actor": "agent", "action": "commit", "claim": "committed 'add tests'", "message": "add tests"},   # lie
            {"actor": "agent", "action": "file", "claim": "wrote tests.py", "path": "tests.py"},                # lie
            {"actor": "agent", "action": "tests", "claim": "tests pass", "cmd": 'python -c "exit(0)"'},
            {"actor": "agent", "action": "tests", "claim": "tests pass", "cmd": 'python -c "exit(1)"'},         # lie
            {"actor": "agent", "action": "push", "claim": "pushed to origin"},                                 # unverifiable
        ]
        results, overall = confirm_chain(chain, repo=repo)
        caught = sum(r["verdict"] == REJECT for r in results)
        esc = sum(r["verdict"] == ESCALATE for r in results)
        print(f"\ncaught {caught} false claim(s); {esc} unverifiable -> escalated. "
              f"Plain narration would have reported all {len(chain)} as done.")
        if html_path:
            from .report import render_report
            render_report(results, overall, html_path, title="veridict demo")
            print(f"report -> {html_path}")
        return overall
    finally:
        shutil.rmtree(repo, ignore_errors=True)


if __name__ == "__main__":
    demo()
