"""
veridict CLI — verify an agent's claimed action chain. The EXIT CODE is the gate:
0 if every step confirmed (ACCEPT), 1 otherwise — so it drops straight into CI/CD.

    veridict verify chain.jsonl --repo .
    veridict demo
"""
from __future__ import annotations
import argparse
import json
import sys

from .core import confirm_chain, ACCEPT


def _load(path):
    txt = open(path, encoding="utf-8").read().strip()
    if path.endswith(".jsonl"):
        return [json.loads(ln) for ln in txt.splitlines() if ln.strip()]
    return json.loads(txt)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="veridict",
                                 description="Verify an AI agent actually did what it claimed.")
    sub = ap.add_subparsers(dest="cmd")
    v = sub.add_parser("verify", help="verify a JSON(L) chain of claimed steps; exit code = gate")
    v.add_argument("chain", help=".jsonl (one step/line) or .json (list of steps)")
    v.add_argument("--repo", default=None, help="default repo path for git checkers")
    v.add_argument("--html", default=None, metavar="PATH", help="also write a hoverable HTML report")
    d = sub.add_parser("demo", help="run the built-in demo against a throwaway git repo")
    d.add_argument("--html", default=None, metavar="PATH", help="also write the demo's HTML report")
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        from .demo import demo
        return 0 if demo(html_path=a.html) == ACCEPT else 1
    if a.cmd == "verify":
        results, overall = confirm_chain(_load(a.chain), repo=a.repo)
        if a.html:
            from .report import render_report
            render_report(results, overall, a.html)
            print(f"  report -> {a.html}")
        return 0 if overall == ACCEPT else 1
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
