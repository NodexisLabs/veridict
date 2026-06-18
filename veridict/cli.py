"""
veridict CLI — verify an agent's claimed action chain. The EXIT CODE is the gate:
0 if every step confirmed (ACCEPT), 1 otherwise — so it drops straight into CI/CD.

    veridict verify chain.jsonl --repo .            # gate a run
    veridict verify chain.jsonl --json - --sarif report.sarif --cert cert.json
    veridict extract trace.json --openai            # tool-call trace -> claim chain
    veridict mcp                                    # run as an MCP server (stdio)
    veridict demo
"""
from __future__ import annotations
import argparse
import json
import os
import sys

from .core import confirm_chain, ACCEPT


def _load(path):
    txt = open(path, encoding="utf-8").read().strip()
    if path.endswith(".jsonl"):
        return [json.loads(ln) for ln in txt.splitlines() if ln.strip()]
    return json.loads(txt)


def _emit(text, dest):
    if dest == "-":
        print(text)
    else:
        open(dest, "w", encoding="utf-8").write(text)
        print(f"  wrote {dest}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="veridict",
                                 description="Verify an AI agent actually did what it claimed.")
    sub = ap.add_subparsers(dest="cmd")

    v = sub.add_parser("verify", help="verify a JSON(L) chain of claimed steps; exit code = gate")
    v.add_argument("chain", help=".jsonl (one step/line) or .json (list of steps)")
    v.add_argument("--repo", default=None, help="default repo path for git checkers")
    v.add_argument("--html", default=None, metavar="PATH", help="write a hoverable HTML report")
    v.add_argument("--json", dest="json_out", default=None, metavar="PATH", help="write JSON verdict ('-' for stdout)")
    v.add_argument("--sarif", default=None, metavar="PATH", help="write SARIF 2.1.0 (PR annotations)")
    v.add_argument("--cert", default=None, metavar="PATH", help="write a tamper-evident certificate (signs with $VERIDICT_KEY if set)")
    v.add_argument("--quiet", action="store_true", help="suppress the narrated terminal output")

    e = sub.add_parser("extract", help="turn an agent tool-call trace into a claim chain")
    e.add_argument("trace", help="JSON file: list of tool calls, or (with --openai) chat messages")
    e.add_argument("--openai", action="store_true", help="trace is OpenAI/compatible chat messages")
    e.add_argument("--repo", default=None)
    e.add_argument("--verify", action="store_true", help="verify the extracted chain immediately")

    d = sub.add_parser("demo", help="run the built-in demo against a throwaway git repo")
    d.add_argument("--html", default=None, metavar="PATH")
    sub.add_parser("mcp", help="run as an MCP server over stdio")
    sub.add_parser("hook", help="Claude Code PostToolUse hook: verify Write/Edit vs disk (reads stdin)")
    ins = sub.add_parser("install", help="wire veridict into a Claude Code project, then self-verify the install")
    ins.add_argument("--dir", default=".", help="project dir (default: cwd)")
    ins.add_argument("--no-hook", action="store_true", help="skip the PostToolUse hook")
    ins.add_argument("--no-mcp", action="store_true", help="skip MCP server registration")
    ins.add_argument("--no-skill", action="store_true", help="skip the /veridict skill")
    ins.add_argument("--matcher", default=None, help="tool matcher for the hook")
    cm = sub.add_parser("claude-md", help="map a CLAUDE.md's checkable rules to checks and run them")
    cm.add_argument("path", nargs="?", default=None, help="path to CLAUDE.md (default: auto-find)")
    cm.add_argument("--repo", default=None, help="repo to check against (default: cwd)")
    a = ap.parse_args(argv)

    if a.cmd == "demo":
        from .demo import demo
        return 0 if demo(html_path=a.html) == ACCEPT else 1

    if a.cmd == "mcp":
        from .mcp import serve
        serve()
        return 0

    if a.cmd == "hook":
        from .hook import main as hook_main
        return hook_main()

    if a.cmd == "claude-md":
        from .claude_md import from_file, find_claude_md
        from .core import ACCEPT as _A
        path = a.path or find_claude_md(a.repo or ".")
        if not path:
            print("no CLAUDE.md found (looked in ./, ./.claude/, ~/.claude/)")
            return 1
        chain, unmapped = from_file(path, repo=a.repo)
        print(f"CLAUDE.md: {path}")
        print(f"  {len(chain)} checkable rule(s) mapped; {len(unmapped)} not gateable\n")
        overall = _A
        if chain:
            _, overall = confirm_chain(chain, repo=a.repo)
        else:
            print("  (no auto-checkable rules found)")
        if unmapped:
            print("\n  not gateable (veridict won't fake a verdict on intent):")
            for rule, why in unmapped:
                print(f"    · {rule[:66]}  —  {why}")
        return 0 if overall == _A else 1

    if a.cmd == "install":
        from .install import install, DEFAULT_MATCHER
        from .core import narrate, ACCEPT as _A
        results, overall, actions = install(a.dir, hook=not a.no_hook, mcp=not a.no_mcp,
                                            skill=not a.no_skill, matcher=a.matcher or DEFAULT_MATCHER)
        for label, path, state in actions:
            print(f"  {label}: {state}  ({path})")
        print("  --- self-verify (veridict confirming its own install) ---")
        narrate(results, overall)
        return 0 if overall == _A else 1

    if a.cmd == "extract":
        from .extract import extract, extract_report, from_openai
        trace = _load(a.trace)
        if a.openai:
            chain = from_openai(trace, repo=a.repo)
            skipped = []
        else:
            chain, skipped = extract_report(trace)
            if a.repo:
                for s in chain:
                    s["repo"] = a.repo
        if a.verify:
            _, overall = confirm_chain(chain, repo=a.repo)
            if skipped:
                print(f"  (skipped {len(skipped)} unmappable tool(s): {', '.join(filter(None, skipped))})")
            return 0 if overall == ACCEPT else 1
        print(json.dumps(chain, indent=2))
        if skipped:
            sys.stderr.write(f"# skipped {len(skipped)} unmappable tool(s): {', '.join(filter(None, skipped))}\n")
        return 0

    if a.cmd == "verify":
        results, overall = confirm_chain(_load(a.chain), repo=a.repo, verbose=not a.quiet)
        if a.html:
            from .report import render_report
            render_report(results, overall, a.html); print(f"  wrote {a.html}")
        if a.json_out:
            from .output import to_json
            _emit(to_json(results, overall), a.json_out)
        if a.sarif:
            from .output import to_sarif
            _emit(to_sarif(results), a.sarif)
        if a.cert:
            from .cert import certify
            _emit(json.dumps(certify(results, overall, key=os.environ.get("VERIDICT_KEY")), indent=2), a.cert)
        return 0 if overall == ACCEPT else 1

    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
