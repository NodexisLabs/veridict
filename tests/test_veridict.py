"""
Exercise every veridict checker against REAL targets — git (incl. push to a local bare remote),
files, commands, a live local HTTP server, a real open/closed port, and the abstain/error paths.
Dependency-free; run:  python tests/test_veridict.py
"""
from __future__ import annotations
import functools
import http.server
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from veridict import confirm_chain, Recorder, register, ACCEPT, REJECT, ESCALATE  # noqa: E402
from veridict.core import confirm_step                                            # noqa: E402

RESULTS = []


def expect(label, got, want):
    ok = got == want
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"   (got {got}, want {want})"))


def v(step, repo=None):
    return confirm_step(step, repo)["verdict"]


def git(repo, *a):
    return subprocess.run(["git", "-C", repo, *a], capture_output=True, text=True)


def make_repo():
    r = tempfile.mkdtemp(prefix="ac_repo_")
    git(r, "init", "-q")
    open(os.path.join(r, "app.py"), "w").write("print('hi')\n")
    git(r, "add", "app.py")
    git(r, "-c", "user.email=a@b.c", "-c", "user.name=ac", "commit", "-q", "-m", "feat: add app")
    git(r, "branch", "dev")
    git(r, "tag", "v1")
    return r


def test_git():
    print("\n[git]")
    r = make_repo()
    nogit = tempfile.mkdtemp(prefix="ac_nogit_")
    expect("commit message present -> ACCEPT", v({"action": "commit", "message": "feat: add app"}, r), ACCEPT)
    expect("commit message absent -> REJECT", v({"action": "commit", "message": "nope nope"}, r), REJECT)
    expect("commit in non-git -> ESCALATE", v({"action": "commit", "message": "x"}, nogit), ESCALATE)
    expect("branch exists -> ACCEPT", v({"action": "branch", "name": "dev"}, r), ACCEPT)
    expect("branch missing -> REJECT", v({"action": "branch", "name": "ghost"}, r), REJECT)
    expect("branch in non-git -> ESCALATE", v({"action": "branch", "name": "dev"}, nogit), ESCALATE)
    expect("tag exists -> ACCEPT", v({"action": "tag", "name": "v1"}, r), ACCEPT)
    expect("tag missing -> REJECT", v({"action": "tag", "name": "v9"}, r), REJECT)
    expect("clean tree -> ACCEPT", v({"action": "clean"}, r), ACCEPT)
    open(os.path.join(r, "app.py"), "a").write("# edit\n")
    expect("dirty tree -> REJECT", v({"action": "clean"}, r), REJECT)


def test_commit_strict():
    print("\n[commit: strict subject + sha resolution]")
    r = make_repo()  # subject is "feat: add app"
    # the red-team slip: a generic substring used to pass. It must not anymore.
    expect("substring of subject -> REJECT (exact by default)",
           v({"action": "commit", "message": "add app"}, r), REJECT)
    expect("substring with loose=True -> ACCEPT",
           v({"action": "commit", "message": "add app", "loose": True}, r), ACCEPT)
    expect("exact subject -> ACCEPT", v({"action": "commit", "message": "feat: add app"}, r), ACCEPT)
    full = git(r, "rev-parse", "HEAD").stdout.strip()
    expect("real full sha -> ACCEPT", v({"action": "commit", "sha": full}, r), ACCEPT)
    expect("real short sha -> ACCEPT", v({"action": "commit", "sha": full[:8]}, r), ACCEPT)
    expect("bogus sha -> REJECT", v({"action": "commit", "sha": "deadbeef"}, r), REJECT)
    expect("sha in non-git -> ESCALATE",
           v({"action": "commit", "sha": full}, tempfile.mkdtemp(prefix="ac_nogit2_")), ESCALATE)


def test_push():
    print("\n[push: against a local bare remote]")
    r = make_repo()
    bare = tempfile.mkdtemp(prefix="ac_bare_")
    subprocess.run(["git", "init", "--bare", "-q", bare], capture_output=True, text=True)
    git(r, "remote", "add", "origin", bare)
    br = git(r, "branch", "--show-current").stdout.strip() or "master"
    expect("no upstream yet -> ESCALATE", v({"action": "push"}, r), ESCALATE)
    git(r, "push", "-u", "-q", "origin", br)
    expect("after push -> ACCEPT", v({"action": "push"}, r), ACCEPT)
    open(os.path.join(r, "b.py"), "w").write("x\n")
    git(r, "add", "b.py")
    git(r, "-c", "user.email=a@b.c", "-c", "user.name=ac", "commit", "-q", "-m", "second")
    expect("new unpushed commit -> REJECT", v({"action": "push"}, r), REJECT)


def test_cmd_file():
    print("\n[cmd / file]")
    r = tempfile.mkdtemp(prefix="ac_f_")
    open(os.path.join(r, "out.txt"), "w").write("version: 2\n")
    expect("cmd exit 0 -> ACCEPT", v({"action": "tests", "cmd": 'python -c "exit(0)"'}), ACCEPT)
    expect("cmd exit 1 -> REJECT", v({"action": "tests", "cmd": 'python -c "exit(1)"'}), REJECT)
    expect("cmd missing -> ESCALATE", v({"action": "cmd"}), ESCALATE)
    expect("file exists -> ACCEPT", v({"action": "file", "path": "out.txt"}, r), ACCEPT)
    expect("file missing -> REJECT", v({"action": "file", "path": "ghost.txt"}, r), REJECT)
    expect("file contains -> ACCEPT", v({"action": "file", "path": "out.txt", "contains": "version: 2"}, r), ACCEPT)
    expect("file !contains -> REJECT", v({"action": "file", "path": "out.txt", "contains": "version: 9"}, r), REJECT)
    expect("file no path -> ESCALATE", v({"action": "file"}, r), ESCALATE)


def test_http_port():
    print("\n[http / port: live local server]")
    d = tempfile.mkdtemp(prefix="ac_www_")
    open(os.path.join(d, "index.html"), "w").write("ok")
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=d)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    httpd.RequestHandlerClass.log_message = lambda *a, **k: None
    pno = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{pno}"
    try:
        expect("http 200 -> ACCEPT", v({"action": "http", "url": base + "/"}), ACCEPT)
        expect("http expect 404, got 200 -> REJECT", v({"action": "http", "url": base + "/", "status": 404}), REJECT)
        expect("http 404 page, expect 404 -> ACCEPT", v({"action": "http", "url": base + "/nope", "status": 404}), ACCEPT)
        expect("http unreachable -> REJECT", v({"action": "http", "url": "http://127.0.0.1:9/", "timeout": 2}), REJECT)
        expect("http no url -> ESCALATE", v({"action": "http"}), ESCALATE)
        expect("port open -> ACCEPT", v({"action": "port", "port": pno}), ACCEPT)
        expect("port closed -> REJECT", v({"action": "port", "port": 9, "timeout": 2}), REJECT)
        expect("port no port -> ESCALATE", v({"action": "port"}), ESCALATE)
    finally:
        httpd.shutdown()


def test_robustness():
    print("\n[robustness / chain logic]")
    expect("unknown action -> ESCALATE", v({"action": "frobnicate"}), ESCALATE)
    register("boom", lambda step, repo: (_ for _ in ()).throw(RuntimeError("kaboom")))
    expect("throwing checker -> ESCALATE (no crash)", v({"action": "boom"}), ESCALATE)
    _, all_ok = confirm_chain([{"action": "cmd", "cmd": 'python -c "exit(0)"'},
                               {"action": "cmd", "cmd": 'python -c "exit(0)"'}], verbose=False)
    expect("all accept -> ACCEPT", all_ok, ACCEPT)
    _, mixed = confirm_chain([{"action": "cmd", "cmd": 'python -c "exit(0)"'},
                              {"action": "cmd", "cmd": 'python -c "exit(1)"'}], verbose=False)
    expect("any reject -> REJECT", mixed, REJECT)
    _, esc = confirm_chain([{"action": "cmd", "cmd": 'python -c "exit(0)"'},
                            {"action": "http"}], verbose=False)
    expect("accept+escalate -> ESCALATE", esc, ESCALATE)
    rec = Recorder(actor="t")
    rec.claim("cmd", "ran", cmd='python -c "exit(0)"')
    _, rv = rec.confirm(verbose=False)
    expect("Recorder confirm -> ACCEPT", rv, ACCEPT)


def main():
    for t in (test_git, test_commit_strict, test_push, test_cmd_file, test_http_port, test_robustness):
        try:
            t()
        except Exception as e:
            RESULTS.append(False)
            print(f"  FAIL  {t.__name__} crashed: {e}")
    p = sum(RESULTS)
    print(f"\n==== {p}/{len(RESULTS)} passed ====")
    return 0 if p == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
