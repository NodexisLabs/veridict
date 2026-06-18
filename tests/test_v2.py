"""
v2 feature tests: hardened checkers, extraction, JSON/SARIF output, certificates,
narration coverage, and the MCP dispatch. Dependency-free; run: python tests/test_v2.py
"""
from __future__ import annotations
import hashlib
import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from veridict import (confirm_step, ACCEPT, REJECT, ESCALATE, extract, extract_report,  # noqa: E402
                      from_openai, to_json, to_sarif, certify, verify_certificate, mention_coverage)

RESULTS = []


def expect(label, got, want):
    ok = got == want
    RESULTS.append(ok)
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + ("" if ok else f"   (got {got!r}, want {want!r})"))


def v(step):
    return confirm_step(step)["verdict"]


def test_hardened_file():
    print("\n[hardened file: sha256 + freshness]")
    d = tempfile.mkdtemp(prefix="v2f_")
    p = os.path.join(d, "out.txt")
    open(p, "w").write("hello v2")
    sha = hashlib.sha256(b"hello v2").hexdigest()
    expect("matching sha256 -> ACCEPT", v({"action": "file", "path": p, "sha256": sha}), ACCEPT)
    expect("wrong sha256 -> REJECT", v({"action": "file", "path": p, "sha256": "0" * 64}), REJECT)
    expect("fresh since -> ACCEPT", v({"action": "file", "path": p, "since": time.time() - 100}), ACCEPT)
    expect("stale since -> REJECT", v({"action": "file", "path": p, "since": time.time() + 100}), REJECT)
    expect("touch can't fake sha (empty file, content sha) -> REJECT",
           v({"action": "file", "path": p, "sha256": hashlib.sha256(b"").hexdigest()}), REJECT)


def test_hardened_cmd():
    print("\n[hardened cmd: timeout + shell=False args]")
    expect("args list (shell=False) exit 0 -> ACCEPT",
           v({"action": "cmd", "args": [sys.executable, "-c", "import sys;sys.exit(0)"]}), ACCEPT)
    expect("args list exit 1 -> REJECT",
           v({"action": "cmd", "args": [sys.executable, "-c", "import sys;sys.exit(1)"]}), REJECT)
    expect("timeout -> ESCALATE (unverifiable, not a pass)",
           v({"action": "cmd", "args": [sys.executable, "-c", "import time;time.sleep(5)"], "timeout": 1}), ESCALATE)


def test_hardened_http():
    print("\n[hardened http: method + json_path]")
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self):
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "data": {"count": 3}}).encode())
        def do_GET(self): self._send()
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0))); self._send()
    httpd = socketserver.TCPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}/"
    try:
        expect("json_path match -> ACCEPT",
               v({"action": "http", "url": base, "json_path": "data.count", "json_expect": 3}), ACCEPT)
        expect("json_path wrong value -> REJECT",
               v({"action": "http", "url": base, "json_path": "data.count", "json_expect": 9}), REJECT)
        expect("json_path missing key -> ESCALATE",
               v({"action": "http", "url": base, "json_path": "data.nope"}), ESCALATE)
        expect("POST method + status -> ACCEPT",
               v({"action": "http", "url": base, "method": "POST", "json": {"x": 1}, "status": 200}), ACCEPT)
    finally:
        httpd.shutdown()


def test_extract():
    print("\n[extract: tool-call trace -> chain]")
    calls = [{"name": "write_file", "arguments": {"path": "a.txt"}},
             {"name": "run_tests", "arguments": {"command": "pytest -q"}},
             {"name": "git_commit", "arguments": {"message": "fix login"}},
             {"name": "frobnicate", "arguments": {}}]
    chain, skipped = extract_report(calls)
    expect("3 of 4 mapped", len(chain), 3)
    expect("actions in order", [s["action"] for s in chain], ["file", "cmd", "commit"])
    expect("path extracted", chain[0]["path"], "a.txt")
    expect("cmd extracted", chain[1]["cmd"], "pytest -q")
    expect("unknown tool skipped+reported", skipped, ["frobnicate"])
    msgs = [{"role": "assistant",
             "tool_calls": [{"function": {"name": "write_text_file", "arguments": '{"path":"x.txt"}'}}]}]
    oai = from_openai(msgs)
    expect("from_openai parses JSON-string args", (oai[0]["action"], oai[0]["path"]), ("file", "x.txt"))


def _sample_results():
    return [confirm_step({"action": "cmd", "args": [sys.executable, "-c", "1"], "claim": "ran", "actor": "agent"}),
            confirm_step({"action": "file", "path": "/no/such/zzz", "claim": "wrote it", "actor": "agent"})]


def test_output():
    print("\n[output: json + sarif]")
    res = _sample_results()
    doc = json.loads(to_json(res, REJECT))
    expect("json overall", doc["overall"], REJECT)
    expect("json counts reject=1", doc["counts"]["REJECT"], 1)
    expect("json has steps", len(doc["steps"]), 2)
    sarif = json.loads(to_sarif(res))
    expect("sarif version", sarif["version"], "2.1.0")
    expect("sarif driver name", sarif["runs"][0]["tool"]["driver"]["name"], "veridict")
    levels = sorted(r["level"] for r in sarif["runs"][0]["results"])
    expect("sarif maps reject->error", "error" in levels, True)


def test_cert():
    print("\n[cert: tamper-evident]")
    res = _sample_results()
    c = certify(res, REJECT)
    ok, _ = verify_certificate(c)
    expect("intact cert verifies", ok, True)
    tampered = json.loads(json.dumps(c))
    tampered["steps"][1]["verdict"] = ACCEPT          # flip a REJECT to ACCEPT
    okt, _ = verify_certificate(tampered)
    expect("tampered cert fails", okt, False)
    cs = certify(res, REJECT, key="s3cret")
    expect("signed verifies with right key", verify_certificate(cs, key="s3cret")[0], True)
    expect("signed fails with wrong key", verify_certificate(cs, key="nope")[0], False)
    expect("signed fails with no key", verify_certificate(cs)[0], False)


def test_coverage():
    print("\n[coverage: advisory narration mentions]")
    res = [{"verdict": ACCEPT, "action": "file", "path": "out.txt", "claim": "", "evidence": ""}]
    cov = mention_coverage("I saved out.txt, and also wrote secret.txt to disk.", res)
    arts = [m["artifact"] for m in cov["unverified_mentions"]]
    expect("flags the uncovered artifact", "secret.txt" in arts, True)
    expect("does not flag the covered one", "out.txt" not in arts, True)
    clean = mention_coverage("I saved out.txt successfully.", res)
    expect("no flags when all covered", clean["unverified_mentions"], [])


def test_mcp():
    print("\n[mcp: jsonrpc dispatch]")
    from veridict.mcp import handle
    init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    expect("initialize -> serverInfo veridict", init["result"]["serverInfo"]["name"], "veridict")
    expect("initialized notification -> no response", handle({"method": "notifications/initialized"}), None)
    lst = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    expect("tools/list exposes verify", lst["result"]["tools"][0]["name"], "verify")
    call = handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                   "params": {"name": "verify",
                              "arguments": {"chain": [{"action": "file", "path": "definitely_missing_zzz.txt", "claim": "x"}]}}})
    payload = json.loads(call["result"]["content"][0]["text"])
    expect("tools/call returns a REJECT verdict", payload["overall"], REJECT)
    expect("tools/call flags isError on non-accept", call["result"]["isError"], True)


def test_mcp_sandbox():
    print("\n[mcp: sandbox blocks SSRF / path-escape / repo override]")
    from veridict.mcp import _verify_chain
    def vmcp(step):
        res, _ = _verify_chain([step], None)
        return res[0]["verdict"], res[0]["evidence"]
    vd, ev = vmcp({"action": "http", "url": "http://169.254.169.254/", "claim": "x"})
    expect("http over MCP -> ESCALATE (SSRF)", (vd, "SSRF" in ev), (ESCALATE, True))
    vd, ev = vmcp({"action": "file", "path": "/etc/passwd", "contains": "root", "claim": "x"})
    expect("absolute path -> ESCALATE (no arbitrary read)", (vd, "escapes" in ev), (ESCALATE, True))
    vd, ev = vmcp({"action": "file", "path": "../../secrets.txt", "claim": "x"})
    expect("traversal path -> ESCALATE", vd, ESCALATE)
    vd, ev = vmcp({"action": "port", "port": 22, "host": "10.0.0.1", "claim": "x"})
    expect("port scan over MCP -> ESCALATE (SSRF)", vd, ESCALATE)


def test_mcp_no_rce():
    print("\n[mcp: executable steps are NOT run by default (no RCE)]")
    from veridict.mcp import handle
    d = tempfile.mkdtemp(prefix="rce_t_")
    sentinel = os.path.join(d, "PWNED")
    handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "verify", "arguments": {"chain": [
                {"action": "cmd", "claim": "x", "args": [sys.executable, "-c", f"open(r'{sentinel}','w').write('x')"]}]}}})
    expect("attacker command did NOT execute", os.path.exists(sentinel), False)
    call = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                   "params": {"name": "verify", "arguments": {"chain": [
                       {"action": "cmd", "claim": "x", "args": ["echo", "hi"]}]}}})
    payload = json.loads(call["result"]["content"][0]["text"])
    expect("cmd step over MCP -> ESCALATE (disabled)", payload["steps"][0]["verdict"], ESCALATE)


def test_cert_require_signed():
    print("\n[cert: require_signed rejects unsigned; unsigned is integrity-only]")
    res = _sample_results()
    unsigned = certify(res, REJECT)
    expect("unsigned + require_signed -> rejected", verify_certificate(unsigned, require_signed=True)[0], False)
    expect("unsigned default -> ok but labeled integrity-only",
           "INTEGRITY ONLY" in verify_certificate(unsigned)[1], True)
    signed = certify(res, REJECT, key="k")
    expect("signed + require_signed + key -> ok", verify_certificate(signed, key="k", require_signed=True)[0], True)


def test_extract_skips_failed():
    print("\n[extract: a failed tool call is not turned into a success claim]")
    calls = [{"name": "write_file", "arguments": {"path": "a.txt"}, "result": {"status": "ERROR"}},
             {"name": "write_file", "arguments": {"path": "b.txt"}}]
    chain, skipped = extract_report(calls)
    expect("only the succeeded call becomes a claim", [s.get("path") for s in chain], ["b.txt"])
    expect("the failed call is reported skipped", any("reported failed" in s for s in skipped), True)


def test_hook():
    print("\n[hook: Claude Code PostToolUse verification]")
    from veridict.hook import evaluate
    d = tempfile.mkdtemp(prefix="hook_")
    real = os.path.join(d, "config.yaml")
    open(real, "w", encoding="utf-8").write("name: forge\nversion: 1.4.2\nenabled: true\n")
    ghost = os.path.join(d, "ghost.txt")

    def ev(tool, ti, cwd=d):
        return evaluate({"tool_name": tool, "tool_input": ti, "cwd": cwd})[0]

    expect("non-file tool -> 0 (ignored)", ev("Bash", {"command": "ls"}), 0)
    expect("no path -> 0", ev("Write", {"content": "x"}), 0)
    expect("real write (content landed) -> 0 ACCEPT",
           ev("Write", {"file_path": real, "content": "version: 1.4.2\n"}), 0)
    expect("ghost write (file never created) -> 2 REJECT",
           ev("Write", {"file_path": ghost, "content": "the answer is 42\n"}), 2)
    expect("content mismatch -> 2 REJECT",
           ev("Write", {"file_path": real, "content": "version: 9.9.9-FAKE\n"}), 2)
    expect("empty content + file exists -> 0 (existence-only)",
           ev("Write", {"file_path": real, "content": ""}), 0)
    expect("empty content + file missing -> 2",
           ev("Write", {"file_path": ghost, "content": ""}), 2)
    expect("MultiEdit edits[] new_string present -> 0",
           ev("MultiEdit", {"file_path": real, "edits": [{"new_string": "enabled: true"}]}), 0)
    expect("NotebookEdit new_source present -> 0",
           ev("NotebookEdit", {"notebook_path": real, "new_source": "name: forge"}), 0)
    # CRLF/LF robustness: file is LF, claim uses CRLF on the marker line -> still ACCEPT
    expect("CRLF claim vs LF file -> 0 (line-ending robust)",
           ev("Write", {"file_path": real, "content": "version: 1.4.2\r\n"}), 0)
    expect("malformed payload (not a dict) -> 0 (never breaks session)", evaluate("not-json")[0], 0)
    expect("non-dict tool_input -> 0 (no crash)",
           evaluate({"tool_name": "Write", "tool_input": [], "cwd": d})[0], 0)
    expect("partial MultiEdit (one edit missing) -> 2",
           ev("MultiEdit", {"file_path": real, "edits": [
               {"new_string": "enabled: true"}, {"new_string": "NEVER_WRITTEN_xyz"}]}), 2)


def test_text_checkers():
    print("\n[built-in checkers: no_match + commit_trailer]")
    d = tempfile.mkdtemp(prefix="vtc_")
    open(os.path.join(d, "a.py"), "w").write("x = 1\nTODO: fix this\n")
    expect("no_match finds pattern -> REJECT", v({"action": "no_match", "path": d, "repo": d, "pattern": r"\bTODO\b"}), REJECT)
    expect("no_match absent -> ACCEPT", v({"action": "no_match", "repo": d, "pattern": r"\bNOPE\b"}), ACCEPT)
    r = tempfile.mkdtemp(prefix="vct_")
    import subprocess
    subprocess.run(["git", "-C", r, "init", "-q"], capture_output=True)
    open(os.path.join(r, "f.txt"), "w").write("x")
    subprocess.run(["git", "-C", r, "add", "f.txt"], capture_output=True)
    subprocess.run(["git", "-C", r, "-c", "user.email=a@b.c", "-c", "user.name=ac",
                    "commit", "-q", "-m", "feat: x\n\nCo-Authored-By: Claude <x@y>"], capture_output=True)
    expect("commit_trailer match -> ACCEPT", v({"action": "commit_trailer", "repo": r, "pattern": r"Co-Authored-By:\s*Claude"}), ACCEPT)
    expect("commit_trailer missing -> REJECT", v({"action": "commit_trailer", "repo": r, "pattern": r"ZZZ-\d+"}), REJECT)


def test_claude_md():
    print("\n[claude_md: map checkable rules, abstain on intent]")
    from veridict.claude_md import map_rule, from_text
    def act(rule): return (map_rule(rule)[0] or {}).get("action")
    expect("'No hardcoded keys' -> no_match", act("No hardcoded keys in any file"), "no_match")
    expect("'No Anthropic API in code — ...' -> no_match (embedded)",
           act("No Anthropic API in code — Claude Code CLI IS the LLM."), "no_match")
    expect("'commits must credit Claude' -> commit_trailer",
           act("Commit messages must credit Claude with a Co-Authored-By trailer"), "commit_trailer")
    expect("'working tree must be clean' -> clean", act("The working tree must be clean before you stop"), "clean")
    # regressions for false maps the real CLAUDE.md surfaced:
    expect("'no hardcoded fallbacks' -> abstain (not a secret rule)",
           map_rule("No placeholder/sample/hardcoded fallbacks.")[0], None)
    expect("'do not print .env' -> abstain (verb print, not code print())",
           map_rule("Do not use Bash to print .env contents")[0], None)
    expect("'be concise' -> abstain (semantic)", map_rule("Drop signal-free words; be concise")[0], None)
    chain, unmapped = from_text("# Rules\n- No hardcoded keys\n- Write clean code\n```\nno hardcoded keys (in code block)\n```\n")
    expect("from_text maps the checkable one", len(chain), 1)
    expect("from_text abstains on the semantic one", len(unmapped), 1)


def test_install():
    print("\n[install: wire project + self-verify with veridict]")
    from veridict.install import install
    d = tempfile.mkdtemp(prefix="vinstall_")
    results, overall, actions = install(d)
    expect("install self-verifies ACCEPT", overall, ACCEPT)
    expect("settings.json has the hook", os.path.exists(os.path.join(d, ".claude", "settings.json")), True)
    expect(".mcp.json registers server", os.path.exists(os.path.join(d, ".mcp.json")), True)
    expect("/veridict skill written", os.path.exists(os.path.join(d, ".claude", "skills", "veridict", "SKILL.md")), True)
    expect("self-verify covers settings+mcp+skill+2 functional probes (5 rows)", len(results), 5)
    _, _, actions2 = install(d)
    expect("hook install is idempotent", dict((a[0], a[2]) for a in actions2)["settings.json"], "already present")


def main():
    for t in (test_hardened_file, test_hardened_cmd, test_hardened_http, test_extract, test_hook, test_install,
              test_output, test_cert, test_coverage, test_mcp,
              test_text_checkers, test_claude_md,
              test_mcp_no_rce, test_mcp_sandbox, test_cert_require_signed, test_extract_skips_failed):
        try:
            t()
        except Exception as e:
            RESULTS.append(False)
            print(f"  FAIL  {t.__name__} crashed: {type(e).__name__}: {e}")
    p = sum(RESULTS)
    print(f"\n==== {p}/{len(RESULTS)} passed ====")
    return 0 if p == len(RESULTS) else 1


if __name__ == "__main__":
    sys.exit(main())
