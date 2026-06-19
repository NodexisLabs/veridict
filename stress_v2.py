"""
Adversarial stress of the v2 features — hunt for the dangerous edges, not the happy path.
Each probe prints CONFIRMED (a real limitation/risk it exposed) or OK (held up). Run:
    python stress_v2.py
"""
from __future__ import annotations
import hashlib, json, os, sys, tempfile, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from veridict import (confirm_step, ACCEPT, REJECT, ESCALATE, extract_report,
                      to_sarif, certify, verify_certificate, mention_coverage)

FINDINGS = []


def finding(sev, feature, what):
    FINDINGS.append((sev, feature, what))
    print(f"  [{sev:8}] {feature}: {what}")


# 1. MCP — can a verify call execute arbitrary commands on the server?
def probe_mcp_rce():
    print("\n[MCP] is `verify` a remote-code-execution surface?")
    from veridict.mcp import handle
    d = tempfile.mkdtemp(prefix="rce_")
    sentinel = os.path.join(d, "PWNED")
    # a chain whose `cmd` step writes a sentinel file — if the server runs it, we're owned
    payload = {"action": "cmd", "claim": "tests pass",
               "args": [sys.executable, "-c", f"open(r'{sentinel}','w').write('x')"]}
    handle({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "verify", "arguments": {"chain": [payload]}}})
    if os.path.exists(sentinel):
        finding("CRITICAL", "mcp", "tools/call ran an attacker-supplied command (cmd/tests = RCE over MCP)")
    else:
        finding("OK", "mcp", "executable steps are not run by the MCP verify tool")


# 2. CERT — is an UNSIGNED certificate tamper-proof, or just a checksum an attacker can recompute?
def probe_cert_forge():
    print("\n[CERT] can an unsigned certificate be forged?")
    res = [confirm_step({"action": "file", "path": "/no/such/zz", "claim": "wrote it", "actor": "a"})]
    c = certify(res, REJECT)                      # unsigned
    # attacker flips the verdict AND recomputes the digest (no key needed)
    c["steps"][0]["verdict"] = ACCEPT
    c["overall"] = ACCEPT
    from veridict.cert import _canonical
    payload = {k: c[k] for k in ("tool", "version", "overall", "steps")}
    c["digest_sha256"] = hashlib.sha256(_canonical(payload)).hexdigest()
    # unsigned is inherently a recomputable checksum; the FIX is require_signed + honest labeling
    ok_default, why = verify_certificate(c)
    ok_strict, why2 = verify_certificate(c, require_signed=True)
    if ok_strict:
        finding("HIGH", "cert", "require_signed failed to reject a forged unsigned cert")
    elif "INTEGRITY ONLY" in why or "integrity" in why.lower():
        finding("OK", "cert", f"unsigned correctly labeled integrity-only + require_signed rejects it ({why2})")
    else:
        finding("HIGH", "cert", f"unsigned cert accepted without an honesty caveat ({why})")
    # signed should resist the same attack
    cs = certify(res, REJECT, key="k")
    cs["steps"][0]["verdict"] = ACCEPT
    cs["digest_sha256"] = hashlib.sha256(_canonical({k: cs[k] for k in ("tool", "version", "overall", "steps")})).hexdigest()
    finding("OK" if not verify_certificate(cs, key="k")[0] else "HIGH", "cert",
            "signed cert resists recomputed-digest forgery" if not verify_certificate(cs, key="k")[0]
            else "signed cert ALSO forgeable (HMAC not covering payload!)")


# 3. SARIF — are emitted locations valid? (cmd is not a file; Windows paths aren't URIs)
def probe_sarif_locations():
    print("\n[SARIF] are result locations valid artifact URIs?")
    res = [confirm_step({"action": "cmd", "args": [sys.executable, "-c", "1"], "claim": "ran", "actor": "a"}),
           confirm_step({"action": "file", "path": r"src\win\path.txt", "claim": "wrote", "actor": "a"})]
    doc = json.loads(to_sarif(res))
    locs = [r.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri")
            for r in doc["runs"][0]["results"]]
    cmd_loc, file_loc = locs[0], locs[1]
    if cmd_loc and not os.path.exists(str(cmd_loc)):
        finding("MEDIUM", "sarif", f"cmd step emitted a bogus artifactLocation uri ({cmd_loc!r}) — not a file")
    else:
        finding("OK", "sarif", "cmd step did not emit a fake file location")
    if file_loc and "\\" in file_loc:
        finding("LOW", "sarif", f"Windows path emitted with backslashes ({file_loc!r}) — not a valid SARIF URI")
    else:
        finding("OK", "sarif", "file location is a forward-slash URI")


# 4. EXTRACT — silent skips, mis-maps, and does it confuse 'attempted' with 'done'?
def probe_extract():
    print("\n[EXTRACT] coverage gaps and attempted-vs-done")
    calls = [{"name": "delete_file", "arguments": {"path": "prod.db"}},     # destructive, unmapped
             {"name": "get_run_status", "arguments": {"id": "x"}},          # ambiguous 'run'
             {"name": "write_file", "arguments": {"destination": "a.txt"}}] # nonstandard arg key
    chain, skipped = extract_report(calls)
    if "delete_file" in skipped:
        finding("DOC", "extract", "destructive 'delete_file' has no mapping — but it's REPORTED in skipped (not silent); documented mapping gap")
    else:
        finding("MEDIUM", "extract", "destructive 'delete_file' neither mapped nor reported")
    actions = [s["action"] for s in chain]
    if "cmd" in actions:
        finding("MEDIUM", "extract", "'get_run_status' mis-mapped to a cmd claim (substring 'run' over-matches)")
    else:
        finding("OK", "extract", "'get_run_status' not mis-mapped")
    # a tool call that ERRORED still becomes a 'success' claim (extraction ignores result/status)
    errored = [{"name": "write_file", "arguments": {"path": "a.txt"}, "result": {"status": "ERROR"}}]
    ch2, _ = extract_report(errored)
    if ch2 and ch2[0]["action"] == "file":
        finding("MEDIUM", "extract", "an ERRORED tool call still becomes a claim — extraction ignores result/status")


# 5. COVERAGE — regex false positives on prose abbreviations / versions
def probe_coverage_fp():
    print("\n[COVERAGE] does the artifact regex false-positive on prose?")
    res = [{"verdict": ACCEPT, "action": "file", "path": "out.txt", "claim": "", "evidence": ""}]
    cov = mention_coverage("Saved out.txt. Configure via e.g. python3.12 and see notes.md done.", res)
    arts = [m["artifact"] for m in cov["unverified_mentions"]]
    fps = [a for a in arts if a in ("e.g.", "python3.12") or a.lower().startswith("e.g")]
    if fps:
        finding("LOW", "coverage", f"flagged non-artifact prose tokens as 'unverified mentions': {fps}")
    else:
        finding("OK", "coverage", "no prose false-positives on this sample")


# 6. HARDENED CHECKERS — json_path dotted keys, sha256 memory
def probe_checkers():
    print("\n[CHECKERS] edge inputs")
    # json_path can't address a key that literally contains a dot
    import veridict.checkers as ck
    try:
        ck._dig({"a.b": 1}, "a.b")
        finding("OK", "http", "json_path addressed a dotted key")
    except Exception:
        finding("LOW", "http", "json_path can't address keys that literally contain '.' (splits on dot)")
    # sha256 reads the whole file into memory
    src = "open(full, \"rb\").read()"
    if src in open(os.path.join(os.path.dirname(__file__), "veridict", "checkers.py"), encoding="utf-8").read():
        finding("LOW", "file", "sha256 reads entire file into memory (no streaming) — large-file DoS risk")


def main():
    for p in (probe_mcp_rce, probe_cert_forge, probe_sarif_locations, probe_extract,
              probe_coverage_fp, probe_checkers):
        try:
            p()
        except Exception as e:
            finding("ERROR", p.__name__, f"{type(e).__name__}: {e}")
    print("\n================ FINDINGS ================")
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "DOC": 4, "OK": 5, "ERROR": 6}
    for sev, feat, what in sorted(FINDINGS, key=lambda x: order.get(x[0], 9)):
        if sev not in ("OK",):
            print(f"  {sev:8} [{feat}] {what}")
    bad = [f for f in FINDINGS if f[0] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "ERROR")]
    print(f"\n  unresolved: {len(bad)} | documented-by-design: {sum(1 for f in FINDINGS if f[0]=='DOC')} "
          f"| held up: {sum(1 for f in FINDINGS if f[0]=='OK')}")


if __name__ == "__main__":
    main()
