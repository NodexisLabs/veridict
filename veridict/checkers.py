"""
veridict.checkers — ground-truth checkers.

Each checker has the signature  (step: dict, repo) -> (ok, evidence)
where ok is True (claim holds), False (claim is false), or None (can't verify -> ESCALATE),
and evidence is a short human string. Checkers inspect the WORLD (git, files, exit codes, the
network) — never the agent's self-report. Stdlib only, deterministic, no LLM.

Add your own:  veridict.register("deployed", my_checker)
"""
from __future__ import annotations
import json as _json
import os
import socket
import subprocess
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError


def _run(c, cwd=None):
    return subprocess.run(c, cwd=cwd, capture_output=True, text=True, shell=isinstance(c, str))


def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo or "."), *a], capture_output=True, text=True)


def commit(step, repo):
    # sha: resolve it as a real commit object, exactly — not a substring of `git log`.
    if step.get("sha"):
        s = step["sha"]
        r = _git(repo, "rev-parse", "--verify", "--quiet", f"{s}^{{commit}}")
        if r.returncode != 0 and not r.stdout.strip():
            # distinguish "not a repo" from "no such commit"
            if _git(repo, "rev-parse", "--git-dir").returncode != 0:
                return None, "not a git repo"
            return (False, f"sha {s[:12]} is not a commit in this repo")
        return (True, f"sha {s[:12]} resolves to commit {r.stdout.strip()[:12]}")
    # message: compare against full commit SUBJECTS, exact (case-insensitive, trimmed).
    # Loose substring matching is opt-in via step['loose']=True, since a generic claim
    # ("fix") would otherwise match any commit that merely contains it.
    if step.get("message"):
        r = _git(repo, "log", "--format=%s", "-n", str(step.get("depth", 50)))
        if r.returncode != 0:
            return None, "not a git repo"
        m = step["message"].strip()
        subjects = [ln.strip() for ln in r.stdout.splitlines()]
        if step.get("loose"):
            found = any(m.lower() in s.lower() for s in subjects)
            how = "loose-substring"
        else:
            found = any(m.lower() == s.lower() for s in subjects)
            how = "exact-subject"
        return (found, f"commit '{m}' {'found' if found else 'NOT in git log'} ({how})")
    r = _git(repo, "log", "--oneline", "-n", "1")
    if r.returncode != 0:
        return None, "not a git repo"
    return (bool(r.stdout.strip()), "repo has commits")


def branch(step, repo):
    n = step.get("name") or step.get("claim")
    r = _git(repo, "branch", "--list", n)
    if r.returncode != 0:
        return None, "not a git repo -> cannot verify branch"
    return (bool(r.stdout.strip()), f"branch '{n}' {'exists' if r.stdout.strip() else 'does NOT exist'}")


def push(step, repo):
    r = _git(repo, "rev-list", "--count", "@{u}..HEAD")
    if r.returncode != 0:
        return None, "no upstream configured -> cannot verify push"
    n = r.stdout.strip()
    return (n == "0", "up to date with remote" if n == "0" else f"{n} commit(s) NOT pushed")


def tag(step, repo):
    n = step.get("name") or step.get("claim")
    r = _git(repo, "tag", "--list", n)
    if r.returncode != 0:
        return None, "not a git repo -> cannot verify tag"
    return (bool(r.stdout.strip()), f"tag '{n}' {'exists' if r.stdout.strip() else 'does NOT exist'}")


def clean_tree(step, repo):
    r = _git(repo, "status", "--porcelain")
    if r.returncode != 0:
        return None, "not a git repo"
    dirty = r.stdout.strip()
    return (not dirty, "working tree clean" if not dirty else "uncommitted changes present")


def cmd(step, repo):
    # `args` (list) runs WITHOUT a shell (shell=False) — the hardened form, no shell injection.
    # `cmd` (string) runs through the shell for convenience. `timeout` (default 120s) keeps a
    # hung command from wedging the gate: a timeout is unverifiable -> ESCALATE, not a pass.
    c = step.get("args") or step.get("cmd")
    if not c:
        return None, "no cmd/args given to verify"
    cwd = str(repo) if repo else None
    timeout = step.get("timeout", 120)
    label = c if isinstance(c, str) else " ".join(c)
    try:
        r = subprocess.run(c, cwd=cwd, capture_output=True, text=True,
                           shell=isinstance(c, str), timeout=timeout)
    except subprocess.TimeoutExpired:
        return None, f"`{label}` did not finish in {timeout}s -> cannot verify"
    return (r.returncode == 0, f"`{label}` -> exit {r.returncode}")


def file(step, repo):
    p = step.get("path")
    if not p:
        return None, "no path given"
    full = os.path.join(str(repo), p) if (repo and not os.path.isabs(p)) else p
    if not os.path.exists(full):
        return False, f"{p} MISSING"
    # freshness: `since` (epoch secs) requires the file was written at/after that time —
    # closes the "stale pre-existing file passes" gap (LIMITATIONS #8).
    if step.get("since") is not None and os.path.getmtime(full) < float(step["since"]) - 1.0:
        return False, f"{p} is STALE (mtime predates since={step['since']})"
    # exact content: `sha256` pins the bytes, so `touch <path>` can't satisfy the claim.
    if step.get("sha256"):
        import hashlib
        hsh = hashlib.sha256()
        with open(full, "rb") as fh:                 # streamed — no large-file memory blowup
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                hsh.update(chunk)
        h = hsh.hexdigest()
        ok = h == step["sha256"].lower()
        return (ok, f"{p} sha256 {'matches' if ok else 'MISMATCH ('+h[:12]+'…)'}")
    if step.get("contains") is not None:
        txt = open(full, encoding="utf-8", errors="ignore").read()
        ok = step["contains"] in txt
        return (ok, f"{p} {'contains' if ok else 'does NOT contain'} '{step['contains']}'")
    return True, f"{p} exists"


def _dig(obj, path):
    """Walk a dotted json path like 'data.items.0.name' (list indices allowed)."""
    cur = obj
    for part in str(path).split("."):
        if isinstance(cur, list) and part.lstrip("-").isdigit():
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


def http(step, repo):
    url = step.get("url")
    if not url:
        return None, "no url given"
    want = int(step.get("status", 200))
    method = (step.get("method") or "GET").upper()
    headers = dict(step.get("headers") or {})
    data = None
    if step.get("json") is not None:                 # send a JSON body
        data = _json.dumps(step["json"]).encode()
        headers.setdefault("Content-Type", "application/json")
    elif step.get("body") is not None:
        data = step["body"].encode() if isinstance(step["body"], str) else step["body"]
    req = Request(url, data=data, headers=headers, method=method)
    try:
        with urlopen(req, timeout=step.get("timeout", 5)) as resp:
            code = getattr(resp, "status", resp.getcode())
            payload = resp.read()
    except HTTPError as e:                            # 4xx/5xx still carry a status to compare
        code, payload = e.code, e.read()
    except URLError as e:
        return (False, f"{method} {url} unreachable: {e.reason}")
    except Exception as e:
        return (None, f"{method} {url} error: {e}")
    if code != want:
        return (False, f"{method} {url} -> {code} (want {want})")
    # optional: assert a value at a dotted path in the JSON response equals `json_expect`
    if step.get("json_path") is not None:
        try:
            got = _dig(_json.loads(payload.decode("utf-8", "ignore")), step["json_path"])
        except Exception as e:
            return (None, f"{method} {url} {code}, but json_path '{step['json_path']}' not found ({type(e).__name__})")
        exp = step.get("json_expect")
        ok = (got == exp) if "json_expect" in step else (got is not None)
        return (ok, f"{method} {url} -> {code}; {step['json_path']}={got!r}" + (f" (want {exp!r})" if "json_expect" in step else ""))
    return (True, f"{method} {url} -> {code} (want {want})")


def port(step, repo):
    pno = step.get("port")
    if not pno:
        return None, "no port given"
    host = step.get("host", "127.0.0.1")
    s = socket.socket()
    s.settimeout(step.get("timeout", 3))
    try:
        ok = s.connect_ex((host, int(pno))) == 0
        return (ok, f"{host}:{pno} {'open' if ok else 'closed'}")
    finally:
        s.close()


def pr(step, repo):
    n = step.get("number") or step.get("name")
    r = _run(["gh", "pr", "view", str(n), "--json", "state", "-q", ".state"], cwd=str(repo) if repo else None)
    if r.returncode != 0:
        return None, f"gh CLI unavailable or PR {n} not found"
    state = r.stdout.strip()
    want = step.get("state", "MERGED")
    return (state == want, f"PR {n} state {state} (want {want})")


CHECKERS = {
    "commit": commit, "branch": branch, "push": push, "tag": tag, "clean": clean_tree,
    "cmd": cmd, "tests": cmd, "file": file, "http": http, "port": port, "pr": pr,
}


def register(action, fn):
    """Plug in a custom checker: register('deployed', fn) where fn(step, repo) -> (ok, evidence)."""
    CHECKERS[action] = fn
