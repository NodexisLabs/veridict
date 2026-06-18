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
        r = _git(repo, "log", "--format=%ct\x1f%s", "-n", str(step.get("depth", 50)))
        if r.returncode != 0:
            return None, "not a git repo"
        m = step["message"].strip()
        since = step.get("since")          # epoch secs: require the matching commit be this fresh
        loose = step.get("loose")
        found = False
        for ln in r.stdout.splitlines():
            ts, _, subj = ln.partition("\x1f")
            if since:
                try:
                    if float(ts) < float(since) - 1.0:
                        continue           # too old to be this run's commit
                except ValueError:
                    pass
            subj = subj.strip()
            if (m.lower() in subj.lower()) if loose else (m.lower() == subj.lower()):
                found = True
                break
        how = ("loose-substring" if loose else "exact-subject") + (f", since={since}" if since else "")
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
    has_status = "status" in step                    # explicit status -> exact; else any non-error
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
    status_ok = (code == want) if has_status else (code < 400)
    target = f"want {want}" if has_status else "want any <400"
    if not status_ok:
        return (False, f"{method} {url} -> {code} ({target})")
    # optional: assert a value at a dotted path in the JSON response equals `json_expect`
    if step.get("json_path") is not None:
        try:
            got = _dig(_json.loads(payload.decode("utf-8", "ignore")), step["json_path"])
        except Exception as e:
            return (None, f"{method} {url} {code}, but json_path '{step['json_path']}' not found ({type(e).__name__})")
        exp = step.get("json_expect")
        ok = (got == exp) if "json_expect" in step else (got is not None)
        return (ok, f"{method} {url} -> {code}; {step['json_path']}={got!r}" + (f" (want {exp!r})" if "json_expect" in step else ""))
    return (True, f"{method} {url} -> {code} ({target})")


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


_SKIP_DIRS = {".git", "node_modules", "__pycache__", "venv", ".venv", "dist", "build",
              ".mypy_cache", ".pytest_cache"}
_CODE_EXT = (".py", ".js", ".ts", ".tsx", ".jsx", ".rs", ".go", ".java", ".rb", ".sh",
             ".c", ".cpp", ".h", ".cs", ".php", ".yaml", ".yml", ".toml", ".json", ".env", ".cfg", ".ini")


def no_match(step, repo):
    """A regex must NOT appear in any source file (e.g. 'no hardcoded keys'). ACCEPT if
    absent; REJECT with up-to-5 file:line hits. `ext` overrides the scanned extensions."""
    import re as _re
    if len(step["pattern"]) > 2000:                   # cheap ReDoS/abuse guard
        return None, "pattern too long to evaluate safely"
    pat = _re.compile(step["pattern"])
    exts = tuple(step.get("ext", _CODE_EXT))
    root = str(repo or ".")
    hits = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d.lower() not in _SKIP_DIRS and not d.lower().endswith(".egg-info")]
        for f in files:
            if not f.endswith(exts):
                continue
            fp = os.path.join(dirpath, f)
            try:
                if os.path.getsize(fp) > step.get("max_bytes", 2_000_000):
                    continue                              # skip huge files
                with open(fp, encoding="utf-8", errors="ignore") as fh:
                    for i, line in enumerate(fh, 1):
                        if pat.search(line):
                            hits.append(f"{os.path.relpath(fp, root)}:{i}")
                            break
            except OSError:
                continue
            if len(hits) >= 5:
                break
        if len(hits) >= 5:
            break
    ok = not hits
    return ok, (f"/{step['pattern']}/ absent from source" if ok
                else f"FOUND /{step['pattern']}/ at: {', '.join(hits)}")


def commit_trailer(step, repo):
    """The latest commit's full message must match `pattern` (e.g. a Co-Authored-By trailer,
    a ticket id, a conventional-commit prefix)."""
    import re as _re
    args = ["log", "-1", "--format=%B"] + ([step["sha"]] if step.get("sha") else [])
    r = _git(repo, *args)                              # `sha` pins a specific commit (vs racing HEAD)
    if r.returncode != 0:
        return None, "not a git repo / no such commit -> cannot verify commit message"
    found = bool(_re.search(step["pattern"], r.stdout))
    return found, (f"latest commit matches /{step['pattern']}/" if found
                   else f"latest commit is MISSING /{step['pattern']}/")


CHECKERS = {
    "commit": commit, "branch": branch, "push": push, "tag": tag, "clean": clean_tree,
    "cmd": cmd, "tests": cmd, "file": file, "http": http, "port": port, "pr": pr,
    "no_match": no_match, "commit_trailer": commit_trailer,
}


def register(action, fn):
    """Plug in a custom checker: register('deployed', fn) where fn(step, repo) -> (ok, evidence)."""
    CHECKERS[action] = fn
