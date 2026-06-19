# Limitations

veridict is a verification tool, so it ships its own honest boundary — the full list of what
it can and can't do. Read it before you trust a verdict. (Reconciled against the source and an
independent audit, so it tracks the code as it actually runs.)

## What it can do

Deterministic, no LLM, zero dependencies. Built-in checkers:

| action | verifies against ground truth |
|---|---|
| `commit` | a `sha` resolves to a real commit, or `message` matches a commit subject (exact; `loose` substring; optional `since` freshness; searches the last `depth`=50) |
| `branch` / `tag` | the named ref exists |
| `push` | nothing unpushed vs the configured upstream |
| `clean` | working tree has no uncommitted (non-ignored) changes |
| `tests` / `cmd` | re-runs the command (string = shell; `args` list = shell-free), checks exit 0, honors `timeout` |
| `file` | path exists; optional `contains` substring, `sha256` exact content, `since` freshness |
| `http` | URL returns `status` (or any `<400` if unspecified); supports `method`/`headers`/`json`/`body` + `json_path` response assertions |
| `port` | a `host:port` is open |
| `pr` | a GitHub PR is in `state` (via `gh`) |
| `no_match` | a regex is **absent** from source files (e.g. "no hardcoded keys") |
| `commit_trailer` | the latest commit (or a given `sha`) message matches a regex (e.g. a Co-Authored-By trailer) |
| custom | anything you `register(action, fn)` where `fn(step, repo) -> (ok, evidence)` |

Verdict per step: ACCEPT / REJECT / **ESCALATE**. Exit-code gate; never crashes (broken or
unknown checker → ESCALATE); CLI + Python API + GitHub Action + Claude Code hook/skill + MCP
server; JSON/SARIF output; tamper-evident certificates.

## What it can't do

### Scope (by design)
1. **Can't judge semantic correctness.** It confirms the commit landed and tests exited 0 — not
   that the fix is *good* or the code is *right*. AI-complete, deliberately out.
2. **`contains` / `json_path` are literal/structural, not meaning.** Bytes present ≠ config valid.
3. **`http` checks status (and an optional `json_path` value), not that the whole response is
   correct; `port` checks open, not healthy.**

### Coverage gaps (the dangerous category — these can let a lie through)
4. **Only checks the steps you emit.** A lie that never becomes a structured step has nothing to
   anchor to. Mitigation: emit a step for every action you want gated.
5. **Omission isn't caught.** It verifies what it's given, not what it *should* have been given.
6. **Trusts the step's parameters.** A wrong path/message means it checks the wrong thing.
7. **A weak check is trivially satisfiable.** `touch tests.py` passes a bare `file` existence
   check; tighten with `contains` / `sha256`.
8. **`no_match` scans a bounded set.** Only known code/config extensions (`.py .js .json .env
   .yaml .toml` …, **not** `.md`/`.txt`/extensionless files like `Dockerfile`), skips vendored
   and build dirs, and skips files > 2 MB. A banned string in an unscanned file type or a huge
   file is **missed → false ACCEPT.** (The verdict is REJECT on *any* hit; the 5-hit cap only
   limits how many are listed, not the outcome.)
9. **No ordering or causality.** Steps are checked independently.

### Freshness & timing
10. **Existence by default; freshness is opt-in.** `file` and `commit` accept `since` (epoch);
    `file` accepts `sha256` for exact content. *Without* them, a stale pre-existing file or an old
    commit with the right subject passes. (The Claude Code hook sets `since` automatically — a
    freshness window, `VERIDICT_HOOK_FRESH_SECS`, default 300s — so a write claim about an old
    file is caught.)
11. **`branch` / `tag` verify existence, not creation.** No portable record of *when* a ref was
    made (reflog is local).
12. **`commit` searches only the last `depth` (50) commits.** A matching commit far behind HEAD
    can fall outside the window → REJECT though it exists. Raise `depth` or pass an exact `sha`.
13. **Time-of-check ≠ time-of-use (TOCTOU).** A snapshot at gate time; state can change after.
14. **`push` / `clean` are git's local view.** `clean` uses `git status --porcelain`, which does
    **not** count `.gitignore`d files — a tree dirty only in ignored paths reports clean. `push`
    can't confirm the remote accepted beyond what local git knows.

### Technical
15. **`tests` / `cmd` re-run the command** — side effects, flaky/slow tests, non-determinism; the
    re-run environment may differ from the agent's.
16. **`file` reads UTF-8 with errors ignored.** A `contains` marker inside a binary or non-UTF-8
    file can be mangled → false REJECT.
17. **`http` follows redirects** (urlopen default) and compares the **final** status — expecting a
    specific `301`/`302` needs care.
18. **`pr` needs `gh` + auth** → ESCALATE if absent.
19. **"Deterministic" describes the checking logic, not your commands.** A flaky test flaps the
    verdict — that's the test, but the effect is real.

### Security
20. **`tests` / `cmd` are arbitrary code execution by design.** The verifier runs whatever command
    the chain contains, with its privileges. **Only gate chains you trust.** (Over MCP they're
    default-denied — see below.)
21. **Checkers do real I/O** (file reads, an HTTP GET, a socket connect) — side-effect-light, not
    provably side-effect-free.

## Feature-specific surfaces

- **MCP server — sandboxed by default** (the caller may be untrusted). Default-DENY over MCP,
  returning ESCALATE: **exec** (`cmd`/`tests` → RCE; opt in `VERIDICT_MCP_ALLOW_EXEC=1`),
  **network** (`http`/`port` → SSRF; `VERIDICT_MCP_ALLOW_NET=1`), **regex-scan**
  (`no_match`/`commit_trailer` → ReDoS + read-amplification; rides `ALLOW_EXEC`), **path escape**
  (absolute/`..`/symlink, caught via realpath canonicalization), and **repo override** (a caller
  `repo` is ignored; confined to `VERIDICT_MCP_REPO` or cwd). The library and CLI run unrestricted
  — there you already trust the chain.
- **Certificates** — unsigned = an integrity checksum only (a recomputable sha256, **not**
  tamper-proof); HMAC-signed = tamper-evident (symmetric, not non-repudiation).
  `verify_certificate(..., require_signed=True)` rejects unsigned.
- **Extraction** — mapping-based, best-effort. Unknown tools (incl. destructive ones like
  `delete_file`) are **skipped and reported**, never silently passed; calls whose result reports
  failure are skipped (not turned into success claims); a write captures a **single-line** content
  marker (not full content). A tool call is a claim *to verify*, not proof.
- **CLAUDE.md mapper (`claude-md`)** — conservative, deterministic, no LLM. Maps only
  confidently-checkable rules (secrets/keys, a few unambiguous banned *code* tokens, commit-message
  patterns) and **abstains on everything else and lists it** — including aspirational rules like
  "keep the tree clean" (deliberately *not* mapped — it would false-reject mid-run) and all
  semantic intent. Never guesses a regex from prose; drops English homographs (e.g. the verb
  "print").
- **Claude Code hook** — a *detector* (PostToolUse runs after the tool; exit 0/2, never
  hard-blocks, never breaks the session on a bad payload). Sets a freshness window so a claimed
  write to a stale file is caught. Content check is a CRLF-robust **single longest line** (not full
  content; a post-write reformat can false-flag — use a `sha256` step for exact). MultiEdit
  verifies every edit.
- **Narration coverage** — advisory, not a gate (text honesty-detection is unreliable).
- **`json_path`** uses dotted segments and can't address a key containing a literal `.`.
  **SARIF** emits `artifactLocation` only for `file` steps.

## The boundary, in one line

veridict answers **"did the claimed action actually happen, against reality?"** — not "is the
output good?" (that's evals / LLM judges) and not "is it correct or safe?" (semantic, AI-complete).
Its guarantee is strong *exactly* where you give it a concrete, checkable claim and trust the chain
it's checking — and honest (ESCALATE) where it can't verify, instead of guessing.
