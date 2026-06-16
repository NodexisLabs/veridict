# Limitations

veridict is a verification tool, so it ships its own honest boundary. This is the full
list of what it can and can't do. Read it before you trust a verdict.

## What it can do

Verifies these against real ground truth — deterministic, no LLM, stdlib only:

| action | verifies against reality |
|---|---|
| `commit` | a `sha` resolves to a real commit (`git rev-parse`), or `message` exactly matches a commit subject (`loose: true` for substring) |
| `branch` / `tag` | the named ref exists |
| `push` | nothing is unpushed vs the configured upstream |
| `clean` | the working tree has no uncommitted changes |
| `tests` / `cmd` | **re-runs** the command and checks for exit 0 |
| `file` | a path exists (optionally `contains` a substring) |
| `http` | a URL returns an expected status code |
| `port` | a `host:port` is open |
| `pr` | a GitHub PR is in a `state` (via `gh`) |
| custom | anything you `register(action, fn)` where `fn(step, repo) -> (ok, evidence)` |

Properties: three-way verdict (ACCEPT / REJECT / **ESCALATE**), exit-code gate for CI,
never crashes the gate (a broken checker → ESCALATE), unknown action → ESCALATE (no silent
pass), CLI + GitHub Action + Python API, HTML report + color terminal (Windows VT-aware).

## What it can't do

### Scope (by design)
1. **Can't judge semantic correctness.** It confirms the commit landed and tests exited 0
   — not that the fix is *good*, the code is *right*, or the config is *sane*. That's
   AI-complete and deliberately out of scope.
2. **`contains` is substring, not meaning.** `"version: 2"` being present doesn't mean the
   config is valid — only that the bytes are there.
3. **`http` checks status, not body. `port` checks open, not healthy.** A 200 doesn't mean
   the response is correct.

### Coverage gaps (the dangerous category — these can let a lie through)
4. **Only checks the steps you emit.** A lie that lives purely in the agent's prose, never
   emitted as a structured step, has nothing to anchor to — it passes. *Mitigation: emit a
   step for every action you want gated* (e.g. a `file` step for the path it claims to have
   written). A live stress test confirmed this boundary.
5. **Omission isn't caught.** If the agent simply *doesn't* claim something it should have,
   there's no step and no check. veridict verifies what it's given, not what it *should*
   have been given.
6. **Trusts the step's parameters.** A wrong path in a `file` claim or a wrong message in a
   `commit` claim means it checks the (possibly wrong) thing you handed it.
7. **A weak check is trivially satisfiable.** `touch tests.py` passes a bare `file`
   existence check; an empty commit with the right subject passes `commit`. Tighten with
   `contains` / `sha` — a checkable claim is only as strong as what it pins down.
8. **No freshness in the built-in `file` checker.** A stale, pre-existing file passes
   `file` exists. (If you need "written *during this run*", supply `contains` with
   run-specific content, or write a custom checker that inspects mtime.)
9. **No ordering or causality.** Steps are checked independently; it does not verify they
   happened in sequence or that one caused another.

### Technical
10. **`tests` / `cmd` re-run the command.** Side effects, flaky tests, slow tests,
    non-determinism, and commands that aren't safe to re-run all bite here. The re-run
    environment may also differ from the agent's.
11. **Time-of-check ≠ time-of-use (TOCTOU).** It verifies state at gate time — a snapshot.
    A file present now can be deleted a second later. A verdict is not a guarantee of
    permanence.
12. **`push` is git's local view of the upstream.** It can't independently confirm the
    remote received and accepted the push beyond what git knows; no remote-side check.
13. **`pr` needs `gh` + auth.** Unavailable → ESCALATE, not a verdict.
14. **`http` is GET-only built-in.** No POST / auth / custom headers without a custom
    checker. In locked-down CI, `http` / `port` may simply fail or ESCALATE.
15. **"Deterministic" describes the checking logic, not your commands.** A flaky test makes
    the verdict flap — that's the test, but the effect is real.

### Security (read this)
16. **`tests` / `cmd` are arbitrary code execution by design.** The verifier runs whatever
    command the chain contains, with the verifier's privileges, via the shell.
    **Only gate chains you trust** — a malicious chain is a malicious script. veridict
    does not sandbox the commands it runs.
17. **Checkers do real I/O.** Mostly side-effect-light (file reads, an HTTP GET, a socket
    connect), but an HTTP GET can still trigger server-side effects; it is not provably
    side-effect-free.

## The boundary, in one line

veridict answers **"did the claimed action actually happen, against reality?"** — not
"is the output good?" (that's evals / LLM judges) and not "is it correct or safe?"
(semantic, AI-complete). Its guarantee is strong *exactly* where you give it a concrete,
checkable claim and trust the chain it's checking — and honest (ESCALATE) where it can't
verify, instead of guessing.
