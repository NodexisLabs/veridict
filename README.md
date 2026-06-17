# veridict

[![CI](https://github.com/NodexisLabs/veridict/actions/workflows/ci.yml/badge.svg)](https://github.com/NodexisLabs/veridict/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/veridict)](https://pypi.org/project/veridict/) [![Python](https://img.shields.io/pypi/pyversions/veridict)](https://pypi.org/project/veridict/) [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Verify an AI agent actually did what it claimed.** A CI gate for autonomous agents: it checks an agent's *claimed* actions against **ground truth** — git history, files, real exit codes, HTTP endpoints, open ports — not the agent's self-report.

Deterministic. No LLM. Stdlib only. Each step gets **ACCEPT / REJECT / ESCALATE**, and the gap (ESCALATE) is honest abstention — it never bluffs.

## The problem

Autonomous coding/devops agents over-report. They'll happily tell you *"committed the fix, tests pass, pushed to prod"* when the commit never landed, the tests actually failed, and nothing was pushed. **Narration is the agent's word for it. Confirmation is checking reality.** veridict does the second.

```text
$ veridict demo
  [OK] agent branch: "on the right branch" -> ACCEPT  (branch 'master' exists)
  [OK] agent file: "wrote app.py" -> ACCEPT  (app.py exists)
  [OK] agent commit: "committed 'add app'" -> ACCEPT  (commit 'add app' found)
  [!!] agent commit: "committed 'add tests'" -> REJECT  (commit 'add tests' NOT in git log)
  [!!] agent file: "wrote tests.py" -> REJECT  (tests.py MISSING)
  [OK] agent tests: "tests pass" -> ACCEPT  (`python -c "exit(0)"` -> exit 0)
  [!!] agent tests: "tests pass" -> REJECT  (`python -c "exit(1)"` -> exit 1)
  [??] agent push: "pushed to origin" -> ESCALATE  (no upstream configured -> cannot verify push)
  => REJECT: 3 false claims caught, 1 unverifiable escalated
```

The agent claimed 8 successful steps. Three were lies. veridict caught them.

## Install

```bash
pip install veridict        # from PyPI
# or, from a clone:  pip install -e .
```

## Use it

**As a CI gate (exit code 0 = all confirmed, 1 = something didn't check out):**
```bash
veridict verify chain.jsonl --repo .   # your agent emits chain.jsonl; this gates the pipeline
```

**As a GitHub Action:**
```yaml
- uses: NodexisLabs/veridict@v0.1.0
  with:
    chain: chain.jsonl   # your agent emits this during the run
    repo: .
```

**In code, accumulate claims then confirm:**
```python
from veridict import Recorder
rec = Recorder(actor="git-driver", repo=".")
rec.claim("commit", "committed the fix", message="fix login")
rec.claim("tests",  "tests pass",        cmd="pytest -q")
rec.claim("push",   "pushed to origin")
results, verdict = rec.confirm()          # verdict in {ACCEPT, REJECT, ESCALATE}
```

**Or pass a chain directly:**
```python
from veridict import confirm_chain
confirm_chain([
    {"action": "http", "claim": "deploy is live", "url": "https://example.com/health", "status": 200},
    {"action": "file", "claim": "wrote config", "path": "config.yaml", "contains": "version: 2"},
], repo=".")
```

## Built-in checkers

| action | verifies against ground truth |
|---|---|
| `commit` | `sha` resolves to a real commit (`git rev-parse`), or `message` equals a commit subject exactly (case-insensitive); pass `loose: true` for substring match |
| `branch` / `tag` | a named branch / tag exists |
| `push` | nothing unpushed vs the upstream |
| `clean` | working tree has no uncommitted changes |
| `tests` / `cmd` | re-runs `cmd`, checks exit 0 (doesn't trust the reported result) |
| `file` | a path exists (optionally `contains` a string) |
| `http` | a URL returns the expected `status` |
| `port` | a `host:port` is open (service up) |
| `pr` | a GitHub PR is in `state` (via `gh`) |

Add your own — a checker is `(step, repo) -> (ok, evidence)`:
```python
from veridict import register
def deployed(step, repo):
    ok = my_cloud.revision() == step["sha"]
    return ok, f"live revision {'matches' if ok else 'does NOT match'} {step['sha']}"
register("deployed", deployed)
```

## Scope (and why the boundary is the point)

veridict verifies **concrete, checkable claims** — did the commit land, did tests pass, is the endpoint up. It deliberately does **not** judge *semantic* correctness ("did it fix the bug *well*") — that's a different, AI-complete problem. Staying inside the checkable boundary is what makes it cheap, deterministic, and trustworthy as a gate: it can say **"I'm not sure" (ESCALATE)** instead of guessing.

## How it relates to eval frameworks (promptfoo, DeepEval, Bedrock evals)

Not a competitor — a different question, at a different time.

Eval frameworks score whether your agent's *output* is good — relevance, faithfulness, tool-call correctness — usually **offline on a test set**, and usually by asking **another LLM to judge** (with you supplying the expected answer). veridict verifies whether the agent's *claimed actions actually happened* — at **runtime**, against **reality**, with **no model in the loop** and nothing for you to pre-supply.

| | eval frameworks | veridict |
|---|---|---|
| question | is the output *good*? | did it *actually happen*? |
| oracle | an LLM judge + your reference answer | the world — git, files, exit codes, HTTP |
| when | dev-time, on a test set | runtime, on the real run |
| output | a score | ACCEPT / REJECT / ESCALATE (a gate) |

Concretely: to make an eval catch *"I committed the fix"* when nothing was committed, you have to **tell it** the commit didn't land (as context) and trust a judge to notice the contradiction. veridict just runs `git log`. If you already know the truth well enough to supply it, you've done the hard part — veridict's job is to *go get* the truth.

Use both: evals to tune what your agent **says**, veridict to gate what it **does**.

## Honest limits

- It checks **what you give it a checker for.** An action with no checker (or an unknown `action`) → ESCALATE, not a silent pass. veridict never invents a verdict it can't ground.
- It checks **the steps you emit**, not free-form prose. If your agent *narrates* "I saved the file" but never emits a step for it, there's nothing to anchor a check to. The fix is to emit a step for every action you want gated — e.g. a `file` step for the path it claims to have written — and veridict will catch the missing file. (A live stress test confirmed this boundary: a model pressured to claim a save it never performed slips past unless you declare the expected artifact.)
- It verifies **occurrence, not quality.** A commit landing and tests exiting 0 doesn't mean the fix is *correct* — only that the claimed thing happened. (See Scope.)
- Checkers run **real side-effect-free reads** (`git log`, a file stat, an HTTP GET) — except `tests`/`cmd`, which **re-run your command.** Only point those at commands that are safe to re-run in CI.
- `commit` matching is **exact by default** (subject equality / real sha) so a generic claim can't match an unrelated commit; opt into `loose` substring only when you mean it.
- ESCALATE is a real outcome, not a soft accept. Decide in your pipeline whether ESCALATE blocks or warns — it exits non-zero by default.

The complete, categorized list — coverage gaps, technical caveats, and the security note that `tests`/`cmd` run arbitrary commands — is in **[LIMITATIONS.md](LIMITATIONS.md)**. Shipping it openly is the point: trust a verifier that tells you where it stops.

## License

MIT.
