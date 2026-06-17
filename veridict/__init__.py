"""
veridict — verify an AI agent actually did what it claimed.

A CI gate for autonomous agents: it checks an agent's *claimed* actions against ground truth
(git, files, exit codes, HTTP, ports) — not the agent's self-report. Deterministic, no LLM,
stdlib only. ACCEPT / REJECT / ESCALATE per step; the gap (ESCALATE) is honest abstention.
"""
from .core import confirm_chain, confirm_step, narrate, ACCEPT, REJECT, ESCALATE
from .checkers import CHECKERS, register
from .recorder import Recorder
from .extract import extract, extract_report, from_openai
from .output import to_json, to_sarif
from .cert import certify, verify_certificate
from .coverage import mention_coverage

__all__ = ["confirm_chain", "confirm_step", "narrate", "Recorder",
           "CHECKERS", "register", "ACCEPT", "REJECT", "ESCALATE",
           "extract", "extract_report", "from_openai",
           "to_json", "to_sarif", "certify", "verify_certificate", "mention_coverage"]
__version__ = "0.2.0"
