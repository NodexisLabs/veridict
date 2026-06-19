"""
veridict.output — machine-readable verdict formats.

  to_json(results, overall)  -> a structured object you can pipe / store.
  to_sarif(results)          -> SARIF 2.1.0, so REJECT/ESCALATE show up as inline
                                annotations on a GitHub PR (like a linter would).
Stdlib only.
"""
from __future__ import annotations

import json

from .core import ACCEPT, REJECT, ESCALATE

__version__ = "0.3.0"

# SARIF severity per verdict: a false claim is an error, an unverifiable one a warning.
_LEVEL = {REJECT: "error", ESCALATE: "warning", ACCEPT: "note"}


def to_json(results, overall, indent=2):
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in (ACCEPT, REJECT, ESCALATE)}
    doc = {"tool": "veridict", "overall": overall, "counts": counts,
           "steps": [{k: r.get(k) for k in
                      ("actor", "action", "claim", "verdict", "evidence", "checked_at", "duration_ms")}
                     for r in results]}
    return json.dumps(doc, indent=indent)


def _file_uri(step):
    """A SARIF artifactLocation only makes sense for a FILE path. A cmd/url is not an
    artifact, so we don't fake a location for it. Backslashes -> forward slashes (URI)."""
    p = step.get("path")
    if p and isinstance(p, str):
        return p.replace("\\", "/")
    return None


def to_sarif(results, indent=2):
    rules, seen = [], set()
    for r in results:
        a = r.get("action", "claim")
        if a not in seen:
            seen.add(a)
            rules.append({"id": a, "name": f"veridict.{a}",
                          "shortDescription": {"text": f"agent claim of type '{a}' vs ground truth"}})
    sarif_results = []
    for r in results:
        res = {"ruleId": r.get("action", "claim"), "level": _LEVEL.get(r["verdict"], "note"),
               "message": {"text": f'{r["verdict"]}: “{r.get("claim","")}” — {r.get("evidence","")}'}}
        uri = _file_uri(r)
        if uri:
            res["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        sarif_results.append(res)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "veridict", "version": __version__,
                                         "informationUri": "https://github.com/NodexisLabs/veridict",
                                         "rules": rules}},
                     "results": sarif_results}]}
    return json.dumps(doc, indent=indent)
