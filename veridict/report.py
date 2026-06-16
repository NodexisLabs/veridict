"""
veridict.report — render a confirmed chain as a self-contained HTML report.

A vertical action timeline (top -> bottom = run order). Each step is a card showing the
verdict, the claim, and WHERE it was checked; hover/click reveals the full logged detail
(raw step, evidence, timestamp, how long the check took). Filter chips toggle
ACCEPT / REJECT / ESCALATE. Inline CSS + vanilla JS only — no dependencies, one file.

    from veridict import confirm_chain
    from veridict.report import render_report
    results, overall = confirm_chain(chain, repo=".")
    render_report(results, overall, "report.html")
"""
from __future__ import annotations

import html
import json

from .core import ACCEPT, REJECT, ESCALATE

# which step field names the "where it happened", per kind of claim
_LOC_KEYS = ("path", "cmd", "url", "message", "sha", "name", "number", "host", "port", "repo")
_META_KEYS = {"actor", "action", "claim", "verdict", "evidence", "checked_at", "duration_ms"}


def _location(step):
    if step.get("action") == "port" and step.get("host"):
        return f"{step['host']}:{step.get('port', '')}"
    for k in _LOC_KEYS:
        if step.get(k) not in (None, ""):
            return str(step[k])
    return ""


def _detail_rows(step):
    """Every step field that isn't already shown on the card face."""
    rows = []
    for k, v in step.items():
        if k in _META_KEYS:
            continue
        rows.append((k, v if isinstance(v, str) else json.dumps(v)))
    return rows


def render_html(results, overall, title="veridict report"):
    e = html.escape
    counts = {v: sum(1 for r in results if r["verdict"] == v) for v in (ACCEPT, REJECT, ESCALATE)}

    nodes = []
    for i, r in enumerate(results, 1):
        verdict = r["verdict"]
        loc = _location(r)
        detail = "".join(
            f'<div class="kv"><span class="k">{e(k)}</span><span class="val">{e(str(v))}</span></div>'
            for k, v in _detail_rows(r))
        nodes.append(f"""
      <li class="node v-{verdict}" data-verdict="{verdict}">
        <div class="dot"></div>
        <button class="card" aria-expanded="false" onclick="toggle(this)">
          <div class="head">
            <span class="badge">{verdict}</span>
            <span class="step">#{i}</span>
            <span class="actor">{e(str(r.get('actor', 'agent')))}</span>
            <span class="action">{e(str(r.get('action', '')))}</span>
            <span class="dur">{e(str(r.get('duration_ms', '')))} ms</span>
          </div>
          <div class="claim">&ldquo;{e(str(r.get('claim', '')))}&rdquo;</div>
          {f'<div class="loc"><span class="loclabel">checked</span> {e(loc)}</div>' if loc else ''}
          <div class="detail">
            <div class="evidence">{e(str(r.get('evidence', '')))}</div>
            {detail}
            <div class="ts">{e(str(r.get('checked_at', '')))}</div>
          </div>
        </button>
      </li>""")

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<style>
  :root {{
    --bg:#0e1116; --panel:#161b22; --line:#2b333d; --txt:#e6edf3; --muted:#8b949e;
    --accept:#3fb950; --reject:#f85149; --escalate:#d29922;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--txt);
    font:14px/1.5 ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif; }}
  header {{ padding:20px 24px; border-bottom:1px solid var(--line); }}
  h1 {{ font-size:16px; margin:0 0 4px; letter-spacing:.3px; }}
  h1 .gw {{ color:var(--muted); font-weight:400; }}
  .overall {{ font-size:13px; color:var(--muted); }}
  .overall b {{ color:var(--{'accept' if overall==ACCEPT else 'reject' if overall==REJECT else 'escalate'}); }}
  .filters {{ display:flex; gap:8px; padding:14px 24px; border-bottom:1px solid var(--line);
    position:sticky; top:0; background:var(--bg); z-index:2; flex-wrap:wrap; }}
  .chip {{ cursor:pointer; user-select:none; border:1px solid var(--line); background:var(--panel);
    color:var(--txt); border-radius:999px; padding:5px 13px; font-size:12.5px; }}
  .chip .n {{ color:var(--muted); margin-left:5px; }}
  .chip[aria-pressed="false"] {{ opacity:.38; }}
  .chip.f-ACCEPT {{ border-color:var(--accept); }}
  .chip.f-REJECT {{ border-color:var(--reject); }}
  .chip.f-ESCALATE {{ border-color:var(--escalate); }}
  ul.tree {{ list-style:none; margin:0; padding:18px 24px 60px; position:relative; max-width:860px; }}
  .node {{ position:relative; padding-left:26px; margin:0 0 10px; }}
  .node::before {{ content:""; position:absolute; left:7px; top:18px; bottom:-10px; width:2px;
    background:var(--line); }}
  .node:last-child::before {{ display:none; }}
  .dot {{ position:absolute; left:0; top:12px; width:16px; height:16px; border-radius:50%;
    border:3px solid var(--bg); }}
  .v-ACCEPT .dot {{ background:var(--accept); }}
  .v-REJECT .dot {{ background:var(--reject); }}
  .v-ESCALATE .dot {{ background:var(--escalate); }}
  .card {{ width:100%; text-align:left; cursor:pointer; background:var(--panel);
    border:1px solid var(--line); border-left:3px solid var(--line); border-radius:10px;
    padding:11px 14px; color:inherit; font:inherit; }}
  .v-ACCEPT .card {{ border-left-color:var(--accept); }}
  .v-REJECT .card {{ border-left-color:var(--reject); }}
  .v-ESCALATE .card {{ border-left-color:var(--escalate); }}
  .card:hover {{ border-color:#3d4651; }}
  .head {{ display:flex; align-items:center; gap:9px; flex-wrap:wrap; }}
  .badge {{ font-size:11px; font-weight:700; letter-spacing:.5px; padding:2px 7px; border-radius:5px; }}
  .v-ACCEPT .badge {{ background:rgba(63,185,80,.16); color:var(--accept); }}
  .v-REJECT .badge {{ background:rgba(248,81,73,.16); color:var(--reject); }}
  .v-ESCALATE .badge {{ background:rgba(210,153,34,.16); color:var(--escalate); }}
  .step {{ color:var(--muted); font-size:12px; }}
  .actor {{ color:var(--muted); }}
  .action {{ font-weight:600; }}
  .dur {{ margin-left:auto; color:var(--muted); font-size:11.5px; }}
  .claim {{ margin-top:5px; color:var(--txt); }}
  .loc {{ margin-top:4px; font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px;
    color:#a9b4c0; word-break:break-all; }}
  .loclabel {{ color:var(--muted); margin-right:5px; }}
  .detail {{ display:none; margin-top:10px; padding-top:10px; border-top:1px dashed var(--line); }}
  .card[aria-expanded="true"] .detail {{ display:block; }}
  .evidence {{ color:var(--txt); margin-bottom:7px; }}
  .kv {{ display:flex; gap:10px; font-size:12.5px; padding:1px 0; }}
  .kv .k {{ color:var(--muted); min-width:84px; font-family:ui-monospace,monospace; }}
  .kv .val {{ font-family:ui-monospace,monospace; word-break:break-all; }}
  .ts {{ margin-top:8px; color:var(--muted); font-size:11.5px; }}
  .hidden {{ display:none !important; }}
</style></head>
<body>
  <header>
    <h1>veridict <span class="gw">— claimed actions vs. ground truth</span></h1>
    <div class="overall">overall: <b>{overall}</b> &middot; {len(results)} steps checked against reality</div>
  </header>
  <div class="filters">
    <span class="chip f-ACCEPT"   aria-pressed="true" onclick="flt(this,'ACCEPT')">ACCEPT<span class="n">{counts[ACCEPT]}</span></span>
    <span class="chip f-REJECT"   aria-pressed="true" onclick="flt(this,'REJECT')">REJECT<span class="n">{counts[REJECT]}</span></span>
    <span class="chip f-ESCALATE" aria-pressed="true" onclick="flt(this,'ESCALATE')">ESCALATE<span class="n">{counts[ESCALATE]}</span></span>
  </div>
  <ul class="tree">{''.join(nodes)}
  </ul>
<script>
  var on = {{ACCEPT:true, REJECT:true, ESCALATE:true}};
  function toggle(btn) {{ btn.setAttribute('aria-expanded', btn.getAttribute('aria-expanded')!=='true'); }}
  function flt(chip, v) {{
    on[v] = !on[v];
    chip.setAttribute('aria-pressed', on[v]);
    document.querySelectorAll('.node').forEach(function(n) {{
      n.classList.toggle('hidden', !on[n.dataset.verdict]);
    }});
  }}
</script>
</body></html>"""


def render_report(results, overall, path, title="veridict report"):
    """Write the HTML report to `path`; return the path."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(results, overall, title))
    return path
