"""Self-contained HTML report renderer.

No CDN, no external fonts, no network requests of any kind — the report opens
correctly on an air-gapped host. The payload is embedded as escaped JSON and the
DOM is built with ``textContent`` only; ``innerHTML`` is never used, so a trace
containing HTML cannot inject markup into the report.

Copyright (c) 2026 kk (kkdev9715). All Rights Reserved. Proprietary — see LICENSE.
"""

from __future__ import annotations

import json

_CSS = """
:root{--bg:#0b0f14;--panel:#121821;--panel2:#0f151d;--line:#1e2836;--ink:#e6edf5;
--dim:#8b9bb0;--accent:#4da3ff;--crit:#ff4d5e;--high:#ff8a3d;--med:#ffd23d;--low:#3ddc97;
--ok:#3ddc97}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:32px 24px 64px}
header{border-bottom:1px solid var(--line);padding-bottom:20px;margin-bottom:28px}
h1{margin:0 0 6px;font-size:26px;letter-spacing:-.02em}
h2{font-size:16px;text-transform:uppercase;letter-spacing:.08em;color:var(--dim);
margin:36px 0 14px;font-weight:600}
.sub{color:var(--dim);font-size:13px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px}
.kpi .v{font-size:26px;font-weight:700;letter-spacing:-.02em}
.kpi .l{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.07em;margin-top:4px}
.verdict{display:inline-block;padding:4px 12px;border-radius:999px;font-weight:700;
font-size:12px;text-transform:uppercase;letter-spacing:.08em}
.v-fail{background:rgba(255,77,94,.15);color:var(--crit);border:1px solid var(--crit)}
.v-warn{background:rgba(255,210,61,.13);color:var(--med);border:1px solid var(--med)}
.v-pass{background:rgba(61,220,151,.13);color:var(--ok);border:1px solid var(--ok)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;
padding:16px;margin-bottom:12px}
.card h3{margin:0 0 8px;font-size:15px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.tag{font-size:11px;padding:2px 8px;border-radius:6px;background:var(--panel2);
border:1px solid var(--line);color:var(--dim)}
.sev{font-size:11px;font-weight:700;padding:2px 8px;border-radius:6px;text-transform:uppercase}
.s-critical{background:rgba(255,77,94,.16);color:var(--crit)}
.s-high{background:rgba(255,138,61,.16);color:var(--high)}
.s-medium{background:rgba(255,210,61,.14);color:var(--med)}
.s-low{background:rgba(61,220,151,.14);color:var(--low)}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:var(--dim)}
.chain{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:8px}
.hop{background:var(--panel2);border:1px solid var(--line);border-radius:6px;
padding:4px 9px;font-size:12px}
.arrow{color:var(--accent);font-weight:700}
.bar{height:8px;background:var(--panel2);border-radius:4px;overflow:hidden;margin-top:8px}
.bar>i{display:block;height:100%;background:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--line)}
th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.warn{background:rgba(255,210,61,.08);border:1px solid rgba(255,210,61,.3);
border-radius:8px;padding:12px;margin-bottom:8px;font-size:13px}
.empty{color:var(--dim);font-style:italic;padding:8px 0}
footer{margin-top:48px;padding-top:20px;border-top:1px solid var(--line);
color:var(--dim);font-size:12px}
"""

_JS = """
(function(){
  var el = document.getElementById('payload');
  var root = document.getElementById('report');
  if(!el || !root){ return; }
  var data;
  try { data = JSON.parse(el.textContent); }
  catch(err){
    var n = document.createElement('div');
    n.className = 'warn';
    n.textContent = 'Report payload could not be parsed: ' + err.message;
    root.insertBefore(n, root.firstChild);
    return;
  }
  var s = data.summary || {};
  function set(id, val){
    var n = document.getElementById(id);
    if(n){ n.textContent = String(val); }
  }
  set('k-risk', (s.risk_score != null ? s.risk_score : 0));
  set('k-auth', (s.authority_exceeded != null ? s.authority_exceeded : 0));
  set('k-blast', (s.max_blast_radius != null ? s.max_blast_radius : 0));
  set('k-viol', (s.violations != null ? s.violations : 0));
  set('k-paths', (s.injection_paths != null ? s.injection_paths : 0));
  set('k-taint', (s.tainted_spans != null ? s.tainted_spans : 0));
  var v = document.getElementById('verdict');
  if(v){
    v.textContent = (s.verdict || 'unknown');
    v.className = 'verdict v-' + (s.verdict || 'warn');
  }
  var sev = document.getElementById('sev');
  if(sev){ sev.textContent = (s.severity || ''); sev.className = 'sev s-' + (s.severity || 'low'); }
})();
"""


def _esc(value: object) -> str:
    """Escape a value for safe embedding in HTML text."""
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _json_for_script(payload: dict) -> str:
    """Serialise the payload for a <script type=application/json> block.

    ``<`` is escaped so a value containing ``</script>`` cannot terminate the
    block early.
    """
    raw = json.dumps(payload, ensure_ascii=False)
    return raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def render_html(payload: dict) -> str:
    """Render an assessment payload as a self-contained HTML document."""
    s = payload.get("summary", {})
    verdict = s.get("verdict", "warn")
    severity = s.get("severity", "low")

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append('<meta name="viewport" content="width=device-width,initial-scale=1">')
    parts.append("<title>Sentinel Trace — agent execution report</title>")
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append('<div class="wrap" id="report">')

    parts.append("<header>")
    parts.append("<h1>Sentinel Trace</h1>")
    parts.append(
        f'<div class="sub">Trace <span class="mono">{_esc(payload.get("trace_id", ""))}</span>'
        f' &middot; generated {_esc(payload.get("generated_at", ""))}</div>'
    )
    parts.append(
        f'<div class="row" style="margin-top:12px">'
        f'<span class="verdict v-{_esc(verdict)}" id="verdict">{_esc(verdict)}</span>'
        f'<span class="sev s-{_esc(severity)}" id="sev">{_esc(severity)}</span>'
        f"</div>"
    )
    parts.append("</header>")

    # KPIs
    parts.append("<h2>Summary</h2><div class='kpis'>")
    for kid, label in (
        ("k-risk", "Risk score"),
        ("k-auth", "Authority exceeded"),
        ("k-blast", "Max blast radius"),
        ("k-viol", "Violations"),
        ("k-paths", "Injection paths"),
        ("k-taint", "Tainted spans"),
    ):
        parts.append(
            f'<div class="kpi"><div class="v" id="{kid}">0</div>'
            f'<div class="l">{_esc(label)}</div></div>'
        )
    parts.append("</div>")

    # Warnings
    warnings = payload.get("warnings", [])
    if warnings:
        parts.append("<h2>Warnings</h2>")
        for w in warnings:
            parts.append(f'<div class="warn">{_esc(w)}</div>')

    # Violations
    parts.append("<h2>Authority violations</h2>")
    violations = payload.get("violations", [])
    if not violations:
        parts.append('<div class="empty">No authority violations found.</div>')
    for v in violations:
        parts.append('<div class="card">')
        parts.append(
            f'<div class="row"><h3>{_esc(v.get("kind", ""))}</h3>'
            f'<span class="tag">span {_esc(v.get("span_id", ""))}</span>'
            f'<span class="tag">agent {_esc(v.get("agent_id", ""))}</span>'
            f'<span class="tag">weight {_esc(v.get("weight", 0))}</span></div>'
        )
        parts.append(f'<div>{_esc(v.get("detail", ""))}</div>')
        parts.append("</div>")

    # Injection paths
    parts.append("<h2>Injection paths</h2>")
    paths = payload.get("injection_paths", [])
    if not paths:
        parts.append('<div class="empty">No untrusted-content influence paths found.</div>')
    for p in paths:
        parts.append('<div class="card">')
        parts.append(
            f'<div class="row"><h3>{_esc(p.get("source_label", ""))} '
            f'&rarr; {_esc(p.get("sink_label", ""))}</h3>'
            f'<span class="tag">{_esc(p.get("length", 0))} hops</span></div>'
        )
        chain = []
        for i, hop in enumerate(p.get("hops", [])):
            if i:
                chain.append('<span class="arrow">&rarr;</span>')
            chain.append(f'<span class="hop">{_esc(hop)}</span>')
        parts.append(f'<div class="chain">{"".join(chain)}</div>')
        if p.get("via_values"):
            parts.append(
                f'<div class="mono" style="margin-top:8px">via '
                f'{_esc(", ".join(p["via_values"]))}</div>'
            )
        parts.append("</div>")

    # Blast radii
    parts.append("<h2>Blast radius by action</h2>")
    radii = payload.get("blast_radii", [])
    if not radii:
        parts.append('<div class="empty">No actions scored.</div>')
    else:
        parts.append("<table><thead><tr><th>Span</th><th>Tool</th><th>Severity</th>"
                     "<th>Score</th><th>Rationale</th></tr></thead><tbody>")
        for b in radii:
            parts.append(
                f'<tr><td class="mono">{_esc(b.get("span_id", ""))}</td>'
                f'<td>{_esc(b.get("tool") or "—")}</td>'
                f'<td><span class="sev s-{_esc(b.get("severity", "low"))}">'
                f'{_esc(b.get("severity", ""))}</span></td>'
                f'<td>{_esc(b.get("score", 0))}</td>'
                f'<td class="mono">{_esc(b.get("rationale", ""))}</td></tr>'
            )
        parts.append("</tbody></table>")

    parts.append(
        "<footer>Sentinel Trace &middot; Copyright (c) 2026 kk (kkdev9715) &middot; "
        "All Rights Reserved &middot; Proprietary. Self-contained report — no external "
        "requests.</footer>"
    )
    parts.append("</div>")

    parts.append(
        f'<script type="application/json" id="payload">{_json_for_script(payload)}</script>'
    )
    parts.append(f"<script>{_JS}</script>")
    parts.append("</body></html>")
    return "\n".join(parts)
