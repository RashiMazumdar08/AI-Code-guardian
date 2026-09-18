"""
Layman / Executive Plain-English HTML Reporter
===============================================
Generates a non-technical, layman-friendly security report designed for
executives, product managers, and non-technical stakeholders.

Converts complex technical scanner findings, taint analysis, and vulnerability
categories into clear, everyday English analogies and actionable steps.
"""
from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, List, Optional

from guardian.core.registry import register_reporter
from guardian.reporting import report_view_model as rvm

_SEV_COLOR = {
    "critical": "#f4374a", "high": "#ff8a3d",
    "medium": "#f5c451", "low": "#4ade80", "info": "#8e8e9a",
}

_PLAIN_ANALOGIES = {
    "sql injection": "SQL Injection — Like giving a visitor a form, but they write commands that trick the database into handing over all secret records.",
    "xss": "Cross-Site Scripting (XSS) — Like an attacker leaving a fake sign in your store that tricks your real customers into handing over their keys.",
    "csrf": "Cross-Site Request Forgery (CSRF) — Like an attacker tricking a logged-in user into unknowingly signing a bank check.",
    "hardcoded secret": "Hardcoded Password/Secret — Storing keys or passwords directly inside source code, like leaving your house key under the doormat.",
    "weak crypto": "Weak Cryptography — Using an outdated lock algorithm that can easily be cracked by modern computers.",
    "broken authentication": "Weak Login System — Flaws in login handling that could let an unauthorized user log in as someone else.",
    "path traversal": "Directory Traversal — An attacker manipulating file names to read private system files outside the intended folder.",
    "ssrf": "Server-Side Request Forgery — Tricking your internal server into making secret web requests on behalf of an attacker.",
    "insecure deserialization": "Dangerous Data Unpacking — Accepting untrusted packages over the internet and automatically executing instructions inside without checking first.",
    "sensitive logging": "Sensitive Data Logging — Writing passwords or private info into log files where unauthorized people could view them.",
    "command injection": "Command Injection — An attacker passing input that tricks the web server into running system terminal commands.",
    "unpinned base image": "Unpinned Software Package — Using external helper packages without locking their exact version number.",
}


def _e(val: Any) -> str:
    return html.escape(str(val if val is not None else ""))


def _sev_badge(sev: str) -> str:
    key = str(sev or "").lower()
    color = _SEV_COLOR.get(key, "#8e8e9a")
    return f"<span class='badge' style='color:#0a0a0f;background:{color}'>{_e(sev or 'Unknown').upper()}</span>"


def render_layman_report_html(report: Dict[str, Any], agentic: Optional[Dict[str, Any]] = None) -> str:
    """Renders a self-contained, executive plain-English HTML report."""
    scan = report.get("scan", {}) or {}
    findings = scan.get("findings", []) or report.get("findings", []) or []
    
    # Process counts
    by_sev = scan.get("by_severity", {}) or {}
    crit_count = by_sev.get("Critical", 0) or sum(1 for f in findings if str(f.get("severity", "")).lower() == "critical")
    high_count = by_sev.get("High", 0) or sum(1 for f in findings if str(f.get("severity", "")).lower() == "high")
    med_count = by_sev.get("Medium", 0) or sum(1 for f in findings if str(f.get("severity", "")).lower() == "medium")
    low_count = by_sev.get("Low", 0) or sum(1 for f in findings if str(f.get("severity", "")).lower() in ("low", "info"))
    
    total_findings = len(findings)
    
    # Verdict logic
    if crit_count > 0:
        verdict_cls = "verdict-bad"
        verdict_badge = "🔴 CRITICAL RISK — IMMEDIATE ACTION REQUIRED"
        verdict_msg = f"Found {crit_count} Critical flaw(s) that could allow full system takeover or data theft."
    elif high_count > 0:
        verdict_cls = "verdict-warn"
        verdict_badge = "⚠️ NEEDS ATTENTION — HIGH PRIORITY ISSUES DETECTED"
        verdict_msg = f"Found {high_count} High-risk issue(s) that require developer attention before shipping."
    elif med_count > 0 or total_findings > 0:
        verdict_cls = "verdict-warn"
        verdict_badge = "🟡 MODERATE RISK — MINOR IMPROVEMENTS NEEDED"
        verdict_msg = f"Found {total_findings} security finding(s), mostly moderate or low risk."
    else:
        verdict_cls = "verdict-good"
        verdict_badge = "✅ SECURE — NO HIGH/CRITICAL ISSUES FOUND"
        verdict_msg = "No critical or high risk security issues were identified in this scan."

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Render Findings Cards
    finding_cards_html = ""
    for idx, f in enumerate(findings[:30], 1):
        fid = f.get("id") or f.get("rule_id") or f"FIND-{idx:03d}"
        cat = str(f.get("category", "")).lower()
        sev = str(f.get("severity", "Medium"))
        file_path = f.get("file") or f.get("file_path") or "unknown"
        line = f.get("line") or f.get("line_number") or 0
        desc = f.get("message") or f.get("description") or f.get("snippet") or ""
        rec = f.get("recommendation") or "Review and fix affected function logic."
        
        analogy = _PLAIN_ANALOGIES.get(cat, rvm.plain_english_category(cat))
        card_sev_cls = f"sev-{sev.lower()}"
        
        finding_cards_html += f"""
        <div class="finding-card {card_sev_cls}">
          <div class="finding-head">
            <span class="fid">{_e(fid)} &middot; {_e(f.get('category', 'Security Concern'))}</span>
            {_sev_badge(sev)}
          </div>
          <p class="plain"><b>What is happening?</b> {_e(analogy)}</p>
          <p class="plain"><b>Where is it located?</b> <code>{_e(file_path)}:{line}</code></p>
          <p class="plain"><b>Details:</b> {_e(desc)}</p>
          <p class="plain"><b>How to fix it:</b> <span class="reco-text">{_e(rec)}</span></p>
        </div>
        """

    if not finding_cards_html:
        finding_cards_html = "<p class='empty'>No security findings were detected in this scan.</p>"

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>AI Code Guardian — Plain-English Executive Security Report</title>
<style>
:root {{
  --bg: #0a0a0f;
  --panel: #111118;
  --panel2: #15151d;
  --border: rgba(255,255,255,.08);
  --text: #f4f4f8;
  --sub: #8e8e9a;
  --orange: #ff5400;
  --orange-dim: rgba(255,84,0,.14);
}}
* {{ box-sizing: border-box; }}
body {{
  font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  margin: 0 auto;
  padding: 2.5rem;
  color: var(--text);
  background: var(--bg);
  max-width: 1050px;
  line-height: 1.5;
}}
h1 {{
  margin: 0 0 .4rem;
  color: var(--orange);
  font-size: 1.7rem;
  font-weight: 700;
  letter-spacing: -0.02em;
}}
h2 {{
  margin: 2.2rem 0 .8rem;
  font-size: 1.15rem;
  border-bottom: 1px solid var(--border);
  padding-bottom: .5rem;
  color: var(--text);
  font-weight: 700;
}}
p.sub {{
  color: var(--sub);
  margin: .3rem 0 1.4rem;
  line-height: 1.6;
  font-size: .88rem;
}}
code {{
  font-size: .82rem;
  background: rgba(255,255,255,.08);
  padding: 3px 7px;
  border-radius: 4px;
  color: #ff8a3d;
  font-family: 'Consolas', 'Courier New', monospace;
}}

.verdict {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 1.4rem 1.6rem;
  margin: 1.4rem 0 1.8rem;
}}
.verdict-bad {{ border-color: rgba(244,55,74,.5); }}
.verdict-warn {{ border-color: rgba(245,196,81,.5); }}
.verdict-good {{ border-color: rgba(74,222,128,.5); }}
.verdict-badge {{
  display: inline-block;
  font-size: .88rem;
  font-weight: 800;
  letter-spacing: .03em;
  padding: .4rem 1rem;
  border-radius: 8px;
  margin-bottom: .8rem;
}}
.verdict-bad .verdict-badge {{ background: rgba(244,55,74,.16); color: #ff8a95; }}
.verdict-warn .verdict-badge {{ background: rgba(245,196,81,.16); color: #f5c451; }}
.verdict-good .verdict-badge {{ background: rgba(74,222,128,.16); color: #4ade80; }}

.stats-grid {{
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin: 1rem 0 1.8rem;
}}
@media (max-width: 640px) {{
  .stats-grid {{ grid-template-columns: repeat(2, 1fr); }}
}}
.stat-card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.1rem;
  text-align: center;
}}
.stat-num {{
  font-size: 1.8rem;
  font-weight: 800;
  color: var(--orange);
  line-height: 1;
}}
.stat-lbl {{
  font-size: .72rem;
  color: var(--sub);
  text-transform: uppercase;
  margin-top: .5rem;
  letter-spacing: .05em;
  font-weight: 600;
}}

.qa-grid {{
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
  margin-bottom: 1.8rem;
}}
@media (max-width: 640px) {{
  .qa-grid {{ grid-template-columns: 1fr; }}
}}
.qa-card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.2rem 1.4rem;
}}
.qa-card .q {{
  font-size: .78rem;
  font-weight: 800;
  color: var(--orange);
  text-transform: uppercase;
  letter-spacing: .04em;
  margin-bottom: .45rem;
}}
.qa-card .a {{
  font-size: .9rem;
  line-height: 1.6;
  color: var(--text);
}}

.finding-list {{
  display: flex;
  flex-direction: column;
  gap: 1.1rem;
  margin-top: 1rem;
}}
.finding-card {{
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1.2rem 1.4rem;
}}
.finding-card.sev-critical {{ border-left: 4px solid #f4374a; }}
.finding-card.sev-high {{ border-left: 4px solid #ff8a3d; }}
.finding-card.sev-medium {{ border-left: 4px solid #f5c451; }}
.finding-card.sev-low {{ border-left: 4px solid #4ade80; }}
.finding-card.sev-info {{ border-left: 4px solid #8e8e9a; }}

.finding-head {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: .7rem;
}}
.fid {{
  font-weight: 700;
  font-size: .92rem;
  color: var(--text);
}}
.plain {{
  font-size: .88rem;
  line-height: 1.6;
  margin: .45rem 0;
  color: var(--text);
}}
.reco-text {{
  color: #7ee6a0;
  font-weight: 600;
}}
.badge {{
  font-size: .68rem;
  padding: 3px 10px;
  border-radius: 10px;
  font-weight: 700;
  white-space: nowrap;
  text-transform: uppercase;
  letter-spacing: .03em;
}}

.glossary-table {{
  width: 100%;
  border-collapse: collapse;
  margin-top: 1rem;
  font-size: .86rem;
  background: var(--panel);
  border-radius: 8px;
  overflow: hidden;
  border: 1px solid var(--border);
}}
.glossary-table th, .glossary-table td {{
  border-bottom: 1px solid var(--border);
  padding: .75rem 1rem;
  text-align: left;
  vertical-align: top;
}}
.glossary-table th {{
  background: var(--panel2);
  color: var(--sub);
  font-size: .72rem;
  text-transform: uppercase;
  letter-spacing: .04em;
}}

.footer {{
  margin-top: 3.5rem;
  padding-top: 1.4rem;
  border-top: 1px solid var(--border);
  color: #5c5c68;
  font-size: .78rem;
  text-align: center;
}}

@media print {{
  :root {{
    --bg: #ffffff;
    --panel: #ffffff;
    --panel2: #f4f4f6;
    --border: #dddddd;
    --text: #111111;
    --sub: #555555;
    --orange: #d94600;
  }}
  body {{ padding: 1rem; color: #111; background: #fff; }}
  .verdict, .stat-card, .qa-card, .finding-card, .glossary-table {{ box-shadow: none; border-color: #ccc; }}
  code {{ background: #f2f2f4; color: #d94600; }}
}}
</style>
</head>
<body>
<h1>🛡️ AI Code Guardian — Plain-English Executive Security Report</h1>
<p class="sub">Generated on {timestamp} &middot; Target: <code>{_e(scan.get('target', 'Repository'))}</code></p>

<!-- SECTION 1: VERDICT BANNER -->
<div class="verdict {verdict_cls}">
  <div class="verdict-badge">{verdict_badge}</div>
  <p class="plain" style="font-size:1.05rem; font-weight:600;">{verdict_msg}</p>
</div>

<!-- SECTION 2: STATS SUMMARY -->
<div class="stats-grid">
  <div class="stat-card">
    <div class="stat-num" style="color:#f4374a;">{crit_count}</div>
    <div class="stat-lbl">Critical Flaws</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#ff8a3d;">{high_count}</div>
    <div class="stat-lbl">High-Risk Flaws</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#f5c451;">{med_count}</div>
    <div class="stat-lbl">Medium Flaws</div>
  </div>
  <div class="stat-card">
    <div class="stat-num" style="color:#4ade80;">{low_count}</div>
    <div class="stat-lbl">Low/Info Items</div>
  </div>
</div>

<!-- SECTION 3: EXECUTIVE Q&A GRID -->
<h2>💡 Executive Summary Q&A</h2>
<div class="qa-grid">
  <div class="qa-card">
    <div class="q">Is the codebase safe to release?</div>
    <div class="a">
      { "No — Critical vulnerabilities exist that must be fixed immediately." if crit_count > 0 else "Needs Review — High priority vulnerabilities require developer fixes before shipping." if high_count > 0 else "Yes — No critical or high severity security vulnerabilities were found." }
    </div>
  </div>
  <div class="qa-card">
    <div class="q">What requires immediate attention?</div>
    <div class="a">
      { f"Focus on fixing the {crit_count + high_count} Critical/High findings listed below." if (crit_count + high_count) > 0 else "No immediate high-risk security flaws require urgent fixes." }
    </div>
  </div>
  <div class="qa-card">
    <div class="q">What happens if these are exploited?</div>
    <div class="a">
      { "Attackers could potentially run unauthorized commands, access database records, or compromise user sessions." if (crit_count + high_count) > 0 else "Minimal risk — standard code quality improvements recommended." }
    </div>
  </div>
  <div class="qa-card">
    <div class="q">What is the recommended next step?</div>
    <div class="a">
      Have your engineering team address the findings below starting with Critical/High items, then re-run the scan to verify.
    </div>
  </div>
</div>

<!-- SECTION 4: FINDINGS IN PLAIN ENGLISH -->
<h2>🔍 Security Findings (Explained in Plain English)</h2>
<p class="sub">Every technical finding from the scan translated into easy-to-understand explanations and fix guidance.</p>
<div class="finding-list">
  {finding_cards_html}
</div>

<!-- SECTION 5: NON-TECHNICAL GLOSSARY -->
<h2>📖 Plain-English Security Glossary</h2>
<table class="glossary-table">
  <thead>
    <tr>
      <th>Term</th>
      <th>What it Means in Plain English</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><b>Deserialization</b></td>
      <td>Unpacking stored data back into active program memory. Unsafe deserialization allows external users to execute arbitrary code.</td>
    </tr>
    <tr>
      <td><b>SQL Injection</b></td>
      <td>Tricking a database by injecting input that alters SQL query instructions to read or corrupt data.</td>
    </tr>
    <tr>
      <td><b>XSS (Cross-Site Scripting)</b></td>
      <td>Injecting malicious scripts into web pages rendered for other users in their browsers.</td>
    </tr>
    <tr>
      <td><b>Unpinned Dependency</b></td>
      <td>Using external helper software without specifying an exact version number, creating future supply-chain risks.</td>
    </tr>
  </tbody>
</table>

<div class="footer">
  AI Code Guardian &middot; Plain-English Executive Security Report &middot; Generated automatically from deterministic scan evidence.
</div>
</body>
</html>"""


class LaymanHtmlReporter:
    """Plugin reporter for Layman Executive HTML exports."""
    name = "layman"
    file_extension = ".layman.html"
    media_type = "text/html"

    def render(self, report: Dict[str, Any]) -> str:
        return render_layman_report_html(report)


@register_reporter
def _register_layman_reporter():
    return LaymanHtmlReporter()
