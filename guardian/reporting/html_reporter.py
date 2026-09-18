"""
Security Report — the deterministic HTML export.

v2.1.0 Phase 1 rework
----------------------
This is the platform's primary, always-available report: it works with
NO agentic run, is understandable to a non-expert in under a minute, and
never loses a technical detail a security engineer needs. Every value
rendered below comes straight from the real ScanPipeline report dict --

    THE DETERMINISTIC SCANNER IS THE SOURCE OF TECHNICAL TRUTH.

This report never blends in agentic (LangGraph) output. Where the
platform's deeper analysis exists, it is offered as a clearly separate,
clearly labeled call-to-action ("AI AGENTIC ANALYSIS AVAILABLE") -- never
silently blended into the numbers on this page. Risk shown here is
always labeled DETERMINISTIC SECURITY RISK.

This report answers "how secure is this repository based on the
available evidence?" -- never a source-control workflow/approval decision.
The Repository Security Status badge is computed by
guardian.reporting.report_view_model.compute_verdict(), the SAME function
the Agentic/Unified reports and the Reports page use, called here with an
empty patch map and no risk_level (this deterministic-only report has
neither) so the label a reader sees is never invented or duplicated logic.

Reuses guardian.reporting.report_view_model -- the same normalization /
plain-English presentation layer the Agentic & Unified reports use --
for severity grouping, path normalization, and the executive-summary
Q&A, rather than re-implementing that logic here (Critical Rule #1:
do not create duplicate systems).

Self-contained HTML -- no external assets, suitable for emailing or
archiving. Deterministic finding data (IDs, severity, CWE/OWASP, line
numbers, evidence, risk score) is passed straight through unchanged;
this file only restructures how it is presented.
"""
from __future__ import annotations

import html
from typing import Any, Dict, List, Optional

from guardian.core.registry import register_reporter
from guardian.reporting._shared import alignment_value, visible_findings
from guardian.reporting import report_view_model as rvm

_SEV_COLOR = {"Critical": "#f4374a", "High": "#ff8a3d",
              "Medium": "#f5c451", "Low": "#4ade80", "Info": "#8e8e9a"}

_SOURCE_BADGE = {
    "DETERMINISTIC": ("#1b5e20", "#e8f5e9", "Static"),
    "AI_VALIDATED": ("#0d47a1", "#e3f2fd", "AI-validated"),
    "AI_SUGGESTED": ("#4a148c", "#f3e5f5", "AI suggestion"),
    "INSUFFICIENT_EVIDENCE": ("#616161", "#eeeeee", "Unproven"),
}


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _badge(source: str) -> str:
    fg, bg, label = _SOURCE_BADGE.get(source, _SOURCE_BADGE["DETERMINISTIC"])
    return f"<span class='badge' style='color:{fg};background:{bg}'>{_e(label)}</span>"


def _sev_badge(sev: str) -> str:
    # Dark text on the bright severity color, matching
    # agentic_html_reporter.py's _sev_badge exactly -- white text on these
    # saturated pastel colors reads poorly on a dark page.
    color = _SEV_COLOR.get(sev, "#8e8e9a")
    return f"<span class='badge' style='color:#0a0a0f;background:{color}'>{_e(sev or 'Unknown')}</span>"


def _empty(message: str) -> str:
    return f"<p class='empty'>{_e(message)}</p>"


# Section 16-style row cap: never drop data from the underlying report,
# only cap how much is RENDERED, with an honest "+N more" note.
def _cap(items: List[Any], limit: int = 40) -> "tuple[List[Any], int]":
    if len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def _more_note(remaining: int, noun: str) -> str:
    if remaining <= 0:
        return ""
    return (f"<p class='more-note'>+ {remaining} more {_e(noun)} not shown above "
            f"(full detail is in the JSON/SARIF/CSV export).</p>")


def _why_it_matters(f: Dict[str, Any]) -> str:
    """Real, deterministic explanation only -- never an invented
    consequence. exploit_scenario / exploitability_score / tainted are all
    populated by guardian.engines.security's taint-analysis pass itself
    (not the agentic layer), so they are safe deterministic truth."""
    scenario = f.get("exploit_scenario")
    if scenario:
        return str(scenario)
    reason = f.get("reason")
    if reason:
        return str(reason)
    score = f.get("exploitability_score")
    if f.get("tainted") or f.get("is_exploitable"):
        if isinstance(score, (int, float)) and score > 0:
            return f"Confirmed via data-flow tracing as exploitable (exploitability score {score:.2f})."
        return "Confirmed via data-flow tracing as exploitable."
    return rvm.IMPACT_UNKNOWN


def _recommended_action(f: Dict[str, Any]) -> str:
    rec = f.get("recommendation")
    if rec:
        return str(rec)
    return "No specific remediation guidance was provided by the scanner for this finding."


@register_reporter
class HtmlReporter:
    name = "html"
    file_extension = ".html"

    def render(self, report: dict) -> str:
        repo = report.get("repository", {}) or {}
        scan = report.get("scan", {}) or {}
        risk = report.get("unified_risk") or report.get("risk", {}) or {}
        domain = report.get("business_domain") or {}
        ai = report.get("ai", {}) or {}
        repo_root = repo.get("root") or report.get("target") or ""
        # Never print the raw local/temp repository path (e.g. a
        # guardian_github_repos clone dir or a Windows temp path) -- show
        # the repo-relative form, falling back to the scan target name.
        display_root = rvm.normalize_path(repo_root) or str(report.get("target") or "")

        findings = visible_findings(report)
        by_sev = {str(k).lower(): v for k, v in (scan.get("by_severity", {}) or {}).items()}
        critical = by_sev.get("critical", 0) or 0
        high = by_sev.get("high", 0) or 0

        bi = report.get("business_intent") or {}
        bi_findings = bi.get("findings", []) if bi.get("status") == "SUCCESS" else []
        unresolved_violations = len([
            v for v in bi_findings
            if str(v.get("status", "")).upper() in ("VIOLATION", "POTENTIAL_VIOLATION")
        ])

        # No agentic data exists on this deterministic-only report -- pass
        # an empty agentic dict/patch map so executive_summary() honestly
        # reports "no attack path / no automated patch" rather than
        # fabricating agentic content.
        summary = rvm.executive_summary(report, {}, critical, high, {}, unresolved_violations)
        # Repository Security Status: reuse the SAME compute_verdict() the
        # Agentic/Unified reports and the Reports page use (Critical Rule
        # #1: do not create duplicate status-computation systems), called
        # with an empty patch map and no risk_level since this
        # deterministic-only report has neither.
        total_findings = scan.get("total_findings", len(findings))
        verdict = rvm.compute_verdict(True, total_findings, critical, high, {}, None)

        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI Code Guardian — Security Report</title><style>{_CSS}</style></head><body>
<h1>AI Code Guardian — Security Report</h1>
<div class="sub">
 {_e(display_root)} &middot; {_e(repo.get('primary_language'))}
 &middot; {_e(', '.join(repo.get('frameworks', []) or []) or 'no framework detected')}
 &middot; domain: {_e(domain.get('domain', 'n/a'))} ({domain.get('confidence', 0):.0%} confidence)<br>
 {scan.get('total_findings', 0)} finding(s) across {scan.get('files_scanned', 0)} file(s)
 in {report.get('duration_seconds', '?')}s
</div>
{self._risk_banner(verdict, critical, high)}
{self._overview_section(summary, findings, critical, high)}
{self._risk_summary(risk, report, verdict)}
{self._ai_status(ai)}
{self._findings_by_severity(findings, repo_root)}
{self._evidence_section(report)}
{self._business_intent(report, bi, bi_findings)}
{self._remediation_guidance(report, findings, critical, high, unresolved_violations)}
{self._scan_statistics(report)}
{self._agentic_cta()}
{self._errors(report)}
<div class="footer">
  THE DETERMINISTIC SCANNER IS THE SOURCE OF TECHNICAL TRUTH. Every finding, score, and count on this page
  comes directly from guardian.core.pipeline.ScanPipeline -- nothing here is inferred or generated. Generated
  by AI Code Guardian.
</div>
</body></html>"""

    # ------------------------------------------------------------------
    # Section 1: single-glance Repository Security Status, derived from
    # the same compute_verdict() the rest of the platform uses -- never a
    # raw source-control decision string.
    # ------------------------------------------------------------------
    def _risk_banner(self, verdict: Dict[str, str], critical: int, high: int) -> str:
        text = f"REPOSITORY SECURITY STATUS: {verdict['label']}"
        return f"<div class='tldr tldr-{_e(verdict['tone'])}'>{_e(text)}</div>"

    # ------------------------------------------------------------------
    # Section 2: Security Overview -- the executive-summary-style answer
    # to "how serious / how many / most important / what to fix first",
    # built only from rvm.executive_summary()'s real-count-derived text.
    # ------------------------------------------------------------------
    def _overview_section(self, summary: Dict[str, str], findings: List[dict],
                          critical: int, high: int) -> str:
        rows = [
            ("Is the repository secure?", summary["security_status_summary"]),
            ("What matters most?", summary["what_matters_most"]),
            ("What could happen if this is exploited?", summary["what_could_happen"]),
            ("What should be fixed first?", summary["what_to_fix_first"]),
        ]
        cards = "".join(
            f"<div class='qa-card'><div class='q'>{_e(q)}</div><div class='a'>{_e(a)}</div></div>"
            for q, a in rows
        )

        # TOP SECURITY CONCERNS -- the highest-severity, highest-
        # exploitability real findings, nothing computed beyond sorting.
        order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        valid_findings = [f for f in findings if rvm.is_valid_finding(f)]
        ranked = sorted(
            valid_findings,
            key=lambda f: (order.get(f.get("severity"), 5), -(f.get("exploitability_score") or 0)),
        )[:5]
        if ranked:
            top_items = "".join(
                f"<li>{_sev_badge(f.get('severity'))} "
                f"{_e(rvm.plain_english_category(f.get('category')))} "
                f"&mdash; <code>{_e(rvm.normalize_path(f.get('file')))}:{_e(f.get('line', ''))}</code></li>"
                for f in ranked
            )
            top_html = f"<ol class='concerns'>{top_items}</ol>"
        else:
            top_html = _empty("No security findings were identified in this scan.")

        if critical:
            priority = "Fix all Critical-severity findings first, then address High-severity findings."
        elif high:
            priority = "No Critical findings. Address High-severity findings next."
        elif findings:
            priority = "No Critical or High-severity findings. Review remaining Medium/Low findings when convenient."
        else:
            priority = "No security findings were identified by the deterministic scan."

        return f"""
        <section>
          <h2>Security Overview</h2>
          <p class="sub">Every answer below is derived directly from the real counts and records shown in the
          sections that follow -- this is not an independently generated narrative.</p>
          <div class="qa-grid">{cards}</div>
          <h3>Top Security Concerns</h3>
          {top_html}
          <h3>Recommended Priority</h3>
          <p class="plain">{_e(priority)}</p>
        </section>
        """

    # ------------------------------------------------------------------
    # Section 3: Risk Summary -- score tiles, explicitly labeled as
    # DETERMINISTIC SECURITY RISK so it is never confused with a future
    # AGENTIC RISK ENRICHMENT figure.
    # ------------------------------------------------------------------
    def _risk_summary(self, risk: dict, report: dict, verdict: Dict[str, str]) -> str:
        pairs = [
            ("security_score", "Security", None),
            (None, "Business alignment", alignment_value(report)),
            ("dependency_risk_score", "Dependencies", None),
            ("maintainability_score", "Maintainability", None),
            ("overall_risk_score", "Overall", None),
        ]
        cells = []
        for key, label, override in pairs:
            value = override if override is not None else risk.get(key)
            if value is None:
                continue
            fmt = f"{value:g}" if override is not None else f"{value:.0f}"
            cells.append(f"<div class='score'><div class='num'>{fmt}</div>"
                         f"<div class='lbl'>{_e(label)}</div></div>")
        tiles = f"<div class='scores'>{''.join(cells)}</div>" if cells else _empty("No risk scores computed.")
        return f"""
        <section>
          <h2>Risk Summary <span class="risk-label">DETERMINISTIC SECURITY RISK</span></h2>
          <p class="sub">Computed entirely from deterministic scan output. No agentic (LangGraph) analysis is
          included in these numbers -- if an Agentic Scan has been run for this codebase, its findings are
          reported separately as AGENTIC RISK ENRICHMENT and never silently combined into the scores below.
          Repository Security Status: <b>{_e(verdict['label'])}</b>.</p>
          {tiles}
        </section>
        """

    def _ai_status(self, ai: dict) -> str:
        if not ai:
            return ""
        if ai.get("configured"):
            return (f"<div class='ok'>Contextual AI assistance active — model "
                    f"<code>{_e(ai.get('model'))}</code>, {ai.get('calls', 0)} call(s), "
                    f"{ai.get('cache_hits', 0)} cached, {ai.get('failures', 0)} failed. "
                    f"Every AI claim below was validated against the evidence store. "
                    f"This is separate from the Agentic Scan / LangGraph workflow.</div>")
        reason = ai.get("unavailable_reason") or ai.get("reason") or "not configured"
        return (f"<div class='note'>Contextual AI assistance unavailable: {_e(reason)}<br>"
                f"All findings shown are deterministic; nothing was inferred.</div>")

    # ------------------------------------------------------------------
    # Sections 4-7: Critical / High / Medium / Low (+ any other real
    # severity value) findings, each its own grouped section. Every card
    # is plain-English-first (What this means / Why it matters /
    # Recommended action / Location) with an expandable Technical
    # Details block retaining every field a security engineer needs.
    # ------------------------------------------------------------------
    def _findings_by_severity(self, findings: List[dict], repo_root: str) -> str:
        groups = rvm.group_findings_by_severity(findings, repo_root)
        if not groups:
            return "<section><h2>Findings</h2>" + _empty("No findings.") + "</section>"

        sections = []
        for sev_key, items in groups:
            label = rvm.SEVERITY_LABEL.get(sev_key, sev_key.title())
            visible, remaining = _cap(items, limit=40)
            cards = "".join(self._finding_card(f) for f in visible)
            sections.append(f"""
            <section>
              <h2>{_e(label)} Findings ({len(items)})</h2>
              <div class="finding-list">{cards}</div>
              {_more_note(remaining, 'findings')}
            </section>
            """)
        return "".join(sections)

    def _finding_card(self, f: Dict[str, Any]) -> str:
        sev = f.get("severity", "Medium")
        location = f"<code>{_e(f['_display_file'])}:{_e(f['_display_line'])}</code>"
        if f.get("function"):
            location += f" in <code>{_e(f['function'])}()</code>"
        evidence_ids = f.get("evidence_ids") or ([f["evidence_id"]] if f.get("evidence_id") else [])
        exploitability = f.get("exploitability_score")

        return f"""
        <div class="finding-card sev-{_e(sev.lower())}">
          <div class="finding-head">
            <span class="fid">{_e(f.get('rule_id') or f.get('category', ''))}</span>
            {_sev_badge(sev)}
            {_badge(f.get('source', 'DETERMINISTIC'))}
          </div>
          <p class="field"><b>What this means:</b> {_e(f['_plain_category'])}</p>
          <p class="field"><b>Why it matters:</b> {_e(_why_it_matters(f))}</p>
          <p class="field"><b>How serious is it?</b> {_e(rvm.severity_explanation(sev) or rvm.IMPACT_UNKNOWN)}</p>
          <p class="field"><b>Recommended action:</b> {_e(_recommended_action(f))}</p>
          <p class="field"><b>Location:</b> {location}</p>
          <details>
            <summary>Technical Details</summary>
            <table class="tech">
              <tr><td>Finding ID</td><td><code>{_e(f.get('finding_id', ''))}</code></td></tr>
              <tr><td>Rule ID</td><td>{_e(f.get('rule_id') or '—')}</td></tr>
              <tr><td>CWE</td><td>{_e(f.get('cwe') or '—')}</td></tr>
              <tr><td>OWASP</td><td>{_e(f.get('owasp') or '—')}</td></tr>
              <tr><td>Severity</td><td>{_e(sev)}</td></tr>
              <tr><td>Confidence</td><td>{_e(f.get('confidence', '—'))}</td></tr>
              <tr><td>Exploitability</td><td>{f"{exploitability:.2f}" if isinstance(exploitability, (int, float)) else '—'}</td></tr>
              <tr><td>Engine</td><td>{_e(f.get('engine') or '—')}</td></tr>
              <tr><td>Function</td><td>{_e(f.get('function') or '—')}</td></tr>
              <tr><td>Evidence ID(s)</td><td>{_e(', '.join(evidence_ids) or '—')}</td></tr>
              <tr><td>Snippet</td><td><code>{_e(str(f.get('snippet', ''))[:300])}</code></td></tr>
            </table>
          </details>
        </div>
        """

    # ------------------------------------------------------------------
    # Section 8: Evidence -- what the evidence store actually collected,
    # never a raw local/temp filesystem dump. Per-finding evidence IDs
    # already appear in each finding's Technical Details above.
    # ------------------------------------------------------------------
    def _evidence_section(self, report: dict) -> str:
        evidence = report.get("evidence") or {}
        if not evidence:
            return ""
        evidence_types = ", ".join(f"{k}: {v}" for k, v in (evidence.get("by_type") or {}).items())
        return f"""
        <section>
          <h2>Evidence</h2>
          <p class="sub">{evidence.get('total', 0)} evidence item(s) collected across every engine that ran.
          Each finding above cites the specific evidence ID(s) it was raised from, in its Technical Details.</p>
          <p class="plain">By type: {_e(evidence_types or 'none')}</p>
        </section>
        """

    def _business_intent(self, report: dict, bi: dict, bi_findings: list) -> str:
        if not bi or bi.get("status") != "SUCCESS":
            return ""
        # Bright colors, not the original dark/muted set -- this text has
        # no background pill (unlike _sev_badge/_badge above), so on the
        # dark report background these need to be light to stay legible,
        # matching the same palette used for severity everywhere else.
        status_colour = {
            "COMPLIANT": "#4ade80", "VIOLATION": "#f4374a",
            "PARTIAL": "#ff8a3d", "POTENTIAL_VIOLATION": "#ff8a3d",
            "INSUFFICIENT_EVIDENCE": "#8e8e9a",
        }
        rows = []
        for v in bi_findings:
            status = v.get("status", "")
            rows.append(
                f"<tr><td><b style='color:{status_colour.get(status, '#f4f4f8')}'>"
                f"{_e(status.replace('_', ' ').title())}</b></td>"
                f"<td>{_e(v.get('rule'))}</td>"
                f"<td>{_e(v.get('what') or '—')}</td>"
                f"<td>{_e(v.get('why') or v.get('evidence') or '—')}</td></tr>")
        return (f"<section><h2>Business Intent</h2>"
                f"<p class='sub'>Alignment {alignment_value(report):g}/100 &middot; "
                f"{bi.get('total_rules', len(bi_findings))} testable policies extracted from "
                f"{_e(', '.join(bi.get('documents', []) or []))}</p>"
                "<table><tr><th>Verdict</th><th>Policy</th>"
                "<th>Implementation found</th><th>Notes</th></tr>"
                f"{''.join(rows)}</table></section>")

    # ------------------------------------------------------------------
    # Section 9: Remediation Guidance -- an aggregate summary of real
    # per-finding recommendations. This report has no agentic patch
    # pipeline, so it NEVER claims PATCH GENERATED / APPLIED / VALIDATED
    # / TEST PASSED -- only "what to review and fix", derived from real
    # counts already shown above.
    # ------------------------------------------------------------------
    def _remediation_guidance(self, report: dict, findings: List[dict],
                              critical: int, high: int, unresolved_violations: int) -> str:
        items: List[str] = []
        if critical:
            items.append(f"<li><b>Address immediately:</b> {_e(critical)} Critical finding(s) are unresolved.</li>")
        elif high:
            items.append(f"<li><b>Needs review:</b> {_e(high)} High-severity finding(s) are present.</li>")
        else:
            items.append("<li><b>No Critical/High findings</b> in this scan.</li>")
        if unresolved_violations:
            items.append(f"<li><b>Review business impact:</b> {_e(unresolved_violations)} business "
                         f"requirement(s) flagged as violated or potentially violated.</li>")

        by_category: Dict[str, int] = {}
        for f in findings:
            cat = f.get("category")
            if cat:
                by_category[cat] = by_category.get(cat, 0) + 1
        if by_category:
            top_cats = sorted(by_category.items(), key=lambda kv: -kv[1])[:5]
            cat_list = ", ".join(f"{_e(c)} ({n})" for c, n in top_cats)
            items.append(f"<li><b>Most frequent finding types:</b> {cat_list}.</li>")

        items.append("<li>No automated patches were generated for this report. To review AI-proposed, "
                     "validation-checked fixes, run an Agentic Scan (see below).</li>")

        return f"""
        <section>
          <h2>Remediation Guidance</h2>
          <p class="sub">Derived only from the real findings above -- not a generated narrative, and no
          remediation status is claimed beyond what this report actually did.</p>
          <ul class="reco">{''.join(items)}</ul>
        </section>
        """

    def _scan_statistics(self, report: dict) -> str:
        ust = report.get("ust") or {}
        if not ust:
            return ""
        parsers = ", ".join(f"{k}: {v}" for k, v in (ust.get("parsers") or {}).items())
        languages = ", ".join(f"{k} ({v})" for k, v in (ust.get("languages") or {}).items())
        return (f"<section><h2>Scan Statistics</h2><p class='sub'>"
                f"Unified syntax tree: {ust.get('files', 0)} files, "
                f"{ust.get('nodes', 0)} nodes, {ust.get('parse_failures', 0)} parse failures<br>"
                f"Languages: {_e(languages or 'none')}<br>"
                f"Parsers: {_e(parsers or 'none')}</p></section>")

    # ------------------------------------------------------------------
    # Mandated call-to-action -- clearly separate from, never blended
    # into, the deterministic numbers above.
    # ------------------------------------------------------------------
    def _agentic_cta(self) -> str:
        return """
        <section>
          <div class="cta">
            <h2 class="cta-title">AI AGENTIC ANALYSIS AVAILABLE</h2>
            <p class="plain">This Security Report is entirely deterministic. Running an Agentic Scan adds a
            separate, clearly-labeled layer of analysis on top of these exact findings:</p>
            <ul class="reco">
              <li>Attack-path modeling — which findings are actually reachable, and how</li>
              <li>Business-rule comparison — code behavior checked against your uploaded requirements</li>
              <li>Composite risk fusion — technical, business, threat, and policy signals combined</li>
              <li>Proposed patches, checked by a real validation pass before being marked ready</li>
              <li>End-to-end evidence traceability from finding to remediation</li>
            </ul>
            <p class="sub">Open the AI Code Guardian dashboard's Security &amp; Compliance tab and choose
            "Run Agentic Analysis" for this scan, then download the Agentic or Unified Report.</p>
          </div>
        </section>
        """

    def _errors(self, report: dict) -> str:
        errors = report.get("errors") or []
        if not errors:
            return ""
        items = "".join(f"<li><code>{_e(e.get('stage'))}</code>: {_e(e.get('error'))}</li>"
                        for e in errors[:20])
        return (f"<section><h2>Partial Results</h2><div class='note'>"
                f"{len(errors)} stage(s) failed and were skipped. Everything else "
                f"completed normally.<ul>{items}</ul></div></section>")


_CSS = """
:root{--bg:#0a0a0f;--panel:#111118;--panel2:#15151d;--border:rgba(255,255,255,.08);
  --text:#f4f4f8;--sub:#8e8e9a;--orange:#ff5400;--orange-dim:rgba(255,84,0,.14)}
*{box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;margin:0;padding:2rem;color:var(--text);background:var(--bg);max-width:1100px}
h1{margin:0 0 .3rem;color:var(--orange)}
h2{margin:2.2rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.35rem;font-size:1.15rem;color:var(--text)}
h3{margin:1.3rem 0 .5rem;font-size:.85rem;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
section{margin-bottom:.3rem}
.sub{color:var(--sub);margin-bottom:1rem;line-height:1.6;font-size:.85rem}
.plain{font-size:.9rem;line-height:1.5}
code{font-size:.78rem;background:rgba(255,255,255,.06);color:#d8d8e0;padding:1px 4px;border-radius:3px}
.empty{color:#5c5c68;font-style:italic;padding:.4rem 0}
.badge{font-size:.68rem;padding:2px 8px;border-radius:10px;font-weight:700;white-space:nowrap;text-transform:uppercase;letter-spacing:.02em}
.note{background:rgba(245,196,81,.1);border-left:4px solid #f5c451;padding:.7rem 1rem;margin:1rem 0;font-size:.85rem;color:var(--text)}
.ok{background:rgba(74,222,128,.1);border-left:4px solid #4ade80;padding:.7rem 1rem;margin:1rem 0;font-size:.85rem;color:var(--text)}
.more-note{color:#5c5c68;font-size:.78rem;font-style:italic;margin-top:.4rem}

.tldr{font-size:1rem;font-weight:700;padding:.85rem 1.2rem;border-radius:8px;margin:.8rem 0 1.4rem}
.tldr-bad{background:rgba(244,55,74,.14);color:#ff8a95;border:1px solid rgba(244,55,74,.4)}
.tldr-warn{background:rgba(245,196,81,.14);color:#f5c451;border:1px solid rgba(245,196,81,.4)}
.tldr-good{background:rgba(74,222,128,.14);color:#4ade80;border:1px solid rgba(74,222,128,.4)}
.tldr-neutral{background:rgba(255,255,255,.06);color:var(--text);border:1px solid var(--border)}

.qa-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:.8rem;margin-bottom:.4rem}
.qa-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.9rem 1.1rem}
.qa-card .q{font-size:.72rem;font-weight:700;color:var(--orange);text-transform:uppercase;letter-spacing:.02em;margin-bottom:.35rem}
.qa-card .a{font-size:.88rem;line-height:1.5;color:var(--text)}
.concerns{padding-left:1.3rem;line-height:2;font-size:.88rem}

.risk-label{display:inline-block;font-size:.62rem;font-weight:700;letter-spacing:.04em;background:rgba(255,255,255,.06);color:var(--sub);border:1px solid var(--border);border-radius:10px;padding:2px 9px;margin-left:.6rem;vertical-align:middle;text-transform:none}

.scores{display:flex;gap:1rem;margin:.8rem 0;flex-wrap:wrap}
.score{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:1rem 1.4rem;text-align:center;min-width:110px}
.num{font-size:1.6rem;font-weight:700;color:var(--orange)} .lbl{color:var(--sub);font-size:.75rem;text-transform:uppercase}

.finding-list{display:flex;flex-direction:column;gap:.7rem;margin-top:.5rem}
.finding-card{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.9rem 1.1rem}
.finding-card.sev-critical{border-left:4px solid #f4374a}
.finding-card.sev-high{border-left:4px solid #ff8a3d}
.finding-card.sev-medium{border-left:4px solid #f5c451}
.finding-card.sev-low{border-left:4px solid #4ade80}
.finding-card.sev-info{border-left:4px solid #8e8e9a}
.finding-head{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap;margin-bottom:.5rem}
.fid{font-weight:700;font-size:.85rem;color:var(--text)}
.field{font-size:.87rem;line-height:1.5;margin:.3rem 0;color:var(--text)}
details{margin-top:.5rem}
details summary{cursor:pointer;font-size:.75rem;color:var(--sub);text-transform:uppercase;letter-spacing:.02em}
table.tech{border-collapse:collapse;width:100%;font-size:.8rem;margin-top:.5rem}
table.tech td{border-bottom:1px solid var(--border);padding:.3rem .5rem;vertical-align:top;color:var(--text)}
table.tech td:first-child{color:var(--sub);width:140px;font-weight:600}

table{border-collapse:collapse;width:100%;background:var(--panel);font-size:.85rem;margin-top:.6rem}
th,td{border:1px solid var(--border);padding:.45rem .6rem;text-align:left;vertical-align:top;color:var(--text)}
th{background:var(--panel2);color:var(--sub)}

.reco{padding-left:1.2rem;line-height:1.8;font-size:.88rem}

.cta{background:var(--orange-dim);border:1px solid rgba(255,84,0,.3);border-radius:10px;padding:1.1rem 1.3rem}
.cta-title{margin:0 0 .5rem;border:none;padding:0;font-size:1rem;color:var(--orange)}

.footer{margin-top:2.5rem;color:#5c5c68;font-size:.75rem;border-top:1px solid var(--border);padding-top:1rem;line-height:1.6}

@media print{
  /* Redefine the theme tokens themselves, same fix as
     agentic_html_reporter.py's print block -- redefining only individual
     element rules here left headings inheriting var(--text)'s near-white
     color against a white print background (nearly invisible) the first
     time this pattern was tried in the sibling reporter. */
  :root{--bg:#fff;--panel:#fff;--panel2:#f2f2f2;--border:#ccc;--text:#111;--sub:#555;--orange:#d94600;--orange-dim:#fff1e8}
  body{padding:1rem}
  .finding-card,.qa-card,.score,table,.cta{box-shadow:none}
  code{background:#f2f2f2;color:#333}
  .tldr-bad{background:#fdecec;color:#b71c1c;border-color:#e59}
  .tldr-warn{background:#fff8e1;color:#8a6100;border-color:#e5c366}
  .tldr-good{background:#e8f5e9;color:#1b5e20;border-color:#8fce9a}
  .tldr-neutral{background:#f2f2f2;color:#333;border-color:#ccc}
  section{page-break-inside:avoid}
}
"""
