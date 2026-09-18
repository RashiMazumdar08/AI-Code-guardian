"""
PDF / Printable Executive Summary Reporter — Clean, formatted report for CISO & security teams.
"""
from __future__ import annotations

from guardian.core.registry import register_reporter
from guardian.reporting._shared import visible_findings
from guardian.reporting import report_view_model as rvm

# Repository Security Status badge colors, keyed on compute_verdict()'s
# real tone (good/warn/bad/neutral) -- never derived from a raw
# source-control decision string.
_VERDICT_TONE_COLORS = {
    "good": ("#dcfce7", "#166534"),
    "warn": ("#fef3c7", "#92400e"),
    "bad": ("#fee2e2", "#991b1b"),
    "neutral": ("#e5e7eb", "#374151"),
}


@register_reporter
class PDFReporter:
    name = "pdf"
    file_extension = ".pdf.html"  # Printable HTML export suitable for PDF conversion

    def render(self, report_dict: dict) -> str:
        scan = report_dict.get("scan", {})
        # Prefer the unified risk assessment; fall back to the legacy report
        # so this reporter still works on an older report dict.
        risk = report_dict.get("unified_risk") or report_dict.get("risk", {})
        repo = report_dict.get("repository", {})
        domain = report_dict.get("business_domain") or {}

        # visible_findings() drops the not-yet-implemented Quantum
        # Readiness "Quantum Migration Inventory" inventory rows -- see
        # guardian/reporting/_shared.py.
        findings = visible_findings(report_dict)
        by_sev = scan.get("by_severity", {})
        by_sev_lower = {str(k).lower(): v for k, v in (by_sev or {}).items()}
        critical_n = by_sev_lower.get("critical", 0) or 0
        high_n = by_sev_lower.get("high", 0) or 0
        total_findings = scan.get("total_findings", len(findings))
        # Repository Security Status: reuse the SAME compute_verdict() the
        # HTML/Agentic/Unified reports and the Reports page use (Critical
        # Rule #1: do not create duplicate status-computation systems),
        # called with an empty patch map and no risk_level since this
        # report has neither.
        verdict = rvm.compute_verdict(True, total_findings, critical_n, high_n, {}, None)
        badge_bg, badge_fg = _VERDICT_TONE_COLORS.get(verdict["tone"], _VERDICT_TONE_COLORS["neutral"])

        rows = ""
        for f in findings:
            sev = f.get("severity", "Info")
            color = {"Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706", "Low": "#2563eb", "Info": "#4b5563"}.get(sev, "#4b5563")
            source = f.get("source", "DETERMINISTIC")
            source_style = ("background:#e8f5e9;color:#1b5e20" if source == "DETERMINISTIC"
                            else "background:#e3f2fd;color:#0d47a1")
            source_label = {"DETERMINISTIC": "Static", "AI_VALIDATED": "AI-validated",
                            "AI_SUGGESTED": "AI suggestion"}.get(source, source)
            location = f"{f.get('file')}:{f.get('line')}"
            if f.get("function"):
                location += f"<br><small style='color:#6b7280'>in {f.get('function')}()</small>"
            rows += f"""
            <tr style="border-bottom: 1px solid #e5e7eb;">
                <td style="padding: 8px;"><span style="background: {color}; color: white; padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 11px;">{sev}</span></td>
                <td style="padding: 8px;"><span style="{source_style}; padding: 2px 7px; border-radius: 10px; font-size: 10px; font-weight: 600;">{source_label}</span></td>
                <td style="padding: 8px;"><strong>{f.get('category')}</strong><br><small style="color: #6b7280;">{f.get('rule_id')}</small></td>
                <td style="padding: 8px;"><code>{location}</code></td>
                <td style="padding: 8px; font-family: monospace; font-size: 12px; background: #f9fafb;">{str(f.get('snippet', ''))[:100]}</td>
                <td style="padding: 8px; font-size: 12px;">{f.get('recommendation')}</td>
            </tr>
            """

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AI Code Guardian — Executive Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 40px; color: #1f2937; }}
        .header {{ border-bottom: 2px solid #2563eb; padding-bottom: 15px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; }}
        .card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 20px; }}
        .grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }}
        .metric {{ background: #ffffff; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px; text-align: center; }}
        .metric .value {{ font-size: 24px; font-weight: bold; color: #0f172a; }}
        .metric .label {{ font-size: 12px; color: #64748b; text-transform: uppercase; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th {{ background: #f1f5f9; text-align: left; padding: 10px; font-size: 12px; font-weight: 600; text-transform: uppercase; color: #475569; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1 style="margin: 0; color: #0f172a;">AI Code Guardian Security Report</h1>
            <p style="margin: 5px 0 0 0; color: #64748b;">Executive Vulnerability & Compliance Assessment</p>
        </div>
        <div style="text-align: right;">
            <div style="font-size: 10px; color: #64748b; text-transform: uppercase; letter-spacing: .04em; margin-bottom: 3px;">Repository Security Status</div>
            <span style="font-size: 18px; font-weight: bold; padding: 6px 12px; border-radius: 6px; background: {badge_bg}; color: {badge_fg};">
                {verdict['label']}
            </span>
        </div>
    </div>

    <div class="grid">
        <div class="metric"><div class="value">{risk.get('security_score', 0):.1f}/100</div><div class="label">Security Score</div></div>
        <div class="metric"><div class="value">{self._alignment_value(report_dict):g}/100</div><div class="label">Business Alignment</div></div>
        <div class="metric"><div class="value">{risk.get('dependency_risk_score', 100):.1f}/100</div><div class="label">Dependency Score</div></div>
        <div class="metric"><div class="value">{risk.get('overall_risk_score', 0):.1f}/100</div><div class="label">Overall</div></div>
    </div>

    <div class="card">
        <h3 style="margin-top: 0;">Repository Profile</h3>
        <p style="margin: 0;">Primary Language: <strong>{repo.get('primary_language', 'Unknown')}</strong>
         | Files Scanned: <strong>{scan.get('files_scanned', 0)}</strong>
         | Total Findings: <strong>{scan.get('total_findings', 0)}</strong>
         | Business Domain: <strong>{domain.get('domain', 'Unclassified')}</strong></p>
        <p style="margin: 6px 0 0 0; font-size: 12px; color: #64748b;">Severity breakdown: {by_sev or 'none'}</p>
    </div>

    {self._business_section(report_dict)}

    <h3>Detailed Vulnerability Findings</h3>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Source</th>
                <th>Category</th>
                <th>Location</th>
                <th>Code Snippet</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>
"""
        return html

    # ------------------------------------------------------------------
    @staticmethod
    def _alignment_value(report_dict: dict) -> float:
        """Single source of truth for the displayed alignment percentage.

        Always prefers the live Business Intent Engine result
        (report_dict["business_intent"], the same POST /api/business-intent
        /analyze shape the Reports tab and Overview tile render from).
        Falls back to unified_risk.alignment_score only when no
        business_intent payload was supplied at all -- that field comes
        from a *different* engine (guardian.engines.business_intent, run
        inside the scan pipeline) with its own scoring and a 100%
        fallback when nothing was judged, which is what previously made
        this report disagree with the live app.
        """
        bi = report_dict.get("business_intent") or {}
        value = bi.get("alignment_percentage")
        if value is None:
            value = bi.get("alignment_score")
        if isinstance(value, (int, float)):
            return float(value)
        risk = report_dict.get("unified_risk") or report_dict.get("risk", {})
        return float(risk.get("alignment_score", 0) or 0)

    @staticmethod
    def _business_section(report_dict: dict) -> str:
        """Business-intent verdicts, when requirements were supplied.

        Reads the same shape POST /api/business-intent/analyze returns
        (status/alignment_percentage/findings[]) -- the exact result the
        Reports tab and Overview tile render from. There is a second,
        older business-intent engine wired into the scan pipeline itself
        (guardian.engines.business_intent) with its own scoring and a
        `verdicts` shape; it defaults to a hardcoded 100 when nothing was
        judged, which previously made this download disagree with the
        live app. The frontend now always overrides business_intent with
        the live analyze-endpoint result before downloading, so this
        renderer only needs to understand that one shape.
        """
        bi = report_dict.get("business_intent")
        if not bi or bi.get("status") != "SUCCESS":
            return ""
        colour = {"COMPLIANT": "#16a34a", "VIOLATION": "#dc2626",
                  "PARTIAL": "#ea580c", "POTENTIAL_VIOLATION": "#ea580c",
                  "INSUFFICIENT_EVIDENCE": "#6b7280"}
        findings = bi.get("findings", [])
        rows = "".join(
            f"<tr style='border-bottom:1px solid #e5e7eb'>"
            f"<td style='padding:8px;color:{colour.get(v.get('status'), '#374151')};"
            f"font-weight:600'>{(v.get('status') or '').replace('_', ' ').title()}</td>"
            f"<td style='padding:8px'>{v.get('rule', '')}</td>"
            f"<td style='padding:8px;font-size:12px;color:#6b7280'>"
            f"{v.get('why') or v.get('evidence') or '—'}</td></tr>"
            for v in findings)
        alignment = PDFReporter._alignment_value(report_dict)
        return f"""
    <div class="card">
        <h3 style="margin-top: 0;">Business Intent — Requirements vs. Implementation</h3>
        <p style="margin:0 0 8px 0; font-size: 13px; color:#64748b;">
            Alignment {alignment:g}/100 across
            {bi.get('total_rules', len(findings))} testable policies.</p>
        <table><thead><tr><th>Verdict</th><th>Policy</th><th>Notes</th></tr></thead>
        <tbody>{rows}</tbody></table>
    </div>"""

