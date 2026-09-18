"""
AI Code Guardian v3 — Export Center Page
=========================================
Exports scan findings and reports to SARIF, JSON, HTML, PDF, CSV, Patch Bundles, and Traces.
Leverages existing reporting engines in guardian.reporting without duplicating business logic.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.models.dashboard_state import DashboardStateView
from guardian.reporting.csv_reporter import CSVReporter
from guardian.reporting.html_reporter import HtmlReporter
from guardian.reporting.json_reporter import JsonReporter
from guardian.reporting.pdf_reporter import PDFReporter
from guardian.reporting.sarif import SarifReporter


class ExportCenterPage:
    """Renders Export Center view and generates export artifacts."""

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        """Exposes export capabilities for all supported report formats."""
        findings = state_view.findings
        scan_id = state_view.scan_id

        report_dict = {
            "scan": {"scan_id": scan_id, "findings": findings},
            "repository": state_view.repository_profile,
            "business_domain": state_view.business_context,
            "risk": state_view.risk_scores,
        }

        sarif_reporter = SarifReporter()
        html_reporter = HtmlReporter()
        pdf_reporter = PDFReporter()
        csv_reporter = CSVReporter()
        json_reporter = JsonReporter()

        sarif_output = sarif_reporter.render(report_dict)
        html_output = html_reporter.render(report_dict)
        pdf_output = pdf_reporter.render(report_dict)
        csv_output = csv_reporter.render(report_dict)
        json_output = json_reporter.render(report_dict)

        patch_bundle = {
            "scan_id": scan_id,
            "git_diff": state_view.git_diff,
            "patches": state_view.patches,
            "developer_explanation": state_view.developer_explanation,
        }

        trace_bundle = {
            "scan_id": scan_id,
            "agent_trace": state_view.agent_trace,
            "execution_metrics": state_view.execution_metrics,
        }

        return {
            "page_title": "Export Center",
            "scan_id": scan_id,
            "supported_formats": ["SARIF", "JSON", "HTML", "PDF", "CSV", "Patch Bundle", "Execution Trace"],
            "sarif_report": sarif_output,
            "html_report": html_output,
            "pdf_report": pdf_output,
            "csv_report": csv_output,
            "json_report": json_output,
            "patch_bundle": patch_bundle,
            "trace_bundle": trace_bundle,
        }
