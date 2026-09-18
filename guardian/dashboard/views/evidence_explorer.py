"""
AI Code Guardian v3 — Evidence Explorer Page
============================================
Searchable table cross-referencing Evidence IDs, source files, line numbers, findings, policies, and patches.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.models.dashboard_state import DashboardStateView


class EvidenceExplorerPage:
    """Renders Evidence Explorer view."""

    def render(self, state_view: DashboardStateView, query: str = "") -> Dict[str, Any]:
        evidence = state_view.evidence
        findings = state_view.findings

        items = []
        for ev in evidence:
            ev_id = ev.get("evidence_id", "")
            f_id = ev.get("finding_id", "")
            matching_f = next((f for f in findings if f.get("finding_id") == f_id or f.get("evidence_id") == ev_id), {})

            item = {
                "evidence_id": ev_id,
                "finding_id": f_id,
                "file_path": matching_f.get("file_path", "N/A"),
                "line_number": matching_f.get("line_number", "N/A"),
                "rule_id": matching_f.get("rule_id", "N/A"),
                "severity": matching_f.get("severity", "LOW"),
            }

            if not query or query.lower() in str(item).lower():
                items.append(item)

        return {
            "page_title": "Evidence Explorer",
            "search_query": query,
            "total_evidence_items": len(items),
            "evidence_items": items,
        }
