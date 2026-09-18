"""
AI Code Guardian v3 — AI Security Copilot Page
==============================================
RAG Chatbot integrated with Qdrant, Neo4j, UST, security findings, evidence, and policies.
Provides evidence-grounded responses citing Evidence IDs, source files, and lines.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from guardian.copilot import synthesize_security_answer
from guardian.dashboard.models.dashboard_state import DashboardStateView

logger = logging.getLogger(__name__)


class CopilotViewPage:
    """Renders AI Security Copilot RAG Chatbot view."""

    def __init__(self, copilot: Optional[Any] = None) -> None:
        self.copilot = copilot

    def render(self, state_view: DashboardStateView, user_query: Optional[str] = None) -> Dict[str, Any]:
        """Processes user question against current scanned workspace state."""
        findings = state_view.findings
        evidence = state_view.evidence
        profile = state_view.repository_profile
        biz_ctx = state_view.business_context
        risk_scores = state_view.risk_scores

        if user_query:
            answer, citations = synthesize_security_answer(
                user_query,
                findings,
                evidence=evidence,
                profile=profile,
                risk_scores=risk_scores,
                persona="Developer",
            )
        else:
            answer, citations = "", []

        return {
            "page_title": "AI Security Copilot (RAG Assistant)",
            "query": user_query,
            "answer": answer,
            "citations": citations,
            "total_findings_indexed": len(findings),
            "total_evidence_indexed": len(evidence),
        }
