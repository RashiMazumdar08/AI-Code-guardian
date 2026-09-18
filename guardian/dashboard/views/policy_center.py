"""
AI Code Guardian v3 — Policy Center Page
=========================================
Manages enterprise security policy packs (PDF, MD, DOCX, TXT), document ingestion, and compliance rules.
"""
from __future__ import annotations

from typing import Any, Dict, List
from guardian.ai.config import AssistantConfig
from guardian.ai.document_loader import DocumentLoader
from guardian.dashboard.models.dashboard_state import DashboardStateView
from guardian.policies.manager import PolicyPackManager


class PolicyCenterViewPage:
    """Renders Policy Center view and document ingestion controls."""

    def __init__(self, config: Optional[AssistantConfig] = None) -> None:
        self.doc_loader = DocumentLoader(config or AssistantConfig())
        self.policy_manager = PolicyPackManager()

    def render(self, state_view: DashboardStateView, uploaded_file: Any = None) -> Dict[str, Any]:
        policy_res = state_view.policy_results

        ingested_doc = None
        if uploaded_file:
            try:
                content = uploaded_file.read()
                filename = getattr(uploaded_file, "name", "uploaded_policy.txt")
                docs = self.doc_loader.load_bytes(content, filename)
                ingested_doc = {"status": "success", "chunks": len(docs), "filename": filename}
            except Exception as e:
                ingested_doc = {"status": "error", "message": str(e)}

        active_pack_names = self.policy_manager.list_packs()
        active_packs = [self.policy_manager.get_pack(name) for name in active_pack_names]

        return {
            "page_title": "Enterprise Policy Center & Compliance Rules",
            "violations_count": policy_res.get("total_violations", 0),
            "violations": policy_res.get("violations", []),
            "active_policy_packs": [
                {
                    "name": p.name,
                    "version": p.version,
                    "description": p.description,
                    "rules_count": len(p.rules),
                } for p in active_packs if p
            ],
            "ingested_document": ingested_doc,
        }
