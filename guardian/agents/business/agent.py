"""
AI Code Guardian v3 — Business Agent
====================================
Specialist agent wrapping the Business Intent Engine to classify business domains,
criticality, compliance requirements, and business capabilities.
"""
from __future__ import annotations

from typing import Any, Dict

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import BusinessContextObject
from guardian.orchestrator.state import AgentWorkflowState


class BusinessAgent(BaseAgent):
    """Specialist agent wrapping Business Intent classification engines."""

    name: str = "business"
    description: str = "Classifies business domain intent, criticality, and compliance mandates."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["business_intent_tool", "knowledge_tool"]

        b_context = state.get("business_context", {})
        findings = state.get("findings", [])

        # Run the real Business Intent Engine -- the same engine that backs the
        # live Reports tab (POST /api/business-intent/analyze) -- instead of the
        # old placeholder business_intent_tool, which just echoed its input back
        # and never touched real business documents.
        try:
            from guardian.intent.engine import BusinessIntentEngine
            engine = BusinessIntentEngine()
            intent_result: Dict[str, Any] = engine.run(scan_findings=findings)
        except Exception as e:
            self.logger.warning(f"Business Intent Engine invocation notice: {e}")
            intent_result = {
                "status": "ERROR",
                "message": str(e),
                "alignment_score": 0.0,
                "alignment_percentage": 0.0,
                "total_rules": 0,
                "matched": 0,
                "violated": 0,
                "partial": 0,
                "insufficient": 0,
                "documents": [],
                "findings": [],
            }

        status = intent_result.get("status", "ERROR")
        violations = [
            f for f in intent_result.get("findings", [])
            if f.get("status") in ("VIOLATION", "POTENTIAL_VIOLATION")
        ]

        # Derive domain/criticality signals from the real engine output rather
        # than fabricating a fixed fintech/PCI-DSS profile. When there are no
        # usable business requirements to evaluate, say so explicitly instead
        # of silently defaulting to a fake "general"/"NORMAL" classification.
        if status == "SUCCESS":
            criticality = "CRITICAL" if violations else b_context.get("criticality", "NORMAL")
            confidence = 0.9 if intent_result.get("total_rules") else 0.5
            reason = (
                f"{intent_result.get('total_rules', 0)} policy rule(s) evaluated "
                f"against {len(intent_result.get('documents', []) or [])} business document(s)."
            )
        else:
            criticality = b_context.get("criticality", "NORMAL")
            confidence = 0.0
            reason = {
                "NO_DOCUMENTS": "NO_BUSINESS_REQUIREMENTS: no business/policy documents found in repository.",
                "NO_VALID_REQUIREMENTS": "NO_BUSINESS_REQUIREMENTS: documents found but no testable requirements parsed.",
                "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE: requirements found but scan evidence was insufficient to judge them.",
            }.get(status, f"Business Intent Engine returned status={status}.")

        domain = b_context.get("domain", "general")

        context_obj: BusinessContextObject = {
            "domain": domain,
            "criticality": criticality,
            "confidence": confidence,
            "critical_assets": b_context.get("critical_assets", []),
            "compliance_frameworks": b_context.get("compliance_frameworks", []),
            "business_capabilities": b_context.get("business_capabilities", []),
            "data_classification": b_context.get(
                "data_classification", "CONFIDENTIAL" if criticality == "CRITICAL" else "INTERNAL"
            ),
        }

        results_with_reason = dict(intent_result)
        results_with_reason["agent_reason"] = reason

        new_state = dict(state)
        new_state["business_context"] = dict(context_obj)
        new_state["business_intent_results"] = results_with_reason
        new_state["business_violations"] = violations
        return new_state
