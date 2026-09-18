"""
AI Code Guardian v3 — Risk Fusion Agent
=======================================
Specialist agent extending UnifiedRiskEngine to calculate composite risk scores,
incorporating technical findings, business criticality, threat exploitability, and policy violations.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.consensus import ReasoningConsensus
from guardian.agents.shared.context import RiskProfile
from guardian.evidence.correlation import EvidenceCorrelationService
from guardian.orchestrator.state import AgentWorkflowState


class RiskFusionAgent(BaseAgent):
    """Specialist agent fusing technical, business, threat, and policy risk models into a composite score."""

    name: str = "risk_fusion"
    description: str = "Calculates unified composite risk, evidence correlations, and consensus confidence."

    def __init__(
        self,
        tool_registry: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        correlation_service: Optional[EvidenceCorrelationService] = None,
        consensus_engine: Optional[ReasoningConsensus] = None
    ) -> None:
        super().__init__(tool_registry=tool_registry, event_bus=event_bus)
        self.correlation_service = correlation_service or EvidenceCorrelationService()
        self.consensus_engine = consensus_engine or ReasoningConsensus()

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["risk_tool", "evidence_tool"]

        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        biz_ctx = state.get("business_context", {})
        threat_ctx = state.get("threat_context", {})
        policy_res = state.get("policy_results", {})
        arch_ctx = state.get("architecture_context", {})
        agent_traces = state.get("agent_trace", [])

        # 1. Calculate Evidence Correlation
        correlated = self.correlation_service.correlate(
            findings=findings,
            evidence=evidence,
            business_context=biz_ctx,
            threat_context=threat_ctx,
            policy_results=policy_res,
        )

        # 2. Calculate Consensus Confidence
        confidence = self.consensus_engine.calculate_confidence(
            security_findings=findings,
            architecture_context=arch_ctx,
            threat_context=threat_ctx,
            policy_results=policy_res,
            agent_traces=agent_traces,
        )

        # 3. Calculate Risk Components
        # NOTE: canonical deterministic Finding.severity is title-case
        # ("Critical"/"High"/"Medium"/"Low"), not upper-case -- normalize
        # before comparing so real ScanPipeline findings actually weight
        # tech_risk by their true severity instead of silently falling
        # through to the 1.0 default for every real finding.
        tech_risk = min(10.0, sum(
            2.5 if f.get("severity", "").upper() == "HIGH"
            else (4.0 if f.get("severity", "").upper() == "CRITICAL" else 1.0)
            for f in findings
        ))
        biz_risk = 9.0 if biz_ctx.get("criticality") == "CRITICAL" else (6.0 if biz_ctx.get("criticality") == "HIGH" else 3.0)
        threat_risk = float(threat_ctx.get("exploitability", 0.5)) * 10.0
        policy_risk = min(10.0, float(policy_res.get("total_violations", 0)) * 2.0)
        reachability_wt = float(threat_ctx.get("reachability", 0.5))

        composite_score = round(
            (tech_risk * 0.35) +
            (biz_risk * 0.25) +
            (threat_risk * 0.20 * reachability_wt) +
            (policy_risk * 0.20),
            2
        )

        risk_level = "CRITICAL" if composite_score >= 8.0 else ("HIGH" if composite_score >= 6.0 else ("MEDIUM" if composite_score >= 3.0 else "LOW"))

        risk_profile_obj: RiskProfile = {
            "composite_risk_score": composite_score,
            "technical_risk_score": tech_risk,
            "business_risk_score": biz_risk,
            "threat_risk_score": threat_risk,
            "policy_risk_score": policy_risk,
            "reachability_weight": reachability_wt,
            "confidence_score": confidence,
            "risk_level": risk_level,
        }

        new_state = dict(state)
        new_state["risk_scores"] = dict(risk_profile_obj)
        new_state["correlated_findings"] = correlated
        return new_state
