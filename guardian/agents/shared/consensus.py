"""
AI Code Guardian v3 — Reasoning Consensus Engine
================================================
Calculates overall multi-agent confidence score across security, architecture,
threat simulation, and policy evaluation steps.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional


class ReasoningConsensus:
    """Calculates weighted consensus confidence across agent traces and evidence groundings."""

    def calculate_confidence(
        self,
        security_findings: List[Dict[str, Any]],
        architecture_context: Optional[Dict[str, Any]] = None,
        threat_context: Optional[Dict[str, Any]] = None,
        policy_results: Optional[Dict[str, Any]] = None,
        agent_traces: Optional[List[Dict[str, Any]]] = None,
    ) -> float:
        """Computes aggregate confidence score (0.0 to 1.0) based on multi-agent alignment."""
        architecture_context = architecture_context or {}
        threat_context = threat_context or {}
        policy_results = policy_results or {}
        agent_traces = agent_traces or []

        if not security_findings:
            return 1.0  # Clean codebase confidence

        base_confidence = 0.85

        # Security Findings Grounding (are all findings linked to evidence IDs?)
        grounded_count = sum(1 for f in security_findings if f.get("evidence_id"))
        grounding_ratio = grounded_count / max(1, len(security_findings))

        # Architecture confirmation (are entry points / trust boundaries defined?)
        arch_confirmed = 1.0 if architecture_context.get("trust_boundaries") else 0.80

        # Threat simulation confirmation (are attack paths verified?)
        threat_confirmed = 1.0 if threat_context.get("attack_paths") else 0.85

        # Policy confirmation
        policy_confirmed = 1.0 if policy_results.get("total_violations", 0) >= 0 else 0.90

        aggregate = (
            (base_confidence * 0.25) +
            (grounding_ratio * 0.35) +
            (arch_confirmed * 0.15) +
            (threat_confirmed * 0.15) +
            (policy_confirmed * 0.10)
        )

        return round(min(1.0, max(0.0, aggregate)), 2)
