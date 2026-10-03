"""
AI Code Guardian v3 — Validation Agent
======================================
Specialist agent executing GroundingEngine verification and PatchVerificationService
mechanical re-verification over generated patch proposals.
NO LLM calls. Pure deterministic validation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.agents.base.agent import BaseAgent
from guardian.agents.validation.verification import PatchVerificationService
from guardian.orchestrator.state import AgentWorkflowState
from guardian.reasoning.grounding.grounding import GroundingEngine


class ValidationAgent(BaseAgent):
    """Specialist agent validating patch syntax, grounding evidence, and mechanical resolution."""

    name: str = "validation"
    description: str = "Executes grounding verification, AST syntax validation, and mechanical re-verification."

    def __init__(
        self,
        tool_registry: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        grounding_engine: Optional[GroundingEngine] = None,
        verification_service: Optional[PatchVerificationService] = None
    ) -> None:
        super().__init__(tool_registry=tool_registry, event_bus=event_bus)
        self.grounding_engine = grounding_engine or GroundingEngine()
        self.verification_service = verification_service or PatchVerificationService()

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["validation_tool", "parser_tool"]

        patches = state.get("patches", [])
        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        profile = state.get("repository_profile", {})
        repo_path_str = profile.get("repo_path")
        repo_path = Path(repo_path_str) if repo_path_str else None

        validation_results: List[Dict[str, Any]] = []
        validated_patches: List[Dict[str, Any]] = []
        grounding_reports: List[Dict[str, Any]] = []

        total_confidence = 0.0

        for patch in patches:
            p_dict = patch if isinstance(patch, dict) else patch.to_dict()
            finding_id = p_dict.get("finding_id", "")
            orig_finding = next((f for f in findings if f.get("finding_id") == finding_id), {})

            # 1. Grounding Verification
            g_report = self.grounding_engine.verify_patch(p_dict, findings, evidence, repo_path)
            grounding_reports.append(g_report)

            # 2. Mechanical Re-verification
            mech_res = self.verification_service.verify_remediation(
                original_finding=orig_finding,
                replacement_snippet=p_dict.get("suggested_replacement", ""),
                language=profile.get("primary_language", "python")
            )

            is_valid = g_report["passed"] and mech_res["resolved"]
            v_status = "PASSED" if is_valid else "REJECTED"

            updated_confidence = round(min(1.0, max(0.0, float(p_dict.get("confidence", 0.90)) + mech_res["confidence_boost"])), 2)
            total_confidence += updated_confidence

            p_dict["validation_status"] = v_status
            p_dict["confidence"] = updated_confidence
            validated_patches.append(p_dict)

            val_record = {
                "patch_id": p_dict.get("patch_id"),
                "finding_id": finding_id,
                "file": p_dict.get("affected_file"),
                "status": v_status,
                "grounding_passed": g_report["passed"],
                "syntax_valid": mech_res["syntax_valid"],
                "remediation_resolved": mech_res["resolved"],
                "issues": g_report["reasons"] + mech_res["issues"],
                "confidence": updated_confidence,
            }
            validation_results.append(val_record)

        avg_confidence = round(total_confidence / max(1, len(validated_patches)), 2)

        # Optional Grok AI finding validation review
        ai_validation_breakdown: List[Dict[str, Any]] = []
        try:
            from guardian.llm.config import LLMConfig
            cfg = LLMConfig.from_env()
            if cfg.is_agent_enabled("validation"):
                from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
                service = ReasoningGateway(config=cfg)
                if service.configured:
                    f_summary = "\n".join(
                        f"[E{i+1}] {f.get('rule_id', 'SEC')}: {f.get('title', '')} in {f.get('file', '')}:{f.get('line', 0)} (source={f.get('source', 'SAST')})"
                        for i, f in enumerate(findings[:8])
                    ) or "[E1] General findings validation"

                    req = ReasoningRequest(
                        task="finding_validation",
                        instruction=(
                            "Review the findings against the evidence. Assess likely false positives, missing evidence, "
                            "and classify each finding as TRUE_POSITIVE, LIKELY_FALSE_POSITIVE, or NEEDS_MANUAL_REVIEW."
                        ),
                        evidence_block=f_summary,
                    )
                    ai_res = service.reason(req)
                    if ai_res.ok and ai_res.findings:
                        for rf in ai_res.findings:
                            status = "TRUE_POSITIVE"
                            if "false" in rf.reason.lower() or "mitigated" in rf.reason.lower():
                                status = "LIKELY_FALSE_POSITIVE"
                            elif "manual" in rf.reason.lower() or "unclear" in rf.reason.lower():
                                status = "NEEDS_MANUAL_REVIEW"

                            val_item = {
                                "rule_id": rf.category or "FINDING-VAL",
                                "file": rf.file,
                                "line": rf.line,
                                "classification": status,
                                "reasoning": rf.reason,
                                "confidence": rf.confidence,
                                "evidence_ids": rf.evidence_ids,
                            }
                            ai_validation_breakdown.append(val_item)

                            # Attach explicit validation fields directly to matching finding objects
                            for f in findings:
                                if (f.get("file") == rf.file or f.get("file_path") == rf.file) and (f.get("line") == rf.line or f.get("line_number") == rf.line or not rf.line):
                                    f["validation_verdict"] = status
                                    f["validation_confidence"] = rf.confidence
                                    f["validation_reasoning"] = rf.reason
                        self.logger.info("Grok AI validation produced %d breakdown item(s)", len(ai_res.findings))
        except Exception as exc:
            self.logger.warning("Optional Grok AI validation reasoning notice: %s", exc)

        new_state = dict(state)
        new_state["patches"] = validated_patches
        new_state["validation_results"] = validation_results
        new_state["validation_report"] = {
            "total_validated": len(validation_results),
            "passed_count": sum(1 for v in validation_results if v["status"] == "PASSED"),
            "rejected_count": sum(1 for v in validation_results if v["status"] == "REJECTED"),
        }
        new_state["grounding_report"] = {
            "total_checked": len(grounding_reports),
            "grounded_passed": sum(1 for g in grounding_reports if g["passed"]),
        }
        new_state["validation_confidence"] = avg_confidence
        if ai_validation_breakdown:
            new_state["ai_validation_breakdown"] = ai_validation_breakdown
        return new_state

