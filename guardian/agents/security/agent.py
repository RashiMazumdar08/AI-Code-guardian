"""
AI Code Guardian v3 — Security Agent
====================================
Adopts deterministic security findings/evidence as the shared evidence
store the rest of the agent graph reasons over. The deterministic scanner
(guardian.core.pipeline.ScanPipeline) is the source of technical truth --
this agent does NOT re-detect vulnerabilities. The backend orchestration
entry point (backend/app/api/v1/agentic_scan.py) always runs the real
deterministic scan first and seeds state["findings"]/state["evidence"]
with its output before the graph starts, so in normal operation this
agent's job is adoption + severity aggregation only.

The lighter guardian.scanner._engine.SecurityRuleEngine scan below is kept
only as a defensive fallback for the case where this agent is invoked
directly with a bare repo_path and no pre-seeded findings (e.g. ad hoc /
test usage) -- it never runs when deterministic findings are already
present, so it can no longer produce a second, competing set of results
alongside the real scanner's.
NO LLM calls.
"""
from __future__ import annotations

import uuid
from pathlib import Path
from typing import Any, Dict, List

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import SecurityContext
from guardian.orchestrator.state import AgentWorkflowState


class SecurityAgent(BaseAgent):
    """Specialist agent wrapping deterministic security scanners."""

    name: str = "security"
    description: str = "Executes deterministic security scanning, taint tracking, and finding normalization."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["evidence_tool", "risk_tool"]

        profile = state.get("repository_profile", {})
        repo_path_str = profile.get("repo_path") or "."

        findings: List[Dict[str, Any]] = list(state.get("findings", []))
        evidence: List[Dict[str, Any]] = list(state.get("evidence", []))
        generated_evidence_ids: List[str] = []

        if findings:
            # Deterministic findings/evidence were already seeded into state
            # (the normal path -- see backend/app/api/v1/agentic_scan.py's
            # _adopt_deterministic_report). Adopt them as-is; do not re-scan.
            self._used_tools = ["evidence_tool", "risk_tool"]
            for ev in evidence:
                eid = ev.get("id") or ev.get("evidence_id")
                if eid:
                    generated_evidence_ids.append(eid)
            self.logger.info(
                f"Adopted {len(findings)} deterministic finding(s) / {len(evidence)} "
                f"evidence item(s) from the shared evidence store (no re-scan)."
            )
        else:
            # Defensive fallback only: this agent was invoked with no
            # pre-seeded deterministic findings at all (e.g. direct/ad hoc
            # use outside the Agentic Scan UI, which always runs the real
            # ScanPipeline first). Falls back to the lighter rule engine so
            # the agent still degrades gracefully rather than producing
            # nothing -- this is not the normal path and never runs
            # alongside real deterministic results.
            self._used_tools = ["parser_tool", "evidence_tool", "risk_tool"]
            repo_path = Path(repo_path_str)
            if repo_path.exists():
                try:
                    from guardian.scanner._engine import SecurityRuleEngine
                    engine = SecurityRuleEngine()
                    scan_res = engine.scan_directory(repo_path)
                    raw_findings = scan_res.findings if hasattr(scan_res, "findings") else []

                    for f in raw_findings:
                        f_id = getattr(f, "finding_id", str(uuid.uuid4()))
                        ev_id = f"ev:{f_id[:8]}"

                        category = getattr(f, "category", "security")
                        file_path = getattr(f, "file", "")
                        line_no = getattr(f, "line", 0)
                        recommendation = getattr(f, "recommendation", "")

                        normalized_finding = {
                            "finding_id": f_id,
                            "rule_id": getattr(f, "rule_id", "SEC-UNKNOWN"),
                            "title": category or "Security Vulnerability",
                            "severity": str(getattr(f, "severity", "MEDIUM")).upper(),
                            "category": category,
                            "file": file_path,
                            "line": line_no,
                            "file_path": file_path,
                            "line_number": line_no,
                            "snippet": getattr(f, "snippet", ""),
                            "description": recommendation,
                            "recommendation": recommendation,
                            "language": getattr(f, "language", None),
                            "confidence": 0.95,
                            "evidence_ids": [ev_id],
                            "evidence_id": ev_id,
                        }
                        findings.append(normalized_finding)

                        evidence_obj = {
                            "id": ev_id,
                            "evidence_id": ev_id,
                            "finding_id": f_id,
                            "file": file_path,
                            "line": line_no,
                            "snippet": getattr(f, "snippet", ""),
                            "code_snippet": getattr(f, "snippet", ""),
                            "source": "deterministic_sast_fallback",
                            "engine": "deterministic_sast_fallback",
                        }
                        evidence.append(evidence_obj)
                        generated_evidence_ids.append(ev_id)
                except Exception as e:
                    self.logger.warning(f"Fallback scanner invocation notice: {e}")

        self._generated_evidence_ids = generated_evidence_ids

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            else:
                severity_counts["MEDIUM"] += 1

        sec_context: SecurityContext = {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
            "engine_counts": {"sast": len(findings)},
            "scanned_files_count": profile.get("total_files", 0),
            "taint_paths_count": 0,
            "secret_findings_count": sum(1 for f in findings if "secret" in (f.get("rule_id") or "").lower()),
            "iac_findings_count": 0,
            "quantum_findings_count": 0,
        }

        new_state = dict(state)
        new_state["findings"] = findings
        new_state["evidence"] = evidence
        new_state["security_context"] = dict(sec_context)
        return new_state
