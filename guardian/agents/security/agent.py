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
from guardian.llm.rate_limit_handler import classify_llm_error
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

        # Optional Grok AI reasoning pass for semantic security insights
        ai_insights: List[Dict[str, Any]] = []
        grok_status: str = "SKIPPED"
        agent_reason: str = "The deterministic security analysis produced a sufficiently conclusive baseline, so additional AI reasoning was not invoked."

        try:
            from guardian.llm.config import LLMConfig
            cfg = LLMConfig.from_env()
            if cfg.is_security_ai_enabled():
                has_high_risk_findings = any(f.get("severity", "MEDIUM").upper() in ("CRITICAL", "HIGH") or f.get("confidence", 1.0) < 0.70 for f in findings)
                has_auth_sql_keywords = any(any(kw in str(f.get("rule_id", "") + f.get("title", "")).lower() for kw in ["auth", "sql", "exec", "cmd", "secret", "token"]) for f in findings)

                ws_profiles = []
                try:
                    from guardian.intent.matcher.rule_matcher import RuleMatcher
                    repo_p = Path(repo_path_str) if repo_path_str else None
                    ws_profiles = RuleMatcher._profiles_from_workspace(repo_p)
                except Exception:
                    pass

                should_call_grok = (len(findings) == 0 and len(ws_profiles) > 0) or has_high_risk_findings or has_auth_sql_keywords
                if should_call_grok:
                    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
                    service = ReasoningGateway(config=cfg)
                    if service.configured:
                        ev_lines = []
                        for ev in evidence[:10]:
                            ev_id = ev.get("id") or ev.get("evidence_id") or "E1"
                            ev_lines.append(
                                f"[{ev_id}] file: {ev.get('file', '')}:{ev.get('line', 0)} "
                                f"snippet: {ev.get('snippet', '') or ev.get('code_snippet', '')}"
                            )

                        if ws_profiles:
                            # Sort workspace profiles by general security relevance score descending
                            sorted_profiles = sorted(
                                ws_profiles,
                                key=lambda p: getattr(p, "security_score", 0.0),
                                reverse=True
                            )
                            existing_files_lines = {(ev.get("file"), ev.get("line")) for ev in evidence}
                            candidate_profiles = [p for p in sorted_profiles if (p.file, p.line) not in existing_files_lines]

                            for idx, wp in enumerate(candidate_profiles[:5]):
                                wp_ev_id = f"E{len(ev_lines)+1}"
                                snippet = getattr(wp, "code_snippet", "")
                                snippet_block = f"\nSource Snippet:\n{snippet}" if snippet else ""
                                ev_lines.append(
                                    f"[{wp_ev_id}] file: {wp.file}:{wp.line} function: {wp.function_name} "
                                    f"actions: {','.join(wp.actions[:3])} controls: {','.join(wp.controls[:3])}"
                                    f"{snippet_block}"
                                )

                        ev_block = "\n".join(ev_lines) if ev_lines else "[E1] General repository security context"

                        req = ReasoningRequest(
                            task="security_reasoning",
                            agent="security",
                            scan_id=state.get("scan_id", ""),
                            instruction=(
                                "Analyze the deterministic security evidence and identify potential semantic gaps, "
                                "complex framework-specific vulnerabilities, or exploitability risks. "
                                "Cite provided evidence IDs."
                            ),
                            evidence_block=ev_block,
                            max_tokens=400,
                        )
                        ai_res = service.reason(req)
                        if ai_res.ok:
                            grok_status = "COMPLETED"
                            if ai_res.findings:
                                agent_reason = "AI Security Analysis completed successfully with verified semantic findings."
                                for rf in ai_res.findings:
                                    ai_f_id = f"ai-sec-{uuid.uuid4().hex[:8]}"
                                    ai_ev_id = rf.evidence_ids[0] if rf.evidence_ids else "E1"
                                    ai_finding = {
                                        "finding_id": ai_f_id,
                                        "rule_id": f"AI-SEC-{(rf.category or 'SEMANTIC')[:15].upper()}",
                                        "title": rf.title or rf.category or "Semantic Security Vulnerability",
                                        "severity": rf.severity.upper() if rf.severity else "MEDIUM",
                                        "category": rf.category or "security",
                                        "file": rf.file or "app.py",
                                        "line": rf.line or 1,
                                        "file_path": rf.file or "app.py",
                                        "line_number": rf.line or 1,
                                        "snippet": rf.reason or "",
                                        "description": rf.reason,
                                        "recommendation": rf.recommendation,
                                        "confidence": min(rf.confidence or 0.8, 0.9),
                                        "evidence_ids": [ai_ev_id],
                                        "evidence_id": ai_ev_id,
                                        "source": "AI_VALIDATED",
                                        "engine": "grok_security_reasoning",
                                    }
                                    findings.append(ai_finding)
                                    ai_insights.append(ai_finding)
                                    self.logger.info("Added Grok AI security finding: %s", ai_finding["rule_id"])
                            else:
                                agent_reason = "SecurityAgent executed successfully and verified no additional semantic AI security findings."
                        else:
                            err_text = getattr(ai_res, "error", None) or getattr(ai_res, "error_message", None) or ""
                            status_type = classify_llm_error(err_text)
                            if status_type == "SKIPPED_BUDGET":
                                grok_status = "SKIPPED_BUDGET"
                                agent_reason = "AI Security Analysis was skipped to preserve token budget for other scan priorities. Deterministic baseline findings are unaffected."
                            elif status_type == "PROVIDER_DAILY_QUOTA":
                                grok_status = "PROVIDER_DAILY_QUOTA"
                                agent_reason = "AI reasoning could not run because the LLM provider's daily token quota (TPD) was exhausted. Deterministic findings are fully preserved."
                            elif status_type == "RATE_LIMITED":
                                grok_status = "RATE_LIMITED"
                                agent_reason = "AI Security Analysis is temporarily rate limited by the provider (TPM limit). Deterministic findings are fully preserved."
                            else:
                                grok_status = "PROVIDER_UNAVAILABLE"
                                agent_reason = err_text or "AI Security Analysis service is temporarily unavailable."
                    else:
                        grok_status = "SKIPPED"
                        agent_reason = "Reasoning service not configured."
                else:
                    grok_status = "SKIPPED"
                    agent_reason = "The deterministic security analysis produced a sufficiently conclusive baseline, so additional AI reasoning was not invoked."
            else:
                grok_status = "DISABLED_BY_CONFIG"
                agent_reason = "AI Security Analysis is disabled by configuration (SECURITY_AGENT_ENABLED=false). Deterministic baseline security analysis remains active."
        except Exception as exc:
            self.logger.warning("Optional Grok AI security reasoning notice: %s", exc)
            status_type = classify_llm_error(exc)
            grok_status = status_type if status_type in ("PROVIDER_DAILY_QUOTA", "RATE_LIMITED", "SKIPPED_BUDGET") else "PROVIDER_UNAVAILABLE"
            agent_reason = f"AI Security Analysis notice: {exc}"

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
            "grok_status": grok_status,
            "agent_reason": agent_reason,
        }

        new_state = dict(state)
        new_state["findings"] = findings
        new_state["evidence"] = evidence
        new_state["security_context"] = dict(sec_context)
        if ai_insights:
            new_state["ai_security_insights"] = ai_insights
        else:
            new_state.pop("ai_security_insights", None)
        return new_state

