"""
AI Code Guardian v3 — Threat Simulation Agent
==============================================
Simulates realistic attacker behavior by evaluating reachability, exploitability,
and attack chains directly grounded in deterministic findings and evidence IDs.
NEVER fabricates vulnerabilities.
"""
from __future__ import annotations

from typing import Any, Dict, List

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import ThreatContext
from guardian.orchestrator.state import AgentWorkflowState


class ThreatSimulationAgent(BaseAgent):
    """Specialist agent modeling attack paths and exploitability grounded in findings."""

    name: str = "threat_simulation"
    description: str = "Simulates attack paths, privilege escalation, and reachability grounded in evidence."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["knowledge_tool", "evidence_tool"]

        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        repo_ctx = state.get("repository_context", {})
        arch_ctx = state.get("architecture_context", {})
        biz_ctx = state.get("business_context", {})

        # Threat Gate: Skip expensive Threat Simulation if no attack paths or security-relevant conditions exist
        if not findings and not evidence and not repo_ctx.get("entry_points"):
            self.logger.info("Threat Gate: Skipping Threat Simulation (no attack paths or security conditions found)")
            threat_ctx: ThreatContext = {
                "status": "SKIPPED_NO_ATTACK_PATHS",
                "skipped": True,
                "reason": "No security findings or entry point attack paths identified in repository context.",
                "exploitability": 0.0,
                "reachability": 0.0,
                "attack_paths": [],
                "privilege_escalation_risk": "LOW",
                "lateral_movement_risk": "LOW",
                "auth_bypass_risk": "LOW",
                "data_exposure_risk": "LOW",
                "business_impact": "LOW",
            }
            new_state = dict(state)
            new_state["threat_context"] = dict(threat_ctx)
            new_state["attack_paths"] = []
            new_state["exploitability"] = 0.0
            return new_state

        attack_paths: List[Dict[str, Any]] = []
        max_exploitability = 0.0

        for f in findings:
            f_id = f.get("finding_id", "")
            rule_id = f.get("rule_id", "")
            ev_id = f.get("evidence_id", "")
            file_path = f.get("file_path", "")
            sev = f.get("severity", "MEDIUM").upper()

            # Prefer the deterministic taint/dataflow engine's OWN exploitability
            # signal when it actually traced this finding (guardian/engines/
            # security.py::_analyze_file sets Finding.tainted/is_exploitable/
            # exploitability_score/exploit_scenario whenever it confirmed a real
            # source -> sink dataflow -- see guardian.core.models.Finding). That
            # is real, per-finding, evidence-backed analysis; this agent was
            # previously ignoring it entirely and recomputing a cruder
            # entry-point-name heuristic from scratch even for findings the
            # engine had already confirmed reachable. Most findings never go
            # through the taint tracer (regex-based detectors, dependency
            # findings, etc.), so the heuristic below remains the fallback for
            # those -- this is additive, not a replacement of the heuristic.
            is_tainted = bool(f.get("tainted"))
            det_score = f.get("exploitability_score")
            has_real_taint_score = is_tainted and isinstance(det_score, (int, float)) and det_score > 0

            is_entry_point = any(file_path.endswith(ep) for ep in repo_ctx.get("entry_points", [])) or "api" in file_path.lower()

            if has_real_taint_score:
                exploitability = float(det_score)
                reachability = "DIRECT"  # a confirmed source->sink dataflow IS a direct reachable path
                grounding = "deterministic taint analysis (confirmed data-flow to a dangerous sink)"
            else:
                exploitability = 0.95 if (sev == "CRITICAL" and is_entry_point) else (0.80 if is_entry_point else 0.50)
                reachability = "DIRECT" if is_entry_point else "INDIRECT"
                grounding = "heuristic (entry-point file-name matching, no confirmed data-flow)"

            # Aggregate exploitability/reachability signals (below) still
            # consider EVERY finding, not just the ones that clear the
            # attack-chain bar -- only the attack_paths list itself is
            # filtered, so risk_fusion's inputs are unaffected.
            if exploitability > max_exploitability:
                max_exploitability = exploitability

            # Not every finding is a meaningful attack chain. An attack path is
            # only modeled here when the finding has a confirmed taint-based
            # dataflow, is reachable from a real entry point, or is severe
            # enough that an indirect chain is still worth surfacing -- using
            # exactly the signals already computed above, nothing invented.
            is_attack_chain_candidate = is_tainted or is_entry_point or sev in ("CRITICAL", "HIGH")
            if not is_attack_chain_candidate:
                continue

            path_obj = {
                "finding_id": f_id,
                "evidence_id": ev_id,
                "title": f"Attack Chain via {rule_id} in {file_path}",
                "entry_point": file_path if is_entry_point else repo_ctx.get("public_apis", ["/api"])[0] if repo_ctx.get("public_apis") else "main.py",
                "target_file": file_path,
                "exploitability": exploitability,
                "reachability": reachability,
                "attack_vector": "HTTP/API Request" if is_entry_point else "Internal Subroutine",
                # Real, honest labeling of what produced this score (Section 9's
                # "never claim confirmed if only inferred" requirement) -- never
                # shown to the user as more certain than this actually says.
                "exploitability_basis": grounding,
                # The taint engine's own real scenario string when it traced
                # one; the report layer falls back to its own plain-English
                # reachability sentence when this is empty -- never invented
                # here.
                "exploit_scenario": f.get("exploit_scenario") or "",
            }
            attack_paths.append(path_obj)

        has_auth_bypass = any("auth" in f.get("rule_id", "").lower() for f in findings)
        has_secret_exposure = any("secret" in f.get("rule_id", "").lower() for f in findings)

        # Optional Grok AI reasoning pass for multi-step attack scenario correlation
        ai_threat_insights = []
        try:
            from guardian.llm.config import LLMConfig
            cfg = LLMConfig.from_env()
            if cfg.is_agent_enabled("threat_simulation"):
                should_call_grok = len(attack_paths) > 0 or has_auth_bypass or has_secret_exposure
                if should_call_grok:
                    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
                    service = ReasoningGateway(config=cfg)
                    if service.configured:
                        path_lines = []
                        for i, p in enumerate(attack_paths[:5]):
                            path_lines.append(
                                f"[E{i+1}] Finding: {p.get('finding_id')} | Entry: {p.get('entry_point')} | Target: {p.get('target_file')} | "
                                f"Reachability: {p.get('reachability')} ({p.get('exploitability_basis', '')}) | Vector: {p.get('attack_vector')} | "
                                f"Scenario: {p.get('exploit_scenario', '') or 'unrestricted route'}"
                            )
                        if not path_lines:
                            path_lines.append(
                                f"[E1] General system entry points | Public APIs: {repo_ctx.get('public_apis', [])} | "
                                f"Auth Bypass Risk: {has_auth_bypass} | Secret Exposure: {has_secret_exposure}"
                            )

                        path_summary = "\n".join(path_lines)

                        req = ReasoningRequest(
                            task="threat_reasoning",
                            agent="threat_simulation",
                            scan_id=state.get("scan_id", ""),
                            instruction=(
                                "Evaluate the attack paths, entry points, and findings. Reason about realistic multi-step exploitation chains, "
                                "privilege escalation, trust boundary crossings, and chained vulnerability risks. Cite evidence IDs."
                            ),
                            evidence_block=path_summary,
                            max_tokens=350,
                        )
                        ai_res = service.reason(req)
                        if ai_res.ok and ai_res.findings:
                            for rf in ai_res.findings:
                                ai_threat_insights.append(rf.to_dict())
                            self.logger.info("Grok AI threat reasoning produced %d insight(s)", len(ai_res.findings))
        except Exception as exc:
            self.logger.warning("Optional Grok AI threat reasoning notice: %s", exc)

        threat_ctx: ThreatContext = {
            "exploitability": max_exploitability,
            "reachability": 0.90 if any(p["reachability"] == "DIRECT" for p in attack_paths) else 0.60,
            "attack_paths": attack_paths,
            "privilege_escalation_risk": "HIGH" if has_auth_bypass else "LOW",
            "lateral_movement_risk": "MEDIUM" if len(arch_ctx.get("service_boundaries", [])) > 1 else "LOW",
            "auth_bypass_risk": "HIGH" if has_auth_bypass else "LOW",
            "data_exposure_risk": "HIGH" if has_secret_exposure else "LOW",
            "business_impact": "CRITICAL" if biz_ctx.get("criticality") == "CRITICAL" and max_exploitability >= 0.8 else "HIGH" if max_exploitability >= 0.8 else "MODERATE",
        }

        new_state = dict(state)
        new_state["threat_context"] = dict(threat_ctx)
        new_state["attack_paths"] = attack_paths
        new_state["exploitability"] = max_exploitability
        if ai_threat_insights:
            new_state["ai_threat_insights"] = ai_threat_insights
        return new_state

