"""
AI Code Guardian v3 — Architecture Agent
=========================================
Specialist agent analyzing system topology, service boundaries, authentication flows,
database relationships, trust boundaries, and API interfaces using KnowledgeService.
"""
from __future__ import annotations

from typing import Any, Dict

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import ArchitectureContext
from guardian.orchestrator.state import AgentWorkflowState


class ArchitectureAgent(BaseAgent):
    """Specialist agent deriving architectural topologies and boundaries."""

    name: str = "architecture"
    description: str = "Analyzes service boundaries, authentication flows, and trust boundaries."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["repository_graph_tool", "knowledge_tool"]

        profile = state.get("repository_profile", {})
        repo_ctx = state.get("repository_context", {})

        # Derive service boundaries and trust boundaries deterministically
        endpoints = profile.get("detected_endpoints", [])
        entry_points = profile.get("entry_points", [])
        frameworks = profile.get("frameworks", [])

        service_boundaries = [f"service:{profile.get('primary_language', 'core')}"]
        auth_flows = repo_ctx.get("auth_modules", ["Session/JWT Authentication Header"])
        db_interactions = repo_ctx.get("database_layers", ["ORM Data Access Layer"])
        api_relationships = [f"API Endpoint: {ep}" for ep in endpoints[:5]]
        external_integrations = [f for f in frameworks if f in ["FastAPI", "Spring Boot", "NestJS", "Actix-web"]]

        # Trust boundaries were previously hardcoded to the same two strings
        # for every repository regardless of any actual signal. Derive them
        # instead from the real, per-repo signals already computed above
        # (detected endpoints/entry points from guardian.discovery.repo_detector's
        # content-signature regex scan, and database_layers surfaced through
        # RepositoryAgent from real framework detections) -- never claim a
        # boundary crossing the repository doesn't actually show evidence of.
        # Real data only -- an empty list here is a real result ("no trust
        # boundary crossing was evidenced"), not an omission. The report
        # layer (guardian/reporting/report_view_model.py) is responsible for
        # turning an empty list into an honest plain-English sentence, the
        # same pattern already used for NO_ATTACK_PATH / SECURITY_STATUS_UNKNOWN
        # -- this agent never synthesizes user-facing prose itself.
        trust_boundaries: list[str] = []
        if endpoints or entry_points:
            trust_boundaries.append(
                "Public HTTP Gateway -> Application Controller "
                f"(evidenced by {len(endpoints)} detected endpoint(s) / "
                f"{len(entry_points)} entry point(s))"
            )
        if repo_ctx.get("database_layers"):
            trust_boundaries.append(
                "Application Layer -> Database "
                f"(evidenced by database layer(s): {', '.join(repo_ctx.get('database_layers', []))})"
            )

        critical_components = entry_points + auth_flows

        # Optional Grok AI reasoning for architectural risk & topology interpretation
        ai_architecture_insights = []
        grok_status: str = "SKIPPED"
        agent_reason: str = "Architecture agent reasoning not invoked."
        try:
            from guardian.llm.config import LLMConfig
            from guardian.llm.rate_limit_handler import classify_llm_error
            cfg = LLMConfig.from_env()
            if cfg.is_agent_enabled("architecture"):
                findings = state.get("findings", [])
                should_call_grok = len(trust_boundaries) > 1 or len(endpoints) > 3 or len(external_integrations) > 0 or len(findings) > 0
                if should_call_grok:
                    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
                    service = ReasoningGateway(config=cfg)
                    if service.configured:
                        ep_coverage = repo_ctx.get("endpoint_coverage", {})
                        auth_mech_str = ", ".join(auth_flows) if auth_flows else "No global auth module detected"

                        arch_ev_items = [
                            f"[E1] Service boundaries: {service_boundaries}",
                            f"[E2] Authentication mechanism: {auth_mech_str}",
                            f"[E3] DB interactions: {db_interactions}",
                            f"[E4] Trust boundaries: {trust_boundaries}",
                        ]

                        if ep_coverage and ep_coverage.get("total_route_endpoints", 0) > 0:
                            total_eps = ep_coverage.get("total_route_endpoints", 0)
                            auth_cnt = ep_coverage.get("authenticated_endpoints_count", 0)
                            unauth_cnt = ep_coverage.get("unauthenticated_endpoints_count", 0)
                            pct = ep_coverage.get("auth_coverage_pct", 0.0)
                            unauth_list = ep_coverage.get("representative_unauthenticated_endpoints", [])

                            arch_ev_items.append(
                                f"[E5] Endpoint authentication coverage: {total_eps} route endpoints detected, "
                                f"{auth_cnt} with route-level authentication, "
                                f"{unauth_cnt} without detected route-level authentication (Coverage: {pct}%)"
                            )
                            if unauth_list:
                                arch_ev_items.append(
                                    f"[E6] Representative endpoints without detected route-level authentication: {', '.join(unauth_list)}"
                                )
                        else:
                            arch_ev_items.append(f"[E5] API Endpoints: {api_relationships[:5]}")

                        req = ReasoningRequest(
                            task="architecture_reasoning",
                            agent="architecture",
                            scan_id=state.get("scan_id", ""),
                            instruction=(
                                "Analyze deterministic service boundaries, call topologies, API relationships, and framework evidence. "
                                "Identify architectural security risks, trust boundary violations, authentication gaps, or unusual structural patterns."
                            ),
                            evidence_block="\n".join(arch_ev_items),
                            max_tokens=500,
                            reasoning_effort="low",
                        )
                        ai_res = service.reason(req)
                        if ai_res.ok:
                            grok_status = "COMPLETED"
                            agent_reason = "ArchitectureAgent executed successfully."
                            if ai_res.findings:
                                import hashlib
                                for rf in ai_res.findings:
                                    d = rf.to_dict()
                                    stable_basis = f"{d.get('title', '')}|{d.get('reason', '')}|{d.get('file', '')}|{d.get('line', 0)}|{d.get('function', '')}"
                                    stable_hash = hashlib.md5(stable_basis.encode("utf-8", errors="ignore")).hexdigest()[:12]
                                    d["id"] = f"ARCH-INSIGHT-{stable_hash}"
                                    d["insight_id"] = d["id"]
                                    ai_architecture_insights.append(d)
                                self.logger.info("Grok AI architecture reasoning produced %d insight(s)", len(ai_res.findings))
                        else:
                            err_text = getattr(ai_res, "error", None) or getattr(ai_res, "error_message", None) or ""
                            status_type = classify_llm_error(err_text)
                            if status_type == "SKIPPED_BUDGET":
                                grok_status = "SKIPPED_BUDGET"
                                agent_reason = "AI Architecture Analysis was skipped to preserve token budget for other scan priorities. Deterministic topology is unaffected."
                            elif status_type == "PROVIDER_DAILY_QUOTA":
                                grok_status = "PROVIDER_DAILY_QUOTA"
                                agent_reason = "AI reasoning could not run because the LLM provider's daily token quota (TPD) was exhausted. Deterministic topology is fully preserved."
                            elif status_type == "RATE_LIMITED":
                                grok_status = "RATE_LIMITED"
                                agent_reason = "AI Architecture Analysis is rate-limited by the provider (TPM limit). Deterministic topology is fully preserved."
                            else:
                                grok_status = "PROVIDER_UNAVAILABLE"
                                agent_reason = err_text or "AI Architecture Analysis service is temporarily unavailable."
                    else:
                        grok_status = "SKIPPED"
                        agent_reason = "Reasoning service not configured."
                else:
                    grok_status = "SKIPPED"
                    agent_reason = "Structural baseline sufficient."
            else:
                grok_status = "SKIPPED"
                agent_reason = "AI Architecture Agent reasoning is disabled."
        except Exception as exc:
            self.logger.warning("Optional Grok AI architecture reasoning notice: %s", exc)
            status_type = classify_llm_error(exc)
            grok_status = status_type if status_type in ("PROVIDER_DAILY_QUOTA", "RATE_LIMITED", "SKIPPED_BUDGET") else "PROVIDER_UNAVAILABLE"
            agent_reason = f"AI Architecture Analysis notice: {exc}"

        arch_context: ArchitectureContext = {
            "service_boundaries": service_boundaries,
            "authentication_flows": auth_flows,
            "database_interactions": db_interactions,
            "api_relationships": api_relationships,
            "external_integrations": external_integrations,
            "trust_boundaries": trust_boundaries,
            "critical_components": critical_components,
            "grok_status": grok_status,
            "agent_reason": agent_reason,
        }

        new_state = dict(state)
        new_state["architecture_context"] = dict(arch_context)
        if ai_architecture_insights:
            new_state["ai_architecture_insights"] = ai_architecture_insights
        return new_state

