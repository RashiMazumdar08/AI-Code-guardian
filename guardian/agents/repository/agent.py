"""
AI Code Guardian v3 — Repository Agent
======================================
Deterministically aggregates repository structure, frameworks, entry points,
public APIs, authentication modules, database layers, and high-risk paths.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import RepositoryContext
from guardian.orchestrator.state import AgentWorkflowState


class RepositoryAgent(BaseAgent):
    """Specialist agent analyzing and summarizing repository structure."""

    name: str = "repository"
    description: str = "Analyzes repository structure, entry points, APIs, and framework signatures."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["repository_graph_tool", "knowledge_tool"]

        profile = state.get("repository_profile", {})
        repo_graph = state.get("repository_graph", {})

        languages = [profile.get("primary_language")] if profile.get("primary_language") else []
        frameworks = profile.get("frameworks", [])
        entry_points = profile.get("entry_points", [])
        public_apis = profile.get("detected_endpoints", [])
        security_markers = profile.get("security_markers", [])

        # Categorize auth modules & DB layers from markers/frameworks
        auth_modules = [m for m in security_markers if any(k in m.lower() for k in ["auth", "jwt", "login", "session", "oauth"])]
        db_layers = [f for f in frameworks if any(k in f.lower() for k in ["sql", "mongo", "postgres", "redis", "orm", "db"])]
        infra = [f for f in profile.get("build_tools", [])] + [f for f in profile.get("manifest_files", [])]

        # High risk directories & high value assets
        high_risk_dirs = ["auth/", "security/", "config/", "api/", "routes/", "admin/"]
        high_value_assets = entry_points + public_apis

        # Compute deterministic endpoint-level authentication coverage using workspace AST profiles
        endpoint_coverage: Dict[str, Any] = {
            "total_route_endpoints": 0,
            "authenticated_endpoints_count": 0,
            "unauthenticated_endpoints_count": 0,
            "auth_coverage_pct": 0.0,
            "representative_unauthenticated_endpoints": [],
        }
        try:
            from guardian.intent.matcher.rule_matcher import RuleMatcher
            ws_profiles = RuleMatcher._profiles_from_workspace()
            auth_keywords = ["auth", "jwt", "login", "permission", "role", "authorize", "bearer", "session", "depends", "security"]
            route_profiles = []
            for wp in ws_profiles:
                snippet_lower = (wp.function_name + " " + wp.code_snippet).lower()
                is_route = any(k in snippet_lower for k in ["@app.route", "@router.", "@get", "@post", "@put", "@delete", "@patch", "apirouter", "getmapping", "postmapping", "requestmapping"])
                if is_route:
                    has_auth = any(ak in snippet_lower for ak in auth_keywords) or any(any(ak in c.lower() for ak in auth_keywords) for c in wp.controls)
                    route_profiles.append({
                        "file": wp.file,
                        "line": wp.line,
                        "function": wp.function_name,
                        "has_auth": has_auth,
                        "controls": wp.controls,
                    })
            if route_profiles:
                total_eps = len(route_profiles)
                auth_eps = sum(1 for r in route_profiles if r["has_auth"])
                no_auth_eps = total_eps - auth_eps
                pct = round((auth_eps / total_eps) * 100, 1)

                unauth_samples = [
                    f"{r['file']}:{r['line']} | {r['function']}"
                    for r in route_profiles if not r["has_auth"]
                ][:5]

                endpoint_coverage = {
                    "total_route_endpoints": total_eps,
                    "authenticated_endpoints_count": auth_eps,
                    "unauthenticated_endpoints_count": no_auth_eps,
                    "auth_coverage_pct": pct,
                    "representative_unauthenticated_endpoints": unauth_samples,
                }
            elif public_apis:
                total_eps = len(public_apis)
                endpoint_coverage = {
                    "total_route_endpoints": total_eps,
                    "authenticated_endpoints_count": 0 if not auth_modules else total_eps,
                    "unauthenticated_endpoints_count": total_eps if not auth_modules else 0,
                    "auth_coverage_pct": 100.0 if auth_modules else 0.0,
                    "representative_unauthenticated_endpoints": public_apis[:5] if not auth_modules else [],
                }
        except Exception as exc:
            self.logger.warning("Endpoint auth coverage computation notice: %s", exc)

        context: RepositoryContext = {
            "languages": languages,
            "frameworks": frameworks,
            "entry_points": entry_points,
            "auth_modules": auth_modules,
            "database_layers": db_layers,
            "infrastructure": infra,
            "public_apis": public_apis,
            "high_risk_directories": high_risk_dirs,
            "high_value_assets": high_value_assets,
            "architecture_type": profile.get("architecture", "monolith"),
            "is_monorepo": profile.get("is_monorepo", False),
            "endpoint_coverage": endpoint_coverage,
            "summary": f"Target repository with primary language {languages} using frameworks {frameworks}.",
        }

        new_state = dict(state)
        new_state["repository_context"] = context
        return new_state
