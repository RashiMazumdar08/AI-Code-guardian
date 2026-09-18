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
            "summary": f"Target repository with primary language {languages} using frameworks {frameworks}.",
        }

        new_state = dict(state)
        new_state["repository_context"] = context
        return new_state
