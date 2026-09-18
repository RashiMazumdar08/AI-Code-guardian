"""
AI Code Guardian v3 — Repository Overview Page
==============================================
Renders repository profile, languages, frameworks, entry points, auth modules, DBs, and health metrics.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.models.dashboard_state import DashboardStateView


class RepositoryOverviewPage:
    """Renders Repository Overview dashboard view."""

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        profile = state_view.repository_profile
        repo_ctx = state_view.repository_context
        biz_ctx = state_view.business_context

        return {
            "page_title": "Repository Overview",
            "repo_path": profile.get("repo_path", "N/A"),
            "primary_language": profile.get("primary_language", "Python"),
            "frameworks": profile.get("frameworks", []),
            "entry_points": profile.get("entry_points", repo_ctx.get("entry_points", [])),
            "auth_modules": repo_ctx.get("authentication_modules", []),
            "database_technologies": repo_ctx.get("database_technologies", []),
            "business_domain": biz_ctx.get("domain", "general"),
            "criticality": biz_ctx.get("criticality", "NORMAL"),
            "critical_assets": biz_ctx.get("critical_assets", []),
        }
