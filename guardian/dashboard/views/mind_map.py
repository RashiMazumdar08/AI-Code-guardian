"""
AI Code Guardian v3 — Repository Mind Map Page
==============================================
Renders hierarchical Mind Map tree breakdown of repository modules, entry points,
security rules, and vulnerable paths.
"""
from __future__ import annotations

from typing import Any, Dict, List
from guardian.dashboard.models.dashboard_state import DashboardStateView


class MindMapViewPage:
    """Renders Repository Mind Map view."""

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        profile = state_view.repository_profile
        repo_ctx = state_view.repository_context
        findings = state_view.findings

        # Build hierarchical tree model
        vulnerable_files = {f.get("file_path") for f in findings if f.get("file_path")}

        tree = {
            "name": profile.get("repo_path", "Repository Root"),
            "type": "root",
            "children": [
                {
                    "name": "Entry Points",
                    "type": "category",
                    "children": [{"name": ep, "type": "file", "vulnerable": ep in vulnerable_files} for ep in repo_ctx.get("entry_points", ["main.py"])],
                },
                {
                    "name": "Auth Modules",
                    "type": "category",
                    "children": [{"name": am, "type": "file", "vulnerable": am in vulnerable_files} for am in repo_ctx.get("auth_modules", ["auth"])],
                },
                {
                    "name": "Database Layers",
                    "type": "category",
                    "children": [{"name": db, "type": "component", "vulnerable": False} for db in repo_ctx.get("database_technologies", ["PostgreSQL"])],
                },
                {
                    "name": "Vulnerable Paths",
                    "type": "category",
                    "children": [{"name": vf, "type": "vulnerable_file", "vulnerable": True} for vf in list(vulnerable_files)[:10]],
                },
            ],
        }

        return {
            "page_title": "Repository Mind Map",
            "tree": tree,
            "total_vulnerable_paths": len(vulnerable_files),
        }
