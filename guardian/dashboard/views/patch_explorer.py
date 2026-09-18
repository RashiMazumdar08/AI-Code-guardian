"""
AI Code Guardian v3 — Patch Explorer Page
=========================================
Displays grounded patch proposals, unified git diffs, side-by-side code diffs, and developer explanations.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.components.code_diff_viewer import CodeDiffViewerComponent
from guardian.dashboard.models.dashboard_state import DashboardStateView


class PatchExplorerPage:
    """Renders Patch Explorer view."""

    def __init__(self, diff_viewer: Optional[CodeDiffViewerComponent] = None) -> None:
        self.diff_viewer = diff_viewer or CodeDiffViewerComponent()

    def render(self, state_view: DashboardStateView, selected_patch_id: Optional[str] = None) -> Dict[str, Any]:
        patches = state_view.patches
        combined_diff = state_view.git_diff
        explanation = state_view.developer_explanation

        selected = None
        if selected_patch_id:
            selected = next((p for p in patches if p.get("patch_id") == selected_patch_id), None)
        if not selected and patches:
            selected = patches[0]

        diff_html = ""
        if selected:
            diff_html = self.diff_viewer.render(
                file_path=selected.get("affected_file", ""),
                original_code=selected.get("original_snippet", ""),
                replacement_code=selected.get("suggested_replacement", ""),
                git_diff=selected.get("git_diff", "")
            )

        return {
            "page_title": "Patch Explorer",
            "total_patches": len(patches),
            "patches": patches,
            "selected_patch": selected,
            "diff_html": diff_html,
            "git_diff_full": combined_diff,
            "developer_explanation": explanation,
        }
