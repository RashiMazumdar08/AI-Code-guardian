"""
AI Code Guardian v3 — Validation Dashboard Page
===============================================
Displays AST syntax checks, grounding status, mechanical re-verification results, and passed/rejected patches.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.models.dashboard_state import DashboardStateView


class ValidationDashboardPage:
    """Renders Validation Dashboard view."""

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        val_results = state_view.validation_results

        passed = [v for v in val_results if v.get("status") == "PASSED"]
        rejected = [v for v in val_results if v.get("status") == "REJECTED"]

        return {
            "page_title": "Validation & Mechanical Re-Verification Dashboard",
            "total_validated": len(val_results),
            "passed_count": len(passed),
            "rejected_count": len(rejected),
            "passed_patches": passed,
            "rejected_patches": rejected,
            "all_results": val_results,
        }
