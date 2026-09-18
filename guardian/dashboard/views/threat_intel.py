"""
AI Code Guardian v3 — Threat Intelligence Page
==============================================
Visualizes attack paths, exploit chains, reachability weights, critical assets, and entry points.
"""
from __future__ import annotations

from typing import Any, Dict
from guardian.dashboard.models.dashboard_state import DashboardStateView


class ThreatIntelViewPage:
    """Renders Threat Intelligence View."""

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        threat_ctx = state_view.threat_context
        biz_ctx = state_view.business_context
        findings = state_view.findings

        # Compute attack vectors based on findings and reachability
        attack_paths = []
        for idx, f in enumerate(findings):
            if f.get("severity") in ("CRITICAL", "HIGH"):
                attack_paths.append({
                    "path_id": f"AP-00{idx+1}",
                    "entry_point": f.get("file_path", "main.py"),
                    "vulnerability": f.get("rule_id", "SEC-001"),
                    "target_asset": biz_ctx.get("critical_assets", ["user_data"])[0] if biz_ctx.get("critical_assets") else "user_data",
                    "exploitability": threat_ctx.get("exploitability", 0.85),
                    "reachability": threat_ctx.get("reachability", 0.90),
                    "risk_impact": f.get("severity", "HIGH"),
                })

        return {
            "page_title": "Threat Intelligence & Attack Vector Explorer",
            "exploitability_score": threat_ctx.get("exploitability", 0.75),
            "reachability_weight": threat_ctx.get("reachability", 0.80),
            "attack_paths": attack_paths,
            "total_attack_paths": len(attack_paths),
            "critical_assets": biz_ctx.get("critical_assets", ["user_data", "auth_service"]),
        }
