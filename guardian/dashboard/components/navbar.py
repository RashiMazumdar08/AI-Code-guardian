"""
AI Code Guardian v3 — Dashboard Navigation Bar Component
=========================================================
"""
from __future__ import annotations

from typing import List


class NavigationBarComponent:
    """Renders top header navigation tabs for the Enterprise Dashboard."""

    def __init__(self, tabs: Optional[List[str]] = None) -> None:
        self.tabs = tabs or [
            "Overview",
            "Knowledge Graph",
            "Workflow Timeline",
            "Agent Trace",
            "Evidence Explorer",
            "Risk Dashboard",
            "Patch Explorer",
            "Validation Dashboard",
            "Metrics Dashboard",
            "Export Center",
        ]

    def render(self, active_tab: str = "Overview") -> str:
        """Generates HTML header string for the navigation bar."""
        items = []
        for tab in self.tabs:
            is_active = (tab.lower() == active_tab.lower())
            style = "font-weight:bold; border-bottom:2px solid #00D2FF; color:#00D2FF;" if is_active else "color:#888;"
            items.append(f"<span style='margin-right:15px; cursor:pointer; {style}'>{tab}</span>")
        return f"<div style='background-color:#1E1E2E; padding:12px; border-radius:8px; margin-bottom:20px;'>{' '.join(items)}</div>"
