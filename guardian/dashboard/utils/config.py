"""
AI Code Guardian v3 — Dashboard Configuration
=============================================
Manages dashboard theme configuration, scan history loading, and repository selection.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DashboardConfig:
    theme: str = "dark"
    selected_repository: str = "default-repo"
    scan_history: List[str] = field(default_factory=list)
    show_debug_metrics: bool = True

    def toggle_theme(self) -> str:
        self.theme = "light" if self.theme == "dark" else "dark"
        return self.theme
