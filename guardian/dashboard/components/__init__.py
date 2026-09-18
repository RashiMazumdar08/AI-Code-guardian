"""
AI Code Guardian v3 — Dashboard Components Package Exports
==========================================================
"""
from guardian.dashboard.components.code_diff_viewer import CodeDiffViewerComponent
from guardian.dashboard.components.metric_cards import MetricCardsComponent
from guardian.dashboard.components.navbar import NavigationBarComponent

__all__ = [
    "NavigationBarComponent",
    "MetricCardsComponent",
    "CodeDiffViewerComponent",
]
