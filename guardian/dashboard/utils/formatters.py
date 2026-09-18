"""
AI Code Guardian v3 — Dashboard UI Formatters
=============================================
Formating helpers for risk scores, timestamps, severity badges, and diff snippets.
"""
from __future__ import annotations

from typing import Any, Dict


def format_risk_score(score: float) -> str:
    """Formats float risk score as percentage or decimal with 2 places."""
    return f"{score:.2f}" if score <= 1.0 else f"{score:.1f}"


def format_severity_badge(severity: str) -> str:
    """Returns Markdown formatted badge for severity levels."""
    sev_upper = severity.upper()
    badges = {
        "CRITICAL": "🔴 **CRITICAL**",
        "HIGH": "🟠 **HIGH**",
        "MEDIUM": "🟡 **MEDIUM**",
        "LOW": "🔵 **LOW**",
        "INFO": "⚪ **INFO**",
    }
    return badges.get(sev_upper, f"🟢 **{sev_upper}**")


def format_confidence_percent(conf: float) -> str:
    """Formats confidence float to percentage string."""
    return f"{int(conf * 100)}%" if conf <= 1.0 else f"{int(conf)}%"
