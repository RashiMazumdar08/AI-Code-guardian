"""
AI Code Guardian v3 — Key Metric Cards Component
=================================================
"""
from __future__ import annotations

from typing import Dict


class MetricCardsComponent:
    """Renders top summary metric cards (findings count, composite risk, patches passed)."""

    def render(self, metrics: Dict[str, Any]) -> str:
        """Returns HTML grid string displaying key performance indicator cards."""
        return (
            f"<div style='display:flex; gap:15px; margin-bottom:20px;'>"
            f"  <div style='flex:1; background:#2A2A3C; padding:15px; border-radius:8px; border-left:4px solid #FF4B4B;'>"
            f"    <div style='font-size:12px; color:#AAA;'>TOTAL FINDINGS</div>"
            f"    <div style='font-size:24px; font-weight:bold; color:#FFF;'>{metrics.get('findings_count', 0)}</div>"
            f"  </div>"
            f"  <div style='flex:1; background:#2A2A3C; padding:15px; border-radius:8px; border-left:4px solid #FF9000;'>"
            f"    <div style='font-size:12px; color:#AAA;'>COMPOSITE RISK</div>"
            f"    <div style='font-size:24px; font-weight:bold; color:#FFF;'>{metrics.get('composite_risk', '0.00')}</div>"
            f"  </div>"
            f"  <div style='flex:1; background:#2A2A3C; padding:15px; border-radius:8px; border-left:4px solid #00D2FF;'>"
            f"    <div style='font-size:12px; color:#AAA;'>PATCHES PASSED</div>"
            f"    <div style='font-size:24px; font-weight:bold; color:#FFF;'>{metrics.get('patches_passed', 0)}</div>"
            f"  </div>"
            f"</div>"
        )
