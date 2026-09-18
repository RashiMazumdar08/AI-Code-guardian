"""
AI Code Guardian v3 — Side-by-Side Code Diff Component
======================================================
"""
from __future__ import annotations


class CodeDiffViewerComponent:
    """Renders side-by-side comparison view between original snippet and suggested patch replacement."""

    def render(self, file_path: str, original_code: str, replacement_code: str, git_diff: str = "") -> str:
        """Generates HTML representation for code diff viewer."""
        return (
            f"<div style='background:#181825; padding:15px; border-radius:8px; border:1px solid #313244; font-family:monospace;'>"
            f"  <div style='color:#00D2FF; font-weight:bold; margin-bottom:10px;'>📄 File: {file_path}</div>"
            f"  <div style='display:flex; gap:10px;'>"
            f"    <div style='flex:1; background:#11111B; padding:10px; border-radius:5px; border-left:3px solid #F38BA8;'>"
            f"      <div style='color:#F38BA8; font-size:11px; margin-bottom:5px;'>- Original Snippet</div>"
            f"      <pre style='margin:0; white-space:pre-wrap; color:#CDD6F4;'>{original_code}</pre>"
            f"    </div>"
            f"    <div style='flex:1; background:#11111B; padding:10px; border-radius:5px; border-left:3px solid #A6E3A1;'>"
            f"      <div style='color:#A6E3A1; font-size:11px; margin-bottom:5px;'>+ Remediation Replacement</div>"
            f"      <pre style='margin:0; white-space:pre-wrap; color:#CDD6F4;'>{replacement_code}</pre>"
            f"    </div>"
            f"  </div>"
            f"</div>"
        )
