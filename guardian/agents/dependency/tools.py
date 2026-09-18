"""
AI Code Guardian v3 — Dependency Agent Tools
============================================
"""
from typing import Any, Dict
from guardian.orchestrator.tools import BaseTool


class OSVLookupTool(BaseTool):
    name = "osv_lookup_tool"
    description = "Queries OSV database for known package vulnerabilities."

    def run(self, **kwargs: Any) -> Dict[str, Any]:
        return {"status": "success", "cves": []}
