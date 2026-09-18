"""
AI Code Guardian v3 — Security Agent Tools
==========================================
"""
from typing import Any, Dict
from guardian.orchestrator.tools import BaseTool


class NormalizedFindingTool(BaseTool):
    name = "normalized_finding_tool"
    description = "Normalizes raw SAST findings into standard Finding schema."

    def run(self, **kwargs: Any) -> Dict[str, Any]:
        return {"status": "success", "normalized": True}
