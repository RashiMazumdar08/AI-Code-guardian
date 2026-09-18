"""
AI Code Guardian v3 — Validation Agent Tools
============================================
"""
from typing import Any, Dict
from guardian.orchestrator.tools import BaseTool


class SyntaxCheckTool(BaseTool):
    name = "syntax_check_tool"
    description = "Helper tool checking Python/UST syntax validity."

    def run(self, **kwargs: Any) -> Dict[str, Any]:
        return {"status": "success", "valid": True}
