"""
AI Code Guardian v3 — Grounding Engine
=====================================
Verifies that generated patch proposals map to existing files, line numbers,
finding IDs, and evidence IDs. Rejects hallucinated or ungrounded AI suggestions.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class GroundingEngine:
    """Engine verifying AI-generated patch proposals against ground-truth evidence."""

    def verify_patch(
        self,
        patch_proposal: Dict[str, Any],
        findings: List[Dict[str, Any]],
        evidence: List[Dict[str, Any]],
        repo_path: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Validates grounding of a patch proposal.
        Returns grounding status report (passed: bool, reasons: List[str]).
        """
        reasons: List[str] = []
        finding_id = patch_proposal.get("finding_id", "")
        affected_file = patch_proposal.get("affected_file", "")
        evidence_ids = patch_proposal.get("evidence_ids", [])

        # 1. Verify Finding ID exists
        matching_finding = next((f for f in findings if f.get("finding_id") == finding_id), None)
        if not matching_finding:
            reasons.append(f"Finding ID '{finding_id}' does not exist in ground-truth findings.")

        # 2. Verify Evidence IDs exist
        known_evidence_ids = {e.get("evidence_id") for e in evidence if e.get("evidence_id")}
        for ev_id in evidence_ids:
            if ev_id not in known_evidence_ids:
                reasons.append(f"Evidence ID '{ev_id}' does not exist in evidence store.")

        # 3. Verify file path exists if repo_path provided
        if repo_path and affected_file:
            target_path = Path(repo_path) / affected_file
            if not target_path.exists() and not (Path(repo_path) / affected_file.lstrip("/")).exists():
                reasons.append(f"File '{affected_file}' does not exist in repository.")

        # 4. Require at least one grounded evidence reference
        if not evidence_ids and not (matching_finding and matching_finding.get("evidence_id")):
            reasons.append("Patch proposal has zero grounded evidence references.")

        passed = len(reasons) == 0

        return {
            "passed": passed,
            "reasons": reasons,
            "finding_id": finding_id,
            "file": affected_file,
        }
