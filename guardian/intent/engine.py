"""
Unified Business Intent Engine Orchestrator (Production Ready)
=============================================================
Orchestrates:
  DocumentLoader -> RuleParser -> RuleMatcher -> AlignmentScorer
Handles real-world status codes:
  - NO_DOCUMENTS
  - NO_VALID_REQUIREMENTS
  - INSUFFICIENT_EVIDENCE
  - SUCCESS
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from guardian.intent.ingestion.document_loader import DocumentLoader, get_business_docs_dir
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.intent.parser.rule_parser import RuleParser
from guardian.intent.scorer import AlignmentScorer

log = logging.getLogger(__name__)


class BusinessIntentEngine:
    """Production-Grade Business Intent Engine."""

    def __init__(self, docs_dir: str | Path | None = None):
        self.loader = DocumentLoader(docs_dir)
        self.parser = RuleParser()
        self.matcher = RuleMatcher()
        self.scorer = AlignmentScorer()

    def run(self, scan_findings: list[dict[str, Any]] | None = None, docs_dir: str | Path | None = None) -> dict[str, Any]:
        """Run intent analysis workflow."""
        if docs_dir:
            self.loader = DocumentLoader(docs_dir)

        docs = self.loader.list_documents()

        # Case 1: No documents in directory
        if not docs:
            return {
                "status": "NO_DOCUMENTS",
                "message": "No business documents uploaded in /data/business_docs/",
                "alignment_score": 0.0,
                "alignment_percentage": 0,
                "total_rules": 0,
                "matched": 0,
                "violated": 0,
                "partial": 0,
                "insufficient": 0,
                "documents": [],
                "findings": []
            }

        # Step 1: Ingestion & Actionable Requirement Extraction
        requirements = self.loader.extract_actionable_requirements()

        # Case 2: Documents uploaded but no valid actionable requirements found
        if not requirements:
            return {
                "status": "NO_VALID_REQUIREMENTS",
                "message": f"Found {len(docs)} document(s) but 0 actionable requirement rules extracted",
                "alignment_score": 0.0,
                "alignment_percentage": 0,
                "total_rules": 0,
                "matched": 0,
                "violated": 0,
                "partial": 0,
                "insufficient": 0,
                "documents": [d["filename"] for d in docs],
                "findings": []
            }

        # Step 2: Strong Rule Parsing (Action, Condition, Control)
        parsed_rules = self.parser.parse_all(requirements)

        # Step 3: Behavior Profiling & Multi-Factor Matching
        evaluated_findings = self.matcher.evaluate_all(parsed_rules, scan_findings)

        # Step 4: Scoring
        metrics = self.scorer.score(evaluated_findings)

        # Case 3: Code has no relevant logic (All findings INSUFFICIENT)
        if metrics["insufficient"] == metrics["total_rules"] and metrics["total_rules"] > 0:
            return {
                "status": "INSUFFICIENT_EVIDENCE",
                "message": "Codebase contains no matching action or control logic for extracted rules",
                "alignment_score": 0.0,
                "alignment_percentage": 0,
                "total_rules": metrics["total_rules"],
                "matched": 0,
                "violated": 0,
                "partial": 0,
                "insufficient": metrics["insufficient"],
                "documents": [d["filename"] for d in docs],
                "findings": evaluated_findings
            }

        # Case 4: Success
        return {
            "status": "SUCCESS",
            "alignment_score": metrics["alignment_score"],
            "alignment_percentage": metrics["alignment_percentage"],
            "total_rules": metrics["total_rules"],
            "matched": metrics["matched"],
            "violated": metrics["violated"],
            "partial": metrics["partial"],
            "insufficient": metrics["insufficient"],
            "documents": [d["filename"] for d in docs],
            "findings": evaluated_findings
        }
