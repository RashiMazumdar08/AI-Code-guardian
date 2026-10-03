"""
Evidence Fusion Module
======================
Fuses deterministic AST evidence with semantic retrieval candidates.
Only triggers semantic search for uncertain cases (PARTIAL / INSUFFICIENT_EVIDENCE).
Maintains strict boundaries: semantic similarity NEVER automatically produces a VIOLATION.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.intent.semantic.semantic_retriever import SemanticRetriever, SemanticSearchResult

log = logging.getLogger(__name__)


@dataclass
class FusedRuleResult:
    rule_id: str
    requirement_text: str
    deterministic_status: str
    deterministic_score: float
    deterministic_evidence: list[dict[str, Any]] = field(default_factory=list)
    semantic_candidates: list[dict[str, Any]] = field(default_factory=list)
    semantic_retrieval_performed: bool = False
    final_status: str = "INSUFFICIENT_EVIDENCE"
    missing_controls: list[str] = field(default_factory=list)
    negative_evidence: list[str] = field(default_factory=list)
    matched_file: str = ""
    matched_function: str = ""
    matched_line: int = 0
    matched_snippet: str = ""
    what: str = ""
    why: str = ""
    how: str = ""
    metrics: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "requirement_text": self.requirement_text,
            "rule": self.requirement_text,
            "status": self.final_status,
            "deterministic_status": self.deterministic_status,
            "deterministic_score": self.deterministic_score,
            "score": round(self.deterministic_score, 3),
            "deterministic_evidence": self.deterministic_evidence,
            "evidence_items": self.deterministic_evidence,
            "semantic_candidates": self.semantic_candidates,
            "semantic_retrieval_performed": self.semantic_retrieval_performed,
            "missing_controls": self.missing_controls,
            "missing_control": ", ".join(self.missing_controls) if self.missing_controls else "",
            "negative_evidence": self.negative_evidence,
            "matched_file": self.matched_file,
            "matched_function": self.matched_function,
            "matched_line": self.matched_line,
            "matched_snippet": self.matched_snippet,
            "what": self.what,
            "why": self.why,
            "how": self.how,
            "metrics": self.metrics,
        }


class EvidenceFusionEngine:
    """Combines deterministic AST analysis with semantic retrieval candidates."""

    def __init__(self, retriever: Optional[SemanticRetriever] = None, workspace_dir: Optional[Path] = None):
        self.retriever = retriever or SemanticRetriever(workspace_dir=workspace_dir)

    def fuse_rule_result(
        self,
        det_result: dict[str, Any],
        top_k: int = 3,
        force_semantic: bool = False,
    ) -> FusedRuleResult:
        """Process a deterministic rule evaluation result and perform evidence fusion.
        
        Triggering Policy:
        - COMPLIANT / VIOLATION → Normally stop (no semantic retrieval)
        - PARTIAL / INSUFFICIENT_EVIDENCE → Trigger semantic retrieval
        """
        start_time = time.perf_counter()

        rule_id = str(det_result.get("rule_id") or "")
        req_text = str(det_result.get("original_requirement") or det_result.get("rule") or "")
        det_status = str(det_result.get("status") or "INSUFFICIENT_EVIDENCE").upper()
        det_score = float(det_result.get("score") or 0.0)

        missing_controls = list(det_result.get("missing_controls") or [])
        if not missing_controls and det_result.get("missing_control"):
            missing_controls = [det_result.get("missing_control")]

        neg_evidence = list(det_result.get("negative_evidence") or [])
        det_evidence = list(det_result.get("evidence_items") or [])

        # Trigger decision: PARTIAL and INSUFFICIENT_EVIDENCE trigger semantic search
        should_trigger = force_semantic or (det_status in ("PARTIAL", "INSUFFICIENT_EVIDENCE", "INSUFFICIENT"))

        semantic_candidates: list[dict[str, Any]] = []
        retrieval_performed = False
        sem_time_ms = 0.0
        searches_count = 0
        candidates_retrieved_count = 0

        if should_trigger:
            retrieval_performed = True
            searches_count = 1
            sem_start = time.perf_counter()

            query = f"{req_text} {' '.join(missing_controls)}"
            search_results: list[SemanticSearchResult] = self.retriever.search(query=query, top_k=top_k)
            sem_time_ms = (time.perf_counter() - sem_start) * 1000.0

            candidates_retrieved_count = len(search_results)
            for res in search_results:
                candidate_dict = res.to_dict()
                candidate_dict["evidence_source"] = "SEMANTIC"
                semantic_candidates.append(candidate_dict)

        total_time_ms = (time.perf_counter() - start_time) * 1000.0

        # MANDATORY GUARDRAIL: Semantic similarity alone CANNOT produce a VIOLATION verdict.
        # High similarity simply attaches semantic candidate evidence to the result object.
        final_status = det_status

        matched_file = str(det_result.get("matched_file") or "")
        matched_fn = str(det_result.get("matched_function") or "")
        matched_line = int(det_result.get("matched_line") or 0)
        matched_snippet = str(det_result.get("matched_snippet") or "")

        # If deterministic match was absent but top semantic candidate exists, reference top candidate in metadata without mutating verdict to VIOLATION
        if not matched_file and semantic_candidates:
            top_cand = semantic_candidates[0]
            matched_file = top_cand.get("file", "")
            matched_fn = top_cand.get("function", "")
            matched_line = top_cand.get("line", 0)
            matched_snippet = top_cand.get("snippet", "")

        metrics = {
            "deterministic_analysis_time_ms": round(total_time_ms - sem_time_ms, 2),
            "semantic_retrieval_time_ms": round(sem_time_ms, 2),
            "number_of_semantic_searches": searches_count,
            "number_of_candidates_retrieved": candidates_retrieved_count,
            "llm_calls_caused_by_semantic_escalation": 0,
        }

        return FusedRuleResult(
            rule_id=rule_id,
            requirement_text=req_text,
            deterministic_status=det_status,
            deterministic_score=det_score,
            deterministic_evidence=det_evidence,
            semantic_candidates=semantic_candidates,
            semantic_retrieval_performed=retrieval_performed,
            final_status=final_status,
            missing_controls=missing_controls,
            negative_evidence=neg_evidence,
            matched_file=matched_file,
            matched_function=matched_fn,
            matched_line=matched_line,
            matched_snippet=matched_snippet,
            what=str(det_result.get("what") or ""),
            why=str(det_result.get("why") or ""),
            how=str(det_result.get("how") or ""),
            metrics=metrics,
        )
