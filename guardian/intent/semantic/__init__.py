"""
Semantic Evidence Retrieval & Fusion Layer for AI Code Guardian
================================================================
Provides semantic evidence retrieval on top of deterministic AST analysis.
Escalates uncertain cases (PARTIAL / INSUFFICIENT_EVIDENCE) to discover
function/class level semantic evidence candidates while maintaining strict
deterministic boundaries.
"""
from __future__ import annotations

from guardian.intent.semantic.code_index import CodeSemanticIndex, CodeChunkRepresentation
from guardian.intent.semantic.semantic_retriever import SemanticRetriever, SemanticSearchResult
from guardian.intent.semantic.evidence_fusion import EvidenceFusionEngine, FusedRuleResult

__all__ = [
    "CodeSemanticIndex",
    "CodeChunkRepresentation",
    "SemanticRetriever",
    "SemanticSearchResult",
    "EvidenceFusionEngine",
    "FusedRuleResult",
]
