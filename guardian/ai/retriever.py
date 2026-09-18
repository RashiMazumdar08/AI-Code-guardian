"""
AI Code Guardian — Retriever
==============================
Translates a natural-language question into a ranked list of
RetrievedChunk objects pulled from the FAISS vector store.

Pipeline
--------
    Question
      → intent classification (which type of knowledge to retrieve)
      → query embedding (CodeBERT for code queries, the local embedder for text)
      → FAISS search (code index + doc index)
      → deduplication by doc_id
      → score filter
      → top-k merge

The retriever is intentionally stateless — call retrieve() for each turn.
"""
from __future__ import annotations

import logging
import re
from typing import Optional

import numpy as np

from guardian.ai.config import AssistantConfig
from guardian.ai.embeddings import EmbeddingRouter
from guardian.ai.models import DocumentType, RAGQuery, RAGResult, RetrievedChunk
from guardian.ai.vector_store import FAISSVectorStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Intent → preferred DocumentType(s)
# ---------------------------------------------------------------------------
_INTENT_PATTERNS: list[tuple[re.Pattern, list[DocumentType]]] = [
    # Security / vulnerability questions
    (re.compile(r"\b(sql injection|xss|csrf|vulnerability|cve|owasp|injection|"
                r"hardcoded|secret|weak crypto|path traversal|finding|risk)\b", re.I),
     [DocumentType.SCAN_REPORT, DocumentType.SOURCE_CODE, DocumentType.OWASP, DocumentType.CWE]),
    # Business / requirements
    (re.compile(r"\b(business rule|requirement|user story|acceptance criteria|"
                r"missing rule|business intent|alignment)\b", re.I),
     [DocumentType.BUSINESS_INTENT, DocumentType.REQUIREMENT]),
    # Quantum / crypto
    (re.compile(r"\b(quantum|rsa|ecc|ecdsa|pqc|ml-kem|nist pqc|sha-1|md5|weak tls)\b", re.I),
     [DocumentType.QUANTUM_REPORT, DocumentType.SOURCE_CODE, DocumentType.NIST]),
    # Auth / security flows
    (re.compile(r"\b(auth|login|password|jwt|token|session|role|permission|oauth|sso)\b", re.I),
     [DocumentType.SOURCE_CODE, DocumentType.SECURITY_POLICY]),
    # Architecture / infra
    (re.compile(r"\b(dockerfile|kubernetes|k8s|deploy|helm|ci[/ -]?cd|pipeline|jenkins)\b", re.I),
     [DocumentType.DOCKERFILE, DocumentType.KUBERNETES, DocumentType.CI_CD]),
    # Policy / compliance
    (re.compile(r"\b(policy|compliance|gdpr|pci|hipaa|rbi|regulation|standard)\b", re.I),
     [DocumentType.SECURITY_POLICY, DocumentType.NIST, DocumentType.OWASP]),
    # API
    (re.compile(r"\b(api|endpoint|openapi|swagger|rest|graphql|route|controller)\b", re.I),
     [DocumentType.API_SPEC, DocumentType.SOURCE_CODE]),
]


def _classify_intent(question: str) -> Optional[list[DocumentType]]:
    for pattern, types in _INTENT_PATTERNS:
        if pattern.search(question):
            return types
    return None


def _is_code_question(question: str) -> bool:
    code_kw = re.compile(
        r"\b(code|function|method|class|implement|algorithm|snippet|file|"
        r"where is|show me|how does|defined)\b", re.I
    )
    return bool(code_kw.search(question))


class Retriever:
    """
    Stateless retriever — new instance per request is fine, or reuse one.
    """

    def __init__(
        self,
        config: AssistantConfig,
        vector_store: FAISSVectorStore,
        embedding_router: EmbeddingRouter,
    ):
        self._cfg      = config
        self._store    = vector_store
        self._embedder = embedding_router

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def retrieve(self, query: RAGQuery) -> RAGResult:
        """
        Main retrieval entry point.
        Returns a RAGResult with merged context and citations.
        """
        if self._store.is_empty:
            logger.warning("Vector store is empty — no retrieval possible")
            return RAGResult(
                query=query,
                chunks=[],
                merged_context="",
                citations=[],
            )

        # 1. Embed query
        prefer_code = _is_code_question(query.question) or not query.include_docs
        query_vec = self._embedder.embed_query(query.question, prefer_code=prefer_code)

        # 2. Classify intent
        intent_types = _classify_intent(query.question)

        # 3. Search
        chunks = self._hybrid_search(query, query_vec, intent_types)

        # 4. Deduplicate
        chunks = self._dedup(chunks)

        # 5. Build merged context + citations
        merged, citations = self._build_context(chunks)

        return RAGResult(
            query=query,
            chunks=chunks,
            merged_context=merged,
            citations=citations,
        )

    # ------------------------------------------------------------------
    # Search strategies
    # ------------------------------------------------------------------

    def _hybrid_search(
        self,
        query: RAGQuery,
        query_vec: np.ndarray,
        intent_types: Optional[list[DocumentType]],
    ) -> list[RetrievedChunk]:
        """
        Search code index and/or doc index, weighted by intent.
        """
        results: list[RetrievedChunk] = []

        if intent_types:
            # Intent-filtered: over-fetch and filter
            raw = self._store.search_all(query_vec, query.top_k * 3)
            type_set = set(intent_types)
            primary   = [r for r in raw if r.document.doc_type in type_set]
            secondary = [r for r in raw if r.document.doc_type not in type_set]
            # Combine: prioritise intent-matched, pad with secondary
            results = (primary + secondary)[: query.top_k]
        else:
            # Generic: split budget between code and docs
            if query.include_code:
                code_k = self._cfg.code_top_k
                code_q_vec = self._embedder.embed_query(query.question, prefer_code=True)
                results += self._store.search_code(code_q_vec, code_k)
            if query.include_docs:
                doc_k = self._cfg.doc_top_k
                doc_q_vec = self._embedder.embed_query(query.question, prefer_code=False)
                results += self._store.search_docs(doc_q_vec, doc_k)

        # Re-rank by score
        results.sort(key=lambda r: r.score)
        for i, r in enumerate(results):
            r.rank = i + 1
        if self._cfg.retrieval_score_threshold > 0:
            results = [r for r in results
                       if r.score <= self._cfg.retrieval_score_threshold]
        return results[: query.top_k]

    # ------------------------------------------------------------------
    # Post-processing
    # ------------------------------------------------------------------

    @staticmethod
    def _dedup(chunks: list[RetrievedChunk]) -> list[RetrievedChunk]:
        """Remove duplicate doc_ids, keeping the best-ranked instance."""
        seen: set[str] = set()
        out: list[RetrievedChunk] = []
        for c in chunks:
            if c.document.doc_id not in seen:
                seen.add(c.document.doc_id)
                out.append(c)
        return out

    def _build_context(
        self,
        chunks: list[RetrievedChunk],
    ) -> tuple[str, list[str]]:
        """
        Assemble the merged context string and citations list.
        Hard cap at max_context_chars to avoid exceeding LLM window.
        """
        budget    = self._cfg.max_context_chars
        parts: list[str] = []
        citations: list[str] = []
        seen_paths: set[str] = set()
        used = 0

        for chunk in chunks:
            doc = chunk.document
            header = (
                f"--- [{doc.doc_type.value.upper()}] {doc.source_path}"
                + (f" (lines {doc.start_line}–{doc.end_line})" if doc.start_line else "")
                + " ---\n"
            )
            block = header + doc.content + "\n"
            if used + len(block) > budget:
                break
            parts.append(block)
            used += len(block)
            # Unique citations
            cite = doc.to_citation()
            if doc.source_path not in seen_paths:
                citations.append(cite)
                seen_paths.add(doc.source_path)

        return "\n".join(parts), citations
