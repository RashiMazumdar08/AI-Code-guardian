"""
Semantic Retriever Module
=========================
Queries CodeSemanticIndex to retrieve Top-K relevant code/control evidence candidates.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Optional

import numpy as np

from guardian.intent.semantic.code_index import CodeChunkRepresentation, CodeSemanticIndex, _get_local_embedder

log = logging.getLogger(__name__)


@dataclass
class SemanticSearchResult:
    match_id: str
    file: str
    function: str
    line: int
    snippet: str
    requirement_or_control: str
    similarity: float
    source: str = "SEMANTIC_RETRIEVAL"
    summary_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "match_id": self.match_id,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "snippet": self.snippet[:400],
            "requirement_or_control": self.requirement_or_control,
            "similarity": round(float(self.similarity), 3),
            "source": self.source,
            "summary_text": self.summary_text,
        }


def _tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9_]{3,}", text.lower()))


class SemanticRetriever:
    """Retrieves Top-K code candidates relevant to a business requirement or control query."""

    def __init__(self, index: Optional[CodeSemanticIndex] = None, workspace_dir: Optional[Path] = None):
        self.index = index or CodeSemanticIndex.get_or_create(workspace_dir)

    def search(self, query: str, top_k: int = 3) -> list[SemanticSearchResult]:
        """Search the code index for the query string.
        
        Args:
            query: Business requirement text, control description, or evidence query.
            top_k: Number of candidates to return (default 3, bounded 1..5).
            
        Returns:
            List of SemanticSearchResult objects sorted by descending similarity.
        """
        if not query or not self.index.chunks:
            return []

        top_k = max(1, min(top_k, 5))
        q_vec = self._embed_query(query)

        if q_vec is None or self.index._vectors is None or len(self.index._vectors) == 0:
            return []

        # Cosine similarity matrix multiplication
        sims = np.dot(self.index._vectors, q_vec)
        top_indices = np.argsort(sims)[::-1][:top_k]

        results: list[SemanticSearchResult] = []
        for idx in top_indices:
            score = float(sims[idx])
            chunk = self.index.chunks[idx]
            if score <= 0.0:
                continue

            res = SemanticSearchResult(
                match_id=chunk.chunk_id,
                file=chunk.file,
                function=chunk.function,
                line=chunk.line,
                snippet=chunk.snippet,
                requirement_or_control=chunk.security_business_behavior or query[:100],
                similarity=score,
                summary_text=chunk.summary_text,
            )
            results.append(res)

        return results

    def _embed_query(self, query: str) -> Optional[np.ndarray]:
        try:
            embedder = _get_local_embedder()
            if embedder and embedder.is_available:
                vec = np.array(embedder.embed(query), dtype=np.float32)
                norm = np.linalg.norm(vec)
                return vec / norm if norm > 0 else vec
        except Exception as exc:
            log.debug("LocalEmbedder query embedding fallback: %s", exc)

        # Fallback query vector using TF-IDF / Vocabulary matching against index
        if self.index._vectors is None or len(self.index._vectors) == 0:
            return None

        q_tokens = _tokenize(query)
        dim = self.index._vectors.shape[1]
        vec = np.zeros(dim, dtype=np.float32)

        for i, chunk in enumerate(self.index.chunks):
            chunk_tokens = _tokenize(chunk.summary_text)
            overlap = len(q_tokens & chunk_tokens)
            if overlap > 0:
                vec += (overlap / (len(q_tokens) + 1.0)) * self.index._vectors[i]

        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else None
