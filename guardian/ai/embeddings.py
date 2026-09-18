"""
AI Code Guardian — Embeddings Router
======================================
Routes documents to the right embedder:
  - Source code  → CodeBERT (768-dim, semantic code understanding)
  - All others   → LocalEmbedder all-MiniLM-L6-v2 (384-dim, local)

Both produce 768-dim vectors so they share the same FAISS index dimension.
The routing is transparent to callers — pass a Document, get a vector back.
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np

from guardian.ai.config import AssistantConfig
from guardian.ai.models import Document, DocumentType

logger = logging.getLogger(__name__)


class EmbeddingRouter:
    """
    Single entry point for all embedding operations.

    Parameters
    ----------
    config : AssistantConfig
    embedder      : LocalEmbedder  (injected)
    codebert      : CodeBERTEmbedder | None
        If None, CodeBERT is not used and all code falls back to LocalEmbedder.
    """

    def __init__(self, config: AssistantConfig, embedder, codebert=None):
        self._cfg          = config
        self._embedder     = embedder
        self._codebert     = codebert
        self._code_types   = {DocumentType.SOURCE_CODE}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed_document(self, doc: Document) -> np.ndarray:
        """Embed a single Document chunk. Returns (dim,) float32 ndarray."""
        if doc.doc_type in self._code_types and self._codebert:
            vec = self._codebert.embed(doc.content)
        else:
            raw = self._safe_embed(doc.content)
            vec = np.array(raw, dtype=np.float32)
        return self._normalise(vec)

    def embed_documents(
        self,
        docs: list[Document],
        show_progress: bool = True,
    ) -> np.ndarray:
        """
        Embed a list of Documents.
        Returns (N, dim) float32 ndarray.
        """
        if not docs:
            return np.zeros((0, self._cfg.embed_dim), dtype=np.float32)

        code_indices = [i for i, d in enumerate(docs) if d.doc_type in self._code_types]
        text_indices = [i for i, d in enumerate(docs) if d.doc_type not in self._code_types]

        result = np.zeros((len(docs), self._cfg.embed_dim), dtype=np.float32)

        # Code → CodeBERT batch
        if code_indices and self._codebert:
            snippets = [docs[i].content for i in code_indices]
            vecs = self._codebert.embed_batch(snippets)
            for j, global_i in enumerate(code_indices):
                result[global_i] = self._normalise(vecs[j])
            if show_progress:
                logger.info("CodeBERT embedded %d code chunks", len(code_indices))

        # Code without CodeBERT → local embedder
        code_without_bert = code_indices if not self._codebert else []

        # Text → local embedder (+ code fallback)
        embed_indices = text_indices + code_without_bert
        if embed_indices:
            for k, global_i in enumerate(embed_indices):
                raw = self._safe_embed(docs[global_i].content)
                result[global_i] = self._normalise(np.array(raw, dtype=np.float32))
                if show_progress and (k + 1) % 50 == 0:
                    logger.info(
                        "Locally embedded %d/%d text chunks",
                        k + 1, len(embed_indices)
                    )

        return result

    def embed_query(self, query: str, prefer_code: bool = False) -> np.ndarray:
        """
        Embed a user query string.
        Uses CodeBERT if the query looks like code or prefer_code=True,
        otherwise uses the local embedder.
        """
        looks_like_code = prefer_code or self._looks_like_code(query)
        if looks_like_code and self._codebert:
            vec = self._codebert.embed(query)
        else:
            raw = self._safe_embed(query)
            vec = np.array(raw, dtype=np.float32)
        return self._normalise(vec)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _safe_embed(self, text: str) -> list[float]:
        """Embed locally, returning a zero vector on failure."""
        try:
            return self._embedder.embed(text)
        except Exception as exc:
            logger.warning("local embed failed, returning zero vector: %s", exc)
            return [0.0] * self._cfg.embed_dim

    @staticmethod
    def _normalise(vec: np.ndarray) -> np.ndarray:
        norm = np.linalg.norm(vec)
        if norm > 0:
            return (vec / norm).astype(np.float32)
        return vec.astype(np.float32)

    @staticmethod
    def _looks_like_code(text: str) -> bool:
        """Heuristic: does the query string look like source code?"""
        code_signals = [
            "def ", "class ", "import ", "public ", "private ", "function ",
            "void ", "return ", "if (", "for (", "while (", "{", "}", "=>",
            "->", "::", ".get(", ".set(", "==", "!=",
        ]
        return sum(1 for sig in code_signals if sig in text) >= 2
