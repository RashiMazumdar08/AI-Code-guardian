"""
AI Code Guardian — FAISS Vector Store
========================================
Manages two FAISS flat-L2 indexes:
  1. code_index   — CodeBERT embeddings for source code chunks
  2. doc_index    — the local embedder embeddings for text/document chunks

Both are persisted to disk and hot-loaded on startup.

Index selection strategy
------------------------
- Fewer than 1000 vectors → IndexFlatL2  (exact, no training needed)
- 1000+ vectors           → IndexIVFFlat (approximate, faster at scale)
"""
from __future__ import annotations

import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np

from guardian.ai.config import AssistantConfig
from guardian.ai.models import Document, DocumentType, IndexStats, RetrievedChunk

logger = logging.getLogger(__name__)

_IVF_THRESHOLD = 1000   # use IVF when more than this many vectors


def _build_faiss_index(dim: int, n_vectors: int, nlist: int, nprobe: int):
    """Build the right FAISS index type based on corpus size."""
    import faiss
    if n_vectors >= _IVF_THRESHOLD:
        quantizer = faiss.IndexFlatL2(dim)
        index = faiss.IndexIVFFlat(quantizer, dim, min(nlist, n_vectors // 10 + 1))
        return index, True   # needs training
    return faiss.IndexFlatL2(dim), False


class FAISSVectorStore:
    """
    Persistent, queryable FAISS vector store for AI Code Guardian.

    Two indexes maintained separately:
      - code_index  : source code (CodeBERT 768-dim)
      - doc_index   : text documents (the local embedder embed 768-dim)

    Both store metadata (Document objects) in parallel pickle lists.
    """

    def __init__(self, config: AssistantConfig):
        self._cfg = config
        # Runtime state
        self._code_index = None     # faiss.Index | None
        self._code_meta: list[Document] = []
        self._doc_index  = None
        self._doc_meta:  list[Document] = []
        # Try to load existing indexes
        self._try_load()

    # ------------------------------------------------------------------
    # Build / update
    # ------------------------------------------------------------------

    def add_documents(
        self,
        docs: list[Document],
        vectors: np.ndarray,
    ) -> None:
        """
        Add documents and their embedding vectors to the appropriate index.
        docs[i] pairs with vectors[i].
        Separate by type: SOURCE_CODE → code index, everything else → doc index.
        """
        if len(docs) != vectors.shape[0]:
            raise ValueError(f"docs ({len(docs)}) and vectors ({vectors.shape[0]}) must match")
        if not docs:
            return

        code_mask = np.array([d.doc_type == DocumentType.SOURCE_CODE for d in docs])
        self._add_to_index("code", [d for d, m in zip(docs, code_mask) if m],
                           vectors[code_mask])
        doc_mask = ~code_mask
        self._add_to_index("doc",  [d for d, m in zip(docs, doc_mask) if m],
                           vectors[doc_mask])

    def _add_to_index(self, kind: str, docs: list[Document], vecs: np.ndarray) -> None:
        if not docs or vecs.shape[0] == 0:
            return
        import faiss
        meta_attr  = f"_{kind}_meta"
        index_attr = f"_{kind}_index"
        dim = vecs.shape[1]

        existing_meta: list[Document] = getattr(self, meta_attr)
        existing_index = getattr(self, index_attr)

        # Build or grow the index
        if existing_index is None:
            index, needs_train = _build_faiss_index(
                dim, len(docs), self._cfg.faiss_nlist, self._cfg.faiss_nprobe
            )
            if needs_train:
                index.train(vecs)
            index.add(vecs)
            setattr(self, index_attr, index)
        else:
            existing_index.add(vecs)

        existing_meta.extend(docs)
        logger.debug("Added %d vectors to %s index (total: %d)", len(docs), kind, len(existing_meta))

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def search_code(
        self,
        query_vec: np.ndarray,
        top_k: int,
    ) -> list[RetrievedChunk]:
        return self._search(self._code_index, self._code_meta, query_vec, top_k)

    def search_docs(
        self,
        query_vec: np.ndarray,
        top_k: int,
    ) -> list[RetrievedChunk]:
        return self._search(self._doc_index, self._doc_meta, query_vec, top_k)

    def search_all(
        self,
        query_vec: np.ndarray,
        top_k: int,
    ) -> list[RetrievedChunk]:
        """Search both indexes and merge by score."""
        code_results = self._search(self._code_index, self._code_meta, query_vec, top_k)
        doc_results  = self._search(self._doc_index,  self._doc_meta,  query_vec, top_k)
        merged = code_results + doc_results
        merged.sort(key=lambda r: r.score)
        for i, r in enumerate(merged):
            r.rank = i + 1
        return merged[:top_k]

    def search_by_type(
        self,
        query_vec: np.ndarray,
        doc_type: DocumentType,
        top_k: int,
    ) -> list[RetrievedChunk]:
        """Filter results to a specific DocumentType after retrieval."""
        # Over-fetch then filter
        all_results = self.search_all(query_vec, top_k * 4)
        filtered = [r for r in all_results if r.document.doc_type == doc_type]
        return filtered[:top_k]

    @staticmethod
    def _search(index, meta: list[Document], query_vec: np.ndarray, top_k: int) -> list[RetrievedChunk]:
        if index is None or not meta:
            return []
        import faiss
        k = min(top_k, len(meta))
        q = query_vec.reshape(1, -1).astype(np.float32)
        distances, indices = index.search(q, k)
        results = []
        for rank, (dist, idx) in enumerate(zip(distances[0], indices[0]), start=1):
            if idx < 0 or idx >= len(meta):
                continue
            results.append(RetrievedChunk(
                document=meta[idx],
                score=float(dist),
                rank=rank,
            ))
        return results

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self) -> None:
        """Persist both indexes and metadata to disk."""
        import faiss
        cfg = self._cfg
        cfg.index_dir.mkdir(parents=True, exist_ok=True)

        if self._code_index and self._code_meta:
            faiss.write_index(self._code_index, str(cfg.code_index_path))
            with open(cfg.code_meta_path, "wb") as f:
                pickle.dump(self._code_meta, f)
            logger.info("Saved code index: %d vectors", self._code_index.ntotal)

        if self._doc_index and self._doc_meta:
            faiss.write_index(self._doc_index, str(cfg.doc_index_path))
            with open(cfg.doc_meta_path, "wb") as f:
                pickle.dump(self._doc_meta, f)
            logger.info("Saved doc index: %d vectors", self._doc_index.ntotal)

    def _try_load(self) -> None:
        """Load persisted indexes if they exist."""
        try:
            import faiss
            cfg = self._cfg
            if cfg.code_index_path.exists() and cfg.code_meta_path.exists():
                self._code_index = faiss.read_index(str(cfg.code_index_path))
                with open(cfg.code_meta_path, "rb") as f:
                    self._code_meta = pickle.load(f)
                logger.info("Loaded code index: %d vectors", self._code_index.ntotal)
            if cfg.doc_index_path.exists() and cfg.doc_meta_path.exists():
                self._doc_index = faiss.read_index(str(cfg.doc_index_path))
                with open(cfg.doc_meta_path, "rb") as f:
                    self._doc_meta = pickle.load(f)
                logger.info("Loaded doc index: %d vectors", self._doc_index.ntotal)
        except Exception as exc:
            logger.warning("Could not load persisted index: %s", exc)

    def clear(self) -> None:
        """Wipe both indexes from memory and disk."""
        self._code_index = None
        self._code_meta  = []
        self._doc_index  = None
        self._doc_meta   = []
        for p in [self._cfg.code_index_path, self._cfg.code_meta_path,
                  self._cfg.doc_index_path,  self._cfg.doc_meta_path]:
            if p.exists():
                p.unlink()
        logger.info("Vector store cleared")

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> IndexStats:
        from collections import Counter
        all_docs = self._code_meta + self._doc_meta
        lang_counter = Counter(d.language for d in all_docs if d.language)
        type_counter = Counter(d.doc_type.value for d in all_docs)
        code_vecs = self._code_index.ntotal if self._code_index else 0
        doc_vecs  = self._doc_index.ntotal  if self._doc_index  else 0
        # Rough size estimate
        size_mb = (code_vecs + doc_vecs) * 768 * 4 / 1_048_576
        return IndexStats(
            total_documents=len(all_docs),
            code_vectors=code_vecs,
            doc_vectors=doc_vecs,
            languages=dict(lang_counter),
            doc_types=dict(type_counter),
            index_size_mb=round(size_mb, 2),
        )

    @property
    def is_empty(self) -> bool:
        code_total = self._code_index.ntotal if self._code_index else 0
        doc_total  = self._doc_index.ntotal  if self._doc_index  else 0
        return (code_total + doc_total) == 0
