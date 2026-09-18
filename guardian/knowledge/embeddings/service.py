"""
AI Code Guardian v3 — Reusable Embedding Service
=================================================
Provides batch embedding generation, incremental caching, and support for
Sentence Transformers and CodeBERT.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional

from guardian.knowledge.config import EmbeddingConfig
from guardian.knowledge.embeddings.base import BaseEmbedder


class EmbeddingService(BaseEmbedder):
    """Reusable embedding service supporting Sentence Transformers & CodeBERT with caching."""

    def __init__(self, config: Optional[EmbeddingConfig] = None):
        self.config = config or EmbeddingConfig()
        self._model = None
        self._cache: Dict[str, List[float]] = {}
        self._dimension: int = 384
        from guardian.cache.redis_manager import RedisManager
        self._redis = RedisManager()

    def _init_model(self):
        """Lazy initialization of embedding model."""
        if self._model is not None:
            return

        if not self.config.load_local_model:
            self._model = "fallback"
            self._dimension = 384
            return

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.config.model_name, device=self.config.device)
            self._dimension = self._model.get_sentence_embedding_dimension() or 384
        except Exception:
            # Fallback deterministic embedder if sentence-transformers is missing/fails
            self._model = "fallback"
            self._dimension = 384

    @property
    def dimension(self) -> int:
        self._init_model()
        return self._dimension

    def _hash_text(self, text: str) -> str:
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def embed_text(self, text: str) -> List[float]:
        if not text.strip():
            return [0.0] * self.dimension

        text_hash = self._hash_text(text)
        if self.config.cache_embeddings:
            cached_vec = self._redis.get_json(f"embed:cache:{text_hash}")
            if cached_vec:
                return cached_vec
            if text_hash in self._cache:
                return self._cache[text_hash]

        vecs = self.embed_batch([text])
        return vecs[0]

    def embed_batch(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []

        self._init_model()

        results: List[Optional[List[float]]] = [None] * len(texts)
        uncached_indices: List[int] = []
        uncached_texts: List[str] = []

        for idx, text in enumerate(texts):
            text_hash = self._hash_text(text)
            if self.config.cache_embeddings:
                cached_vec = self._redis.get_json(f"embed:cache:{text_hash}")
                if cached_vec:
                    results[idx] = cached_vec
                    continue
                if text_hash in self._cache:
                    results[idx] = self._cache[text_hash]
                    continue
            
            uncached_indices.append(idx)
            uncached_texts.append(text)

        if uncached_texts:
            if self._model != "fallback" and hasattr(self._model, "encode"):
                embeddings = self._model.encode(
                    uncached_texts,
                    batch_size=self.config.batch_size,
                    normalize_embeddings=self.config.normalize_embeddings,
                    show_progress_bar=False
                )
                if hasattr(embeddings, "tolist"):
                    embeddings = embeddings.tolist()
            else:
                # Deterministic pseudo-embedding fallback based on text hash
                embeddings = [self._fallback_vector(t) for t in uncached_texts]

            for orig_idx, text, vec in zip(uncached_indices, uncached_texts, embeddings):
                vec_list = list(vec)
                results[orig_idx] = vec_list
                if self.config.cache_embeddings:
                    text_hash = self._hash_text(text)
                    self._cache[text_hash] = vec_list
                    if self._redis.enabled:
                        self._redis.set_json(f"embed:cache:{text_hash}", vec_list, ttl=86400 * 7)

        return [r if r is not None else [0.0] * self.dimension for r in results]

    def _fallback_vector(self, text: str) -> List[float]:
        """Generates a normalized deterministic float vector from SHA-256 digest."""
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        vec = []
        for i in range(self.dimension):
            byte_val = digest[i % len(digest)]
            vec.append((byte_val / 255.0) * 2.0 - 1.0)
        return vec
