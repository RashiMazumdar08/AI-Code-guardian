"""
AI Code Guardian v3 — Qdrant Vector DB Integration
===================================================
Provides QdrantManager for storing, indexing, filtering, and semantically retrieving
repository documentation, policies, requirements, and compliance standards.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from guardian.knowledge.config import QdrantConfig
from guardian.knowledge.embeddings.service import EmbeddingService


@dataclass
class DocumentPoint:
    """Represents a document indexed in Qdrant."""
    id: str
    content: str
    vector: List[float]
    metadata: Dict[str, Any] = field(default_factory=dict)
    category: str = "general"               # e.g., README, policy, owasp, nist, requirement
    repo_id: str = "default"


class QdrantManager:
    """Manages vector storage, indexing, filtering, and semantic search."""

    def __init__(
        self,
        config: Optional[QdrantConfig] = None,
        embedder: Optional[EmbeddingService] = None
    ):
        self.config = config or QdrantConfig()
        self.embedder = embedder or EmbeddingService()
        self._client = None
        self._in_memory_store: Dict[str, List[DocumentPoint]] = {}
        self._is_qdrant_client_available: Optional[bool] = None

    def _init_client(self):
        """Initializes connection to Qdrant server or memory store."""
        if self._is_qdrant_client_available is not None:
            return

        try:
            import qdrant_client
            from qdrant_client import QdrantClient
            if self.config.location == ":memory:":
                self._client = QdrantClient(location=":memory:")
            else:
                self._client = QdrantClient(
                    host=self.config.host,
                    port=self.config.port,
                    api_key=self.config.api_key
                )
            self._is_qdrant_client_available = True
        except Exception:
            self._is_qdrant_client_available = False

    def create_collection(self, collection_name: str, vector_size: Optional[int] = None) -> bool:
        """Creates a collection in Qdrant if it does not exist."""
        self._init_client()
        v_size = vector_size or self.config.vector_size

        if self._is_qdrant_client_available and self._client is not None:
            try:
                from qdrant_client.http import models
                collections = [c.name for c in self._client.get_collections().collections]
                if collection_name not in collections:
                    self._client.create_collection(
                        collection_name=collection_name,
                        vectors_config=models.VectorParams(
                            size=v_size,
                            distance=models.Distance.COSINE
                        )
                    )
                return True
            except Exception:
                pass

        # Fallback memory store
        if collection_name not in self._in_memory_store:
            self._in_memory_store[collection_name] = []
        return True

    def insert_documents(
        self,
        documents: List[Dict[str, Any]],
        collection_name: Optional[str] = None,
        category: str = "general",
        repo_id: str = "default"
    ) -> List[str]:
        """
        Inserts document dicts into Qdrant collection.
        Document dict format: {"content": str, "metadata": dict, "id": optional str}
        """
        target_collection = collection_name or self.config.default_collection
        self.create_collection(target_collection)

        texts = [doc["content"] for doc in documents]
        vectors = self.embedder.embed_batch(texts)

        points: List[DocumentPoint] = []
        point_ids: List[str] = []

        for doc, vec in zip(documents, vectors):
            doc_id = doc.get("id") or str(uuid.uuid4())
            metadata = doc.get("metadata", {}).copy()
            metadata["category"] = category
            metadata["repo_id"] = repo_id

            dp = DocumentPoint(
                id=doc_id,
                content=doc["content"],
                vector=vec,
                metadata=metadata,
                category=category,
                repo_id=repo_id
            )
            points.append(dp)
            point_ids.append(doc_id)

        if self._is_qdrant_client_available and self._client is not None:
            try:
                from qdrant_client.http import models
                q_points = [
                    models.PointStruct(
                        id=p.id,
                        vector=p.vector,
                        payload={"content": p.content, **p.metadata}
                    )
                    for p in points
                ]
                self._client.upsert(collection_name=target_collection, points=q_points)
                return point_ids
            except Exception:
                pass

        # Fallback memory store
        self._in_memory_store[target_collection].extend(points)
        return point_ids

    def search(
        self,
        query: str,
        collection_name: Optional[str] = None,
        limit: int = 5,
        category_filter: Optional[str] = None,
        repo_id_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Performs semantic vector search against indexed documents."""
        target_collection = collection_name or self.config.default_collection
        self.create_collection(target_collection)

        query_vec = self.embedder.embed_text(query)

        if self._is_qdrant_client_available and self._client is not None:
            try:
                from qdrant_client.http import models
                must_filters = []
                if category_filter:
                    must_filters.append(models.FieldCondition(key="category", match=models.MatchValue(value=category_filter)))
                if repo_id_filter:
                    must_filters.append(models.FieldCondition(key="repo_id", match=models.MatchValue(value=repo_id_filter)))

                q_filter = models.Filter(must=must_filters) if must_filters else None

                results = self._client.search(
                    collection_name=target_collection,
                    query_vector=query_vec,
                    query_filter=q_filter,
                    limit=limit
                )

                output = []
                for res in results:
                    payload = dict(res.payload or {})
                    content = payload.pop("content", "")
                    output.append({
                        "id": str(res.id),
                        "score": float(res.score),
                        "content": content,
                        "metadata": payload
                    })
                return output
            except Exception:
                pass

        # Fallback cosine search over memory store
        points = self._in_memory_store.get(target_collection, [])
        scored = []
        for p in points:
            if category_filter and p.category != category_filter:
                continue
            if repo_id_filter and p.repo_id != repo_id_filter:
                continue

            score = self._cosine_similarity(query_vec, p.vector)
            scored.append({
                "id": p.id,
                "score": round(score, 4),
                "content": p.content,
                "metadata": p.metadata
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:limit]

    def delete_documents(self, document_ids: List[str], collection_name: Optional[str] = None) -> bool:
        """Deletes documents by ID."""
        target_collection = collection_name or self.config.default_collection
        if self._is_qdrant_client_available and self._client is not None:
            try:
                from qdrant_client.http import models
                self._client.delete(
                    collection_name=target_collection,
                    points_selector=models.PointIdsList(points=document_ids)
                )
                return True
            except Exception:
                pass

        if target_collection in self._in_memory_store:
            id_set = set(document_ids)
            self._in_memory_store[target_collection] = [
                p for p in self._in_memory_store[target_collection] if p.id not in id_set
            ]
        return True

    def _cosine_similarity(self, v1: List[float], v2: List[float]) -> float:
        if not v1 or not v2 or len(v1) != len(v2):
            return 0.0
        dot = sum(a * b for a, b in zip(v1, v2))
        norm1 = sum(a * a for a in v1) ** 0.5
        norm2 = sum(b * b for b in v2) ** 0.5
        if norm1 == 0 or norm2 == 0:
            return 0.0
        return dot / (norm1 * norm2)
