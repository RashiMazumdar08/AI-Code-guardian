"""
AI Code Guardian v3 — Knowledge Package
==========================================
Provides Qdrant vector storage, Neo4j knowledge graph, embedding services,
and the unified KnowledgeService facade.
"""
from guardian.knowledge.config import KnowledgeConfig, EmbeddingConfig, QdrantConfig, Neo4jConfig
from guardian.knowledge.embeddings import EmbeddingService, BaseEmbedder
from guardian.knowledge.qdrant import QdrantManager
from guardian.knowledge.graph import Neo4jManager, RepositoryGraphBuilder
from guardian.knowledge.services import KnowledgeService

__all__ = [
    "KnowledgeConfig",
    "EmbeddingConfig",
    "QdrantConfig",
    "Neo4jConfig",
    "EmbeddingService",
    "BaseEmbedder",
    "QdrantManager",
    "Neo4jManager",
    "RepositoryGraphBuilder",
    "KnowledgeService",
]
