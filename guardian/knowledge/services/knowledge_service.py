"""
AI Code Guardian v3 — Unified Knowledge Service
=================================================
The single facade and abstraction layer for all repository knowledge graph queries
and Qdrant semantic vector retrievals.

All future LangGraph agents communicate exclusively with KnowledgeService.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.discovery.repo_detector import RepositoryProfile
from guardian.knowledge.config import KnowledgeConfig
from guardian.knowledge.embeddings.service import EmbeddingService
from guardian.knowledge.graph.builder import RepositoryGraphBuilder
from guardian.knowledge.graph.manager import Neo4jManager
from guardian.knowledge.qdrant.manager import QdrantManager
from guardian.knowledge.retrieval.engine import RetrievalEngine
from guardian.ust.models import USTFile


class KnowledgeService:
    """Unified repository graph and semantic intelligence facade for AI agents."""

    def __init__(self, config: Optional[KnowledgeConfig] = None):
        self.config = config or KnowledgeConfig()

        self.embedder = EmbeddingService(self.config.embedding)
        self.qdrant = QdrantManager(self.config.qdrant, embedder=self.embedder)
        self.neo4j = Neo4jManager(self.config.neo4j)
        self.graph_builder = RepositoryGraphBuilder(self.neo4j)
        self.retrieval = RetrievalEngine(self.qdrant, self.neo4j)

    def build_repository_graph(
        self,
        repo_path: Path,
        profile: RepositoryProfile,
        ust_files: Optional[List[USTFile]] = None
    ) -> Dict[str, int]:
        """Populates Neo4j knowledge graph from repository files, profile, and UST AST nodes."""
        return self.graph_builder.build_graph(repo_path, profile, ust_files)

    def index_documents(
        self,
        documents: List[Dict[str, Any]],
        category: str = "documentation",
        repo_id: str = "default"
    ) -> List[str]:
        """Indexes semantic text documents (README, specs, policies, OWASP/NIST) into Qdrant."""
        return self.qdrant.insert_documents(
            documents=documents,
            category=category,
            repo_id=repo_id
        )

    def semantic_search(
        self,
        query: str,
        limit: int = 5,
        category: Optional[str] = None,
        repo_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Performs semantic vector retrieval against indexed documents."""
        return self.qdrant.search(
            query=query,
            limit=limit,
            category_filter=category,
            repo_id_filter=repo_id
        )

    def get_symbol_graph(self, symbol_or_func: str) -> Dict[str, Any]:
        """Retrieves graph topology (calls, imports, enclosing class) for a given symbol."""
        return self.retrieval.find_connected_symbols(symbol_or_func)

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Retrieves all API endpoints registered in the repository knowledge graph."""
        return self.retrieval.get_endpoints()

    def get_architecture_context(self, repo_name: str) -> Dict[str, Any]:
        """Retrieves architecture shape, file counts, and graph topology summary."""
        return self.retrieval.get_repository_topology(repo_name)

    def get_related_files(self, file_path: str) -> List[str]:
        """Retrieves files imported by or connected to a target file in the knowledge graph."""
        file_node_id = f"file:{file_path}"
        imports = self.neo4j.get_outgoing_relationships(file_node_id, Neo4jManager.REL_IMPORTS)
        return [imp.target_id.replace("module:", "") for imp in imports]

    def get_policy_context(self, repo_id: str = "default") -> List[Dict[str, Any]]:
        """Retrieves semantic policy documents for a given repository."""
        return self.semantic_search("compliance security policy rules", category="policy", repo_id=repo_id)

    def get_business_context(self, repo_id: str = "default") -> List[Dict[str, Any]]:
        """Retrieves business intent documentation for a given repository."""
        return self.semantic_search("business domain criticality requirements", category="requirements", repo_id=repo_id)

    def get_threat_context(self, repo_id: str = "default") -> List[Dict[str, Any]]:
        """Retrieves threat modeling vectors and attack surface context."""
        return self.semantic_search("threat model attack vector vulnerability", category="threat", repo_id=repo_id)

    def lookup_evidence(self, evidence_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves evidence object details from vector store or graph."""
        res = self.qdrant.search(query=evidence_id, limit=1)
        return res[0] if res else None

    def traverse_graph(self, start_node_id: str, depth: int = 2) -> Dict[str, Any]:
        """Traverses knowledge graph topology outwards from a starting node."""
        node = self.neo4j.get_node(start_node_id)
        rels = self.neo4j.get_outgoing_relationships(start_node_id)
        return {
            "node": node.__dict__ if node else None,
            "connected_relationships": [r.__dict__ for r in rels[:10]],
            "depth": depth
        }

    def search_architecture(self, query: str) -> List[Dict[str, Any]]:
        """Performs architecture semantic search."""
        return self.semantic_search(query, category="architecture")

    def get_patch_context(self, finding_id: str) -> Dict[str, Any]:
        """Retrieves symbol and AST context needed for downstream patch generation."""
        return self.get_symbol_graph(finding_id)

    def close(self):
        """Cleanly releases database resources."""
        self.neo4j.close()
