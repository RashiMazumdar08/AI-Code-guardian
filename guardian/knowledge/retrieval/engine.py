"""
AI Code Guardian v3 — Retrieval Engine
=======================================
Combines vector semantic search (QdrantManager) and structural graph queries (Neo4jManager)
into unified hybrid retrieval results.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from guardian.knowledge.graph.manager import Neo4jManager
from guardian.knowledge.qdrant.manager import QdrantManager


class RetrievalEngine:
    """Hybrid semantic and structural graph query engine."""

    def __init__(self, qdrant_manager: QdrantManager, graph_manager: Neo4jManager):
        self.qdrant = qdrant_manager
        self.graph = graph_manager

    def search_documentation(
        self,
        query: str,
        limit: int = 5,
        category: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Performs semantic vector search across indexed repository docs and policies."""
        return self.qdrant.search(query=query, limit=limit, category_filter=category)

    def find_connected_symbols(self, symbol_or_func_id: str) -> Dict[str, Any]:
        """Finds all imported modules, calls, and enclosing containers for a symbol."""
        node = self.graph.get_node(symbol_or_func_id)
        if not node:
            # Try searching by label/name
            all_funcs = self.graph.find_nodes_by_label(Neo4jManager.NODE_FUNCTION)
            for f in all_funcs:
                if f.properties.get("name") == symbol_or_func_id or f.properties.get("symbol") == symbol_or_func_id:
                    node = f
                    break

        if not node:
            return {"node": None, "outgoing_calls": [], "imports": []}

        outgoing_calls = self.graph.get_outgoing_relationships(node.id, Neo4jManager.REL_CALLS)
        imports = self.graph.get_outgoing_relationships(node.id, Neo4jManager.REL_IMPORTS)

        return {
            "node": node.properties,
            "outgoing_calls": [rel.target_id for rel in outgoing_calls],
            "imports": [rel.target_id for rel in imports]
        }

    def get_endpoints(self) -> List[Dict[str, Any]]:
        """Returns all public API endpoint nodes."""
        endpoint_nodes = self.graph.find_nodes_by_label(Neo4jManager.NODE_ENDPOINT)
        return [ep.properties for ep in endpoint_nodes]

    def get_repository_topology(self, repo_name: str) -> Dict[str, Any]:
        """Returns high-level graph topology summary for a repository."""
        repo_nodes = self.graph.find_nodes_by_label(Neo4jManager.NODE_REPOSITORY)
        files = self.graph.find_nodes_by_label(Neo4jManager.NODE_FILE)
        endpoints = self.graph.find_nodes_by_label(Neo4jManager.NODE_ENDPOINT)
        dependencies = self.graph.find_nodes_by_label(Neo4jManager.NODE_DEPENDENCY)

        target_repo = repo_nodes[0].properties if repo_nodes else {"name": repo_name}
        return {
            "repository": target_repo,
            "total_files": len(files),
            "total_endpoints": len(endpoints),
            "total_dependencies": len(dependencies),
            "files": [f.properties.get("path") for f in files if f.properties.get("path")],
            "endpoints": [ep.properties.get("url") for ep in endpoints if ep.properties.get("url")]
        }
