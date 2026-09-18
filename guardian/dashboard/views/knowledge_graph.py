"""
AI Code Guardian v3 — Knowledge Graph Page
==========================================
Visualizes Neo4j repository graph elements retrieved strictly via KnowledgeService facade.
Never queries Neo4j directly.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from guardian.knowledge.services.knowledge_service import KnowledgeService


class KnowledgeGraphPage:
    """Renders interactive Knowledge Graph navigation view using KnowledgeService."""

    def __init__(self, knowledge_service: Optional[KnowledgeService] = None) -> None:
        self.ks = knowledge_service or KnowledgeService()

    def render(self, state_view: Optional[Any] = None, query_node: str = "Root") -> Dict[str, Any]:
        """Retrieves architecture and graph elements from KnowledgeService facade."""
        target_query = query_node if isinstance(query_node, str) else "Root"
        arch_data = self.ks.search_architecture(target_query)
        graph_nodes = self.ks.traverse_graph(target_query)

        if not arch_data and state_view and hasattr(state_view, "architecture_context"):
            arch_ctx = getattr(state_view, "architecture_context", {})
            arch_data = arch_ctx.get("components", [
                {"name": "FastAPI API Backend", "type": "Framework", "query_match": target_query},
                {"name": "Security Scanner", "type": "Engine", "query_match": target_query},
            ])

        if not graph_nodes and state_view and hasattr(state_view, "repository_context"):
            repo_ctx = getattr(state_view, "repository_context", {})
            graph_nodes = [
                {"node_id": "root", "label": "RepositoryRoot", "path": repo_ctx.get("summary", "Monolith Root")},
                {"node_id": "entry", "label": "EntryPoint", "path": ", ".join(repo_ctx.get("entry_points", [])) or "main.py"},
                {"node_id": "auth", "label": "AuthModule", "path": ", ".join(repo_ctx.get("auth_modules", [])) or "auth"},
            ]

        return {
            "page_title": "Knowledge Graph Explorer",
            "query_node": query_node,
            "architecture_nodes": arch_data,
            "traversed_nodes": graph_nodes,
            "total_nodes_found": len(graph_nodes) + len(arch_data),
        }
