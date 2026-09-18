"""
AI Code Guardian v3 — Parallel Hybrid Dual-Path RRF Retrieval Engine
======================================================================
Executes parallel vector (semantic) and Neo4j graph (structural) searches via
`asyncio.gather`, merges ranked sets using Reciprocal Rank Fusion (RRF, k=60),
and formats payloads using ContextBudgetManager.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Set

from guardian.knowledge.graph.manager import Neo4jManager
from guardian.knowledge.qdrant.manager import QdrantManager
from guardian.knowledge.retrieval.budget_manager import ContextBudgetManager


class ParallelHybridEngine:
    """Parallel dual-path hybrid retrieval engine powered by RRF (k=60)."""

    def __init__(
        self,
        qdrant_manager: Optional[QdrantManager] = None,
        graph_manager: Optional[Neo4jManager] = None,
        budget_manager: Optional[ContextBudgetManager] = None,
        rrf_k: int = 60
    ) -> None:
        self.qdrant = qdrant_manager or QdrantManager()
        self.graph = graph_manager or Neo4jManager()
        self.budget_manager = budget_manager or ContextBudgetManager()
        self.rrf_k = rrf_k

    async def _async_semantic_search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Executes vector search across indexed security rules, policies, and code vectors."""
        def _sync_search():
            try:
                return self.qdrant.search(query=query, limit=limit)
            except Exception:
                return []
        return await asyncio.to_thread(_sync_search)

    async def _async_structural_search(self, query: str, limit: int) -> List[Dict[str, Any]]:
        """Executes Neo4j structural graph queries for CALLS, IMPORTS, EXPOSES relationships."""
        def _sync_graph_search():
            results = []
            try:
                # 1. Search nodes by name/symbol/id
                func_nodes = self.graph.find_nodes_by_label(Neo4jManager.NODE_FUNCTION)
                ep_nodes = self.graph.find_nodes_by_label(Neo4jManager.NODE_ENDPOINT)
                file_nodes = self.graph.find_nodes_by_label(Neo4jManager.NODE_FILE)

                q_lower = query.lower()
                for fn in func_nodes:
                    name = fn.properties.get("name", "")
                    if name and name.lower() in q_lower:
                        calls = self.graph.get_outgoing_relationships(fn.id, Neo4jManager.REL_CALLS)
                        imports = self.graph.get_outgoing_relationships(fn.id, Neo4jManager.REL_IMPORTS)
                        results.append({
                            "id": f"graph_fn_{fn.id}",
                            "title": f"Function: {name}",
                            "content": f"Function '{name}' calls {[c.target_id for c in calls]} and imports {[i.target_id for i in imports]}",
                            "source_type": "structural_graph",
                            "category": "graph_call_tree",
                            "metadata": fn.properties
                        })

                for ep in ep_nodes:
                    url = ep.properties.get("url", "")
                    if url and (url.lower() in q_lower or "endpoint" in q_lower or "api" in q_lower):
                        results.append({
                            "id": f"graph_ep_{ep.id}",
                            "title": f"Endpoint: {url}",
                            "content": f"Exposed API Endpoint '{url}' with properties {ep.properties}",
                            "source_type": "structural_graph",
                            "category": "graph_endpoint",
                            "metadata": ep.properties
                        })

                for fl in file_nodes[:limit]:
                    path = fl.properties.get("path", "")
                    if path and any(token in path.lower() for token in q_lower.split()):
                        results.append({
                            "id": f"graph_file_{fl.id}",
                            "title": f"File Topology: {path}",
                            "content": f"Repository File '{path}' with structural metadata {fl.properties}",
                            "source_type": "structural_graph",
                            "category": "graph_file",
                            "metadata": fl.properties
                        })
            except Exception:
                pass
            return results[:limit]

        return await asyncio.to_thread(_sync_graph_search)

    def apply_rrf(
        self,
        rankings: List[List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """
        Calculates Reciprocal Rank Fusion (RRF) scores across multiple ranked lists:
        RRF_Score(d) = sum( 1 / (k + rank(d)) ) for each list where d occurs.
        """
        doc_map: Dict[str, Dict[str, Any]] = {}
        score_map: Dict[str, float] = {}

        for rank_list in rankings:
            for rank_0idx, doc in enumerate(rank_list):
                # Unique key for doc
                doc_id = str(doc.get("id") or doc.get("finding_id") or doc.get("title") or doc.get("content")[:50])
                rank_1idx = rank_0idx + 1
                rrf_contrib = 1.0 / (self.rrf_k + rank_1idx)

                score_map[doc_id] = score_map.get(doc_id, 0.0) + rrf_contrib
                if doc_id not in doc_map:
                    doc_map[doc_id] = dict(doc)

        # Update rrf_score property on each doc
        fused_docs = []
        for doc_id, doc in doc_map.items():
            doc_copy = dict(doc)
            doc_copy["rrf_score"] = score_map[doc_id]
            fused_docs.append(doc_copy)

        fused_docs.sort(key=lambda d: d["rrf_score"], reverse=True)
        return fused_docs

    async def hybrid_search(
        self,
        query: str,
        top_k: int = 10,
        active_evidence_ids: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Executes parallel semantic and structural searches via asyncio.gather,
        applies RRF fusion (k=60), and formats payload via ContextBudgetManager.
        """
        # Parallel Execution
        semantic_res, structural_res = await asyncio.gather(
            self._async_semantic_search(query, top_k),
            self._async_structural_search(query, top_k)
        )

        # Apply Reciprocal Rank Fusion (RRF)
        fused_items = self.apply_rrf([semantic_res, structural_res])

        # Hand-off to ContextBudgetManager
        budgeted_payload = self.budget_manager.trim_and_format(
            items=fused_items,
            active_evidence_ids=active_evidence_ids
        )

        return {
            "query": query,
            "semantic_count": len(semantic_res),
            "structural_count": len(structural_res),
            "fused_total": len(fused_items),
            "results": budgeted_payload["included_items"],
            "formatted_context": budgeted_payload["formatted_context"],
            "used_tokens": budgeted_payload["used_tokens"],
            "evidence_ids_included": budgeted_payload["evidence_ids_included"]
        }
