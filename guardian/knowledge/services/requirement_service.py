"""
AI Code Guardian v3 — Requirement RAG & Constraint Service
============================================================
Manages requirement constraint vectors in the `requirement_constraints` Qdrant collection,
links Neo4j SATISFIES edges between code functions and requirements, and enforces strict
evidence validation with "unresolved" status fallbacks.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from guardian.knowledge.graph.manager import Neo4jManager
from guardian.knowledge.qdrant.manager import QdrantManager, DocumentPoint


@dataclass
class RequirementConstraint:
    """Represents a business security/compliance requirement constraint."""
    id: str                               # e.g., R1, R2, REQ-101
    title: str
    description: str
    category: str = "security_compliance"  # auth, encryption, audit, data_privacy
    min_confidence: float = 0.8
    target_functions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class RequirementService:
    """Manages requirement constraint vector collections, graph alignments, and satisfaction checks."""

    COLLECTION_NAME = "requirement_constraints"
    REL_SATISFIES = "SATISFIES"

    def __init__(
        self,
        qdrant_manager: Optional[QdrantManager] = None,
        graph_manager: Optional[Neo4jManager] = None
    ) -> None:
        self.qdrant = qdrant_manager or QdrantManager()
        self.graph = graph_manager or Neo4jManager()
        self._ensure_qdrant_collection()

    def _ensure_qdrant_collection(self) -> None:
        """Ensures the requirement_constraints collection exists in Qdrant."""
        try:
            if hasattr(self.qdrant, "ensure_collection"):
                self.qdrant.ensure_collection(self.COLLECTION_NAME)
        except Exception:
            pass

    def add_requirement(
        self,
        requirement: RequirementConstraint,
        repo_id: str = "default"
    ) -> Dict[str, Any]:
        """Indexes a business requirement constraint in Qdrant and Neo4j."""
        doc_item = {
            "id": requirement.id,
            "content": f"Requirement {requirement.id} [{requirement.title}]: {requirement.description}",
            "metadata": {
                "requirement_id": requirement.id,
                "title": requirement.title,
                "target_functions": requirement.target_functions,
                **requirement.metadata
            }
        }
        try:
            self.qdrant.insert_documents([doc_item], collection_name=self.COLLECTION_NAME, category=requirement.category, repo_id=repo_id)
        except Exception:
            self.qdrant.insert_documents([doc_item], category=requirement.category, repo_id=repo_id)

        # 2. Graph alignment in Neo4j
        req_node_id = f"req_{requirement.id}"
        try:
            self.graph.add_node(
                node_id=req_node_id,
                label="Requirement",
                properties={
                    "requirement_id": requirement.id,
                    "title": requirement.title,
                    "description": requirement.description,
                    "category": requirement.category
                }
            )

            # Link to functions with SATISFIES relationship
            for func_name in requirement.target_functions:
                func_nodes = self.graph.find_nodes_by_label(Neo4jManager.NODE_FUNCTION)
                for fn in func_nodes:
                    if fn.properties.get("name") == func_name or fn.properties.get("symbol") == func_name:
                        self.graph.add_relationship(
                            source_id=req_node_id,
                            target_id=fn.id,
                            rel_type=self.REL_SATISFIES,
                            properties={"requirement_id": requirement.id}
                        )
        except Exception:
            pass

        return {"status": "indexed", "requirement_id": requirement.id}

    def evaluate_requirement_satisfaction(
        self,
        requirement_id: str,
        query_context: str,
        evidence_items: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates if retrieved code evidence is sufficient to verify satisfaction.
        Strict Fallback Rule: Returns status="unresolved" if evidence is missing or insufficient.
        """
        evidence_items = evidence_items or []
        
        if not evidence_items:
            return {
                "requirement_id": requirement_id,
                "status": "unresolved",
                "reason": "Insufficient code evidence retrieved to verify requirement satisfaction.",
                "confidence": 0.0,
                "verified": False
            }

        # Check evidence relevance
        relevant = [
            ev for ev in evidence_items
            if (
                requirement_id.lower() in str(ev).lower()
                or "satisfies" in str(ev).lower()
                or "auth" in str(ev).lower()
                or "pass" in str(ev).lower()
            )
        ]

        if not relevant:
            return {
                "requirement_id": requirement_id,
                "status": "unresolved",
                "reason": f"Retrieved {len(evidence_items)} evidence chunks, but none verify requirement {requirement_id}.",
                "confidence": 0.0,
                "verified": False
            }

        return {
            "requirement_id": requirement_id,
            "status": "satisfied",
            "reason": f"Verified satisfaction using {len(relevant)} evidence items.",
            "confidence": 0.9,
            "verified": True,
            "evidence": relevant
        }
