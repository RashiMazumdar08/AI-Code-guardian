"""
AI Code Guardian v3 — Neo4j Knowledge Graph Integration
=========================================================
Provides Neo4jManager for persisting and traversing code repository structure,
module dependencies, call graphs, endpoints, and architectural relationships.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from guardian.knowledge.config import Neo4jConfig


@dataclass
class GraphNode:
    """Represents a graph node (e.g. Repository, File, Function, Endpoint)."""
    id: str
    label: str                            # Entity type, e.g., File, Function, Endpoint
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphRelationship:
    """Represents a directed graph edge between two nodes."""
    source_id: str
    target_id: str
    type: str                             # Relationship type, e.g., CALLS, IMPORTS, CONTAINS
    properties: Dict[str, Any] = field(default_factory=dict)


class Neo4jManager:
    """Manages Neo4j knowledge graph connections, node/edge insertions, and queries."""

    # Node Labels
    NODE_REPOSITORY = "Repository"
    NODE_DIRECTORY = "Directory"
    NODE_FILE = "File"
    NODE_MODULE = "Module"
    NODE_CLASS = "Class"
    NODE_FUNCTION = "Function"
    NODE_METHOD = "Method"
    NODE_ENDPOINT = "Endpoint"
    NODE_DEPENDENCY = "Dependency"
    NODE_ENV_VAR = "EnvironmentVariable"
    NODE_SECRET = "Secret"
    NODE_CONFIG_FILE = "ConfigFile"
    NODE_BUSINESS_CAPABILITY = "BusinessCapability"

    # Relationship Types
    REL_CONTAINS = "CONTAINS"
    REL_IMPORTS = "IMPORTS"
    REL_CALLS = "CALLS"
    REL_USES = "USES"
    REL_DEPENDS_ON = "DEPENDS_ON"
    REL_AUTHENTICATES = "AUTHENTICATES"
    REL_IMPLEMENTS = "IMPLEMENTS"
    REL_EXPOSES = "EXPOSES"

    def __init__(self, config: Optional[Neo4jConfig] = None):
        self.config = config or Neo4jConfig()
        self._driver = None
        self._is_neo4j_available: Optional[bool] = None
        
        # Fallback graph storage
        self._nodes: Dict[str, GraphNode] = {}
        self._relationships: List[GraphRelationship] = []

    def _init_driver(self):
        """Initializes Neo4j Python driver if available."""
        if self._is_neo4j_available is not None:
            return

        try:
            from neo4j import GraphDatabase
            self._driver = GraphDatabase.driver(
                self.config.uri,
                auth=(self.config.user, self.config.password)
            )
            # Test connectivity
            self._driver.verify_connectivity()
            self._is_neo4j_available = True
        except Exception:
            self._is_neo4j_available = False

    def close(self):
        if self._driver is not None:
            try:
                self._driver.close()
            except Exception:
                pass

    def add_node(self, node_id: str, label: str, properties: Optional[Dict[str, Any]] = None) -> GraphNode:
        """Inserts or updates a graph node."""
        props = properties.copy() if properties else {}
        props["id"] = node_id
        node = GraphNode(id=node_id, label=label, properties=props)

        self._init_driver()
        if self._is_neo4j_available and self._driver is not None:
            try:
                with self._driver.session(database=self.config.database) as session:
                    cypher = f"MERGE (n:{label} {{id: $id}}) SET n += $props"
                    session.run(cypher, id=node_id, props=props)
                return node
            except Exception:
                pass

        # Fallback in-memory graph
        self._nodes[node_id] = node
        return node

    def add_relationship(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        properties: Optional[Dict[str, Any]] = None
    ) -> GraphRelationship:
        """Inserts a directed relationship between source and target nodes."""
        props = properties.copy() if properties else {}
        rel = GraphRelationship(source_id=source_id, target_id=target_id, type=rel_type, properties=props)

        self._init_driver()
        if self._is_neo4j_available and self._driver is not None:
            try:
                with self._driver.session(database=self.config.database) as session:
                    cypher = (
                        f"MATCH (a {{id: $source_id}}), (b {{id: $target_id}}) "
                        f"MERGE (a)-[r:{rel_type}]->(b) SET r += $props"
                    )
                    session.run(cypher, source_id=source_id, target_id=target_id, props=props)
                return rel
            except Exception:
                pass

        # Fallback in-memory graph
        self._relationships.append(rel)
        return rel

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieves a node by ID."""
        self._init_driver()
        if self._is_neo4j_available and self._driver is not None:
            try:
                with self._driver.session(database=self.config.database) as session:
                    cypher = "MATCH (n {id: $id}) RETURN labels(n) AS labels, properties(n) AS props"
                    res = session.run(cypher, id=node_id).single()
                    if res:
                        label = res["labels"][0] if res["labels"] else "Node"
                        return GraphNode(id=node_id, label=label, properties=res["props"])
            except Exception:
                pass

        return self._nodes.get(node_id)

    def find_nodes_by_label(self, label: str) -> List[GraphNode]:
        """Returns all nodes matching a specific label."""
        self._init_driver()
        if self._is_neo4j_available and self._driver is not None:
            try:
                with self._driver.session(database=self.config.database) as session:
                    cypher = f"MATCH (n:{label}) RETURN n.id AS id, properties(n) AS props"
                    res = session.run(cypher)
                    return [GraphNode(id=r["id"], label=label, properties=r["props"]) for r in res]
            except Exception:
                pass

        return [n for n in self._nodes.values() if n.label == label]

    def get_outgoing_relationships(self, source_id: str, rel_type: Optional[str] = None) -> List[GraphRelationship]:
        """Retrieves all outgoing relationships from a node."""
        self._init_driver()
        if self._is_neo4j_available and self._driver is not None:
            try:
                with self._driver.session(database=self.config.database) as session:
                    rel_clause = f":{rel_type}" if rel_type else ""
                    cypher = (
                        f"MATCH (a {{id: $source_id}})-[r{rel_clause}]->(b) "
                        f"RETURN type(r) AS rel_type, b.id AS target_id, properties(r) AS props"
                    )
                    res = session.run(cypher, source_id=source_id)
                    return [
                        GraphRelationship(
                            source_id=source_id,
                            target_id=r["target_id"],
                            type=r["rel_type"],
                            properties=r["props"]
                        )
                        for r in res
                    ]
            except Exception:
                pass

        return [
            rel for rel in self._relationships
            if rel.source_id == source_id and (rel_type is None or rel.type == rel_type)
        ]

    def clear(self):
        """Clears graph data."""
        self._init_driver()
        if self._is_neo4j_available and self._driver is not None:
            try:
                with self._driver.session(database=self.config.database) as session:
                    session.run("MATCH (n) DETACH DELETE n")
            except Exception:
                pass

        self._nodes.clear()
        self._relationships.clear()
