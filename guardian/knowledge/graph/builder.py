"""
AI Code Guardian v3 — Repository Knowledge Graph Builder
===========================================================
Deterministically extracts structural nodes and relationships from repository files,
AST/UST structures, and RepositoryProfile, persisting them into Neo4jManager.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from guardian.discovery.repo_detector import RepositoryProfile
from guardian.knowledge.graph.manager import Neo4jManager
from guardian.ust.models import USTFile, USTNodeType


class RepositoryGraphBuilder:
    """Builds a deterministic structural graph of a repository."""

    def __init__(self, graph_manager: Optional[Neo4jManager] = None):
        self.graph = graph_manager or Neo4jManager()

    def build_graph(
        self,
        repo_path: Path,
        profile: RepositoryProfile,
        ust_files: Optional[List[USTFile]] = None
    ) -> Dict[str, int]:
        """
        Populates Neo4j graph with repository nodes and relationships.
        Returns node/relationship generation counts.
        """
        repo_path = Path(repo_path).resolve()
        repo_id = f"repo:{repo_path.name}"

        # 1. Create Repository Node
        self.graph.add_node(
            node_id=repo_id,
            label=Neo4jManager.NODE_REPOSITORY,
            properties={
                "name": repo_path.name,
                "path": str(repo_path),
                "primary_language": profile.primary_language,
                "frameworks": profile.frameworks,
                "build_tools": profile.build_tools,
                "architecture": profile.architecture,
                "is_monorepo": profile.is_monorepo,
            }
        )

        nodes_created = 1
        rels_created = 0

        # 2. Add Dependencies Nodes
        for manifest_file in profile.manifest_files:
            m_path = Path(manifest_file)
            dep_node_id = f"dep:{m_path.name}"
            self.graph.add_node(
                node_id=dep_node_id,
                label=Neo4jManager.NODE_DEPENDENCY,
                properties={"manifest": m_path.name, "path": str(m_path)}
            )
            nodes_created += 1

            self.graph.add_relationship(
                source_id=repo_id,
                target_id=dep_node_id,
                rel_type=Neo4jManager.REL_DEPENDS_ON
            )
            rels_created += 1

        # 3. Add Detected Endpoints Nodes
        for endpoint_url in profile.detected_endpoints:
            ep_id = f"endpoint:{endpoint_url}"
            self.graph.add_node(
                node_id=ep_id,
                label=Neo4jManager.NODE_ENDPOINT,
                properties={"url": endpoint_url}
            )
            nodes_created += 1

            self.graph.add_relationship(
                source_id=repo_id,
                target_id=ep_id,
                rel_type=Neo4jManager.REL_EXPOSES
            )
            rels_created += 1

        # 4. Extract Files, Classes, Functions, and Calls from UST
        if ust_files:
            dir_cache: Set[str] = set()

            for ust_file in ust_files:
                rel_cand = getattr(ust_file, "rel_path", None) or getattr(ust_file, "filepath", None) or getattr(ust_file, "path", "")
                try:
                    p = Path(rel_cand).resolve()
                    if p.is_absolute():
                        file_rel = str(p.relative_to(repo_path))
                    else:
                        file_rel = rel_cand
                except Exception:
                    file_rel = rel_cand

                file_node_id = f"file:{file_rel}"

                # Create Directory Nodes up the path
                file_path = Path(file_rel)
                parent_dir = file_path.parent
                if str(parent_dir) not in (".", ""):
                    dir_node_id = f"dir:{parent_dir}"
                    if dir_node_id not in dir_cache:
                        self.graph.add_node(
                            node_id=dir_node_id,
                            label=Neo4jManager.NODE_DIRECTORY,
                            properties={"path": str(parent_dir)}
                        )
                        self.graph.add_relationship(
                            source_id=repo_id,
                            target_id=dir_node_id,
                            rel_type=Neo4jManager.REL_CONTAINS
                        )
                        dir_cache.add(dir_node_id)
                        nodes_created += 1
                        rels_created += 1

                # Create File Node
                self.graph.add_node(
                    node_id=file_node_id,
                    label=Neo4jManager.NODE_FILE,
                    properties={
                        "path": file_rel,
                        "language": ust_file.language,
                        "loc": getattr(ust_file, "line_count", 0),
                        "is_entry_point": file_rel in profile.entry_points
                    }
                )
                nodes_created += 1

                self.graph.add_relationship(
                    source_id=repo_id,
                    target_id=file_node_id,
                    rel_type=Neo4jManager.REL_CONTAINS
                )
                rels_created += 1

                # Add File Imports
                for imp_name in ust_file.imports:
                    mod_id = f"module:{imp_name}"
                    self.graph.add_node(
                        node_id=mod_id,
                        label=Neo4jManager.NODE_MODULE,
                        properties={"name": imp_name}
                    )
                    self.graph.add_relationship(
                        source_id=file_node_id,
                        target_id=mod_id,
                        rel_type=Neo4jManager.REL_IMPORTS
                    )
                    nodes_created += 1
                    rels_created += 1

                # Traverse UST Nodes for Classes & Functions
                for n in ust_file.nodes:
                    start_line = n.span.start_line if hasattr(n, "span") and hasattr(n.span, "start_line") else 0
                    if n.type == USTNodeType.CLASS:
                        class_id = f"class:{file_rel}#{n.name}"
                        self.graph.add_node(
                            node_id=class_id,
                            label=Neo4jManager.NODE_CLASS,
                            properties={"name": n.name, "file": file_rel, "line": start_line}
                        )
                        self.graph.add_relationship(
                            source_id=file_node_id,
                            target_id=class_id,
                            rel_type=Neo4jManager.REL_CONTAINS
                        )
                        nodes_created += 1
                        rels_created += 1

                    elif n.type == USTNodeType.FUNCTION:
                        func_id = f"func:{file_rel}#{n.name}"
                        self.graph.add_node(
                            node_id=func_id,
                            label=Neo4jManager.NODE_FUNCTION,
                            properties={
                                "name": n.name,
                                "file": file_rel,
                                "line": start_line,
                                "is_entry_point": "entry_point" in n.business_tags
                            }
                        )
                        self.graph.add_relationship(
                            source_id=file_node_id,
                            target_id=func_id,
                            rel_type=Neo4jManager.REL_CONTAINS
                        )
                        nodes_created += 1
                        rels_created += 1

                    elif n.type in (USTNodeType.CALL, USTNodeType.API_ENDPOINT):
                        if n.symbol:
                            target_call_id = f"symbol:{n.symbol}"
                            self.graph.add_node(
                                node_id=target_call_id,
                                label=Neo4jManager.NODE_FUNCTION,
                                properties={"symbol": n.symbol}
                            )
                            self.graph.add_relationship(
                                source_id=file_node_id,
                                target_id=target_call_id,
                                rel_type=Neo4jManager.REL_CALLS,
                                properties={"line": start_line}
                            )
                            nodes_created += 1
                            rels_created += 1

        return {"nodes": nodes_created, "relationships": rels_created}
