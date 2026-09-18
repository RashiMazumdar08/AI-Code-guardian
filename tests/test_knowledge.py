"""
AI Code Guardian v3 — Phase 2 Knowledge Layer Tests
===================================================
Tests for EmbeddingService, QdrantManager, Neo4jManager, RepositoryGraphBuilder,
and the unified KnowledgeService facade.
"""
import tempfile
from pathlib import Path

import pytest
from guardian.discovery.repo_detector import RepositoryDetector, RepositoryProfile
from guardian.config import GuardianConfig
from guardian.core.pipeline import ScanPipeline
from guardian.knowledge import (
    EmbeddingService,
    KnowledgeConfig,
    KnowledgeService,
    Neo4jManager,
    QdrantManager,
    RepositoryGraphBuilder,
)
from guardian.ust.models import USTFile, USTNode, USTNodeType, SourceSpan


def test_embedding_service():
    service = EmbeddingService()
    text = "Security requirements for JWT authorization."
    vec = service.embed_text(text)

    assert isinstance(vec, list)
    assert len(vec) == service.dimension

    # Test batch embedding & caching
    batch_vecs = service.embed_batch([text, "Another sample document."])
    assert len(batch_vecs) == 2
    assert batch_vecs[0] == vec  # Returned from cache


def test_qdrant_manager_indexing_and_search():
    qdrant = QdrantManager()
    docs = [
        {"content": "OWASP A01:2021 Broken Access Control details.", "id": "doc1"},
        {"content": "NIST FIPS 203 Post-Quantum Cryptography standards.", "id": "doc2"},
    ]

    doc_ids = qdrant.insert_documents(docs, category="standards", repo_id="test_repo")
    assert len(doc_ids) == 2

    # Semantic search
    results = qdrant.search("Broken Access Control", limit=2, category_filter="standards")
    assert len(results) > 0
    assert "Broken Access Control" in results[0]["content"]

    # Delete
    qdrant.delete_documents(["doc1"])
    deleted_search = qdrant.search("Broken Access Control", limit=2, category_filter="standards")
    assert not any(r["id"] == "doc1" for r in deleted_search)


def test_neo4j_manager_graph():
    graph = Neo4jManager()
    graph.clear()

    n1 = graph.add_node("repo:test", Neo4jManager.NODE_REPOSITORY, {"name": "test"})
    n2 = graph.add_node("file:app.py", Neo4jManager.NODE_FILE, {"path": "app.py"})
    r1 = graph.add_relationship(n1.id, n2.id, Neo4jManager.REL_CONTAINS)

    assert graph.get_node("repo:test") is not None
    assert graph.get_node("file:app.py") is not None

    rels = graph.get_outgoing_relationships("repo:test", Neo4jManager.REL_CONTAINS)
    assert len(rels) == 1
    assert rels[0].target_id == "file:app.py"


def test_repository_graph_builder():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        (repo_path / "requirements.txt").write_text("fastapi\n")
        app_file = repo_path / "main.py"
        app_file.write_text("import fastapi\n")

        detector = RepositoryDetector()
        profile = detector.detect(repo_path, [repo_path / "requirements.txt", app_file])

        ust_file = USTFile(
            path=str(app_file),
            language="python",
            imports=["fastapi"],
            nodes=[
                USTNode(
                    type=USTNodeType.FUNCTION,
                    language="python",
                    file="main.py",
                    name="main",
                    symbol="main",
                    span=SourceSpan(start_line=1, end_line=5)
                )
            ]
        )

        graph_mgr = Neo4jManager()
        builder = RepositoryGraphBuilder(graph_mgr)
        counts = builder.build_graph(repo_path, profile, ust_files=[ust_file])

        assert counts["nodes"] > 0
        assert counts["relationships"] > 0
        assert graph_mgr.get_node("repo:" + repo_path.name) is not None
        assert graph_mgr.get_node("file:main.py") is not None


def test_knowledge_service_facade():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        (repo_path / "README.md").write_text("# Project AI Guardian\nMulti-agent security platform.")

        service = KnowledgeService()

        # Index document
        doc_ids = service.index_documents(
            documents=[{"content": "Security policy: JWT lifetime must not exceed 3600 seconds.", "id": "pol1"}],
            category="policy",
            repo_id=repo_path.name
        )
        assert len(doc_ids) == 1

        # Search documents
        results = service.semantic_search("JWT lifetime policy", category="policy")
        assert len(results) > 0
        assert "JWT" in results[0]["content"]

        # Build repository graph via service
        profile = RepositoryProfile(root=str(repo_path), primary_language="Python")
        res = service.build_repository_graph(repo_path, profile)
        assert res["nodes"] >= 1

        # Retrieve architecture topology
        topology = service.get_architecture_context(repo_path.name)
        assert "repository" in topology
        assert topology["total_files"] >= 0

        service.close()


def test_pipeline_scan_can_build_knowledge_context():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir)
        (repo_path / "README.md").write_text("# API Service\nDocuments JWT policy and public endpoints.")
        (repo_path / "requirements.txt").write_text("fastapi\n")
        (repo_path / "app.py").write_text(
            "from fastapi import FastAPI\n"
            "app = FastAPI()\n\n"
            "@app.get('/health')\n"
            "def health():\n"
            "    return {'ok': True}\n"
        )

        report = ScanPipeline(GuardianConfig(enable_knowledge=True)).scan(repo_path)

        assert report["knowledge"]["enabled"] is True
        assert report["knowledge"]["graph"]["nodes"] >= 1
        assert report["knowledge"]["documents_indexed"] >= 1
        assert any(ep.get("url") == "/health" for ep in report["knowledge"]["endpoints"])
