# Phase 2 Migration Document — Knowledge Layer (Qdrant + Neo4j)

> **Phase Status**: Completed  
> **Verification Result**: 400 passed, 1 skipped in 33.25s (`pytest tests/ -q`)

---

## 1. Overview of Phase 2 Additions

Phase 2 builds the **Knowledge Layer** for **AI Code Guardian v3**, establishing the shared memory infrastructure used by future LangGraph agents.

It introduces:
1. **Embedding Pipeline (`guardian/knowledge/embeddings/`)**: Batch embedding service using Sentence Transformers and CodeBERT with caching and deterministic fallback.
2. **Qdrant Vector DB Integration (`guardian/knowledge/qdrant/`)**: `QdrantManager` for indexing and semantically retrieving repository documentation, policies, requirements, and compliance standards (OWASP/NIST).
3. **Neo4j Knowledge Graph (`guardian/knowledge/graph/`)**: `Neo4jManager` for storing structural graph topology (Repository, Files, Classes, Functions, Endpoints, Dependencies) and relationships (`CONTAINS`, `IMPORTS`, `CALLS`, `DEPENDS_ON`, `EXPOSES`).
4. **Repository Graph Builder (`guardian/knowledge/graph/builder.py`)**: Deterministic extraction of repository file structures, dependencies, entry points, and AST call graphs.
5. **Unified Knowledge Service Facade (`guardian/knowledge/services/knowledge_service.py`)**: `KnowledgeService` abstraction layer. Future LangGraph agents communicate exclusively through this service.

---

## 2. Directory Tree of Added & Modified Files

```
AI-Code-Guardian/
├── docs/
│   └── phases/
│       ├── phase1.md                         [PRESERVED] Phase 1 documentation
│       └── phase2.md                         [NEW] Documentation for Phase 2 migration
├── phases/
│   ├── phase1.md                         [PRESERVED] Phase 1 documentation
│   └── phase2.md                         [NEW] Mirror Phase 2 documentation
├── guardian/
│   └── knowledge/                            [NEW DIRECTORY]
│       ├── __init__.py                       [NEW] Master package exports
│       ├── config.py                         [NEW] KnowledgeConfig, EmbeddingConfig, QdrantConfig, Neo4jConfig
│       ├── embeddings/                       [NEW SUBDIRECTORY]
│       │   ├── __init__.py                   [NEW] Embeddings package exports
│       │   ├── base.py                       [NEW] BaseEmbedder interface
│       │   └── service.py                    [NEW] EmbeddingService (SentenceTransformers, CodeBERT & fallback)
│       ├── qdrant/                           [NEW SUBDIRECTORY]
│       │   ├── __init__.py                   [NEW] Qdrant package exports
│       │   └── manager.py                    [NEW] QdrantManager (Vector indexing, filtering & semantic search)
│       ├── graph/                            [NEW SUBDIRECTORY]
│       │   ├── __init__.py                   [NEW] Graph package exports
│       │   ├── manager.py                    [NEW] Neo4jManager (Node & edge graph manager with fallback)
│       │   └── builder.py                    [NEW] RepositoryGraphBuilder (AST/Profile graph generator)
│       ├── retrieval/                        [NEW SUBDIRECTORY]
│       │   ├── __init__.py                   [NEW] Retrieval package exports
│       │   └── engine.py                     [NEW] RetrievalEngine (Hybrid vector + graph queries)
│       └── services/                         [NEW SUBDIRECTORY]
│           ├── __init__.py                   [NEW] Services package exports
│           └── knowledge_service.py          [NEW] KnowledgeService facade for future LangGraph agents
└── tests/
    └── test_knowledge.py                     [NEW] Unit tests for EmbeddingService, Qdrant, Neo4j, Builder & KnowledgeService
```

---

## 3. Detail of New & Modified Files

### 3.1 New Modules & Files Added

1. **[`guardian/knowledge/config.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/config.py)**
   - Configurable settings for `EmbeddingConfig` (model name, batch size, device), `QdrantConfig` (host, port, location, collection names), and `Neo4jConfig` (uri, credentials, fallback flags).

2. **[`guardian/knowledge/embeddings/service.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/embeddings/service.py)**
   - `EmbeddingService` implementing `BaseEmbedder`. Provides batch embedding generation, SHA-256 result caching, and deterministic fallback when remote models are unavailable.

3. **[`guardian/knowledge/qdrant/manager.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/qdrant/manager.py)**
   - `QdrantManager` managing vector collection creation, batch document insertion, payload metadata filtering (category, `repo_id`), and cosine similarity search. Includes in-memory vector store fallback.

4. **[`guardian/knowledge/graph/manager.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/graph/manager.py)**
   - `Neo4jManager` handling node creation (`Repository`, `Directory`, `File`, `Class`, `Function`, `Endpoint`, `Dependency`), edge creation (`CONTAINS`, `IMPORTS`, `CALLS`, `DEPENDS_ON`, `EXPOSES`), Cypher query execution, and fallback in-memory graph driver.

5. **[`guardian/knowledge/graph/builder.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/graph/builder.py)**
   - `RepositoryGraphBuilder` deterministically walking `RepositoryProfile` and `USTFile` objects to populate the knowledge graph.

6. **[`guardian/knowledge/retrieval/engine.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/retrieval/engine.py)**
   - `RetrievalEngine` performing hybrid queries across vector search (Qdrant) and structural call/import graphs (Neo4j).

7. **[`guardian/knowledge/services/knowledge_service.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/knowledge/services/knowledge_service.py)**
   - `KnowledgeService` master facade providing `build_repository_graph`, `index_documents`, `semantic_search`, `get_symbol_graph`, `get_endpoints`, and `get_architecture_context`.

8. **[`tests/test_knowledge.py`](file:///d:/CDAC/AI-Code-Guardian/tests/test_knowledge.py)**
   - Comprehensive test suite covering embeddings, Qdrant search, Neo4j graph nodes/edges, graph builder, and `KnowledgeService`.

---

## 4. Execution & Information Flow

```
[ Target Repository ]
         │
         ▼
[ Repository Profiler & UST Parsers ]
         │
         ├─────────────────────────────────────────┐
         ▼                                         ▼
[ RepositoryGraphBuilder ]               [ Document Ingestion ]
(Extracts Nodes & Edges)                 (README, OWASP, Policies)
         │                                         │
         ▼                                         ▼
  [ Neo4jManager ]                          [ QdrantManager ]
(Structural Knowledge Graph)               (Semantic Vector Store)
         └────────────────────┬────────────────────┘
                              │
                              ▼
                   [ RetrievalEngine ]
                              │
                              ▼
                 [ KnowledgeService Facade ]
                              │
                              ▼
               (Future LangGraph Agents in Phase 3+)
```

---

## 5. Key Design Decisions & Offline Fallbacks

* **Strict Abstraction**: No module outside `KnowledgeService` directly communicates with Qdrant or Neo4j.
* **Offline-First Zero-Dependency Fallback**:
  - If a live Qdrant daemon is unavailable, `QdrantManager` automatically uses an in-memory vector store with cosine similarity matching.
  - If a live Neo4j database is unavailable, `Neo4jManager` automatically uses an in-memory graph driver.
* **100% Backward Compatibility**: Zero changes to existing engines or pipeline runners. All 395 baseline tests + 5 new Phase 2 tests pass without regressions.

---

## 6. Verification Summary

* Executed Pytest suite across all tests:
  ```bash
  pytest tests/ -q
  ```
* Output: `400 passed, 1 skipped in 33.25s`. Zero regressions.
