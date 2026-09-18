"""
AI Code Guardian — Code Indexer
==================================
Orchestrates the complete indexing pipeline:

    File paths / uploaded bytes
          ↓
    DocumentLoader  (chunk)
          ↓
    EmbeddingRouter (embed via CodeBERT or the local embedder)
          ↓
    FAISSVectorStore (store + persist)

Also accepts scan reports and business intent reports as JSON strings
so fresh scan results are always searchable within the same session.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Optional

from guardian.ai.config import AssistantConfig
from guardian.ai.document_loader import DocumentLoader
from guardian.ai.embeddings import EmbeddingRouter
from guardian.ai.models import Document, DocumentType, IndexStats
from guardian.ai.vector_store import FAISSVectorStore

logger = logging.getLogger(__name__)


class CodeIndexer:
    """
    Top-level indexing orchestrator.

    Typical usage
    -------------
        indexer = CodeIndexer(config, vector_store, embedding_router, loader)
        indexer.index_directory(Path("/path/to/repo"))
        indexer.index_scan_report(scan_json_str)
        # vector_store is now populated and persisted
    """

    def __init__(
        self,
        config: AssistantConfig,
        vector_store: FAISSVectorStore,
        embedding_router: EmbeddingRouter,
        document_loader: DocumentLoader,
    ):
        self._cfg      = config
        self._store    = vector_store
        self._embedder = embedding_router
        self._loader   = document_loader

    # ------------------------------------------------------------------
    # Indexing entry points
    # ------------------------------------------------------------------

    def index_directory(self, root: Path, clear_first: bool = False) -> IndexStats:
        """
        Walk `root` and index every supported file.
        Pass clear_first=True to rebuild the index from scratch.
        """
        if clear_first:
            self._store.clear()
        t0 = time.time()
        docs = self._loader.load_directory(root)
        if not docs:
            logger.warning("No documents found in %s", root)
            return self._store.stats()
        self._embed_and_store(docs)
        elapsed = round(time.time() - t0, 1)
        stats = self._store.stats()
        logger.info(
            "Indexed %s in %.1fs — %d code vectors, %d doc vectors",
            root, elapsed, stats.code_vectors, stats.doc_vectors,
        )
        return stats

    def index_files(self, paths: list[Path], root: Optional[Path] = None) -> int:
        """Index a specific list of files (e.g. uploaded via Streamlit)."""
        docs = self._loader.load_files(paths, root)
        if docs:
            self._embed_and_store(docs)
        return len(docs)

    def index_text(
        self,
        text: str,
        source_name: str,
        doc_type: DocumentType = DocumentType.GENERAL,
    ) -> int:
        """Index raw text — useful for scan reports produced in-session."""
        docs = self._loader.load_text(text, source_name, doc_type)
        if docs:
            self._embed_and_store(docs)
        return len(docs)

    def index_scan_report(self, scan_json: str | dict, label: str = "scan_report.json") -> int:
        """
        Index a complete ScanResult / RiskReport / QuantumReport JSON.
        Converts the JSON to a readable summary string before indexing.
        """
        if isinstance(scan_json, dict):
            text = json.dumps(scan_json, indent=2, default=str)
        else:
            text = scan_json
        # Pretty-up JSON for the LLM — extract key fields as readable text
        readable = self._flatten_report(text, label)
        return self.index_text(readable, label, DocumentType.SCAN_REPORT)

    def index_business_intent_report(self, report_json: str | dict) -> int:
        """Index a BusinessAlignmentReport for chatbot querying."""
        if isinstance(report_json, dict):
            text = json.dumps(report_json, indent=2, default=str)
        else:
            text = report_json
        readable = self._flatten_report(text, "business_intent_report.json")
        return self.index_text(readable, "business_intent_report.json", DocumentType.BUSINESS_INTENT)

    def index_quantum_report(self, report_json: str | dict) -> int:
        if isinstance(report_json, dict):
            text = json.dumps(report_json, indent=2, default=str)
        else:
            text = report_json
        return self.index_text(text, "quantum_report.json", DocumentType.QUANTUM_REPORT)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _embed_and_store(self, docs: list[Document]) -> None:
        """Embed all documents and add to the vector store, then persist."""
        import numpy as np
        batch_size = 200   # embed in batches to avoid OOM
        for i in range(0, len(docs), batch_size):
            batch = docs[i : i + batch_size]
            try:
                vecs = self._embedder.embed_documents(batch, show_progress=True)
                self._store.add_documents(batch, vecs)
            except Exception as exc:
                logger.error("Embedding batch %d failed: %s", i, exc)
        self._store.save()

    @staticmethod
    def _flatten_report(json_text: str, label: str) -> str:
        """Convert a JSON report into a human-readable text block."""
        try:
            data = json.loads(json_text)
        except json.JSONDecodeError:
            return json_text

        lines = [f"=== {label} ===\n"]

        def _walk(obj, indent=0):
            prefix = "  " * indent
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if isinstance(v, (dict, list)):
                        lines.append(f"{prefix}{k}:")
                        _walk(v, indent + 1)
                    else:
                        lines.append(f"{prefix}{k}: {v}")
            elif isinstance(obj, list):
                for item in obj[:50]:   # cap list length for context window
                    _walk(item, indent)
            else:
                lines.append(f"{prefix}{obj}")

        _walk(data)
        return "\n".join(lines)
