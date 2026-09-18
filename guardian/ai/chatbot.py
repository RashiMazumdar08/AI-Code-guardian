"""
AI Code Guardian — Chatbot Facade
=====================================
Single object that Streamlit imports and calls.
Wires all sub-components and exposes a clean interface.

Usage
-----
    chatbot = AISecurityCopilot.create(config)
    chatbot.index_directory(Path("./my_repo"))
    chatbot.index_scan_report(scan_json)

    # Non-streaming
    response = chatbot.ask("Show all SQL injection risks")
    print(response.answer)

    # Streaming (Streamlit)
    for token in chatbot.ask_stream("Explain the authentication flow"):
        st.write(token)
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from guardian.ai.code_indexer import CodeIndexer
from guardian.ai.config import AssistantConfig
from guardian.ai.conversation_memory import ConversationMemory
from guardian.ai.document_loader import DocumentLoader
from guardian.ai.embeddings import EmbeddingRouter
from guardian.ai.models import AssistantResponse, DocumentType, IndexStats
from guardian.ai.local_embedder import LocalEmbedder
from guardian.llm.base import BaseLLM
from guardian.llm.factory import create_llm
from guardian.ai.prompt_builder import PromptBuilder
from guardian.ai.rag_pipeline import RAGPipeline
from guardian.ai.retriever import Retriever
from guardian.ai.vector_store import FAISSVectorStore

logger = logging.getLogger(__name__)


class AISecurityCopilot:
    """
    The top-level chatbot object.  All sub-components are wired here.
    Use AISecurityCopilot.create(config) to get a ready instance.
    """

    def __init__(
        self,
        config: AssistantConfig,
        pipeline: RAGPipeline,
        indexer: CodeIndexer,
        vector_store: FAISSVectorStore,
        memory: ConversationMemory,
        llm: BaseLLM,
    ):
        self._cfg     = config
        self._pipeline = pipeline
        self._indexer  = indexer
        self._store    = vector_store
        self._memory   = memory
        self._llm      = llm

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, config: Optional[AssistantConfig] = None) -> "AISecurityCopilot":
        """
        Create a fully wired AISecurityCopilot instance.
        CodeBERT loading is attempted but gracefully skipped if torch
        is not installed (the local embedder covers code as fallback).
        """
        cfg = config or AssistantConfig()
        _configure_logging(cfg)

        # Core services
        # LLM: built through the factory — the chatbot never imports a
        # provider class directly (spec §1, §14). Construction is lazy-safe:
        # a missing API key surfaces here with an actionable message rather
        # than at first question.
        llm = create_llm(cfg.llm_provider)
        # Embeddings stay LOCAL (see guardian/ai/local_embedder.py).
        embedder_backend = LocalEmbedder(
            model_name=cfg.embed_model, device=cfg.embed_device,
            dim=cfg.embed_dim, batch_size=cfg.embed_batch_size,
            load_timeout=cfg.model_load_timeout_seconds)
        store   = FAISSVectorStore(cfg)
        memory  = ConversationMemory(max_turns=cfg.max_history_turns)

        # CodeBERT (optional — needs torch + transformers)
        codebert = _try_load_codebert(cfg)

        # Embedding router
        embedder = EmbeddingRouter(cfg, embedder_backend, codebert)

        # Document loader
        loader = DocumentLoader(cfg)

        # Retriever
        retriever = Retriever(cfg, store, embedder)

        # Prompt builder
        builder = PromptBuilder(cfg)

        # Indexer
        indexer = CodeIndexer(cfg, store, embedder, loader)

        # RAG pipeline
        pipeline = RAGPipeline(cfg, llm, retriever, builder, memory)

        instance = cls(cfg, pipeline, indexer, store, memory, llm)
        logger.info(
            "AISecurityCopilot ready — model: %s, embed: %s, codebert: %s",
            cfg.chat_model, cfg.embed_model, codebert is not None,
        )
        return instance

    # ------------------------------------------------------------------
    # Indexing API
    # ------------------------------------------------------------------

    def index_directory(self, path: Path, clear_first: bool = False) -> IndexStats:
        """Index a local code directory or document folder."""
        stats = self._indexer.index_directory(path, clear_first=clear_first)
        self._memory.add_indexed_path(str(path))
        self._memory.build_repo_summary(stats)
        return stats

    def index_uploaded_files(self, paths: list[Path], root: Optional[Path] = None) -> int:
        """Index files uploaded via Streamlit file_uploader."""
        count = self._indexer.index_files(paths, root)
        stats = self._store.stats()
        self._memory.build_repo_summary(stats)
        return count

    def index_scan_report(self, scan_json: str | dict, label: str = "scan_report.json",
                          repo_root: Optional[str] = None) -> int:
        count = self._indexer.index_scan_report(scan_json, label)
        self._memory.add_scan_label(label)
        # Ground the pipeline: exact-match finding injection + mechanical
        # answer validation against this report (and repo, when given).
        import json as _json
        report = _json.loads(scan_json) if isinstance(scan_json, str) else scan_json
        self._pipeline.attach_scan_context(scan_report=report, repo_root=repo_root)
        return count

    def index_business_intent(self, report_json: str | dict) -> int:
        return self._indexer.index_business_intent_report(report_json)

    def index_quantum_report(self, report_json: str | dict) -> int:
        return self._indexer.index_quantum_report(report_json)

    def index_raw_text(
        self, text: str, source_name: str, doc_type: DocumentType = DocumentType.GENERAL
    ) -> int:
        return self._indexer.index_text(text, source_name, doc_type)

    # ------------------------------------------------------------------
    # Chat API
    # ------------------------------------------------------------------

    def ask(self, question: str) -> AssistantResponse:
        """Blocking ask — returns complete response."""
        return self._pipeline.ask(question)

    def ask_stream(self, question: str) -> Generator[str, None, None]:
        """Streaming ask — yields tokens. Use with Streamlit st.write_stream()."""
        return self._pipeline.ask_stream(question)

    def clear_history(self) -> None:
        self._memory.clear()

    def clear_index(self) -> None:
        """Wipe the vector store (both code and doc indexes).

        Used when the active repository changes: index_scan_report() /
        index_text() only ever ADD to the FAISS store, they never remove
        the previous repository's content. Without an explicit clear
        between repositories, a second scan's chat questions could be
        answered (and "grounded") using retrieved chunks left over from
        the first repository's scan report -- a cross-repository leak.
        See backend/app/api/v1/chat.py::_sync_latest_scan.
        """
        self._store.clear()
        logger.info("Vector store cleared (repository/scan changed)")

    def get_stats(self) -> IndexStats:
        return self._store.stats()

    def is_ready(self) -> bool:
        """True if the LLM provider is reachable and the store has content."""
        return self._llm.is_healthy() and not self._store.is_empty

    def is_llm_healthy(self) -> bool:
        """Provider-agnostic health probe (never raises)."""
        return self._llm.is_healthy()

    @property
    def llm(self) -> BaseLLM:
        return self._llm

    @property
    def model_name(self) -> str:
        return self._llm.model_name

    def available_models(self) -> list[str]:
        return self._llm.available_models()

    @property
    def config(self) -> AssistantConfig:
        return self._cfg

    @property
    def memory(self) -> ConversationMemory:
        return self._memory


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _try_load_codebert(cfg: AssistantConfig):
    if os.getenv("ACG_ENABLE_CODEBERT", "false").lower() not in {"1", "true", "yes"}:
        logger.info("CodeBERT disabled; using the local embedding model")
        return None
    try:
        from guardian.ai.codebert import CodeBERTEmbedder
        return CodeBERTEmbedder(cfg)
    except ImportError:
        logger.warning(
            "torch/transformers not installed — CodeBERT disabled. "
            "Code will be embedded via the local embedder. pip install torch transformers"
        )
        return None
    except Exception as exc:
        logger.warning("CodeBERT load failed (%s) — falling back to local embedder", exc)
        return None


def _configure_logging(cfg: AssistantConfig) -> None:
    handlers = [logging.StreamHandler()]
    if cfg.log_file:
        handlers.append(logging.FileHandler(cfg.log_file))
    logging.basicConfig(
        level=getattr(logging, cfg.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        handlers=handlers,
    )
