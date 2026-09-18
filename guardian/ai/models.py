"""
AI Code Guardian — AI Assistant Data Models
=============================================
All shared data types for the assistant pipeline.
No business logic here — pure data containers.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Document types
# ---------------------------------------------------------------------------

class DocumentType(str, Enum):
    SOURCE_CODE    = "source_code"
    REQUIREMENT    = "requirement"
    SECURITY_POLICY = "security_policy"
    SCAN_REPORT    = "scan_report"
    RISK_REPORT    = "risk_report"
    QUANTUM_REPORT = "quantum_report"
    BUSINESS_INTENT = "business_intent"
    ARCHITECTURE   = "architecture"
    API_SPEC       = "api_spec"
    README         = "readme"
    OWASP          = "owasp"
    NIST           = "nist"
    CWE            = "cwe"
    DOCKERFILE     = "dockerfile"
    KUBERNETES     = "kubernetes"
    CI_CD          = "ci_cd"
    GENERAL        = "general"


@dataclass
class Document:
    """
    A unit of indexed knowledge — either a chunk of source code or a
    chunk of a text/document file.
    """
    doc_id:      str                      # stable unique ID (sha1 of source + offset)
    content:     str                      # text content of this chunk
    source_path: str                      # original file path (relative to repo root)
    doc_type:    DocumentType
    language:    Optional[str] = None     # e.g. "java", "python"
    start_line:  int           = 0
    end_line:    int           = 0
    metadata:    dict[str, Any] = field(default_factory=dict)

    def to_citation(self) -> str:
        """Human-readable citation string shown to the user."""
        loc = f" (lines {self.start_line}–{self.end_line})" if self.start_line else ""
        return f"`{self.source_path}`{loc} [{self.doc_type.value}]"


@dataclass
class RetrievedChunk:
    """A Document with its retrieval score attached."""
    document:  Document
    score:     float       # L2 distance (lower = more similar for FAISS flat L2)
    rank:      int         # 1-based rank in the result set

    @property
    def similarity(self) -> float:
        """Convert L2 distance to a 0-1 similarity approximation."""
        return 1.0 / (1.0 + self.score)


# ---------------------------------------------------------------------------
# Conversation
# ---------------------------------------------------------------------------

class MessageRole(str, Enum):
    USER      = "user"
    ASSISTANT = "assistant"
    SYSTEM    = "system"


@dataclass
class ChatMessage:
    role:    MessageRole
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)   # citations, sources, etc.


@dataclass
class ConversationContext:
    """
    Everything the chatbot needs to answer a question.
    Built fresh for each turn from memory + retrieval.
    """
    history:         list[ChatMessage]
    retrieved_docs:  list[RetrievedChunk]
    query:           str
    repo_summary:    str    = ""
    active_findings: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# RAG pipeline
# ---------------------------------------------------------------------------

@dataclass
class RAGQuery:
    """Input to the RAG pipeline."""
    question:        str
    top_k:           int  = 8
    filter_type:     Optional[DocumentType] = None   # restrict retrieval to one type
    include_code:    bool = True
    include_docs:    bool = True


@dataclass
class RAGResult:
    """Output of the RAG pipeline, before LLM generation."""
    query:          RAGQuery
    chunks:         list[RetrievedChunk]
    merged_context: str
    citations:      list[str]           # one citation string per unique source


@dataclass
class AssistantResponse:
    """Full response returned to the Streamlit UI."""
    answer:      str
    citations:   list[str]
    grounded:    bool               # True if evidence was found
    chunks_used: list[RetrievedChunk]
    latency_ms:  float = 0.0
    # GENERAL_SECURITY / REPOSITORY / MIXED (guardian.ai.intent_router.
    # ChatIntent), or "CONVERSATIONAL" for the greeting fast-path, which
    # short-circuits before intent routing runs. A plain str (not the enum
    # itself) so this module has no import-time dependency on
    # intent_router -- kept as its own field, deliberately, so this dataclass
    # doesn't need to change shape if the routing logic grows more intents.
    intent: str = "MIXED"


# ---------------------------------------------------------------------------
# Index metadata
# ---------------------------------------------------------------------------

@dataclass
class IndexStats:
    total_documents:  int
    code_vectors:     int
    doc_vectors:      int
    languages:        dict[str, int]   # language → count
    doc_types:        dict[str, int]   # DocumentType → count
    index_size_mb:    float
