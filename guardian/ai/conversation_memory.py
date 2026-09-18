"""
AI Code Guardian — Conversation Memory
=========================================
Maintains per-session chat history and attaches contextual metadata
(which files were cited, which findings are active) to each turn.

Design
------
- In-memory only (Streamlit session_state is the persistence layer)
- Each message carries metadata: citations, findings, source files
- Supports clearing history and injecting a synthetic context summary
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from guardian.ai.models import AssistantResponse, ChatMessage, MessageRole

logger = logging.getLogger(__name__)


@dataclass
class SessionContext:
    """
    Contextual state for the current session:
    active findings, repository summary, etc.
    This is prepended to the prompt when relevant.
    """
    repo_summary:    str       = ""
    active_findings: list[dict] = field(default_factory=list)
    indexed_paths:   list[str]  = field(default_factory=list)
    scan_labels:     list[str]  = field(default_factory=list)   # e.g. "scan_report_20240101"


class ConversationMemory:
    """
    Manages chat history for one user session.

    Usage
    -----
        memory = ConversationMemory(max_turns=10)
        memory.add_user_message("What is the risk score?")
        memory.add_assistant_message(response)
        history = memory.get_history()
    """

    def __init__(self, max_turns: int = 10):
        self._max_turns = max_turns
        self._messages: list[ChatMessage] = []
        self.context = SessionContext()

    # ------------------------------------------------------------------
    # Message management
    # ------------------------------------------------------------------

    def add_user_message(self, content: str) -> None:
        self._messages.append(
            ChatMessage(role=MessageRole.USER, content=content)
        )
        self._trim()

    def add_assistant_message(self, response: AssistantResponse) -> None:
        metadata = {
            "citations":   response.citations,
            "grounded":    response.grounded,
            "latency_ms":  response.latency_ms,
        }
        self._messages.append(
            ChatMessage(
                role=MessageRole.ASSISTANT,
                content=response.answer,
                metadata=metadata,
            )
        )

    def add_assistant_text(self, text: str, citations: Optional[list[str]] = None) -> None:
        """Simpler variant — called after streaming is complete."""
        self._messages.append(
            ChatMessage(
                role=MessageRole.ASSISTANT,
                content=text,
                metadata={"citations": citations or [], "grounded": bool(citations)},
            )
        )

    def get_history(self) -> list[ChatMessage]:
        return list(self._messages)

    def clear(self) -> None:
        self._messages.clear()
        logger.debug("Conversation history cleared")

    def last_n(self, n: int) -> list[ChatMessage]:
        return self._messages[-n * 2:]   # n turns = n*2 messages

    # ------------------------------------------------------------------
    # Session context helpers
    # ------------------------------------------------------------------

    def set_repo_summary(self, summary: str) -> None:
        self.context.repo_summary = summary

    def set_active_findings(self, findings: list[dict]) -> None:
        self.context.active_findings = findings

    def add_indexed_path(self, path: str) -> None:
        if path not in self.context.indexed_paths:
            self.context.indexed_paths.append(path)

    def add_scan_label(self, label: str) -> None:
        if label not in self.context.scan_labels:
            self.context.scan_labels.append(label)

    def build_repo_summary(self, stats) -> str:
        """Build a one-paragraph repository summary from IndexStats."""
        if not stats:
            return ""
        langs = ", ".join(
            f"{lang} ({count} chunks)"
            for lang, count in sorted(stats.languages.items(), key=lambda x: -x[1])[:5]
        )
        types = ", ".join(
            f"{t} ({c})"
            for t, c in sorted(stats.doc_types.items(), key=lambda x: -x[1])[:6]
        )
        summary = (
            f"Indexed repository: {stats.total_documents} total chunks, "
            f"{stats.code_vectors} code vectors, {stats.doc_vectors} doc vectors. "
            f"Languages: {langs}. "
            f"Document types: {types}. "
            f"Index size: {stats.index_size_mb:.1f} MB."
        )
        if self.context.indexed_paths:
            summary += f" Indexed {len(self.context.indexed_paths)} source(s)."
        self.context.repo_summary = summary
        return summary

    # ------------------------------------------------------------------
    # Private
    # ------------------------------------------------------------------

    def _trim(self) -> None:
        """Keep only last max_turns * 2 messages."""
        max_msgs = self._max_turns * 2
        if len(self._messages) > max_msgs:
            self._messages = self._messages[-max_msgs:]
