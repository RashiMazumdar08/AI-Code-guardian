"""
LLM Layer — Provider-Agnostic Interface
=======================================
Every consumer in the platform (RAG pipeline, chatbot, recommendation
engine, future agents) codes against `BaseLLM`. Swapping providers is a
config change, never a code change (spec §1, §8, §14).

Contract:
    chat()        — blocking completion, returns LLMResponse
    chat_stream() — token generator for Streamlit st.write_stream()
    is_healthy()  — provider reachability probe for dashboard status
    model_name    — the model actually in use (for logging/telemetry)
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Generator, Optional


class LLMError(Exception):
    """Base class for all provider failures. Consumers catch this, never
    an SDK-specific exception — that would leak the provider upward."""


class LLMTimeoutError(LLMError):
    """Request exceeded the configured timeout."""


class LLMRateLimitError(LLMError):
    """Provider returned 429 / quota exhaustion."""


class LLMAuthError(LLMError):
    """Missing or rejected credentials."""


@dataclass
class LLMResponse:
    """Normalised provider response + telemetry (spec §12)."""
    content: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.content.strip()


class BaseLLM(ABC):
    """Provider-agnostic LLM interface."""

    @property
    @abstractmethod
    def model_name(self) -> str:
        ...

    @abstractmethod
    def chat(self, messages: list[dict], *, temperature: Optional[float] = None,
             max_tokens: Optional[int] = None) -> LLMResponse:
        """Blocking completion. `messages` is OpenAI-style:
        [{"role": "system"|"user"|"assistant", "content": str}, ...]"""
        ...

    @abstractmethod
    def chat_stream(self, messages: list[dict], *,
                    temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Generator[str, None, None]:
        """Yield content tokens as they arrive."""
        ...

    @abstractmethod
    def is_healthy(self) -> bool:
        """True when the provider is reachable and credentials work.
        Must never raise — dashboards call this on every render."""
        ...

    def available_models(self) -> list[str]:
        """Optional capability; default is 'just the configured model'."""
        return [self.model_name]
