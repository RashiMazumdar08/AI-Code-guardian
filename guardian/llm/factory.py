"""
LLM Layer — Factory (spec §14: Factory Pattern, Dependency Injection)
=====================================================================
The single sanctioned constructor for LLM instances. Consumers call
`create_llm()` and receive a `BaseLLM`; they never import a provider
class directly. NVIDIA Nemotron is the only supported implementation.
"""
from __future__ import annotations

import logging
from typing import Optional

from guardian.llm.base import BaseLLM
from guardian.llm.config import LLMConfig

log = logging.getLogger(__name__)

_SUPPORTED_PROVIDER_KEYS = ("gemini", "google", "grok", "xai", "nemotron", "nvidia")


def available_providers() -> list[str]:
    return list(_SUPPORTED_PROVIDER_KEYS)


def create_llm(provider: Optional[str] = None,
               config: Optional[LLMConfig] = None) -> BaseLLM:
    """Build an LLM client.

    Args:
        provider: registered provider key (default derived from config/env).
        config:   explicit config; defaults to LLMConfig.from_env().

    Raises:
        ValueError: unknown provider, or invalid/missing configuration.
    """
    cfg = config or LLMConfig.from_env()
    key = (provider or cfg.provider or "gemini").lower()

    if key not in _SUPPORTED_PROVIDER_KEYS:
        raise ValueError(
            f"Unknown LLM provider {key!r}. Available: {available_providers()}"
        )

    log.debug("creating LLM provider=%s %r", key, cfg)

    if key in ("gemini", "google"):
        from guardian.llm.gemini import GeminiLLM
        return GeminiLLM(cfg)
    elif key in ("grok", "xai"):
        from guardian.llm.grok import GrokLLM
        return GrokLLM(cfg)
    else:
        from guardian.llm.nemotron import NemotronLLM
        return NemotronLLM(cfg)

