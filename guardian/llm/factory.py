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

_NEMOTRON_PROVIDER_KEYS = ("nemotron", "nvidia")


def available_providers() -> list[str]:
    return list(_NEMOTRON_PROVIDER_KEYS)


def create_llm(provider: str = "nemotron",
               config: Optional[LLMConfig] = None) -> BaseLLM:
    """Build an LLM client.

    Args:
        provider: registered provider key (default "nemotron").
        config:   explicit config; defaults to LLMConfig.from_env().

    Raises:
        ValueError: unknown provider, or invalid/missing configuration.
    """
    key = (provider or "nemotron").lower()
    if key not in _NEMOTRON_PROVIDER_KEYS:
        raise ValueError(
            f"Unknown LLM provider {provider!r}. Available: {available_providers()}"
        )
    cfg = config or LLMConfig.from_env()
    log.debug("creating LLM provider=%s %r", key, cfg)
    from guardian.llm.nemotron import NemotronLLM
    return NemotronLLM(cfg)
