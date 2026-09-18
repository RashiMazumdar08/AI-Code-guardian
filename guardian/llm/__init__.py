"""
AI Code Guardian — LLM Layer
============================
The ONLY package permitted to talk to an LLM provider API.

Public surface:
    BaseLLM          — provider-agnostic interface every module codes against
    NemotronLLM      — NVIDIA Nemotron implementation (OpenAI-compatible API)
    LLMConfig        — provider configuration (env-driven, no hardcoded keys)
    create_llm       — factory; the only sanctioned way to build an LLM
    ResponseParser   — Nemotron text -> structured SecurityAnalysis JSON
    GuardrailPipeline — inbound + outbound safety checks

Architectural rule (spec §1): no module outside `guardian.llm` may import
an SDK or call a provider endpoint directly. Modules depend on BaseLLM.
"""
from guardian.llm.base import BaseLLM, LLMError, LLMResponse, LLMTimeoutError, LLMRateLimitError
from guardian.llm.config import LLMConfig
from guardian.llm.factory import create_llm
from guardian.llm.nemotron import NemotronLLM
from guardian.llm.parser import ResponseParser, SecurityAnalysis
from guardian.llm.guardrails import GuardrailPipeline, GuardrailVerdict

__all__ = [
    "BaseLLM", "LLMError", "LLMResponse", "LLMTimeoutError", "LLMRateLimitError",
    "LLMConfig", "create_llm", "NemotronLLM",
    "ResponseParser", "SecurityAnalysis",
    "GuardrailPipeline", "GuardrailVerdict",
]
