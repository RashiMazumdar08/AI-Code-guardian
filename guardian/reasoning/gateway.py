"""
NVIDIA Nemotron Reasoning Service (LLM Gateway)
===============================================
The single door between this platform and a language model.

Before this existed, Business Intent and the domain classifier each built
their own prompt, called their own client, and swallowed their own errors
— which is how two of them ended up calling methods (`llm.complete()`)
that `BaseLLM` does not have, failing silently on every run. One gateway
means one place for credentials, timeouts, retries, caching, token
budgets, logging and fallback.

Guarantees
----------
* **Never raises to a caller.** `reason()` returns a `ReasoningResult`
  whose `available` flag says whether the model was reachable. A scan
  with no API key produces deterministic results and an explicit
  "AI layer unavailable" note — it does not fail.
* **Never sends a repository.** The gateway accepts a `ReasoningRequest`
  carrying pre-selected evidence and an optional bounded snippet. It
  enforces a hard character budget and records what it dropped.
* **Never returns prose.** Responses are parsed against a declared
  schema (`guardian.reasoning.schemas`) before returning.
* **Never logs a prompt by default** — prompts contain source code;
  `LLM_LOG_PROMPTS=true` opts in.

Credentials come from `LLMConfig.from_env()` (NVIDIA_API_KEY). Nothing
here reads or writes a key anywhere else.
"""
from __future__ import annotations

import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from tenacity import retry, wait_exponential, stop_after_attempt, retry_if_exception

_nim_semaphore = threading.Semaphore(2)

def _is_retryable_error(exception: Exception) -> bool:
    err_str = str(exception).lower()
    return "resourceexhausted" in err_str or "limit reached" in err_str or "connection" in err_str or "timeout" in err_str or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str or "429" in err_str

from guardian.llm.base import BaseLLM, LLMAuthError, LLMError
from guardian.llm.config import LLMConfig
from guardian.llm.guardrails import GuardrailPipeline
from guardian.reasoning.schemas import (
    ReasoningResponse, parse_business_intent_response, parse_quantum_context_response,
    parse_reasoning_response,
)

log = logging.getLogger(__name__)

#: Hard ceiling on the characters of context sent for one reasoning task.
#: Roughly 3.5 chars/token, so ~3.5k tokens — small on purpose.
DEFAULT_CONTEXT_BUDGET = 12_000

#: Task name -> response parser.
PARSERS: dict[str, Callable[..., ReasoningResponse]] = {
    "business_intent": parse_business_intent_response,
    "quantum_readiness": parse_quantum_context_response,
}


@dataclass
class ReasoningRequest:
    """One bounded reasoning task.

    `evidence_block` and `knowledge_block` are pre-rendered by
    `guardian.reasoning.context`; the gateway does not go looking for
    more. That is what keeps "never send the whole repository" a
    structural property rather than a convention.
    """

    task: str
    instruction: str
    schema_instruction: str
    evidence_block: str = ""
    knowledge_block: str = ""
    business_block: str = ""
    ust_block: str = ""
    code_snippet: str = ""
    snippet_label: str = ""
    system_role: str = (
        "You are a senior application security engineer performing contextual "
        "analysis. You reason only about the evidence you are given. You never "
        "invent files, functions, line numbers, algorithms or evidence IDs.")
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    cache_key_extra: str = ""

    def cache_key(self) -> str:
        basis = "|".join([self.task, self.instruction, self.evidence_block,
                          self.knowledge_block, self.business_block, self.ust_block,
                          self.code_snippet, self.cache_key_extra])
        return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:32]


@dataclass
class ReasoningResult:
    """What the gateway returns. Always safe to consume."""

    response: Optional[ReasoningResponse] = None
    available: bool = True
    error: str = ""
    cached: bool = False
    latency_ms: float = 0.0
    prompt_chars: int = 0
    truncated_sections: list[str] = field(default_factory=list)
    redactions: int = 0

    @property
    def findings(self):
        return self.response.findings if self.response else []

    @property
    def ok(self) -> bool:
        return self.available and self.response is not None and self.response.ok

    def to_dict(self) -> dict:
        return {
            "available": self.available,
            "error": self.error,
            "cached": self.cached,
            "latency_ms": self.latency_ms,
            "prompt_chars": self.prompt_chars,
            "truncated_sections": self.truncated_sections,
            "redactions": self.redactions,
            "response": self.response.to_dict() if self.response else None,
        }


class NemotronReasoningService:
    """Shared contextual-reasoning service. Construct once per scan."""

    def __init__(self, config: Optional[LLMConfig] = None, *,
                 llm: Optional[BaseLLM] = None,
                 context_budget: int = DEFAULT_CONTEXT_BUDGET,
                 enable_cache: bool = True,
                 guardrails: Optional[GuardrailPipeline] = None) -> None:
        self._config = config or LLMConfig.from_env()
        self._llm = llm                     # injected client (tests / alt providers)
        self._llm_error: str = ""
        self._context_budget = context_budget
        self._enable_cache = enable_cache
        self._cache: dict[str, ReasoningResult] = {}
        self._lock = threading.Lock()
        self._guardrails = guardrails or GuardrailPipeline(enforce_scope=False)
        self.calls = 0
        self.cache_hits = 0
        self.failures = 0

    # ------------------------------------------------------------------
    @property
    def configured(self) -> bool:
        """True when a credential is present. Does not perform a network call."""
        return bool(self._llm is not None or self._config.is_configured)

    @property
    def model_name(self) -> str:
        if self._llm is not None:
            return self._llm.model_name
        return self._config.model

    def unavailable_reason(self) -> str:
        if self._llm_error:
            return self._llm_error
        if not self.configured:
            return ("NVIDIA_API_KEY is not set — contextual AI analysis is disabled. "
                    "Deterministic results are unaffected.")
        return ""

    def _client(self) -> Optional[BaseLLM]:
        if self._llm is not None:
            return self._llm
        if not self._config.is_configured:
            self._llm_error = self.unavailable_reason()
            return None
        try:
            from guardian.llm.factory import create_llm
            self._llm = create_llm(self._config.extras.get("provider", "nemotron"),
                                   config=self._config)
        except Exception as exc:  # noqa: BLE001 — construction must not kill a scan
            self._llm_error = f"could not initialise Nemotron client: {exc}"
            log.warning(self._llm_error)
            return None
        return self._llm

    # ------------------------------------------------------------------
    def reason(self, request: ReasoningRequest) -> ReasoningResult:
        """Run one reasoning task. Never raises."""
        cache_key = request.cache_key()
        if self._enable_cache:
            with self._lock:
                hit = self._cache.get(cache_key)
            if hit is not None:
                self.cache_hits += 1
                return ReasoningResult(response=hit.response, available=hit.available,
                                       error=hit.error, cached=True,
                                       latency_ms=0.0, prompt_chars=hit.prompt_chars,
                                       truncated_sections=hit.truncated_sections,
                                       redactions=hit.redactions)

        client = self._client()
        if client is None:
            return ReasoningResult(available=False, error=self.unavailable_reason())

        prompt, truncated = self._build_prompt(request)

        # Outbound guardrail: redact credentials before they leave the machine.
        verdict = self._guardrails.check_prompt(prompt)
        prompt = verdict.sanitised_text or prompt

        messages = [{"role": "system", "content": request.system_role},
                    {"role": "user", "content": prompt}]

        if self._config.log_prompts:
            log.debug("reasoning prompt (%s):\n%s", request.task, prompt)
        else:
            log.debug("reasoning task=%s prompt_chars=%d truncated=%s",
                      request.task, len(prompt), truncated)

        started = time.time()
        self.calls += 1
        
        @retry(
            wait=wait_exponential(multiplier=1, min=2, max=10),
            stop=stop_after_attempt(15),
            retry=retry_if_exception(_is_retryable_error),
            reraise=True
        )
        def _safe_chat():
            with _nim_semaphore:
                return client.chat(messages, temperature=request.temperature, max_tokens=request.max_tokens)
                
        try:
            completion = _safe_chat()
        except LLMAuthError as exc:
            self.failures += 1
            self._llm_error = f"Nemotron authentication failed: {exc}"
            log.warning(self._llm_error)
            return ReasoningResult(available=False, error=self._llm_error,
                                   latency_ms=(time.time() - started) * 1000)
        except LLMError as exc:
            self.failures += 1
            log.warning("Nemotron reasoning task '%s' failed: %s", request.task, exc)
            return ReasoningResult(available=False, error=str(exc),
                                   latency_ms=round((time.time() - started) * 1000, 1))
        except Exception as exc:  # noqa: BLE001 — an unexpected client bug is not fatal
            self.failures += 1
            log.error("unexpected Nemotron failure on task '%s': %s", request.task, exc)
            return ReasoningResult(available=False, error=str(exc),
                                   latency_ms=round((time.time() - started) * 1000, 1))

        parser = PARSERS.get(request.task, parse_reasoning_response)
        try:
            if parser is parse_reasoning_response:
                response = parser(completion.content, task=request.task,
                                  model=completion.model)
            else:
                response = parser(completion.content, model=completion.model)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not parse Nemotron response for '%s': %s", request.task, exc)
            response = ReasoningResponse(task=request.task, model=completion.model,
                                         raw=completion.content,
                                         problems=[f"parser error: {exc}"])

        result = ReasoningResult(response=response, available=True,
                                 latency_ms=round((time.time() - started) * 1000, 1),
                                 prompt_chars=len(prompt),
                                 truncated_sections=truncated,
                                 redactions=verdict.redactions)
        if self._enable_cache:
            with self._lock:
                self._cache[cache_key] = result
        return result

    # ------------------------------------------------------------------
    def _build_prompt(self, request: ReasoningRequest) -> tuple[str, list[str]]:
        """Assemble the prompt under a hard budget.

        Sections are dropped from the least to the most important, so an
        oversized task loses background knowledge before it loses the
        evidence it is supposed to reason about. What was dropped is
        reported, never silently discarded.
        """
        sections: list[tuple[str, str, str]] = [
            # (key, header, body) — ordered most to least important
            ("task", "TASK", request.instruction),
            ("evidence", "EVIDENCE (cite these IDs; no others exist)", request.evidence_block),
            ("business", "BUSINESS CONTEXT", request.business_block),
            ("ust", "CODE STRUCTURE (from the unified syntax tree)", request.ust_block),
            ("knowledge", "REFERENCE KNOWLEDGE", request.knowledge_block),
            ("code", f"SOURCE EXCERPT ({request.snippet_label or 'excerpt'})",
             _fence(request.code_snippet)),
        ]
        # Drop order: knowledge first, then the raw excerpt, then structure.
        drop_order = ["knowledge", "code", "ust", "business"]

        order = [key for key, _, _ in sections]
        present = {key: (header, body) for key, header, body in sections if body.strip()}
        truncated: list[str] = []

        def render() -> str:
            # Read bodies from `present`, not from `sections` — `present` is
            # what truncation mutates, and rendering the originals made the
            # whole budget enforcement a no-op.
            blocks = [f"## {present[key][0]}\n{present[key][1]}"
                      for key in order if key in present]
            blocks.append(f"## OUTPUT FORMAT\n{request.schema_instruction}")
            return "\n\n".join(blocks)

        prompt = render()
        for key in drop_order:
            if len(prompt) <= self._context_budget:
                break
            if key not in present:
                continue
            header, body = present[key]
            excess = len(prompt) - self._context_budget
            if len(body) <= excess + 200:
                del present[key]
                truncated.append(f"{key} (removed)")
            else:
                present[key] = (header, body[:len(body) - excess] + "\n… [truncated]")
                truncated.append(f"{key} (truncated)")
            prompt = render()

        if len(prompt) > self._context_budget:
            # Evidence itself is too large: trim it, but never remove it.
            header, body = present["evidence"]
            keep = max(1000, len(body) - (len(prompt) - self._context_budget))
            present["evidence"] = (header, body[:keep] + "\n… [evidence truncated]")
            truncated.append("evidence (truncated)")
            prompt = render()

        return prompt, truncated

    # ------------------------------------------------------------------
    def health(self) -> dict:
        """Diagnostics for the dashboard. Performs no network call."""
        return {
            "configured": self.configured,
            "model": self.model_name,
            "calls": self.calls,
            "cache_hits": self.cache_hits,
            "failures": self.failures,
            "context_budget": self._context_budget,
            "unavailable_reason": self.unavailable_reason(),
        }

    def clear_cache(self) -> None:
        with self._lock:
            self._cache.clear()


def _fence(code: str) -> str:
    return f"```\n{code}\n```" if code.strip() else ""
