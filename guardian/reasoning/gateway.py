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

_nim_semaphore = threading.Semaphore(5)


from guardian.llm.rate_limit_handler import is_rate_limit_error, format_rate_limit_warning

def _is_retryable_error(exception: Exception) -> bool:
    if is_rate_limit_error(exception):
        return False
    err_str = str(exception).lower()
    return "connection" in err_str or "timeout" in err_str or "500" in err_str or "502" in err_str or "503" in err_str or "504" in err_str

from guardian.llm.base import BaseLLM, LLMAuthError, LLMError
from guardian.llm.config import LLMConfig
from guardian.llm.guardrails import GuardrailPipeline
from guardian.reasoning.schemas import (
    ReasoningResponse, parse_business_intent_response, parse_dependency_reasoning_response, parse_quantum_context_response,
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
    "dependency_reasoning": parse_dependency_reasoning_response,
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
    schema_instruction: str = ""
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
    reasoning_effort: Optional[str] = None
    cache_key_extra: str = ""
    agent: str = ""
    scan_id: str = ""

    def cache_key(self) -> str:
        basis = "|".join([self.task, self.instruction, self.evidence_block,
                          self.knowledge_block, self.business_block, self.ust_block,
                          self.code_snippet, self.cache_key_extra, self.agent, self.scan_id])
        return hashlib.sha256(basis.encode("utf-8", errors="ignore")).hexdigest()[:32]


_TASK_TO_AGENT_MAP = {
    "business_intent": "business",
    "security_reasoning": "security",
    "architecture_reasoning": "architecture",
    "threat_reasoning": "threat_simulation",
    "validation_reasoning": "validation",
    "patch_reasoning": "patch",
    "quantum_readiness": "security",
    "dependency_reasoning": "dependency",
}


import os


def get_default_agent_caps() -> dict[str, int]:
    sec_env = os.getenv("SECURITY_AGENT_ENABLED", "false").lower().strip()
    sec_cap = 2200 if sec_env in ("true", "1", "yes", "on") else 0
    return {
        "security": sec_cap,
        "business": 4000,
        "architecture": 1100,
        "threat_simulation": 1000,
        "dependency": 1000,
        "patch": 450,
        "validation": 450,
        "shared": 100,
    }


DEFAULT_AGENT_CAPS: dict[str, int] = get_default_agent_caps()


class ScanTokenTracker:
    """Thread-safe per-scan token budget and dynamic admission tracker for LLM admission control."""

    def __init__(self, total_budget: int = 6500, agent_reservations: Optional[dict[str, int]] = None) -> None:
        self.total_budget = total_budget
        self.remaining_budget = total_budget
        self._agent_caps = dict(agent_reservations) if agent_reservations is not None else get_default_agent_caps()
        self.agent_spent: dict[str, int] = {}
        self._lock = threading.Lock()

    @property
    def agent_caps(self) -> dict[str, int]:
        return self._agent_caps

    @agent_caps.setter
    def agent_caps(self, val: dict[str, int]) -> None:
        self._agent_caps = val

    @property
    def agent_reservations(self) -> dict[str, int]:
        """Backwards compatibility alias for agent_caps."""
        return self._agent_caps

    @agent_reservations.setter
    def agent_reservations(self, val: dict[str, int]) -> None:
        self._agent_caps = val

    def admit_request(self, agent: str, requested_tokens: int) -> tuple[bool, str, int, int, int]:
        """Dynamic admission check.

        Evaluates against remaining_budget and per-agent cap without static locking.
        Strictly enforces per-agent cap before making any network call.
        """
        with self._lock:
            agent_cap = self._agent_caps.get(agent, 900)
            spent = self.agent_spent.get(agent, 0)
            agent_remaining_cap = max(0, agent_cap - spent)
            usable_capacity = min(self.remaining_budget, agent_remaining_cap)

            if (spent + requested_tokens) > agent_cap:
                return False, "SKIPPED_AGENT_CAP", self.remaining_budget, agent_cap, usable_capacity
            elif requested_tokens > self.remaining_budget:
                return False, "SKIPPED_BUDGET", self.remaining_budget, agent_cap, usable_capacity
            else:
                self.remaining_budget -= requested_tokens
                self.agent_spent[agent] = spent + requested_tokens
                return True, "EXECUTED", self.remaining_budget, agent_cap, usable_capacity

    def release_unused(self, agent: str, reserved_tokens: int, actual_used_tokens: int) -> int:
        """Reconcile actual token usage against reserved tokens."""
        with self._lock:
            actual_used = max(0, actual_used_tokens)
            diff = reserved_tokens - actual_used
            if diff > 0:
                self.remaining_budget += diff
                spent = self.agent_spent.get(agent, 0)
                self.agent_spent[agent] = max(0, spent - diff)
                return diff
            elif diff < 0:
                extra = abs(diff)
                self.remaining_budget = max(0, self.remaining_budget - extra)
                spent = self.agent_spent.get(agent, 0)
                self.agent_spent[agent] = spent + extra
                return 0
            return 0

    def refund(self, agent: str, estimated_tokens: int) -> None:
        """Full refund on error or cancellation."""
        self.release_unused(agent, estimated_tokens, 0)

    def get_summary(self) -> dict[str, Any]:
        """Return full telemetry summary of token budget and agent usage."""
        with self._lock:
            total_spent = sum(self.agent_spent.values())
            return {
                "total_budget": self.total_budget,
                "total_spent": total_spent,
                "remaining_budget": self.remaining_budget,
                "agent_spent": dict(self.agent_spent),
                "agent_caps": dict(self._agent_caps),
                "agent_status": {
                    agent: ("EXECUTED" if self.agent_spent.get(agent, 0) > 0 else "SKIPPED")
                    for agent in self._agent_caps
                },
            }


_SCAN_TRACKERS: dict[str, ScanTokenTracker] = {}
_SCAN_TRACKER_LOCK = threading.Lock()


def get_scan_token_tracker(scan_id: str = "default_scan", total_budget: int = 6500) -> ScanTokenTracker:
    with _SCAN_TRACKER_LOCK:
        if scan_id not in _SCAN_TRACKERS:
            _SCAN_TRACKERS[scan_id] = ScanTokenTracker(total_budget=total_budget)
        return _SCAN_TRACKERS[scan_id]


def reset_scan_token_trackers() -> None:
    with _SCAN_TRACKER_LOCK:
        _SCAN_TRACKERS.clear()


def format_scan_token_report(scan_id: str = "default_scan") -> str:
    """Format final scan token budget summary report for telemetry and CLI logs."""
    tracker = get_scan_token_tracker(scan_id)
    summary = tracker.get_summary()
    lines = [
        "==================================================",
        "SCAN TOKEN BUDGET SUMMARY REPORT",
        "==================================================",
        f"Total Scan Budget : {summary['total_budget']} tokens",
        f"Total Actual Used : {summary['total_spent']} tokens",
        f"Total Unused      : {summary['remaining_budget']} tokens",
        "--------------------------------------------------",
        "Agent Statuses:"
    ]
    for agent, cap in summary["agent_caps"].items():
        spent = summary["agent_spent"].get(agent, 0)
        status = "EXECUTED" if spent > 0 else "SKIPPED"
        lines.append(f"  {agent:<18}: {status:<8} (spent {spent:<4} tokens / cap {cap})")
    lines.append("==================================================")
    return "\n".join(lines)


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


_GLOBAL_REASONING_CACHE: dict[str, ReasoningResult] = {}
_GLOBAL_REASONING_LOCK = threading.Lock()


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
        self._cache: dict[str, ReasoningResult] = _GLOBAL_REASONING_CACHE
        self._lock: threading.Lock = _GLOBAL_REASONING_LOCK
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
            return ("LLM Reasoning is not configured (XAI_API_KEY/NVIDIA_API_KEY unset or LLM_ENABLED=false) — "
                    "contextual AI analysis is disabled. Deterministic results are unaffected.")
        return ""

    def _client(self) -> Optional[BaseLLM]:
        if self._llm is not None:
            return self._llm
        if not self._config.is_configured:
            self._llm_error = self.unavailable_reason()
            return None
        try:
            from guardian.llm.factory import create_llm
            self._llm = create_llm(self._config.provider, config=self._config)
        except Exception as exc:  # noqa: BLE001 — construction must not kill a scan
            self._llm_error = f"could not initialise LLM client ({self._config.provider}): {exc}"
            log.warning(self._llm_error)
            return None
        return self._llm

    # ------------------------------------------------------------------
    def reason(self, request: ReasoningRequest) -> ReasoningResult:
        """Run one reasoning task. Never raises."""
        cache_key = f"{id(self._llm)}|{self._context_budget}|{request.cache_key()}" if self._llm is not None else f"{self._context_budget}|{request.cache_key()}"
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

        agent_name = request.agent or _TASK_TO_AGENT_MAP.get(request.task, "general")
        scan_id = request.scan_id

        # Telemetry: calculate token estimates (safe, never logging keys)
        sys_tokens_est = len(request.system_role) // 4
        user_tokens_est = len(prompt) // 4
        ev_tokens_est = len(request.evidence_block) // 4
        bus_tokens_est = len(request.business_block) // 4
        input_tokens_est = sys_tokens_est + user_tokens_est
        max_output_tokens = request.max_tokens if request.max_tokens is not None else min(self._config.max_tokens, 1000)
        total_requested_tokens_est = input_tokens_est + max_output_tokens

        # Admission Control against shared per-scan token budget
        tracker = get_scan_token_tracker(scan_id) if scan_id else None
        if tracker:
            admitted, decision, remaining_budget, agent_cap, usable_capacity = tracker.admit_request(agent_name, total_requested_tokens_est)
        else:
            admitted, decision, remaining_budget, agent_cap, usable_capacity = True, "EXECUTED", 6500, 2200, 6500

        log.info(
            "[TOKEN ADMISSION] Check: agent=%s | provider=%s | model=%s | "
            "estimated_input_tokens~%d | max_output_tokens=%d | total_requested_tokens~%d | "
            "agent_cap=%d | usable_capacity=%d | remaining_budget=%d | decision=%s",
            agent_name,
            self._config.provider,
            self.model_name,
            input_tokens_est,
            max_output_tokens,
            total_requested_tokens_est,
            agent_cap,
            usable_capacity,
            remaining_budget,
            decision
        )

        if not admitted:
            return ReasoningResult(
                available=False,
                error=(
                    f"{decision}: Token budget limit for agent '{agent_name}' reached. "
                    f"Requested ~{total_requested_tokens_est} tokens, "
                    f"remaining budget is {remaining_budget} tokens."
                ),
                latency_ms=0.0,
                prompt_chars=len(prompt),
                truncated_sections=truncated,
            )

        if self._config.log_prompts:
            log.debug("reasoning prompt (%s):\n%s", request.task, prompt)
        else:
            log.debug("reasoning task=%s prompt_chars=%d truncated=%s",
                      request.task, len(prompt), truncated)

        started = time.time()
        self.calls += 1
        
        @retry(
            wait=wait_exponential(multiplier=1, min=1, max=4),
            stop=stop_after_attempt(self._config.max_retries),
            retry=retry_if_exception(_is_retryable_error),
            reraise=True
        )

        def _safe_chat():
            with _nim_semaphore:
                kwargs = {}
                if request.reasoning_effort:
                    kwargs["reasoning_effort"] = request.reasoning_effort
                return client.chat(messages, temperature=request.temperature, max_tokens=request.max_tokens, **kwargs)
                
        try:
            completion = _safe_chat()
        except LLMAuthError as exc:
            if tracker:
                tracker.refund(agent_name, total_requested_tokens_est)
            self.failures += 1
            self._llm_error = f"LLM authentication failed: {exc}"
            log.warning(self._llm_error)
            return ReasoningResult(available=False, error=self._llm_error,
                                   latency_ms=(time.time() - started) * 1000)
        except LLMError as exc:
            if tracker:
                tracker.refund(agent_name, total_requested_tokens_est)
            self.failures += 1
            log.warning("LLM reasoning task '%s' failed: %s", request.task, exc)
            err_msg = format_rate_limit_warning(exc) if is_rate_limit_error(exc) else str(exc)
            return ReasoningResult(available=False, error=err_msg,
                                   latency_ms=round((time.time() - started) * 1000, 1))
        except Exception as exc:  # noqa: BLE001 — an unexpected client bug is not fatal
            if tracker:
                tracker.refund(agent_name, total_requested_tokens_est)
            self.failures += 1
            log.error("unexpected LLM failure on task '%s': %s", request.task, exc)
            err_msg = format_rate_limit_warning(exc) if is_rate_limit_error(exc) else str(exc)
            return ReasoningResult(available=False, error=err_msg,
                                   latency_ms=round((time.time() - started) * 1000, 1))

        # Calculate actual token usage and release unused reservation back to scan budget
        actual_used_tokens = getattr(completion, "total_tokens", 0) or (input_tokens_est + (len(completion.content) // 4))
        released_tokens = tracker.release_unused(agent_name, total_requested_tokens_est, actual_used_tokens) if tracker else 0

        log.info(
            "[TOKEN ADMISSION] Complete: agent=%s | provider=%s | model=%s | "
            "actual_used_tokens=%d | released_tokens=%d | remaining_budget=%d",
            agent_name,
            self._config.provider,
            getattr(completion, "model", self.model_name),
            actual_used_tokens,
            released_tokens,
            tracker.remaining_budget if tracker else 6500
        )

        parser = PARSERS.get(request.task, parse_reasoning_response)
        try:
            if parser is parse_reasoning_response:
                response = parser(completion.content, task=request.task,
                                  model=completion.model)
            else:
                response = parser(completion.content, model=completion.model)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not parse LLM response for '%s': %s", request.task, exc)
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
            from guardian.reasoning.schemas import (
                BASE_SCHEMA_INSTRUCTION, BUSINESS_INTENT_SCHEMA_INSTRUCTION, DEPENDENCY_SCHEMA_INSTRUCTION, QUANTUM_SCHEMA_INSTRUCTION,
            )
            default_schema = (
                BUSINESS_INTENT_SCHEMA_INSTRUCTION if request.task == "business_intent"
                else QUANTUM_SCHEMA_INSTRUCTION if request.task == "quantum_readiness"
                else DEPENDENCY_SCHEMA_INSTRUCTION if request.task == "dependency_reasoning"
                else BASE_SCHEMA_INSTRUCTION
            )
            schema_text = request.schema_instruction or default_schema
            blocks = [f"## {present[key][0]}\n{present[key][1]}"
                      for key in order if key in present]
            blocks.append(f"## OUTPUT FORMAT\n{schema_text}")
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


ReasoningGateway = NemotronReasoningService
ReasoningService = NemotronReasoningService

