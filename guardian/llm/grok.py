"""
LLM Layer — Grok / xAI Provider
===============================
Implements `BaseLLM` against xAI Grok's OpenAI-compatible REST API.

Transport strategy: the `openai` SDK is used when available (configured with
`base_url="https://api.x.ai/v1"` and `api_key=...`); otherwise falls back to plain
`requests` against the standard `/chat/completions` contract. Both paths return
`LLMResponse` objects and handle retries with exponential backoff and jitter.
"""
from __future__ import annotations

import logging
import random
import time
from typing import Any, Generator, Optional

from guardian.llm.base import (
    BaseLLM, LLMAuthError, LLMError, LLMRateLimitError, LLMResponse, LLMTimeoutError,
)
from guardian.llm.config import LLMConfig

log = logging.getLogger(__name__)


class GrokLLM(BaseLLM):
    """Grok / xAI LLM implementation via OpenAI-compatible API."""

    def __init__(self, config: Optional[LLMConfig] = None):
        self._cfg = config or LLMConfig.from_env()
        self._cfg.validate()
        self._client: Any = None
        self._transport = "uninitialised"

    @property
    def _sdk(self):
        """Lazily construct the OpenAI-compatible client or fallback to requests."""
        if self._client is not None or self._transport == "requests":
            return self._client
        try:
            from openai import OpenAI
            self._client = OpenAI(
                base_url=self._cfg.base_url,
                api_key=self._cfg.api_key,
                timeout=self._cfg.timeout,
                max_retries=0,  # retry policy managed internally
            )
            self._transport = "openai-sdk"
            log.debug("Grok transport: openai SDK (%s)", self._cfg.base_url)
        except ImportError:
            self._transport = "requests"
            log.debug("Grok transport: requests fallback")
        return self._client

    @property
    def model_name(self) -> str:
        return self._cfg.model

    @property
    def config(self) -> LLMConfig:
        return self._cfg

    def chat(self, messages: list[dict], *, temperature: Optional[float] = None,
             max_tokens: Optional[int] = None, reasoning_effort: Optional[str] = None) -> LLMResponse:
        payload = self._payload(messages, temperature, max_tokens, stream=False)
        t0 = time.time()
        raw = self._request_with_retry(payload)
        latency = (time.time() - t0) * 1000

        content, finish, usage = self._extract(raw)
        if not content.strip():
            raise LLMError(f"Grok returned an empty response (finish_reason={finish!r}).")

        response = LLMResponse(
            content=content,
            model=self._cfg.model,
            prompt_tokens=usage.get("prompt_tokens", 0),
            completion_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            latency_ms=round(latency, 1),
            finish_reason=finish,
            raw=raw,
        )
        if self._cfg.log_token_usage:
            log.info("grok model=%s latency=%.0fms tokens=%d/%d/%d finish=%s",
                     response.model, response.latency_ms, response.prompt_tokens,
                     response.completion_tokens, response.total_tokens, finish)
        return response

    def chat_stream(self, messages: list[dict], *, temperature: Optional[float] = None,
                    max_tokens: Optional[int] = None) -> Generator[str, None, None]:
        payload = self._payload(messages, temperature, max_tokens, stream=True)
        if self._sdk is not None:
            yield from self._stream_sdk(payload)
        else:
            yield from self._stream_rest(payload)

    def is_healthy(self) -> bool:
        """Never raises — safe health probe for status checks."""
        if not self._cfg.is_configured:
            return False
        try:
            self.chat([
                {"role": "system", "content": "Return exactly: ok"},
                {"role": "user", "content": "health check"},
            ], max_tokens=2)
            return True
        except Exception as exc:
            log.debug("Grok health check notice: %s", exc)
            return False

    def available_models(self) -> list[str]:
        try:
            if self._sdk is not None:
                return sorted(m.id for m in self._sdk.models.list().data)
            import requests
            r = requests.get(f"{self._cfg.base_url}/models",
                             headers=self._headers(), timeout=self._cfg.timeout)
            r.raise_for_status()
            return sorted(m["id"] for m in r.json().get("data", []))
        except Exception as exc:
            log.debug("model listing notice: %s", exc)
            return [self._cfg.model]

    # -- internals -------------------------------------------------------
    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._cfg.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _payload(self, messages: list[dict], temperature: Optional[float],
                 max_tokens: Optional[int], stream: bool) -> dict:
        return {
            "model": self._cfg.model,
            "messages": messages,
            "temperature": self._cfg.temperature if temperature is None else temperature,
            "max_tokens": self._cfg.max_tokens if max_tokens is None else max_tokens,
            "top_p": self._cfg.top_p,
            "stream": stream,
        }

    def _request_with_retry(self, payload: dict) -> dict:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self._cfg.max_retries + 1):
            try:
                return self._request_once(payload)
            except LLMRateLimitError:
                raise  # Quota / rate limit exhausted: fail fast without retrying
            except LLMTimeoutError as exc:
                last_exc = exc
            except LLMAuthError:
                raise
            except LLMError as exc:
                last_exc = exc
            if attempt < self._cfg.max_retries:
                cap = getattr(self._cfg, "retry_backoff_max", 15.0)
                delay = min(self._cfg.retry_backoff ** (attempt - 1), cap) + random.uniform(0, 0.5)
                log.warning("Grok attempt %d/%d failed (%s); retrying in %.1fs",
                            attempt, self._cfg.max_retries, last_exc, delay)
                time.sleep(delay)
        raise LLMError(
            f"Grok request failed after {self._cfg.max_retries} attempts: {last_exc}"
        ) from last_exc

    def _request_once(self, payload: dict) -> dict:
        if self._sdk is not None:
            return self._request_sdk(payload)
        return self._request_rest(payload)

    def _request_sdk(self, payload: dict) -> dict:
        try:
            completion = self._sdk.chat.completions.create(**payload)
            return completion.model_dump()
        except Exception as exc:
            raise self._classify(exc) from exc

    def _request_rest(self, payload: dict) -> dict:
        try:
            import requests
        except ImportError as exc:
            raise LLMError("Neither 'openai' SDK nor 'requests' is installed.") from exc
        try:
            r = requests.post(f"{self._cfg.base_url}/chat/completions",
                              headers=self._headers(), json=payload,
                              timeout=self._cfg.timeout)
        except Exception as exc:
            raise self._classify(exc) from exc
        if r.status_code == 401:
            raise LLMAuthError("Grok rejected the API key (401). Check XAI_API_KEY.")
        if r.status_code == 429:
            raise LLMRateLimitError(f"Grok rate limit exceeded (429): {r.text[:300]}")
        if r.status_code >= 400:
            raise LLMError(f"Grok API error {r.status_code}: {r.text[:300]}")
        try:
            return r.json()
        except ValueError as exc:
            raise LLMError(f"Malformed JSON from Grok: {r.text[:300]}") from exc

    def _stream_sdk(self, payload: dict) -> Generator[str, None, None]:
        try:
            for chunk in self._sdk.chat.completions.create(**payload):
                if not chunk.choices:
                    continue
                delta = chunk.choices[0].delta
                token = getattr(delta, "content", None)
                if token:
                    yield token
        except Exception as exc:
            raise self._classify(exc) from exc

    def _stream_rest(self, payload: dict) -> Generator[str, None, None]:
        import json as _json
        try:
            import requests
            with requests.post(f"{self._cfg.base_url}/chat/completions",
                               headers=self._headers(), json=payload,
                               timeout=self._cfg.timeout, stream=True) as r:
                if r.status_code >= 400:
                    raise LLMError(f"Grok API error {r.status_code}: {r.text[:300]}")
                for raw_line in r.iter_lines():
                    if not raw_line:
                        continue
                    line = raw_line.decode("utf-8", errors="ignore")
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        chunk = _json.loads(data)
                    except ValueError:
                        continue
                    choices = chunk.get("choices") or []
                    if choices:
                        delta = choices[0].get("delta") or {}
                        token = delta.get("content")
                        if token:
                            yield token
        except LLMError:
            raise
        except Exception as exc:
            raise self._classify(exc) from exc

    @staticmethod
    def _extract(raw: dict) -> tuple[str, str, dict]:
        choices = raw.get("choices") or []
        if not choices:
            raise LLMError(f"Grok response contained no choices: {str(raw)[:200]}")
        message = choices[0].get("message") or {}
        content = message.get("content") or ""
        finish = choices[0].get("finish_reason") or ""
        usage = raw.get("usage") or {}
        return content, finish, usage

    @staticmethod
    def _classify(exc: Exception) -> LLMError:
        name = type(exc).__name__.lower()
        text = str(exc).lower()
        if "timeout" in name or "timeout" in text or "timed out" in text:
            return LLMTimeoutError(f"Grok request timed out: {exc}")
        if "ratelimit" in name or "429" in text or "rate limit" in text:
            return LLMRateLimitError(f"Grok rate limit: {exc}")
        if "authentication" in name or "401" in text or "unauthorized" in text or "api key" in text:
            return LLMAuthError(f"Grok authentication failed: {exc}")
        if "connection" in name or "connection" in text or "network" in text:
            return LLMError(f"Grok network failure: {exc}")
        return LLMError(f"Grok request failed: {exc}")
