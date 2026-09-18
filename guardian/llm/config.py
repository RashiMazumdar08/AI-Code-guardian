"""
LLM Layer — Configuration (spec §3, §10)
========================================
All provider settings in one dataclass, loaded from environment
variables with a `.env` file as an optional convenience.

SECURITY: the API key is read from the environment only. It is never
written to a config file, never logged, and `__repr__` masks it — a
config object can safely appear in a stack trace or debug dump.

Environment variables
---------------------
    NVIDIA_API_KEY      (required)  provider credential
    NVIDIA_BASE_URL     (optional)  default https://integrate.api.nvidia.com/v1
    NVIDIA_MODEL        (optional)  default nvidia/nemotron-3-ultra-550b-a55b
    LLM_TEMPERATURE     (optional)  default 1.0  — recommended for Nemotron Ultra
    LLM_MAX_TOKENS      (optional)  default 16384
    LLM_TIMEOUT         (optional)  default 120  seconds
    LLM_MAX_RETRIES     (optional)  default 3
    LLM_RETRY_BACKOFF   (optional)  default 2.0  exponential base
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def load_dotenv(path: str | Path = ".env", override: bool = False) -> int:
    """Minimal .env loader — avoids adding python-dotenv as a hard
    dependency. Returns the number of variables applied. Lines are
    KEY=VALUE; blank lines and '#' comments are ignored."""
    p = Path(path)
    if not p.is_file():
        return 0
    applied = 0
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and (override or key not in os.environ):
            os.environ[key] = value
            applied += 1
    return applied


DEFAULT_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"


@dataclass
class LLMConfig:
    """Provider configuration. Construct via `LLMConfig.from_env()`."""

    api_key: str = ""
    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL

    # generation
    temperature: float = 1.0
    max_tokens: int = 16384
    top_p: float = 0.95

    # Nemotron Ultra reasoning (chain-of-thought)
    enable_thinking: bool = True
    reasoning_budget: int = 16384

    # transport
    timeout: int = 120
    # BUG FIX: this was 10, but the module docstring documents (and the
    # UX requires) a default of 3. With a 120s per-attempt timeout and
    # unbounded exponential backoff, 10 retries could turn one slow/
    # blocked network into a 20+ minute silent hang on a single chat
    # request before any error ever reached the user.
    max_retries: int = 3
    retry_backoff: float = 2.0
    retry_backoff_max: float = 15.0  # cap on any single retry delay, in seconds
    retry_on_status: tuple[int, ...] = (408, 429, 500, 502, 503, 504)

    # observability (spec §12)
    log_prompts: bool = False       # opt-in: prompts may contain source code
    log_token_usage: bool = True

    extras: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, dotenv_path: str | Path = ".env") -> "LLMConfig":
        load_dotenv(dotenv_path)

        def _f(name: str, default: float) -> float:
            try:
                return float(os.getenv(name, default))
            except (TypeError, ValueError):
                return default

        def _i(name: str, default: int) -> int:
            try:
                return int(os.getenv(name, default))
            except (TypeError, ValueError):
                return default

        return cls(
            api_key=os.getenv("NVIDIA_API_KEY", ""),
            base_url=os.getenv("NVIDIA_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            model=os.getenv("NVIDIA_MODEL", DEFAULT_MODEL),
            temperature=_f("LLM_TEMPERATURE", 1.0),
            max_tokens=_i("LLM_MAX_TOKENS", 16384),
            top_p=_f("LLM_TOP_P", 0.95),
            timeout=_i("LLM_TIMEOUT", 120),
            max_retries=_i("LLM_MAX_RETRIES", 10),
            retry_backoff=_f("LLM_RETRY_BACKOFF", 2.0),
            log_prompts=os.getenv("LLM_LOG_PROMPTS", "false").lower() == "true",
            enable_thinking=os.getenv("LLM_ENABLE_THINKING", "true").lower() == "true",
            reasoning_budget=_i("LLM_REASONING_BUDGET", 16384),
        )

    # ------------------------------------------------------------------
    def validate(self) -> None:
        """Raise ValueError with an actionable message if unusable."""
        if not self.api_key:
            raise ValueError(
                "NVIDIA_API_KEY is not set. Export it or add it to .env:\n"
                "    export NVIDIA_API_KEY='nvapi-...'\n"
                "Get a key at https://build.nvidia.com/ (API Keys section)."
            )
        if not self.base_url.startswith("https://"):
            raise ValueError(
                f"NVIDIA_BASE_URL must be HTTPS (got {self.base_url!r}). "
                "Source code is transmitted to this endpoint; plaintext HTTP "
                "is not permitted."
            )
        self.base_url = self.base_url.rstrip("/")
        if not 0.0 <= self.temperature <= 2.0:
            raise ValueError(f"LLM_TEMPERATURE must be 0.0-2.0 (got {self.temperature})")
        if self.max_tokens < 1:
            raise ValueError(f"LLM_MAX_TOKENS must be positive (got {self.max_tokens})")

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    @property
    def masked_key(self) -> str:
        if not self.api_key:
            return "<unset>"
        return f"{self.api_key[:6]}...{self.api_key[-4:]}" if len(self.api_key) > 12 else "<set>"

    def __repr__(self) -> str:  # never leak the key into logs/tracebacks
        return (f"LLMConfig(model={self.model!r}, base_url={self.base_url!r}, "
                f"api_key={self.masked_key}, temperature={self.temperature}, "
                f"max_tokens={self.max_tokens}, timeout={self.timeout})")
