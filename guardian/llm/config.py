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

DEFAULT_GROK_BASE_URL = "https://api.x.ai/v1"
DEFAULT_GROK_MODEL = "grok-2-latest"

DEFAULT_GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/openai/"
DEFAULT_GEMINI_MODEL = "gemini-3.8-flash"


@dataclass
class LLMConfig:
    """Provider configuration. Construct via `LLMConfig.from_env()`."""

    api_key: str = ""
    base_url: str = DEFAULT_GEMINI_BASE_URL
    model: str = DEFAULT_GEMINI_MODEL
    provider: str = "gemini"

    # Global and per-agent AI toggles
    enabled: bool = True
    security_agent_enabled: bool = False
    enabled_agents: set[str] = field(
        default_factory=lambda: {
            "security", "business", "architecture", "threat_simulation",
            "validation", "patch", "chat", "dependency"
        }
    )

    # generation
    temperature: float = 1.0
    max_tokens: int = 16384
    top_p: float = 0.95

    # Nemotron Ultra reasoning (chain-of-thought)
    enable_thinking: bool = True
    reasoning_budget: int = 16384

    # transport
    timeout: int = 120
    max_retries: int = 3
    retry_backoff: float = 2.0
    retry_backoff_max: float = 15.0  # cap on any single retry delay, in seconds
    retry_on_status: tuple[int, ...] = (408, 429, 500, 502, 503, 504)

    # observability (spec §12)
    log_prompts: bool = False       # opt-in: prompts may contain source code
    log_token_usage: bool = True

    # Rule Parser LLM Configuration (Local Qwen2.5-3B-Instruct)
    rule_parser_enabled: bool = True
    rule_parser_model: str = "Qwen2.5-3B-Instruct"
    rule_parser_timeout: int = 30
    rule_parser_local_path: str = ""

    extras: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    @classmethod
    def from_env(cls, dotenv_path: str | Path = ".env", agent: Optional[str] = None) -> "LLMConfig":
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

        agent_provider = os.getenv(f"{agent.upper()}_LLM_PROVIDER") or os.getenv(f"{agent.upper()}_PROVIDER") if agent else None
        provider_env = (agent_provider or os.getenv("LLM_PROVIDER") or "").lower().strip()

        gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GEMINI_KEY", "")
        grok_key = os.getenv("XAI_API_KEY") or os.getenv("GROK_API_KEY", "")
        nvidia_key = os.getenv("NVIDIA_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY", "")

        if provider_env in ("gemini", "google") or (not provider_env and gemini_key):
            provider = "gemini"
            api_key = gemini_key or nvidia_key
            base_url = os.getenv("GEMINI_BASE_URL") or os.getenv("NVIDIA_BASE_URL", DEFAULT_GEMINI_BASE_URL)
            model = os.getenv("GEMINI_MODEL") or os.getenv("NVIDIA_MODEL", DEFAULT_GEMINI_MODEL)
        elif provider_env in ("grok", "xai") or (not provider_env and grok_key):
            provider = "grok"
            api_key = grok_key
            base_url = os.getenv("XAI_BASE_URL") or os.getenv("GROK_BASE_URL", DEFAULT_GROK_BASE_URL)
            model = os.getenv("XAI_MODEL") or os.getenv("GROK_MODEL", DEFAULT_GROK_MODEL)
        elif provider_env in ("nemotron", "nvidia"):
            provider = "nemotron"
            api_key = nvidia_key
            base_url = os.getenv("NVIDIA_BASE_URL", DEFAULT_BASE_URL)
            model = os.getenv("NVIDIA_MODEL", DEFAULT_MODEL)
        else:
            provider = "gemini"
            api_key = gemini_key or nvidia_key
            base_url = os.getenv("GEMINI_BASE_URL") or os.getenv("NVIDIA_BASE_URL", DEFAULT_GEMINI_BASE_URL)
            model = os.getenv("GEMINI_MODEL") or os.getenv("NVIDIA_MODEL", DEFAULT_GEMINI_MODEL)

        base_url = base_url.rstrip("/")

        # Global LLM enablement
        llm_enabled_str = os.getenv("LLM_ENABLED", "").lower()
        if llm_enabled_str in ("false", "0", "no", "off"):
            enabled = False
        else:
            enabled = bool(api_key)

        # Per-agent enablement parsing
        agents_env = os.getenv("LLM_AGENTS_ENABLED", "").lower().strip()
        if agents_env:
            enabled_agents = {a.strip() for a in agents_env.split(",") if a.strip()}
        else:
            enabled_agents = {
                "security", "business", "architecture", "threat_simulation",
                "validation", "patch", "chat", "dependency"
            }

        rule_parser_enabled_str = os.getenv("LLM_RULE_PARSER_ENABLED", "true").lower().strip()
        rule_parser_enabled = rule_parser_enabled_str not in ("false", "0", "no", "off", "disabled")

        extras = {"provider": provider}

        sec_enabled_str = os.getenv("SECURITY_AGENT_ENABLED", "false").lower().strip()
        security_agent_enabled = sec_enabled_str in ("true", "1", "yes", "on")

        return cls(
            api_key=api_key,
            base_url=base_url,
            model=model,
            provider=provider,
            enabled=enabled,
            security_agent_enabled=security_agent_enabled,
            enabled_agents=enabled_agents,
            temperature=_f("LLM_TEMPERATURE", 1.0),
            max_tokens=_i("LLM_MAX_TOKENS", 16384),
            top_p=_f("LLM_TOP_P", 0.95),
            timeout=_i("LLM_TIMEOUT", 120),

            max_retries=_i("LLM_MAX_RETRIES", 3),
            retry_backoff=_f("LLM_RETRY_BACKOFF", 2.0),
            log_prompts=os.getenv("LLM_LOG_PROMPTS", "false").lower() == "true",
            enable_thinking=os.getenv("LLM_ENABLE_THINKING", "true").lower() == "true",
            reasoning_budget=_i("LLM_REASONING_BUDGET", 16384),
            rule_parser_enabled=rule_parser_enabled,
            rule_parser_model=os.getenv("LLM_RULE_PARSER_MODEL", "Qwen2.5-3B-Instruct"),
            rule_parser_timeout=_i("LLM_RULE_PARSER_TIMEOUT", 30),
            rule_parser_local_path=os.getenv("LLM_RULE_PARSER_LOCAL_PATH", ""),
            extras=extras,
        )

    # ------------------------------------------------------------------
    def validate(self) -> None:
        """Raise ValueError with an actionable message if unusable."""
        if not self.api_key:
            raise ValueError(
                "No API key set. Export XAI_API_KEY (or NVIDIA_API_KEY) or add it to .env:\n"
                "    export XAI_API_KEY='xai-...'\n"
                "Get a key at https://x.ai/ (API section)."
            )
        if not self.base_url.startswith("https://"):
            raise ValueError(
                f"LLM Base URL must be HTTPS (got {self.base_url!r}). "
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
        return bool(self.api_key) and self.enabled

    def is_agent_enabled(self, agent_name: str) -> bool:
        return self.is_configured and (agent_name in self.enabled_agents)

    def is_security_ai_enabled(self) -> bool:
        sec_env = os.getenv("SECURITY_AGENT_ENABLED", "false").lower().strip()
        return sec_env in ("true", "1", "yes", "on") and self.is_agent_enabled("security")

    def get_agent_config(self, agent_name: str) -> "LLMConfig":
        """Return a provider configuration for a specific agent if customized via env vars."""
        agent_upper = agent_name.upper()
        agent_provider = os.getenv(f"{agent_upper}_LLM_PROVIDER") or os.getenv(f"{agent_upper}_PROVIDER")
        if not agent_provider:
            return self

        agent_key = (
            os.getenv(f"{agent_upper}_API_KEY") or
            os.getenv(f"{agent_upper}_GEMINI_API_KEY") or
            os.getenv(f"{agent_upper}_NVIDIA_API_KEY") or
            os.getenv(f"{agent_upper}_XAI_API_KEY") or
            self.api_key
        )
        agent_base_url = os.getenv(f"{agent_upper}_BASE_URL") or self.base_url
        agent_model = os.getenv(f"{agent_upper}_MODEL") or self.model

        import copy
        cfg = copy.copy(self)
        cfg.provider = agent_provider.lower().strip()
        cfg.api_key = agent_key
        cfg.base_url = agent_base_url
        cfg.model = agent_model
        return cfg

    @property
    def masked_key(self) -> str:
        if not self.api_key:
            return "<unset>"
        return f"{self.api_key[:6]}...{self.api_key[-4:]}" if len(self.api_key) > 12 else "<set>"

    def __repr__(self) -> str:  # never leak the key into logs/tracebacks
        return (f"LLMConfig(provider={self.provider!r}, model={self.model!r}, base_url={self.base_url!r}, "
                f"api_key={self.masked_key}, enabled={self.enabled}, temperature={self.temperature}, "
                f"max_tokens={self.max_tokens}, timeout={self.timeout})")

