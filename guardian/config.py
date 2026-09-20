"""
AI Code Guardian 2.0 — Configuration
====================================
Single source of configuration truth. Everything the platform does is
driven by this object; no module may hardcode repository-specific
behavior. Precedence: explicit kwargs > YAML file > environment
variables > built-in fallback defaults. The env vars are read once, as
each field's default_factory, so a bare GuardianConfig() (the common
case -- see guardian/core/pipeline.py) already honours them without
going through load().
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DEFAULT_JUNK_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "coverage", "__pycache__",
    ".venv", "venv", ".cache", "target", "vendor", "bin", "obj", ".idea", ".vscode",
}

DEFAULT_IGNORE_DIRS = DEFAULT_JUNK_DIRS | {
    ".hg", ".svn", ".venv-app", "env", ".mypy_cache", ".pytest_cache", ".tox",
    "bower_components", ".nuxt", ".turbo", ".output", ".acg_index", "tests",
}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default.yaml"


@dataclass
class GuardianConfig:
    # discovery
    ignore_dirs: set[str] = field(default_factory=lambda: set(DEFAULT_IGNORE_DIRS))
    follow_symlinks: bool = False
    # MAX_FILES / MAX_FILE_SIZE_MB (env) let an operator tune the discovery
    # cap per-deployment without a code change; guardian/discovery/file_walker.py
    # already enforces both fields below -- this only makes their *default*
    # env-driven, it doesn't change how they're used.
    max_files: int = field(default_factory=lambda: int(os.getenv("MAX_FILES", "200000")))
    max_file_bytes: int = field(default_factory=lambda: int(
        float(os.getenv("MAX_FILE_SIZE_MB", "0.2")) * 1_000_000))  # skip files larger than this many MB (200KB max default)
    # Exclude test files (foo.spec.ts, test_foo.py, FooTest.java, ...) from
    # the security-scanned source set. Directory-based ignore_dirs can't
    # catch these on its own: Angular/Jest/Jasmine conventions put
    # foo.component.spec.ts right next to foo.component.ts in the same
    # folder, not under a separate "tests" directory, so mock/fixture data
    # in test assertions (e.g. `expect(body).toEqual({password: '...'})`)
    # was being flagged as a real hardcoded-secret finding in production
    # code. On by default, matching standard practice for security scanners.
    exclude_test_files: bool = True

    # analysis toggles
    enable_dependencies: bool = True
    enable_infrastructure: bool = True
    enable_quantum: bool = False
    enable_quantum_gate: bool = False  # opt-in: hard-block merges on Shor-class crypto inventory
    enable_intent: bool = True
    enable_threat_intel: bool = False   # requires network; off by default
    enable_ai: bool = False             # requires NVIDIA_API_KEY; off by default
    enable_sandbox: bool = False         # scan an isolated copy of the repository
    enable_knowledge: bool = False       # build repository graph and semantic doc index

    # risk
    alignment_score_default: float = 75.0
    fail_on_severity: Optional[str] = None  # e.g. "High" for CI gating

    # ai / rag
    llm_provider: str = "nemotron"      # see guardian/llm/factory.py
    llm_model: str = ""                 # blank = provider default (NVIDIA_MODEL)
    rag_persist: bool = False

    # reporting
    report_formats: list[str] = field(default_factory=lambda: ["json"])

    # performance
    # UST_MAX_WORKERS: bounded process-pool size for parallel Tree-sitter
    # parsing of cache-miss files (guardian/ust/builder.py). 1 disables
    # parallelism and parses sequentially.
    ust_max_workers: int = field(default_factory=lambda: int(os.getenv("UST_MAX_WORKERS", "4")))
    # CACHE_TTL: seconds a cached per-file UST entry is kept in Redis.
    cache_ttl_seconds: int = field(default_factory=lambda: int(os.getenv("CACHE_TTL", "86400")))
    # ENGINE_MAX_WORKERS: bounded thread-pool size for running the
    # deterministic engines (security/quantum/business_intent) concurrently
    # instead of sequentially (guardian/core/pipeline.py). Defaults to 1
    # (today's sequential behaviour) rather than being on by default like
    # UST_MAX_WORKERS: engines are read-independent and EvidenceStore.add()
    # is lock-protected, so concurrent execution is SAFE, but EvidenceStore
    # assigns evidence IDs from a shared incrementing counter (unlike UST
    # node IDs, which are content-hashed) -- under real thread interleaving
    # the same scan can assign different ID *numbers* to the same evidence
    # on different runs. Same findings, same evidence, different E-numbers.
    # An operator who wants the speed and accepts that opts in explicitly.
    engine_max_workers: int = field(default_factory=lambda: int(os.getenv("ENGINE_MAX_WORKERS", "4")))

    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Optional[str | Path] = None, **overrides) -> "GuardianConfig":
        data: dict[str, Any] = {}
        cfg_path = Path(path) if path else DEFAULT_CONFIG_PATH
        if yaml is not None and cfg_path.exists():
            loaded = yaml.safe_load(cfg_path.read_text()) or {}
            data.update(loaded)
        data.update({k: v for k, v in overrides.items() if v is not None})

        known = {f for f in cls.__dataclass_fields__}
        kwargs = {k: v for k, v in data.items() if k in known}
        extras = {k: v for k, v in data.items() if k not in known}
        if "ignore_dirs" in kwargs:
            kwargs["ignore_dirs"] = set(kwargs["ignore_dirs"]) | DEFAULT_IGNORE_DIRS
        cfg = cls(**kwargs)
        cfg.extras.update(extras)
        return cfg
