"""
AI Code Guardian v3 — Sandbox Configuration Model
===================================================
Defines isolation parameters, resource constraints, and safety controls
for repository execution inside Docker containers or process sandboxes.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional


DEFAULT_REDACT_PATTERNS = [
    re.compile(r"(?i)(api[_-]?key|secret|token|password|auth|passwd|credential|private[_-]?key)"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key ID
    re.compile(r"nvapi-[A-Za-z0-9_-]{32,}"),  # NVIDIA API key
    re.compile(r"sk-[A-Za-z0-9]{32,}"),  # OpenAI API key
]


@dataclass
class SandboxConfig:
    """Configures sandbox isolation and safety boundaries."""
    cpu_limit: float = 2.0                 # Max CPU cores allocated
    memory_limit: str = "4g"               # Max memory allocation (e.g. 4g)
    read_only: bool = True                 # Mount repository as read-only
    network_disabled: bool = True          # Disable network access by default
    timeout_seconds: int = 300             # Execution timeout in seconds
    work_dir: str = "/tmp/workspace"       # Temporary working directory
    tmpfs_size: str = "512m"               # Size of temporary in-memory filesystem
    redact_env: bool = True                # Automatically sanitize environment secrets
    env_vars: Dict[str, str] = field(default_factory=dict) # Explicit allowed env vars
    custom_docker_image: str = "python:3.12-slim"

    def sanitize_environment(self, env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """Redacts credentials and sensitive values from the environment dictionary."""
        source_env = env if env is not None else dict(os.environ)
        clean_env: Dict[str, str] = {}

        for k, v in source_env.items():
            is_sensitive = False
            for pattern in DEFAULT_REDACT_PATTERNS:
                if pattern.search(k) or pattern.search(v):
                    is_sensitive = True
                    break
            
            if is_sensitive and self.redact_env:
                clean_env[k] = "[REDACTED_BY_GUARDIAN_SANDBOX]"
            else:
                clean_env[k] = v

        # Apply explicitly allowed env vars
        clean_env.update(self.env_vars)
        return clean_env
