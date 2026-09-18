"""
AI Code Guardian v3 — Safe Docker Sandbox Runner
=================================================
Executes repository tasks inside isolated Docker containers or process sandboxes
with read-only volume mounts, resource caps, network isolation, and secret redaction.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

from guardian.sandbox.config import SandboxConfig


class SandboxExecutionError(Exception):
    """Raised when sandbox execution fails or violates security boundaries."""
    pass


class DockerSandboxRunner:
    """Orchestrates containerized and process-isolated sandbox execution."""

    def __init__(self, config: Optional[SandboxConfig] = None):
        self.config = config or SandboxConfig()
        self._docker_available: Optional[bool] = None

    @property
    def is_docker_available(self) -> bool:
        """Checks if Docker engine is installed and accessible."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            res = subprocess.run(
                ["docker", "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5
            )
            self._docker_available = (res.returncode == 0)
        except (OSError, subprocess.SubprocessError):
            self._docker_available = False

        return self._docker_available

    def run_command(
        self,
        command: List[str],
        repo_path: Path,
        extra_env: Optional[Dict[str, str]] = None
    ) -> Tuple[int, str, str]:
        """
        Executes a command safely inside the sandbox.
        Falls back to process sandbox if Docker is unavailable.
        """
        clean_env = self.config.sanitize_environment(extra_env)
        repo_path = Path(repo_path).resolve()

        if not repo_path.exists():
            raise SandboxExecutionError(f"Repository path does not exist: {repo_path}")

        if self.is_docker_available:
            return self._run_in_docker(command, repo_path, clean_env)
        else:
            return self._run_in_process_sandbox(command, repo_path, clean_env)

    def _run_in_docker(
        self,
        command: List[str],
        repo_path: Path,
        clean_env: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """Executes command inside a Docker container with security constraints."""
        docker_cmd = [
            "docker", "run", "--rm",
            "--cpus", str(self.config.cpu_limit),
            "--memory", self.config.memory_limit,
            "-v", f"{repo_path}:{self.config.work_dir}:ro" if self.config.read_only else f"{repo_path}:{self.config.work_dir}",
            "-w", self.config.work_dir,
        ]

        if self.config.network_disabled:
            docker_cmd.append("--network=none")

        for k, v in clean_env.items():
            docker_cmd.extend(["-e", f"{k}={v}"])

        docker_cmd.append(self.config.custom_docker_image)
        docker_cmd.extend(command)

        try:
            res = subprocess.run(
                docker_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.config.timeout_seconds
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            raise SandboxExecutionError(f"Sandbox execution timed out after {self.config.timeout_seconds}s")
        except Exception as e:
            raise SandboxExecutionError(f"Docker sandbox failure: {e}")

    def _run_in_process_sandbox(
        self,
        command: List[str],
        repo_path: Path,
        clean_env: Dict[str, str]
    ) -> Tuple[int, str, str]:
        """Executes command in a process-isolated sandbox with sanitized environment."""
        with tempfile.TemporaryDirectory(prefix="acg_sandbox_") as tmpdir:
            tmp_path = Path(tmpdir) / "repo"
            if self.config.read_only:
                # Copy repo to temporary dir to prevent accidental modifications to original repo
                shutil.copytree(repo_path, tmp_path, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))
                target_cwd = tmp_path
            else:
                target_cwd = repo_path

            try:
                res = subprocess.run(
                    command,
                    cwd=target_cwd,
                    env=clean_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=self.config.timeout_seconds
                )
                return res.returncode, res.stdout, res.stderr
            except subprocess.TimeoutExpired:
                raise SandboxExecutionError(f"Process sandbox execution timed out after {self.config.timeout_seconds}s")
            except Exception as e:
                raise SandboxExecutionError(f"Process sandbox failure: {e}")

    def prepare_isolated_workspace(self, repo_path: Path, base_dir: Optional[Path] = None) -> Path:
        """Creates a temporary isolated copy of the repository for safe analysis."""
        repo_path = Path(repo_path).resolve()
        temp_dir = Path(base_dir) if base_dir is not None else Path(tempfile.mkdtemp(prefix="acg_workspace_"))
        workspace_path = temp_dir / repo_path.name

        shutil.copytree(
            repo_path,
            workspace_path,
            ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "node_modules")
        )
        return workspace_path
