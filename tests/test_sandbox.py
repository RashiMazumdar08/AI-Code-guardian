"""
Tests for AI Code Guardian v3 — Docker & Process Sandbox Runner
"""
import os
import tempfile
from pathlib import Path

import pytest
from guardian.sandbox.config import SandboxConfig
from guardian.sandbox.docker_runner import DockerSandboxRunner, SandboxExecutionError
from guardian.config import GuardianConfig
from guardian.core.pipeline import ScanPipeline


def test_sandbox_config_defaults():
    config = SandboxConfig()
    assert config.cpu_limit == 2.0
    assert config.memory_limit == "4g"
    assert config.read_only is True
    assert config.network_disabled is True


def test_environment_redaction():
    config = SandboxConfig(redact_env=True)
    dirty_env = {
        "NORMAL_VAR": "hello",
        "NVIDIA_API_KEY": "nvapi-1234567890abcdef1234567890abcdef",
        "AWS_SECRET_ACCESS_KEY": "secret_key_value",
        "DB_PASSWORD": "my_password_123",
    }
    clean_env = config.sanitize_environment(dirty_env)
    assert clean_env["NORMAL_VAR"] == "hello"
    assert clean_env["NVIDIA_API_KEY"] == "[REDACTED_BY_GUARDIAN_SANDBOX]"
    assert clean_env["AWS_SECRET_ACCESS_KEY"] == "[REDACTED_BY_GUARDIAN_SANDBOX]"
    assert clean_env["DB_PASSWORD"] == "[REDACTED_BY_GUARDIAN_SANDBOX]"


def test_sandbox_runner_process_fallback():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "test_repo"
        repo_dir.mkdir()
        (repo_dir / "sample.py").write_text("print('hello sandbox')")

        config = SandboxConfig(read_only=True)
        runner = DockerSandboxRunner(config=config)
        # Force fallback to process sandbox
        runner._docker_available = False

        code, stdout, stderr = runner.run_command(["python", "sample.py"], repo_path=repo_dir)
        assert code == 0
        assert "hello sandbox" in stdout


def test_sandbox_isolated_workspace():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "my_project"
        repo_dir.mkdir()
        (repo_dir / "main.py").write_text("print('workspace test')")

        runner = DockerSandboxRunner()
        isolated_path = runner.prepare_isolated_workspace(repo_dir)
        assert isolated_path.exists()
        assert (isolated_path / "main.py").exists()
        assert (isolated_path / "main.py").read_text() == "print('workspace test')"


def test_pipeline_scan_can_use_sandbox_copy():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "sandboxed_project"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("print('scan me')\n")

        report = ScanPipeline(GuardianConfig(enable_sandbox=True)).scan(repo_dir)

        assert report["sandbox"]["enabled"] is True
        assert report["sandbox"]["mode"] == "isolated_workspace"
        assert report["repository"]["root"] == str(repo_dir.resolve())
        assert report["scan"]["target"] == str(repo_dir.resolve())
        assert report["discovery"]["source_files"] == 1


def test_sandboxed_knowledge_report_uses_source_paths():
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_dir = Path(tmpdir) / "sandboxed_knowledge_project"
        repo_dir.mkdir()
        (repo_dir / "README.md").write_text("# Service\nKnowledge docs.")
        (repo_dir / "app.py").write_text("print('scan me')\n")

        cfg = GuardianConfig(enable_sandbox=True, enable_knowledge=True)
        report = ScanPipeline(cfg).scan(repo_dir)

        arch_repo = report["knowledge"]["architecture"]["repository"]
        assert arch_repo["path"] == str(repo_dir.resolve())
        assert "acg_scan_workspace_" not in str(report)
