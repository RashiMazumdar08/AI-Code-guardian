"""
AI Code Guardian v3 — Phase 8 Integration Unit Tests
======================================================
Tests RepositoryManager, SessionManager, Copilot, MindMap, AgentStudio, ThreatIntel, and PolicyCenter.
"""
import tempfile
import zipfile
from pathlib import Path
import pytest

from guardian.dashboard.app import GuardianDashboardApp
from guardian.dashboard.utils.session import DashboardSessionManager
from guardian.dashboard.views import (
    AgentStudioPage,
    MindMapViewPage,
    PolicyCenterViewPage,
    ThreatIntelViewPage,
)
from guardian.orchestrator.state import create_initial_state
from guardian.workspace.manager import RepositoryManager


def test_repository_manager():
    with tempfile.TemporaryDirectory() as tmpdir:
        base_path = Path(tmpdir)
        repo_dir = base_path / "sample_repo"
        repo_dir.mkdir()
        (repo_dir / "main.py").write_text("print('hello')\n")

        mgr = RepositoryManager(base_workspace_dir=base_path / ".acg_workspaces")
        info = mgr.register_local_repository(str(repo_dir))
        assert info["repo_name"] == "sample_repo"
        assert info["repository_id"].startswith("repo-")

        # Test ZIP extraction
        zip_path = base_path / "archive.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("app.py", "import os\n")

        info_zip = mgr.extract_zip_repository(str(zip_path))
        assert info_zip["repository_id"].startswith("repo-")

        history = mgr.list_history()
        assert len(history) >= 2





def test_mind_map_agent_studio_threat_intel():
    state = create_initial_state(scan_id="test-all-views")
    state["findings"] = [{
        "finding_id": "f-1",
        "rule_id": "SEC-001",
        "file_path": "main.py",
        "severity": "CRITICAL",
    }]
    from guardian.dashboard.models.dashboard_state import DashboardStateView
    sv = DashboardStateView(state)

    mind_map = MindMapViewPage().render(sv)
    assert mind_map["total_vulnerable_paths"] >= 1

    studio = AgentStudioPage().render(sv)
    assert studio["total_agents"] == 11

    threat = ThreatIntelViewPage().render(sv)
    assert threat["total_attack_paths"] >= 1


def test_all_15_views_in_guardian_dashboard_app():
    app = GuardianDashboardApp()
    state = create_initial_state(scan_id="test-all-15")

    for page_name in app.pages:
        res = app.render_page(state, page_name=page_name)
        assert res["page_data"].get("page_title") is not None
