"""
AI Code Guardian v3 — Phase 7 Unit Tests
========================================
Tests for GuardianDashboardApp, DashboardStateView, DashboardConfig, UI components,
and all 10 dashboard pages (Repository Overview, Knowledge Graph, Workflow Timeline,
Agent Trace, Evidence Explorer, Risk Dashboard, Patch Explorer, Validation Dashboard,
Metrics Dashboard, Export Center).
"""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest

from guardian.dashboard import (
    DashboardConfig,
    DashboardStateView,
    GuardianDashboardApp,
)
from guardian.dashboard.components import (
    CodeDiffViewerComponent,
    MetricCardsComponent,
    NavigationBarComponent,
)
from guardian.dashboard.views import (
    AgentTraceExplorerPage,
    EvidenceExplorerPage,
    ExportCenterPage,
    KnowledgeGraphPage,
    MetricsDashboardPage,
    PatchExplorerPage,
    RepositoryOverviewPage,
    RiskDashboardPage,
    ValidationDashboardPage,
    WorkflowTimelinePage,
)
from guardian.orchestrator import create_initial_state


def test_dashboard_config_and_formatters():
    cfg = DashboardConfig(theme="dark")
    assert cfg.theme == "dark"
    assert cfg.toggle_theme() == "light"
    assert cfg.toggle_theme() == "dark"


def test_dashboard_state_view():
    state = create_initial_state(
        scan_id="scan-view-test",
        findings=[{"finding_id": "f-1", "severity": "HIGH"}],
        evidence=[{"evidence_id": "ev-1", "finding_id": "f-1"}],
    )
    state["patches"] = [{"patch_id": "p-1", "finding_id": "f-1"}]
    state["validation_results"] = [{"patch_id": "p-1", "status": "PASSED"}]

    view = DashboardStateView(state)
    assert view.scan_id == "scan-view-test"
    assert len(view.findings) == 1
    assert len(view.evidence) == 1
    assert len(view.patches) == 1
    assert len(view.validation_results) == 1


def test_ui_components():
    navbar = NavigationBarComponent()
    nav_html = navbar.render(active_tab="Overview")
    assert "Overview" in nav_html

    metric_cards = MetricCardsComponent()
    cards_html = metric_cards.render({"findings_count": 5, "composite_risk": "0.75", "patches_passed": 3})
    assert "TOTAL FINDINGS" in cards_html
    assert "5" in cards_html

    diff_viewer = CodeDiffViewerComponent()
    diff_html = diff_viewer.render("app.py", "eval(input)", "safe_eval(input)")
    assert "app.py" in diff_html
    assert "eval(input)" in diff_html


def test_dashboard_pages():
    state = create_initial_state(
        scan_id="scan-page-test",
        repository_profile={"repo_path": "/tmp/repo", "primary_language": "Python"},
        business_context={"domain": "fintech", "criticality": "CRITICAL"},
        findings=[{"finding_id": "f-1", "severity": "HIGH", "file_path": "main.py", "rule_id": "SEC-004"}],
        evidence=[{"evidence_id": "ev-1", "finding_id": "f-1"}],
    )
    state["agent_trace"] = [{"agent_name": "planner", "execution_time": 0.05, "confidence": 0.95}]
    state["patches"] = [{"patch_id": "p-1", "finding_id": "f-1", "affected_file": "main.py", "original_snippet": "A", "suggested_replacement": "B"}]
    state["validation_results"] = [{"patch_id": "p-1", "status": "PASSED"}]

    view = DashboardStateView(state)

    # 1. Overview Page
    overview_res = RepositoryOverviewPage().render(view)
    assert overview_res["primary_language"] == "Python"
    assert overview_res["business_domain"] == "fintech"

    # 2. Knowledge Graph Page
    kg_res = KnowledgeGraphPage().render("Root")
    assert "architecture_nodes" in kg_res

    # 3. Workflow Timeline Page
    timeline_res = WorkflowTimelinePage().render(view)
    assert timeline_res["total_agents"] == 1

    # 4. Agent Trace Explorer Page
    trace_res = AgentTraceExplorerPage().render(view)
    assert trace_res["total_traces"] == 1

    # 5. Evidence Explorer Page
    ev_res = EvidenceExplorerPage().render(view)
    assert ev_res["total_evidence_items"] == 1

    # 6. Risk Dashboard Page
    risk_res = RiskDashboardPage().render(view)
    assert "composite_risk_score" in risk_res

    # 7. Patch Explorer Page
    patch_res = PatchExplorerPage().render(view)
    assert patch_res["total_patches"] == 1

    # 8. Validation Dashboard Page
    val_res = ValidationDashboardPage().render(view)
    assert val_res["passed_count"] == 1

    # 9. Metrics Dashboard Page
    metrics_res = MetricsDashboardPage().render(view)
    assert "performance_summary" in metrics_res


def test_export_center_page():
    state = create_initial_state(
        scan_id="scan-export-test",
        findings=[{
            "finding_id": "f-1",
            "rule_id": "SEC-004",
            "file_path": "main.py",
            "line_number": 10,
            "severity": "HIGH",
            "description": "Hardcoded secret key",
        }],
    )
    state["git_diff"] = "--- a/main.py\n+++ b/main.py\n-secret=1\n+secret=os.environ.get('SECRET')"

    view = DashboardStateView(state)
    export_page = ExportCenterPage()
    res = export_page.render(view)

    assert res["scan_id"] == "scan-export-test"
    assert "SARIF" in res["supported_formats"]
    assert "runs" in res["sarif_report"]
    assert "html" in res["html_report"].lower() or "doctype" in res["html_report"].lower()
    assert "patch_bundle" in res


def test_guardian_dashboard_app():
    state = create_initial_state(
        scan_id="scan-app-test",
        repository_profile={"primary_language": "Python"},
        findings=[{"finding_id": "f-1", "severity": "CRITICAL"}],
    )

    app = GuardianDashboardApp()

    for page in ["Overview", "Knowledge Graph", "Workflow Timeline", "Agent Trace", "Evidence Explorer", "Risk Dashboard", "Patch Explorer", "Validation Dashboard", "Metrics Dashboard", "Export Center"]:
        render_res = app.render_page(state, page_name=page)
        assert render_res["active_page"] == page
        assert "navbar_html" in render_res
        assert "metrics_html" in render_res
        assert "page_data" in render_res
