"""
AI Code Guardian v3 — Enterprise Security Platform Master Engine
==================================================================
Master dashboard orchestrator exposing all 13 observability, reasoning, and remediation views.
Integrates Repository Workspace, AI Copilot RAG Chatbot, Interactive Knowledge Graphs,
Mind Maps, Agent Studio, Threat Intel, Policy Center, and Export Center.
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from typing import Any, Dict, Optional

from guardian.core.pipeline import ScanPipeline

from guardian.dashboard.components.metric_cards import MetricCardsComponent
from guardian.dashboard.components.navbar import NavigationBarComponent
from guardian.dashboard.models.dashboard_state import DashboardStateView
from guardian.dashboard.utils.config import DashboardConfig
from guardian.dashboard.utils.session import DashboardSessionManager
from guardian.dashboard.views import (
    AgentStudioPage,
    AgentTraceExplorerPage,
    InteractiveAssistantPage,
    EvidenceExplorerPage,
    ExportCenterPage,
    KnowledgeGraphPage,
    MetricsDashboardPage,
    MindMapViewPage,
    PatchExplorerPage,
    PolicyCenterViewPage,
    RepositoryExplorerPage,
    RepositoryOverviewPage,
    RiskDashboardPage,
    ThreatIntelViewPage,
    ValidationDashboardPage,
    WorkflowTimelinePage,
)
from guardian.knowledge.services.knowledge_service import KnowledgeService
from guardian.orchestrator.state import AgentWorkflowState, create_initial_state
from guardian.workspace.manager import RepositoryManager


class GuardianDashboardApp:
    """Master application engine orchestrating Enterprise Dashboard views."""

    def __init__(
        self,
        config: Optional[DashboardConfig] = None,
        knowledge_service: Optional[KnowledgeService] = None,
        repo_manager: Optional[RepositoryManager] = None
    ) -> None:
        self.config = config or DashboardConfig()
        self.knowledge_service = knowledge_service or KnowledgeService()
        self.repo_manager = repo_manager or RepositoryManager()

        # Component & Page Initializers
        self.navbar = NavigationBarComponent()
        self.metric_cards = MetricCardsComponent()

        self.pages = {
            "Overview": RepositoryOverviewPage(),
            "Repository Explorer": RepositoryExplorerPage(),
            "Knowledge Graph": KnowledgeGraphPage(knowledge_service=self.knowledge_service),
            "Mind Map": MindMapViewPage(),
            "Workflow Timeline": WorkflowTimelinePage(),
            "Agent Studio": AgentStudioPage(),
            "Agent Trace": AgentTraceExplorerPage(),
            "Evidence Explorer": EvidenceExplorerPage(),
            "Threat Intelligence": ThreatIntelViewPage(),
            "Risk Dashboard": RiskDashboardPage(),
            "Patch Explorer": PatchExplorerPage(),
            "Validation Dashboard": ValidationDashboardPage(),
            "Policy Center": PolicyCenterViewPage(),
            "Metrics Dashboard": MetricsDashboardPage(),
            "Export Center": ExportCenterPage(),
            "Interactive Assistant": InteractiveAssistantPage(),
        }

    def render_page(self, state: AgentWorkflowState, page_name: str = "Overview", **kwargs: Any) -> Dict[str, Any]:
        """Renders target dashboard page using a read-only state view."""
        state_view = DashboardStateView(state)
        handler = self.pages.get(page_name, self.pages["Overview"])

        page_output = handler.render(state_view, **kwargs) if hasattr(handler, "render") else {}

        summary_metrics = {
            "findings_count": len(state_view.findings),
            "composite_risk": f"{state_view.risk_scores.get('composite_risk_score', 0.0):.2f}",
            "patches_passed": sum(1 for v in state_view.validation_results if v.get("status") == "PASSED"),
        }

        return {
            "navbar_html": self.navbar.render(active_tab=page_name),
            "metrics_html": self.metric_cards.render(summary_metrics),
            "active_page": page_name,
            "page_data": page_output,
        }


def _report_to_workflow_state(scan_id: str, repo_path: str, report: Dict[str, Any],
                              domain: str, criticality: str) -> AgentWorkflowState:
    """Adapts a `guardian.core.pipeline.ScanPipeline.scan()` report dict into
    the `AgentWorkflowState` shape `DashboardStateView` and the page renderers
    expect, so the dashboard reflects real scan results end-to-end."""
    scan = report.get("scan", {}) or {}
    findings = scan.get("findings", [])
    evidence = report.get("evidence_items", [])
    risk = report.get("risk", {}) or {}
    unified_risk = report.get("unified_risk", {}) or {}

    risk_scores = dict(risk)
    risk_scores.update(unified_risk)
    risk_scores.setdefault("composite_risk_score", risk.get("overall_risk_score", 0.0))

    state = create_initial_state(
        scan_id=scan_id,
        repository_profile=report.get("repository", {"repo_path": repo_path}),
        business_context={"domain": domain, "criticality": criticality},
        policy_context={"frameworks": ["OWASP_TOP_10", "NIST_800_53"]},
        repository_context=report.get("discovery", {}),
        findings=findings,
        evidence=evidence,
        threat_context=report.get("quantum_summary") or {},
        policy_results={},
    )
    state["security_context"] = {"engines": report.get("engines", {})}
    state["dependency_context"] = {"analyzers": report.get("analyzers", {})}
    state["architecture_context"] = report.get("business_domain") or {}
    state["risk_scores"] = risk_scores
    state["agent_trace"] = [{
        "agent_name": "scan_pipeline",
        "execution_time": report.get("duration_seconds", 0.0),
        "current_task": "deterministic_scan",
        "tools_used": ["ScanPipeline"],
        "evidence_ids": [e.get("evidence_id", "") for e in evidence if isinstance(e, dict)],
        "confidence": 1.0,
        "result": {"files_scanned": scan.get("files_scanned", 0)},
        "errors": report.get("errors", []),
    }]
    state["execution_metrics"] = {
        "total_execution_time": report.get("duration_seconds", 0.0),
        "agent_runtime": {"scan_pipeline": report.get("duration_seconds", 0.0)},
        "tool_runtime": {},
        "retrieval_latency": 0.0,
        "graph_query_latency": 0.0,
        "embedding_retrieval_latency": 0.0,
        "number_of_findings": len(findings),
        "number_of_policies_applied": 0,
        "number_of_evidence_objects": len(evidence),
    }
    return state


def main():
    """Streamlit Entry Point rendering interactive Enterprise AI Security Platform."""
    try:
        import streamlit as st
    except ImportError:
        print("Streamlit package is required to launch UI.")
        return

    st.set_page_config(
        page_title="AI Code Guardian v3 — Enterprise Security Platform",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    DashboardSessionManager.initialize_session(st)
    app = GuardianDashboardApp()

    # Sidebar Repository Workspace Manager
    st.sidebar.title("🛡️ AI Code Guardian")
    st.sidebar.caption("Enterprise Observability & Multi-Agent Security Platform")

    st.sidebar.subheader("📂 Repository Workspace")
    workspace_mode = st.sidebar.radio("Source Type", ["Local Directory", "Upload ZIP Archive", "Clone GitHub Repo"])

    target_repo_path = os.getcwd()
    repo_info = DashboardSessionManager.get_active_repository(st)

    if workspace_mode == "Local Directory":
        local_input = st.sidebar.text_input("Repository Directory Path", value=os.getcwd())
        if st.sidebar.button("Register & Select Directory"):
            try:
                info = app.repo_manager.register_local_repository(local_input)
                DashboardSessionManager.set_active_repository(st, info)
                st.sidebar.success(f"Registered: {info['repo_name']}")
                st.rerun()
            except Exception as e:
                st.sidebar.error(str(e))

    elif workspace_mode == "Upload ZIP Archive":
        uploaded_zip = st.sidebar.file_uploader("Upload Codebase ZIP", type=["zip"])
        if uploaded_zip and st.sidebar.button("Extract & Select ZIP Workspace"):
            try:
                info = app.repo_manager.extract_zip_repository(uploaded_zip, filename=uploaded_zip.name)
                DashboardSessionManager.set_active_repository(st, info)
                st.sidebar.success(f"Extracted & Registered: {info['repo_name']}")
                st.rerun()
            except Exception as e:
                st.sidebar.error(str(e))

    elif workspace_mode == "Clone GitHub Repo":
        git_url = st.sidebar.text_input("GitHub Clone URL", value="https://github.com/")
        if st.sidebar.button("Clone & Register GitHub Repo"):
            try:
                with st.spinner("Cloning GitHub repository..."):
                    info = app.repo_manager.clone_github_repository(git_url)
                    DashboardSessionManager.set_active_repository(st, info)
                    st.sidebar.success(f"Cloned: {info['repo_name']}")
                    st.rerun()
            except Exception as e:
                st.sidebar.error(str(e))

    # Active Workspace Metadata Banner
    if repo_info:
        target_repo_path = repo_info.get("repo_path", os.getcwd())
        st.sidebar.info(
            f"**Active Workspace**: `{repo_info.get('repo_name')}`\n"
            f"**ID**: `{repo_info.get('repository_id')}`\n"
            f"**Size**: `{repo_info.get('size_mb')} MB`"
        )

    domain = st.sidebar.selectbox("Business Domain", ["fintech", "healthcare", "ecommerce", "saas", "general"])
    criticality = st.sidebar.selectbox("Business Criticality", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def run_scan(repo_path: str) -> AgentWorkflowState:
        """Runs the real deterministic ScanPipeline (UST + engines + legacy
        plugins) instead of the placeholder multi-agent OrchestratorWorkflow,
        then adapts its report into the AgentWorkflowState shape the
        dashboard views already know how to render."""
        scan_id = f"scan-{os.urandom(4).hex()}"

        async def _run() -> dict:
            pipeline = ScanPipeline()
            return pipeline.scan(repo_path)

        report = asyncio.run(_run())
        return _report_to_workflow_state(scan_id, repo_path, report, domain, criticality)

    if st.sidebar.button("⚡ Run Multi-Agent Scan"):
        with st.spinner(f"Executing Security Scan Pipeline on `{target_repo_path}`..."):
            state_res = run_scan(target_repo_path)
            DashboardSessionManager.set_current_state(st, state_res)
            st.sidebar.success("Scan Complete!")
            st.rerun()

    state = DashboardSessionManager.get_current_state(st)
    
    if state is None:
        st.markdown(
            """
            <div style="text-align: center; padding: 100px 20px;">
                <h1>🛡️ AI Code Guardian</h1>
                <p style="font-size: 1.2rem; color: #94a3b8; max-width: 600px; margin: 20px auto;">
                    Welcome to the Enterprise Security Dashboard.<br/><br/>
                    Please register or select a repository from the sidebar workspace and click <b>⚡ Run Multi-Agent Scan</b> to begin your analysis.
                </p>
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    selected_page = st.sidebar.radio("Navigation Pages", list(app.pages.keys()))

    res = app.render_page(state, page_name=selected_page)

    # Render Header Navigation and Top Metric Cards
    st.markdown(res["navbar_html"], unsafe_allow_html=True)
    st.markdown(res["metrics_html"], unsafe_allow_html=True)

    page_data = res["page_data"]
    st.title(f"🛡️ {page_data.get('page_title', selected_page)}")

    # 1. OVERVIEW PAGE
    if selected_page == "Overview":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("📋 Repository Workspace Metadata")
            st.write(f"**Path**: `{page_data.get('repo_path')}`")
            st.write(f"**Primary Language**: `{page_data.get('primary_language')}`")
            st.write(f"**Frameworks**: {', '.join(page_data.get('frameworks', [])) or 'None'}")
            st.write(f"**Entry Points**: {', '.join(page_data.get('entry_points', [])) or 'None'}")
            st.write(f"**Auth Modules**: {', '.join(page_data.get('auth_modules', [])) or 'None'}")

        with col2:
            st.subheader("🏢 Business & Security Context")
            st.write(f"**Domain**: `{page_data.get('business_domain')}`")
            st.write(f"**Criticality**: `{page_data.get('criticality')}`")
            st.write(f"**Critical Assets**: {', '.join(page_data.get('critical_assets', [])) or 'Standard Assets'}")

    # 2. KNOWLEDGE GRAPH PAGE
    elif selected_page == "Knowledge Graph":
        search_query = st.text_input("Graph Node Search Query", value="Root")
        if search_query != page_data.get("query_node"):
            res = app.render_page(state, page_name=selected_page, query_node=search_query)
            page_data = res["page_data"]

        col1, col2 = st.columns(2)
        with col1:
            st.subheader("🏛️ Architecture Nodes")
            st.dataframe(page_data.get("architecture_nodes", []))
        with col2:
            st.subheader("🔗 Traversed Graph Nodes")
            st.dataframe(page_data.get("traversed_nodes", []))

    # 3. MIND MAP PAGE
    elif selected_page == "Mind Map":
        st.write(f"Total Vulnerable Paths Identified: **{page_data.get('total_vulnerable_paths')}**")
        st.json(page_data.get("tree", {}))

    # 4. WORKFLOW TIMELINE PAGE
    elif selected_page == "Workflow Timeline":
        st.info(f"Total Agents Executed: **{page_data.get('total_agents')}** | Total Pipeline Time: **{page_data.get('total_execution_time'):.4f}s**")
        st.table(page_data.get("timeline", []))

    # 5. AGENT STUDIO PAGE
    elif selected_page == "Agent Studio":
        st.subheader("🤖 LangGraph Agent Telemetry")
        for ag in page_data.get("agents", []):
            with st.expander(f"Agent: {ag.get('agent_name').upper()} | Status: {ag.get('status')} | Time: {ag.get('execution_time'):.4f}s"):
                st.write(f"**Task**: {ag.get('current_task')}")
                st.write(f"**Tools Used**: {ag.get('tools_used')}")
                st.write(f"**Evidence IDs**: {ag.get('evidence_ids')}")
                st.write(f"**Confidence**: {ag.get('confidence')}")
                st.json(ag.get("result", {}))

    # 6. AGENT TRACE PAGE
    elif selected_page == "Agent Trace":
        traces = page_data.get("traces", [])
        agent_names = [t.get("agent_name") for t in traces]
        sel_agent = st.selectbox("Select Specialist Agent", ["ALL"] + agent_names)

        filtered_traces = traces if sel_agent == "ALL" else [t for t in traces if t.get("agent_name") == sel_agent]
        for t in filtered_traces:
            with st.expander(f"🤖 Agent: {t.get('agent_name').upper()} | Time: {t.get('execution_time'):.4f}s | Confidence: {t.get('confidence')}"):
                st.write("**Result Payload**:")
                st.json(t.get("result", t.get("output", {})))
                st.write(f"**Evidence IDs**: {t.get('evidence_ids', [])}")
                st.write(f"**Tools Used**: {t.get('tools_used', [])}")

    # 7. EVIDENCE EXPLORER PAGE
    elif selected_page == "Evidence Explorer":
        search = st.text_input("Filter Evidence Store", value="")
        res = app.render_page(state, page_name=selected_page, query=search)
        items = res["page_data"].get("evidence_items", [])
        st.subheader(f"Evidence Items ({len(items)} items)")
        if items:
            st.dataframe(items)
        else:
            st.warning("No matching evidence items found in store.")

    # 8. THREAT INTELLIGENCE PAGE
    elif selected_page == "Threat Intelligence":
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Exploitability Score", f"{page_data.get('exploitability_score'):.2f}")
            st.metric("Reachability Weight", f"{page_data.get('reachability_weight'):.2f}")
        with col2:
            st.subheader("Critical Assets")
            st.write(page_data.get("critical_assets", []))

        st.subheader("Attack Paths & Exploit Chains")
        st.dataframe(page_data.get("attack_paths", []))

    # 9. RISK DASHBOARD PAGE
    elif selected_page == "Risk Dashboard":
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Composite Risk Score", f"{page_data.get('composite_risk_score'):.2f}", page_data.get("risk_level"))
            st.subheader("Dimensional Risk Breakdown")
            st.json(page_data.get("risk_breakdown", {}))
        with col2:
            st.subheader("Severity Distribution")
            st.json(page_data.get("severity_distribution", {}))
            st.subheader("Top Findings")
            st.dataframe(page_data.get("top_findings", []))

    # 10. PATCH EXPLORER PAGE
    elif selected_page == "Patch Explorer":
        patches = page_data.get("patches", [])
        if patches:
            p_ids = [p.get("patch_id") for p in patches]
            sel_patch = st.selectbox("Select Proposed Patch", p_ids)
            cur_patch = next((p for p in patches if p.get("patch_id") == sel_patch), patches[0])

            is_app = DashboardSessionManager.is_patch_approved(st, sel_patch)
            btn_label = "✅ Disapprove Patch" if is_app else "👍 Approve Patch Proposal"
            if st.button(btn_label):
                new_app = DashboardSessionManager.toggle_patch_approval(st, sel_patch)
                st.success(f"Patch {sel_patch} approval set to {new_app}")
                st.rerun()

            st.write(f"**File**: `{cur_patch.get('affected_file')}` | **Lines**: `{cur_patch.get('affected_lines')}` | **Status**: `{cur_patch.get('validation_status')}` | **Approval**: `{is_app}`")
            st.markdown(res["page_data"].get("diff_html", ""), unsafe_allow_html=True)

            with st.expander("Unified Git Diff Output"):
                st.code(cur_patch.get("git_diff", ""), language="diff")

            st.subheader("Developer Remediation Explanation")
            st.markdown(cur_patch.get("explanation", ""))
        else:
            st.success("Zero remediation patches required.")

    # 11. VALIDATION DASHBOARD PAGE
    elif selected_page == "Validation Dashboard":
        col1, col2 = st.columns(2)
        with col1:
            st.subheader(f"✅ Passed Patches ({page_data.get('passed_count')})")
            st.dataframe(page_data.get("passed_patches", []))
        with col2:
            st.subheader(f"❌ Rejected Patches ({page_data.get('rejected_count')})")
            st.dataframe(page_data.get("rejected_patches", []))

    # 12. POLICY CENTER PAGE
    elif selected_page == "Policy Center":
        st.subheader("📄 Upload Company Security Policy Document")
        policy_file = st.file_uploader("Upload Policy Pack (PDF, MD, DOCX, TXT)", type=["pdf", "md", "docx", "txt"])
        if policy_file and st.button("Ingest Policy Document"):
            res = app.render_page(state, page_name=selected_page, uploaded_file=policy_file)
            page_data = res["page_data"]
            st.success("Policy Document Ingested & Embedded Successfully!")

        st.subheader(f"Active Policy Packs ({len(page_data.get('active_policy_packs', []))})")
        st.json(page_data.get("active_policy_packs", []))
        st.subheader("Policy Violations Detected")
        st.json(page_data.get("violations", []))

    # 13. METRICS DASHBOARD PAGE
    elif selected_page == "Metrics Dashboard":
        st.subheader("⚡ Performance Observability Summary")
        st.json(page_data.get("performance_summary", {}))
        st.subheader("Agent Runtime Runtimes (seconds)")
        st.dataframe([{"Agent": k, "Runtime (s)": v} for k, v in page_data.get("agent_runtime_breakdown", {}).items()])

    # 14. EXPORT CENTER PAGE
    elif selected_page == "Export Center":
        st.subheader("📥 Export Security Artifacts")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.download_button("📄 Download SARIF Report", data=str(page_data.get("sarif_report", "")), file_name="guardian.sarif", mime="application/json")
            st.download_button("🌐 Download HTML Report", data=str(page_data.get("html_report", "")), file_name="guardian.html", mime="text/html")
        with col2:
            st.download_button("📊 Download CSV Report", data=str(page_data.get("csv_report", "")), file_name="guardian.csv", mime="text/csv")
            st.download_button("📋 Download JSON Report", data=str(page_data.get("json_report", "")), file_name="guardian.json", mime="application/json")
        with col3:
            st.download_button("🧩 Download Patch Bundle", data=str(page_data.get("patch_bundle", {})), file_name="patch_bundle.json", mime="application/json")
            st.download_button("🔍 Download Execution Trace", data=str(page_data.get("trace_bundle", {})), file_name="execution_trace.json", mime="application/json")

    # 15. INTERACTIVE ASSISTANT PAGE (STREAMING RAG)
    elif selected_page == "Interactive Assistant":
        app.pages["Interactive Assistant"].render_ui()

if __name__ in ("__main__", "streamlit.runtime.scriptrunner.script_runner"):
    main()
