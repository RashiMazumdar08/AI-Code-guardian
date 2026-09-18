"""
AI Code Guardian v3 — Repository Explorer Page
==============================================
Provides an interactive VS Code-style repository file tree explorer with security finding markers.
"""
from __future__ import annotations

import html
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

import streamlit as st
from guardian.dashboard.models.dashboard_state import DashboardStateView

class RepositoryExplorerPage:
    """Renders Repository Explorer view with interactive file tree and annotated code viewer."""

    def _build_file_tree(self, repo_root: Path, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Builds a hierarchical representation of the file system annotated with vulnerabilities."""
        vuln_map = {}
        for f in findings:
            file_path = f.get("file", "").replace("\\", "/")
            if not file_path:
                continue
            if file_path not in vuln_map:
                vuln_map[file_path] = {"count": 0, "max_severity": "INFO", "findings": []}
            vuln_map[file_path]["count"] += 1
            vuln_map[file_path]["findings"].append(f)

            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            curr_sev = f.get("severity", "INFO").upper()
            max_sev = vuln_map[file_path]["max_severity"]
            if severity_order.get(curr_sev, 0) > severity_order.get(max_sev, 0):
                vuln_map[file_path]["max_severity"] = curr_sev

        def get_node(path: Path) -> Optional[Dict[str, Any]]:
            try:
                rel_path = path.relative_to(repo_root).as_posix()
            except ValueError:
                # Fallback if somehow not relative
                return None

            node = {
                "name": path.name,
                "path": rel_path,
                "type": "directory" if path.is_dir() else "file",
                "has_vulnerabilities": False,
                "vulnerability_count": 0,
                "max_severity": None,
                "findings": []
            }

            if path.is_dir():
                children = []
                dir_vuln_count = 0
                dir_max_sev = "INFO"
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

                try:
                    for child in path.iterdir():
                        if child.name in {".git", ".venv", "__pycache__", "node_modules", ".next"}:
                            continue
                        child_node = get_node(child)
                        if child_node:
                            children.append(child_node)

                            if child_node["has_vulnerabilities"]:
                                node["has_vulnerabilities"] = True
                                dir_vuln_count += child_node["vulnerability_count"]
                                if severity_order.get(child_node["max_severity"], 0) > severity_order.get(dir_max_sev, 0):
                                    dir_max_sev = child_node["max_severity"]
                except PermissionError:
                    pass

                node["children"] = sorted(children, key=lambda x: (x["type"] != "directory", x["name"].lower()))
                node["vulnerability_count"] = dir_vuln_count
                node["max_severity"] = dir_max_sev if node["has_vulnerabilities"] else None
            else:
                if rel_path in vuln_map:
                    node["has_vulnerabilities"] = True
                    node["vulnerability_count"] = vuln_map[rel_path]["count"]
                    node["max_severity"] = vuln_map[rel_path]["max_severity"]
                    node["findings"] = vuln_map[rel_path]["findings"]

            return node

        root_node = get_node(repo_root)
        if root_node:
            root_node["name"] = repo_root.name or "workspace"
        return root_node or {"name": "workspace", "path": "", "type": "directory", "children": []}

    def _render_tree_node(self, node: Dict[str, Any], depth: int = 0):
        """Recursively renders the file tree UI using Streamlit layout."""
        if node["type"] == "directory":
            icon = "📂"
            badge = f" ({node['vulnerability_count']})" if node.get("has_vulnerabilities") else ""
            title = f"{icon} {node['name']}{badge}"
            
            expanded = depth == 0 or node.get("has_vulnerabilities", False)
            
            with st.expander(title, expanded=expanded):
                for child in node.get("children", []):
                    self._render_tree_node(child, depth + 1)
        else:
            icon = "📄"
            sev = node.get("max_severity")
            sev_icon = ""
            if sev == "CRITICAL": sev_icon = "🔴 "
            elif sev == "HIGH": sev_icon = "🟠 "
            elif sev == "MEDIUM": sev_icon = "🟡 "
            elif sev == "LOW" or sev == "INFO": sev_icon = "🔵 "
            
            label = f"{sev_icon}{icon} {node['name']}"
            if st.button(label, key=f"file_btn_{node['path']}", use_container_width=True):
                st.session_state["explorer_selected_file"] = node["path"]
                st.session_state["explorer_selected_findings"] = node.get("findings", [])

    def render(self, state_view: DashboardStateView) -> Dict[str, Any]:
        st.markdown(
            """
            <style>
            .finding-card {
                background-color: #262730;
                border-left: 4px solid #ff4b4b;
                padding: 10px;
                border-radius: 4px;
                margin-bottom: 10px;
                color: #fafafa;
                font-family: monospace;
            }
            .finding-title { font-weight: bold; font-size: 1.1em; margin-bottom: 5px; }
            .finding-meta { font-size: 0.9em; color: #a3a8b8; margin-bottom: 5px; }
            .finding-desc { margin-top: 5px; font-size: 0.95em; }
            </style>
            """,
            unsafe_allow_html=True
        )

        repo_path_str = state_view.repository_profile.get("repo_path")
        if not repo_path_str or not os.path.exists(repo_path_str):
            st.error(f"Repository path `{repo_path_str}` not found or inaccessible.")
            return {"page_title": "Repository Explorer"}

        repo_root = Path(repo_path_str)
        tree = self._build_file_tree(repo_root, state_view.findings)

        col1, col2 = st.columns([1, 2])

        with col1:
            st.subheader("📁 File Explorer")
            self._render_tree_node(tree)

        with col2:
            st.subheader("📝 Code Viewer")
            selected_file = st.session_state.get("explorer_selected_file")
            selected_findings = st.session_state.get("explorer_selected_findings", [])

            if not selected_file:
                st.info("Select a file from the explorer pane to view its contents.")
            else:
                st.markdown(f"**Viewing:** `{selected_file}`")
                
                full_path = repo_root / selected_file
                if not full_path.exists() or not full_path.is_file():
                    st.error(f"File cannot be read: `{selected_file}`")
                else:
                    try:
                        content = full_path.read_text(encoding="utf-8", errors="replace")
                        
                        ext = full_path.suffix.lstrip('.')
                        if not ext: ext = "text"
                        st.code(content, language=ext, line_numbers=True)

                        if selected_findings:
                            st.markdown("### 🚨 Security Findings")
                            for finding in sorted(selected_findings, key=lambda x: x.get("line", 0)):
                                sev = finding.get("severity", "UNKNOWN").upper()
                                color = "#ff4b4b" if sev in ("CRITICAL", "HIGH") else "#ffa421" if sev == "MEDIUM" else "#21c354"
                                
                                st.markdown(
                                    f"""
                                    <div class="finding-card" style="border-left-color: {color};">
                                        <div class="finding-title">Line {finding.get('line', 'N/A')}: {html.escape(finding.get('category', 'Vulnerability'))}</div>
                                        <div class="finding-meta">Severity: {sev} | Rule: {html.escape(finding.get('rule_id', 'N/A'))}</div>
                                        <div class="finding-desc">{html.escape(finding.get('description', finding.get('reason', '')))}</div>
                                        <div class="finding-desc"><i>Evidence ID: {html.escape(', '.join(finding.get('evidence_ids', [])))}</i></div>
                                    </div>
                                    """,
                                    unsafe_allow_html=True
                                )
                        else:
                            st.success("No security findings in this file. 🎉")

                    except Exception as e:
                        st.error(f"Error reading file contents: {e}")

        return {"page_title": "Repository Explorer"}
