"""
AI Code Guardian v3 — Dependency Agent
======================================
Specialist agent wrapping DependencyAnalyzer to parse manifests, collect library
inventories, detect unpinned packages, and flag known CVEs.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import DependencyContext
from guardian.orchestrator.state import AgentWorkflowState


class DependencyAgent(BaseAgent):
    """Specialist agent parsing dependencies and manifest files."""

    name: str = "dependency"
    description: str = "Parses dependency manifests, tracks package versions, and flags CVE vulnerabilities."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["parser_tool", "evidence_tool"]

        profile = state.get("repository_profile", {})
        repo_path_str = profile.get("repo_path") or "."
        manifests = profile.get("manifest_files", [])

        detected_libraries: List[Dict[str, Any]] = []
        dep_findings: List[Dict[str, Any]] = []

        repo_path = Path(repo_path_str)
        if repo_path.exists():
            try:
                from guardian.dependencies.analyzer import DependencyAnalyzer
                # OSV vulnerability lookup is enabled by default (see
                # DependencyAnalyzer's default); a prior override here
                # silently disabled real CVE checking for this agent path.
                analyzer = DependencyAnalyzer(enable_osv=True)

                manifest_paths = [repo_path / m for m in manifests if (repo_path / m).exists()]
                deps = analyzer.collect(manifest_paths)

                for d in deps:
                    detected_libraries.append({
                        "name": getattr(d, "name", ""),
                        "version": getattr(d, "version", "unpinned"),
                        "ecosystem": getattr(d, "ecosystem", ""),
                        "manifest": getattr(d, "manifest", ""),
                    })

                raw_findings = analyzer.analyze(repo_path, manifest_paths)
                for f in raw_findings:
                    dep_findings.append({
                        "finding_id": f"dep-{len(dep_findings)+1}",
                        "rule_id": getattr(f, "rule_id", "DEP-001"),
                        "title": getattr(f, "category", "Dependency Vulnerability"),
                        "severity": str(getattr(f, "severity", "LOW")).upper(),
                        "category": "dependency",
                        "file_path": getattr(f, "file", ""),
                        "line_number": getattr(f, "line", 1),
                        "snippet": getattr(f, "snippet", ""),
                        "description": getattr(f, "recommendation", ""),
                        "confidence": 0.90,
                    })

            except Exception as e:
                self.logger.warning(f"Dependency analyzer execution notice: {e}")

        # Append findings to master findings list
        findings = list(state.get("findings", []))
        findings.extend(dep_findings)

        dep_context: DependencyContext = {
            "total_dependencies": len(detected_libraries),
            "direct_dependencies_count": len(detected_libraries),
            "transitive_dependencies_count": 0,
            "vulnerable_dependencies_count": len(dep_findings),
            "manifest_files": manifests,
            "detected_libraries": detected_libraries,
            "cve_list": [f.get("rule_id", "") for f in dep_findings if "CVE" in f.get("rule_id", "")],
        }

        new_state = dict(state)
        new_state["findings"] = findings
        new_state["dependency_context"] = dict(dep_context)
        return new_state
