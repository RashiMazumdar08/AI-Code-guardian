"""
AI Code Guardian v3 — Dependency Agent
======================================
Specialist agent wrapping DependencyAnalyzer to parse manifests, collect library
inventories, detect unpinned packages, and flag known CVEs, enhanced with
Groq AI contextual analysis for vulnerable dependencies.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import DependencyContext
from guardian.orchestrator.state import AgentWorkflowState


class DependencyAgent(BaseAgent):
    """Specialist agent parsing dependencies, manifest files, and providing AI supply-chain analysis."""

    name: str = "dependency"
    description: str = "Parses dependency manifests, tracks package versions, flags CVE vulnerabilities, and provides AI contextual analysis."

    def _find_package_usage(self, repo_path: Path, pkg_name: str) -> List[str]:
        """Search repository files for code evidence referencing a package."""
        if not repo_path.exists() or not pkg_name or not pkg_name.strip():
            return []
        clean_name = pkg_name.strip().lower().replace("-", "_")
        pkg_lower = pkg_name.strip().lower()
        snippets: List[str] = []

        valid_exts = {".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".cs", ".rb", ".php", ".rs", ".kt"}

        try:
            for file_path in repo_path.rglob("*"):
                if file_path.is_file() and file_path.suffix.lower() in valid_exts:
                    path_parts = [p.lower() for p in file_path.parts]
                    if any(ignored in path_parts for ignored in ("node_modules", ".venv", "venv", "dist", "build", ".git", "__pycache__")):
                        continue
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        content_lower = content.lower()
                        if clean_name in content_lower or pkg_lower in content_lower:
                            for line_no, line in enumerate(content.splitlines(), start=1):
                                l_lower = line.lower()
                                if clean_name in l_lower or pkg_lower in l_lower:
                                    rel_path = file_path.relative_to(repo_path).as_posix()
                                    snippets.append(f"{rel_path}:{line_no} -> {line.strip()[:100]}")
                                    if len(snippets) >= 3:
                                        break
                    except Exception:
                        continue
                if len(snippets) >= 3:
                    break
        except Exception:
            pass
        return snippets

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
                        "package": getattr(f, "package", ""),
                    })

            except Exception as e:
                self.logger.warning(f"Dependency analyzer execution notice: {e}")

        # Combine newly detected dependency findings and any dependency findings already in state
        all_state_findings = list(state.get("findings", []))
        all_dep_findings = list(dep_findings)
        for sf in all_state_findings:
            if sf not in all_dep_findings:
                cat = str(sf.get("category") or "").lower()
                rule = str(sf.get("rule_id") or "").lower()
                title = str(sf.get("title") or "").lower()
                if cat == "dependency" or rule.startswith("dep-") or "cve" in rule or "vulnerable dependency" in title:
                    all_dep_findings.append(sf)

        # Optional Groq AI reasoning for contextual dependency analysis
        ai_dependency_insights: List[Dict[str, Any]] = []
        grok_status: str = "SKIPPED"
        agent_reason: str = "Dependency agent AI reasoning not invoked."

        try:
            from guardian.llm.config import LLMConfig
            from guardian.llm.rate_limit_handler import classify_llm_error
            cfg = LLMConfig.from_env(agent="dependency")

            if cfg.is_agent_enabled("dependency"):
                # Gating logic:
                # - No vulnerability -> no LLM
                # - LOW/INFO -> deterministic only by default
                # - MEDIUM -> LLM only when useful code context exists
                # - HIGH/CRITICAL -> eligible for LLM analysis
                vulnerable_findings = [
                    f for f in all_dep_findings
                    if str(f.get("severity") or "").upper() in ("MEDIUM", "HIGH", "CRITICAL")
                ]

                eligible_findings: List[Dict[str, Any]] = []
                code_usage_map: Dict[str, List[str]] = {}

                for f in vulnerable_findings:
                    sev = str(f.get("severity") or "").upper()
                    pkg_name = f.get("package") or f.get("title") or ""
                    # Normalize pkg_name if title contains "Vulnerable Dependency: <pkg>"
                    if "vulnerable dependency:" in pkg_name.lower():
                        parts = pkg_name.split(":", 1)
                        if len(parts) > 1:
                            pkg_name = parts[1].split("(")[0].strip()

                    usage_snippets = self._find_package_usage(repo_path, pkg_name)
                    if usage_snippets:
                        code_usage_map[pkg_name] = usage_snippets

                    if sev in ("HIGH", "CRITICAL"):
                        eligible_findings.append(f)
                    elif sev == "MEDIUM" and usage_snippets:
                        eligible_findings.append(f)

                if eligible_findings:
                    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
                    service = ReasoningGateway(config=cfg)
                    if service.configured:
                        dep_ev_items: List[str] = []
                        for idx, f in enumerate(eligible_findings, start=1):
                            pkg_name = f.get("package") or f.get("title") or ""
                            rule_id = f.get("rule_id", "DEP-001")
                            sev = f.get("severity", "LOW")
                            file_path = f.get("file_path", "")
                            desc = f.get("description", "")
                            usage_info = code_usage_map.get(pkg_name, [])
                            usage_str = "; ".join(usage_info) if usage_info else "NONE_DETECTED"

                            dep_ev_items.append(
                                f"[E{idx}] Package: {pkg_name} | Vulnerability ID: {rule_id} | Severity: {sev} | "
                                f"Manifest: {file_path} | Description: {desc} | Repository Code Usage: {usage_str}"
                            )

                        req = ReasoningRequest(
                            task="dependency_reasoning",
                            agent="dependency",
                            scan_id=state.get("scan_id", ""),
                            instruction=(
                                "Analyze the supplied vulnerable dependency evidence for this repository. "
                                "Evaluate application security impact, usage relevance (RELEVANT, POTENTIALLY_RELEVANT, or INSUFFICIENT_EVIDENCE), "
                                "and practical remediation guidance. Do NOT invent repository usage or override CVE IDs/severity. "
                                "If Repository Code Usage is NONE_DETECTED, set relevance to INSUFFICIENT_EVIDENCE."
                            ),
                            evidence_block="\n".join(dep_ev_items),
                            max_tokens=600,
                            reasoning_effort="low",
                        )
                        ai_res = service.reason(req)
                        if ai_res.ok:
                            grok_status = "COMPLETED"
                            agent_reason = "DependencyAgent AI analysis executed successfully."
                            if ai_res.findings:
                                for rf in ai_res.findings:
                                    d = rf.to_dict()
                                    pkg = d.get("package") or ""
                                    vuln_id = d.get("vulnerability_id") or ""

                                    # Match with original deterministic finding to enforce exact rule_id & severity
                                    matched_f = next(
                                        (ef for ef in eligible_findings if ef.get("rule_id") == vuln_id or (pkg and pkg.lower() in str(ef.get("title") or "").lower())),
                                        None
                                    )
                                    if matched_f:
                                        d["vulnerability_id"] = matched_f.get("rule_id", vuln_id)
                                        d["severity"] = matched_f.get("severity", d.get("severity"))
                                        if not d.get("package"):
                                            d["package"] = matched_f.get("package") or matched_f.get("title")

                                    # Enforce INSUFFICIENT_EVIDENCE when no code usage evidence exists
                                    current_pkg = d.get("package") or pkg
                                    if not code_usage_map.get(current_pkg):
                                        d["relevance"] = "INSUFFICIENT_EVIDENCE"

                                    stable_basis = f"{current_pkg}|{d.get('vulnerability_id', '')}|{d.get('analysis', '')}|{d.get('relevance', '')}"
                                    stable_hash = hashlib.md5(stable_basis.encode("utf-8", errors="ignore")).hexdigest()[:12]
                                    d["id"] = f"DEP-INSIGHT-{stable_hash}"
                                    d["insight_id"] = d["id"]
                                    ai_dependency_insights.append(d)
                                self.logger.info("Grok AI dependency reasoning produced %d insight(s)", len(ai_dependency_insights))
                        else:
                            err_text = getattr(ai_res, "error", None) or getattr(ai_res, "error_message", None) or ""
                            status_type = classify_llm_error(err_text)
                            if status_type == "SKIPPED_BUDGET":
                                grok_status = "SKIPPED_BUDGET"
                                agent_reason = "AI Dependency Analysis was skipped to preserve token budget for other scan priorities. Deterministic results are unaffected."
                            elif status_type == "PROVIDER_DAILY_QUOTA":
                                grok_status = "PROVIDER_DAILY_QUOTA"
                                agent_reason = "AI reasoning could not run because the LLM provider's daily token quota (TPD) was exhausted. Deterministic dependency scan is fully preserved."
                            elif status_type == "RATE_LIMITED":
                                grok_status = "RATE_LIMITED"
                                agent_reason = "AI Dependency Analysis is rate-limited by the provider (TPM limit). Deterministic dependency scan is fully preserved."
                            else:
                                grok_status = "PROVIDER_UNAVAILABLE"
                                agent_reason = err_text or "AI Dependency Analysis service is temporarily unavailable."
                    else:
                        grok_status = "SKIPPED"
                        agent_reason = "Reasoning service not configured."
                else:
                    grok_status = "SKIPPED"
                    agent_reason = "No eligible HIGH/CRITICAL or contextual MEDIUM vulnerable dependencies found."
            else:
                grok_status = "SKIPPED"
                agent_reason = "AI Dependency Agent reasoning is disabled."
        except Exception as exc:
            self.logger.warning("Optional Grok AI dependency reasoning notice: %s", exc)
            status_type = classify_llm_error(exc)
            grok_status = status_type if status_type in ("PROVIDER_DAILY_QUOTA", "RATE_LIMITED", "SKIPPED_BUDGET") else "PROVIDER_UNAVAILABLE"
            agent_reason = f"AI Dependency Analysis notice: {exc}"

        # Append findings to master findings list
        findings = list(state.get("findings", []))
        findings.extend(dep_findings)

        dep_context: DependencyContext = {
            "total_dependencies": len(detected_libraries),
            "direct_dependencies_count": len(detected_libraries),
            "transitive_dependencies_count": 0,
            "vulnerable_dependencies_count": len(all_dep_findings),
            "manifest_files": manifests,
            "detected_libraries": detected_libraries,
            "cve_list": [f.get("rule_id", "") for f in all_dep_findings if "CVE" in f.get("rule_id", "")],
            "grok_status": grok_status,
            "agent_reason": agent_reason,
        }

        new_state = dict(state)
        new_state["findings"] = findings
        new_state["dependency_context"] = dict(dep_context)
        if ai_dependency_insights:
            new_state["ai_dependency_insights"] = ai_dependency_insights
        return new_state
