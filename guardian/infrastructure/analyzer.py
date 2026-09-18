"""Infrastructure Analyzer — Analyzer plugin applying the IaC rule
catalog to every infrastructure file discovered by the walker."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from guardian.core.models import Finding
from guardian.core.registry import register_analyzer
from guardian.infrastructure.rules import RULES


import yaml

@register_analyzer
class InfrastructureAnalyzer:
    name = "infrastructure"

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        findings: list[Finding] = []
        for fp in files:
            applicable = [r for r in RULES if r.applies(fp)]
            if not applicable:
                continue
            try:
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            try:
                label = str(fp.relative_to(repo_root))
            except ValueError:
                label = str(fp)

            # Structural AST analysis for YAML files (Kubernetes / Docker Compose)
            if fp.suffix.lower() in (".yml", ".yaml"):
                self._analyze_yaml_ast(text, label, findings)

            # Standard line-by-line pattern application
            for lineno, line in enumerate(text.splitlines(), 1):
                for rule in applicable:
                    if rule.pattern.search(line):
                        # Avoid duplicates if structural scanner already caught it
                        if not any(f.file == label and f.rule_id == rule.rule_id and f.line == lineno for f in findings):
                            findings.append(Finding(
                                category=rule.category, severity=rule.severity,
                                rule_id=rule.rule_id, file=label, line=lineno,
                                snippet=line.strip()[:200],
                                recommendation=rule.recommendation, confidence=0.8,
                            ))
        return findings

    def _analyze_yaml_ast(self, text: str, label: str, findings: list[Finding]) -> None:
        """Parse YAML documents and inspect nested structural keys for security violations."""
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:
            return

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            # Docker Compose structural check
            services = doc.get("services", {})
            if isinstance(services, dict):
                for sname, sdef in services.items():
                    if isinstance(sdef, dict) and sdef.get("privileged") is True:
                        findings.append(Finding(
                            category="Privileged Container", severity="Critical",
                            rule_id="IAC-CMP-001", file=label, line=1,
                            snippet=f"services.{sname}.privileged: true",
                            recommendation="Remove privileged: true; grant specific capabilities instead.",
                            confidence=0.95,
                        ))

            # Kubernetes structural check
            self._check_k8s_spec(doc, label, findings)

    def _check_k8s_spec(self, doc: dict, label: str, findings: list[Finding]) -> None:
        spec = doc.get("spec", {})
        if not isinstance(spec, dict):
            return

        # Check template spec if workload (Deployment, StatefulSet, DaemonSet, Job)
        pod_spec = spec.get("template", {}).get("spec", spec) if isinstance(spec.get("template"), dict) else spec
        if not isinstance(pod_spec, dict):
            return

        if pod_spec.get("hostNetwork") is True:
            findings.append(Finding(
                category="Host Network Access", severity="High",
                rule_id="IAC-K8S-003", file=label, line=1,
                snippet="spec.hostNetwork: true",
                recommendation="Avoid hostNetwork; expose via Services/Ingress.",
                confidence=0.95,
            ))

        containers = pod_spec.get("containers", [])
        if isinstance(containers, list):
            for c in containers:
                if not isinstance(c, dict):
                    continue
                sec = c.get("securityContext", {})
                if isinstance(sec, dict):
                    if sec.get("privileged") is True:
                        findings.append(Finding(
                            category="Privileged Container", severity="Critical",
                            rule_id="IAC-K8S-001", file=label, line=1,
                            snippet=f"container {c.get('name', '')}.securityContext.privileged: true",
                            recommendation="Remove privileged: true from securityContext.",
                            confidence=0.95,
                        ))
                    if sec.get("runAsUser") == 0:
                        findings.append(Finding(
                            category="Root Container", severity="High",
                            rule_id="IAC-K8S-002", file=label, line=1,
                            snippet=f"container {c.get('name', '')}.securityContext.runAsUser: 0",
                            recommendation="Set runAsNonRoot: true and a non-zero runAsUser.",
                            confidence=0.95,
                        ))

