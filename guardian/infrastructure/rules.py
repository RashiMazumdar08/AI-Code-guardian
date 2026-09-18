"""
Infrastructure-as-Code rule catalog — line-oriented pattern rules over
Dockerfiles, docker-compose, Kubernetes manifests, Terraform, and CI
pipeline definitions. Deliberately simple and data-driven: each rule is
(file matcher, regex, category, severity, recommendation), so adding
coverage means adding a row, not code.
TODO(iac-roadmap): YAML/HCL structural parsing for k8s + terraform to
cut context-blind regex false positives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from pathlib import Path


@dataclass(frozen=True)
class IacRule:
    rule_id: str
    applies: Callable[[Path], bool]
    pattern: re.Pattern
    category: str
    severity: str
    recommendation: str


def _is_dockerfile(p: Path) -> bool:
    return p.name.lower() == "dockerfile" or p.name.lower().startswith("dockerfile.")


def _is_compose(p: Path) -> bool:
    return p.name.lower() in ("docker-compose.yml", "docker-compose.yaml")


def _is_k8s(p: Path) -> bool:
    return p.suffix.lower() in (".yml", ".yaml") and not _is_compose(p)


def _is_tf(p: Path) -> bool:
    return p.suffix.lower() in (".tf", ".tfvars")


def _is_ci(p: Path) -> bool:
    s = str(p).replace("\\", "/")
    return ("/.github/workflows/" in s or p.name.lower() in
            ("jenkinsfile", ".gitlab-ci.yml", "azure-pipelines.yml"))


RULES: list[IacRule] = [
    # --- Docker ---
    IacRule("IAC-DKR-001", _is_dockerfile, re.compile(r'^\s*USER\s+root\b', re.I),
            "Root Container", "High", "Run containers as a non-root user (USER app)."),
    IacRule("IAC-DKR-002", _is_dockerfile, re.compile(r'(?i)\b(ENV|ARG)\s+\w*(PASSWORD|SECRET|TOKEN|KEY)\w*\s*=?\s*\S+'),
            "Exposed Secret", "Critical", "Never bake secrets into images; use build secrets or a vault."),
    IacRule("IAC-DKR-003", _is_dockerfile, re.compile(r'^\s*FROM\s+\S+:latest\b', re.I),
            "Unpinned Base Image", "Medium", "Pin base images to a digest or explicit version tag."),
    IacRule("IAC-DKR-004", _is_dockerfile, re.compile(r'curl[^|]*\|\s*(ba)?sh', re.I),
            "Curl-Pipe-Shell", "High", "Download, verify checksum/signature, then execute."),
    # --- Compose / K8s ---
    IacRule("IAC-CMP-001", _is_compose, re.compile(r'privileged:\s*true', re.I),
            "Privileged Container", "Critical", "Remove privileged mode; grant specific capabilities instead."),
    IacRule("IAC-K8S-001", _is_k8s, re.compile(r'privileged:\s*true', re.I),
            "Privileged Container", "Critical", "Remove privileged: true from securityContext."),
    IacRule("IAC-K8S-002", _is_k8s, re.compile(r'runAsUser:\s*0\b'),
            "Root Container", "High", "Set runAsNonRoot: true and a non-zero runAsUser."),
    IacRule("IAC-K8S-003", _is_k8s, re.compile(r'hostNetwork:\s*true', re.I),
            "Host Network Access", "High", "Avoid hostNetwork; expose via Services/Ingress."),
    IacRule("IAC-K8S-004", _is_k8s, re.compile(r'allowPrivilegeEscalation:\s*true', re.I),
            "Privilege Escalation", "High", "Set allowPrivilegeEscalation: false."),
    # --- Terraform ---
    IacRule("IAC-TF-001", _is_tf, re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"'),
            "Open Security Group", "High", "Restrict ingress CIDR ranges to known networks."),
    IacRule("IAC-TF-002", _is_tf, re.compile(r'(?i)(password|secret|access_key)\s*=\s*"[^"$]{4,}"'),
            "Exposed Secret", "Critical", "Use variables + secret managers, never literals in .tf files."),
    IacRule("IAC-TF-003", _is_tf, re.compile(r'acl\s*=\s*"public-read'),
            "Public Storage Bucket", "High", "Make buckets private; serve via CDN/signed URLs."),
    # --- CI pipelines ---
    IacRule("IAC-CI-001", _is_ci, re.compile(r'(?i)(password|token|secret|api_key)\s*[:=]\s*["\']?[A-Za-z0-9_\-/+=]{8,}'),
            "Exposed Secret", "Critical", "Move credentials to the CI secret store; never inline them."),
    IacRule("IAC-CI-002", _is_ci, re.compile(r'pull_request_target', re.I),
            "Weak CI Pipeline", "High", "pull_request_target with checkout of PR code enables secret theft; review carefully."),
]
