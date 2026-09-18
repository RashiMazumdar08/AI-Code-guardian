"""
Snyk Adapter — optional dependency/SCA vulnerability scanner, complementary
to the existing offline OSV-based DependencyAnalyzer
(guardian/dependencies/analyzer.py). OFF by default; enabled via
ENABLE_SNYK=true.

Rashi's call on this one (2026-09-14): build the adapter interface so it's
a one-env-var flip away from working, but don't wire up a real Snyk
account/token from here -- that requires credentials only she can provide.
Unlike the Semgrep adapter, this one has never been run against a real
Snyk account/CLI in this session; it's built to the same degrade-gracefully
contract and unit-tested for its "unavailable" path (no CLI / no token),
but the "ok" path (real `snyk test --json` output parsing) is UNVERIFIED
against real Snyk output -- flagged honestly rather than claimed as tested.

Implements the same `Analyzer` protocol (guardian/core/interfaces.py) and
`@register_analyzer` registration as DependencyAnalyzer and
SemgrepAnalyzer (guardian/scanner/semgrep_adapter.py) -- no new adapter
framework, reuses the existing extension point.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Optional

from guardian.core.models import Finding
from guardian.core.registry import register_analyzer

log = logging.getLogger(__name__)

_SEVERITY_MAP = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
DEFAULT_TIMEOUT_SECONDS = 120


def snyk_available() -> bool:
    return shutil.which("snyk") is not None


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


@register_analyzer
class SnykAnalyzer:
    """Analyzer protocol implementation -- see module docstring. Requires
    BOTH ENABLE_SNYK=true and a SNYK_TOKEN (or a machine already
    authenticated via `snyk auth`) to actually run; missing either degrades
    to status="unavailable"/"disabled" rather than failing the scan."""

    name = "snyk"

    def __init__(self, enabled: Optional[bool] = None, timeout: Optional[int] = None) -> None:
        self.enabled = enabled if enabled is not None else _truthy(os.getenv("ENABLE_SNYK"))
        self.timeout = timeout or int(os.getenv("SNYK_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS)))
        self.status = "disabled"

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        if not self.enabled:
            self.status = "disabled"
            return []
        if not snyk_available():
            log.info("ENABLE_SNYK is set but the snyk binary is not on PATH; "
                     "skipping Snyk -- native/OSV dependency scanning is unaffected.")
            self.status = "unavailable"
            return []
        if not os.getenv("SNYK_TOKEN"):
            log.info("ENABLE_SNYK is set but SNYK_TOKEN is not configured; skipping Snyk "
                     "(set SNYK_TOKEN, or run `snyk auth` once on this machine).")
            self.status = "unavailable"
            return []

        try:
            proc = subprocess.run(
                ["snyk", "test", "--json", f"--severity-threshold=low"],
                cwd=str(repo_root), capture_output=True, text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            log.warning("snyk test timed out after %ss; continuing without it", self.timeout)
            self.status = "error"
            return []
        except Exception as exc:  # noqa: BLE001 — an optional tool must never kill the scan
            log.warning("snyk failed to run (%s); continuing without it", exc)
            self.status = "error"
            return []

        # `snyk test` exits non-zero when vulnerabilities are found (by
        # design) -- only a missing/unparseable stdout means the run itself
        # failed, not the exit code.
        if not proc.stdout:
            log.warning("snyk produced no output (exit %s); continuing without it", proc.returncode)
            self.status = "error"
            return []

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            log.warning("snyk produced unparseable output (%s); continuing without it", exc)
            self.status = "error"
            return []

        self.status = "ok"
        findings: list[Finding] = []
        for vuln in payload.get("vulnerabilities", []) or []:
            try:
                findings.append(self._to_finding(vuln))
            except Exception as exc:  # noqa: BLE001 — one malformed entry must not drop the rest
                log.debug("skipping one unparseable snyk vulnerability: %s", exc)
        return findings

    @staticmethod
    def _to_finding(vuln: dict[str, Any]) -> Finding:
        severity = _SEVERITY_MAP.get(str(vuln.get("severity", "")).lower(), "Medium")
        package = vuln.get("packageName", "") or vuln.get("name", "")
        version = vuln.get("version", "")
        manifest = (vuln.get("from") or [package])[-1] if vuln.get("from") else package
        identifiers = vuln.get("identifiers") or {}
        cve_list = identifiers.get("CVE") or []
        cve = cve_list[0] if cve_list else None
        reason = vuln.get("title", "") + (f" ({cve})" if cve else "")

        return Finding(
            category="Vulnerable Dependency",
            severity=severity,
            rule_id=vuln.get("id", "SNYK"),
            file=str(manifest),
            line=1,
            snippet=f"{package}@{version}",
            recommendation=(
                f"Upgrade to {vuln['upgradePath'][-1]}" if vuln.get("upgradePath")
                else "Upgrade to a patched version; see Snyk advisory."
            ),
            cwe=None,
            owasp=None,
            confidence=0.9,
            source="DETERMINISTIC",
            reason=reason,
            engine="snyk",
        )
