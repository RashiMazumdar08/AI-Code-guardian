"""
Semgrep Adapter — optional pattern-based SAST, complementary to the native
UST/Tree-sitter engine (guardian/engines/security.py). OFF by default;
enabled via ENABLE_SEMGREP=true (or ENABLE_SEMGREP=1/yes).

Deliberately implements the EXISTING `Analyzer` protocol
(guardian/core/interfaces.py) and registers via the EXISTING
`@register_analyzer` decorator (guardian/core/registry.py) -- the same
extension point `DependencyAnalyzer` (guardian/dependencies/analyzer.py)
and the infrastructure analyzer already use. guardian/core/pipeline.py's
`_run_legacy_analyzers()` already iterates `self.registry.analyzers.items()`
and calls `.analyze(repo_root, files)` on each, publishing results into the
shared evidence store and merging findings -- so this file plugs in with
ZERO changes needed to the orchestration loop itself. No new adapter
framework, no duplicate scanner system.

Runs the real `semgrep` CLI (pip-installable, no account or API key needed
for its default open-source rulesets like p/security-audit) as a
subprocess and normalizes its JSON output into the platform's existing
Finding model (guardian/core/models.py).

Failure policy, per the "optional tools must fail independently" rule:
  - ENABLE_SEMGREP unset/false            -> status="disabled", [] findings
  - `semgrep` binary not on PATH          -> status="unavailable", [] findings
  - scan times out / crashes / bad output -> status="error", [] findings
  - never raises; never fails the deterministic scan either way.
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

#: semgrep's own severity vocabulary -> this platform's Severity values.
_SEVERITY_MAP = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}

#: Default, no-account-needed ruleset covering the categories the spec asks
#: for: injection, insecure APIs, XSS, command injection, framework-specific
#: issues, dangerous patterns. Overridable via SEMGREP_CONFIG.
DEFAULT_CONFIG = "p/security-audit"

#: Hard cap so a huge repo can't turn this into a multi-minute scan.
DEFAULT_TIMEOUT_SECONDS = 120


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


@register_analyzer
class SemgrepAnalyzer:
    """Analyzer protocol implementation -- see module docstring."""

    name = "semgrep"

    def __init__(self, enabled: Optional[bool] = None,
                 config: Optional[str] = None,
                 timeout: Optional[int] = None) -> None:
        self.enabled = enabled if enabled is not None else _truthy(os.getenv("ENABLE_SEMGREP"))
        self.config = config or os.getenv("SEMGREP_CONFIG", DEFAULT_CONFIG)
        self.timeout = timeout or int(os.getenv("SEMGREP_TIMEOUT", str(DEFAULT_TIMEOUT_SECONDS)))
        # Surfaced in report["optional_scanners"]["semgrep"] (see
        # guardian/core/pipeline.py) -- not part of the existing
        # analyzer_stats int-count contract, so adding it can't break any
        # existing consumer of that dict.
        self.status = "disabled"

    def analyze(self, repo_root: Path, files: Iterable[Path]) -> list[Finding]:
        if not self.enabled:
            self.status = "disabled"
            return []
        if not semgrep_available():
            log.info("ENABLE_SEMGREP is set but the semgrep binary is not on PATH; "
                     "skipping Semgrep -- native deterministic scanning is unaffected.")
            self.status = "unavailable"
            return []

        try:
            proc = subprocess.run(
                ["semgrep", "scan", "--config", self.config, "--json", "--quiet",
                 "--metrics=off", "--disable-version-check",
                 # Without --disable-version-check, semgrep hangs AFTER
                 # writing its JSON output while it tries to phone home to
                 # check for a newer version -- harmless with normal
                 # internet access (a few seconds), but on a machine with
                 # restricted/no egress to semgrep.dev this can hang past
                 # any --timeout given to semgrep itself (that flag only
                 # bounds the scan phase, not the exit-time check), and
                 # was only caught here by subprocess.run's OWN timeout
                 # below, which discards any output already produced.
                 "--timeout", str(self.timeout), str(repo_root)],
                capture_output=True, text=True, timeout=self.timeout + 15,
            )
        except subprocess.TimeoutExpired:
            log.warning("semgrep scan timed out after %ss; continuing without it", self.timeout)
            self.status = "error"
            return []
        except Exception as exc:  # noqa: BLE001 — an optional tool must never kill the scan
            log.warning("semgrep failed to run (%s); continuing without it", exc)
            self.status = "error"
            return []

        if not proc.stdout:
            # semgrep exits 1 when it found results with --error unset in some
            # versions; treat "ran, no stdout" as an error only when combined
            # with a genuinely bad returncode, not the normal "zero results".
            self.status = "ok" if proc.returncode in (0, 1) else "error"
            return []

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            log.warning("semgrep produced unparseable output (%s); continuing without it", exc)
            self.status = "error"
            return []

        self.status = "ok"
        findings: list[Finding] = []
        for result in payload.get("results", []) or []:
            try:
                findings.append(self._to_finding(result, repo_root))
            except Exception as exc:  # noqa: BLE001 — one malformed result must not drop the rest
                log.debug("skipping one unparseable semgrep result: %s", exc)
        for err in payload.get("errors", []) or []:
            log.debug("semgrep reported a per-rule/file error: %s", err.get("message", err))
        return findings

    @staticmethod
    def _to_finding(result: dict[str, Any], repo_root: Path) -> Finding:
        extra = result.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}
        start = result.get("start", {}) or {}
        end = result.get("end", {}) or {}
        severity = _SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "Medium")

        raw_path = result.get("path", "")
        try:
            rel_path = str(Path(raw_path).resolve().relative_to(Path(repo_root).resolve()))
        except (ValueError, OSError):
            rel_path = raw_path  # already relative in most semgrep invocations

        def _first(value: Any) -> Optional[str]:
            if isinstance(value, list):
                return str(value[0]) if value else None
            return str(value) if value else None

        technology = metadata.get("technology")
        language = _first(technology) or ""

        return Finding(
            category=metadata.get("category") or "Semgrep Finding",
            severity=severity,
            rule_id=result.get("check_id", "semgrep"),
            file=rel_path,
            line=int(start.get("line") or 1),
            end_line=int(end.get("line") or 0),
            snippet=(extra.get("lines") or "")[:500],
            recommendation=extra.get("message") or "Review the Semgrep finding.",
            cwe=_first(metadata.get("cwe")),
            owasp=_first(metadata.get("owasp")),
            confidence=0.85,
            language=language,
            source="DETERMINISTIC",
            reason=extra.get("message") or "",
            engine="semgrep",
        )
