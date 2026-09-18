"""
AI Finding Verifier — False-Positive Triage
===========================================
Takes deterministic findings and asks Nemotron whether each high-severity
one is exploitable in context, so a reviewer can prioritise.

This module previously imported a class that does not exist
(`LLMGuardrails`; the class is `GuardrailPipeline`), called
`create_llm(config)` with the wrong signature, and invoked
`llm.complete(prompt)` / `response.text` — neither of which is on
`BaseLLM`. It therefore raised on import and could never have run. It is
now routed through the shared reasoning service like every other
contextual consumer, which redacts secrets and enforces the context
budget on its behalf.

Triage never deletes a finding. A suppressed false positive is
confidence-demoted and annotated, so it stays in the report with the
model's reasoning attached and a human can disagree.
"""
from __future__ import annotations

import logging
from pathlib import Path

from guardian.core.models import Finding

log = logging.getLogger(__name__)

TRIAGE_SCHEMA = """Return exactly one JSON object, no prose:
{
  "findings": [
    {
      "evidence_ids": ["<the finding id you were given>"],
      "verdict": "true_positive|false_positive|needs_review",
      "confidence": 0.0-1.0,
      "reason": "<why, referring only to the code shown>",
      "recommendation": "<action>"
    }
  ]
}
Judge only the code shown. If the surrounding context needed to decide is
not present, return "needs_review" rather than guessing."""

#: A false-positive verdict must be at least this confident to demote a
#: finding. Below it, the deterministic result stands unchanged.
SUPPRESSION_THRESHOLD = 0.7


class AIFindingVerifier:
    """Contextual false-positive triage over high-severity findings."""

    def __init__(self, service=None, *, context_window: int = 10,
                 max_findings: int = 25) -> None:
        self._service = service
        self.context_window = context_window
        self.max_findings = max_findings

    # ------------------------------------------------------------------
    @property
    def service(self):
        if self._service is None:
            from guardian.reasoning.gateway import NemotronReasoningService
            self._service = NemotronReasoningService()
        return self._service

    def verify_findings(self, repo_root: Path,
                        findings: list[Finding]) -> list[Finding]:
        """Annotate high/critical findings with a triage verdict.

        Returns the same list, in the same order. Findings are mutated in
        place; none are removed.
        """
        try:
            service = self.service
        except Exception as exc:  # noqa: BLE001
            log.info("AI verification unavailable: %s", exc)
            return findings

        if not service.configured:
            log.info("NVIDIA_API_KEY not configured — skipping AI triage pass.")
            return findings

        candidates = [f for f in findings
                      if f.severity in ("High", "Critical")][: self.max_findings]
        for finding in candidates:
            try:
                self._triage(repo_root, finding, service)
            except Exception as exc:  # noqa: BLE001 — triage is best-effort
                log.debug("AI triage skipped for %s: %s", finding.rule_id, exc)
        return findings

    # ------------------------------------------------------------------
    def _triage(self, repo_root: Path, finding: Finding, service) -> None:
        from guardian.reasoning.gateway import ReasoningRequest
        from guardian.reasoning.schemas import extract_json

        snippet = self._context_window(Path(repo_root) / finding.file, finding.line)
        if not snippet:
            return

        result = service.reason(ReasoningRequest(
            task="false_positive_triage",
            instruction=(
                f"Decide whether this scanner finding is exploitable in context.\n"
                f"Rule: {finding.rule_id}\nCategory: {finding.category}\n"
                f"Severity: {finding.severity}\n"
                f"Location: {finding.file}:{finding.line}"
                + (f" in {finding.function}()" if finding.function else "")
                + (f"\nScanner reasoning: {finding.reason}" if finding.reason else "")),
            schema_instruction=TRIAGE_SCHEMA,
            evidence_block=f"FINDING ID: {finding.finding_id}\n"
                           f"Flagged line: {finding.snippet}",
            code_snippet=snippet,
            snippet_label=f"{finding.file} around line {finding.line}",
            cache_key_extra=finding.finding_id,
        ))
        if not result.available or result.response is None:
            return

        data = extract_json(result.response.raw) or {}
        claims = data.get("findings") or []
        if not claims or not isinstance(claims[0], dict):
            return

        claim = claims[0]
        verdict = str(claim.get("verdict", "")).strip().lower()
        reason = str(claim.get("reason", "")).strip()[:300]
        try:
            confidence = float(claim.get("confidence", 0.0))
        except (TypeError, ValueError):
            confidence = 0.0

        if verdict == "false_positive" and confidence >= SUPPRESSION_THRESHOLD:
            # Demote, never delete: a model disagreeing with a deterministic
            # detector is a signal for a reviewer, not a verdict.
            finding.confidence = round(min(finding.confidence, 0.3), 3)
            finding.recommendation += f"  [AI triage — likely false positive: {reason}]"
            log.info("AI triage demoted %s at %s:%d", finding.rule_id,
                     finding.file, finding.line)
        elif verdict == "true_positive" and reason:
            finding.recommendation += f"  [AI triage — confirmed exploitable: {reason}]"
        elif reason:
            finding.recommendation += f"  [AI triage — needs review: {reason}]"

    def _context_window(self, file_path: Path, line_no: int) -> str:
        try:
            lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return ""
        start = max(0, line_no - self.context_window - 1)
        end = min(len(lines), line_no + self.context_window)
        return "\n".join(lines[start:end])
