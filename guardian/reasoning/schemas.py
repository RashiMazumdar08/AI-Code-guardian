"""
Structured Reasoning Schemas
============================
Nemotron never returns prose to the platform. Every reasoning task
declares a schema, and the response is parsed and validated against it
before anything downstream sees it.

Validation is implemented here with plain dataclasses rather than a
runtime schema library: the project's only hard dependency is PyYAML,
and adding a heavyweight validator for four schemas would be a poor
trade. `SchemaError` accumulates *all* problems rather than failing on
the first, so a rejected response can be logged with a complete
explanation.

Schemas
-------
`ReasoningFinding`     one contextual claim, always citing evidence IDs
`ReasoningResponse`    a list of findings plus a summary
`BusinessIntentClaim`  adds the compliance verdict and the policy it judged
`QuantumContextClaim`  adds migration urgency/approach for a crypto asset

The hard rule encoded here: a finding with no `evidence_ids` is invalid.
A model that cannot point at evidence has not reasoned about the code.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S | re.I)
_SMART_QUOTES = {"“": '"', "”": '"', "‘": "'", "’": "'"}

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


class ComplianceVerdict(str, Enum):
    COMPLIANT = "COMPLIANT"
    VIOLATION = "VIOLATION"
    POTENTIAL_VIOLATION = "POTENTIAL_VIOLATION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class MigrationUrgency(str, Enum):
    IMMEDIATE = "IMMEDIATE"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_REQUIRED = "NOT_REQUIRED"


class SchemaError(Exception):
    """Raised when a response cannot be coerced into its declared schema."""

    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


# ---------------------------------------------------------------------------
# Core schema
# ---------------------------------------------------------------------------
@dataclass
class ReasoningFinding:
    """One contextual claim from the model."""

    evidence_ids: list[str] = field(default_factory=list)
    category: str = ""
    severity: str = "Info"
    confidence: float = 0.0
    reason: str = ""
    recommendation: str = ""

    title: str = ""
    file: str = ""
    line: int = 0
    function: str = ""

    # task-specific extensions, validated by the subclass schemas below
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "evidence_ids": self.evidence_ids,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "function": self.function,
            **self.extras,
        }


@dataclass
class ReasoningResponse:
    """A parsed, schema-valid model response."""

    findings: list[ReasoningFinding] = field(default_factory=list)
    summary: str = ""
    task: str = ""
    model: str = ""
    raw: str = ""
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict:
        return {
            "task": self.task,
            "model": self.model,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "problems": self.problems,
        }


# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------
def extract_json(text: str) -> Optional[dict]:
    """Pull the first JSON object out of a model response.

    Tolerates markdown fences, smart quotes and trailing commas — those are
    transport noise, not schema drift. Does NOT tolerate missing or
    misnamed fields; that is the validator's job and it must stay strict.
    """
    if not text or not text.strip():
        return None

    candidates = [text.strip()]
    candidates.extend(m.group(1).strip() for m in _FENCE.finditer(text))
    balanced = _balanced_object(text)
    if balanced:
        candidates.append(balanced)

    for candidate in candidates:
        for attempt in (candidate, _repair(candidate)):
            try:
                parsed = json.loads(attempt)
            except (TypeError, ValueError):
                continue
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list):
                return {"findings": parsed}
    return None


def _balanced_object(text: str) -> Optional[str]:
    start = text.find("{")
    if start == -1:
        return None
    depth, in_string, escaped = 0, False, False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    return None


def _repair(text: str) -> str:
    for bad, good in _SMART_QUOTES.items():
        text = text.replace(bad, good)
    text = re.sub(r",\s*([}\]])", r"\1", text)      # trailing commas
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)  # line comments
    return text


# ---------------------------------------------------------------------------
# Coercion helpers
# ---------------------------------------------------------------------------
def _as_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    return str(value)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _as_confidence(value: Any) -> float:
    """Accept 0-1 floats, 0-100 percentages, and High/Medium/Low words."""
    if value is None:
        return 0.0
    if isinstance(value, bool):
        return 1.0 if value else 0.0
    if isinstance(value, (int, float)):
        numeric = float(value)
        return round(min(1.0, numeric / 100.0), 3) if numeric > 1.0 else round(max(0.0, numeric), 3)
    words = {"very high": 0.95, "high": 0.85, "medium": 0.6, "moderate": 0.6,
             "low": 0.3, "very low": 0.15, "none": 0.0}
    text = str(value).strip().lower()
    if text in words:
        return words[text]
    match = re.search(r"(\d+(?:\.\d+)?)", text)
    if not match:
        return 0.0
    numeric = float(match.group(1))
    return round(min(1.0, numeric / 100.0), 3) if numeric > 1.0 else round(numeric, 3)


def _as_severity(value: Any) -> str:
    text = _as_string(value).title()
    return {"Informational": "Info", "Warning": "Medium", "Error": "High",
            "Crit": "Critical", "": "Info"}.get(text, text)


def _as_id_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        # "E1, E2" or "E1"
        return [part.strip() for part in re.split(r"[,\s]+", value) if part.strip()]
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [str(value).strip()]


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def parse_reasoning_response(text: str, *, task: str = "", model: str = "",
                             require_evidence: bool = True,
                             extra_fields: tuple[str, ...] = ()) -> ReasoningResponse:
    """Parse and validate a model response. Never raises.

    Problems are collected on the response rather than thrown so the
    caller can log a complete rejection reason and fall back to
    deterministic results.
    """
    data = extract_json(text)
    if data is None:
        return ReasoningResponse(
            task=task, model=model, raw=text or "",
            problems=["response contained no JSON object"])

    problems: list[str] = []
    raw_findings = data.get("findings")
    if isinstance(raw_findings, dict):
        raw_findings = [raw_findings]
    if raw_findings is None:
        raw_findings = []
        problems.append("missing required field 'findings'")
    elif not isinstance(raw_findings, list):
        problems.append("'findings' must be an array")
        raw_findings = []

    findings: list[ReasoningFinding] = []
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            problems.append(f"findings[{index}] is not an object")
            continue
        finding, item_problems = _parse_finding(item, index, require_evidence,
                                                extra_fields)
        problems.extend(item_problems)
        if finding is not None:
            findings.append(finding)

    return ReasoningResponse(
        findings=findings,
        summary=_as_string(data.get("summary")),
        task=task, model=model, raw=text or "", problems=problems)


def _parse_finding(item: dict, index: int, require_evidence: bool,
                   extra_fields: tuple[str, ...]) -> tuple[Optional[ReasoningFinding], list[str]]:
    problems: list[str] = []

    evidence_ids = _as_id_list(item.get("evidence_ids") or item.get("evidence"))
    if require_evidence and not evidence_ids:
        # This is the load-bearing rule of the whole AI layer: a claim
        # that cites nothing cannot be checked, so it is not admitted.
        problems.append(f"findings[{index}] cites no evidence_ids")
        return None, problems

    severity = _as_severity(item.get("severity"))
    if severity not in VALID_SEVERITIES:
        problems.append(f"findings[{index}].severity invalid: {severity!r}")
        severity = "Info"

    confidence = _as_confidence(item.get("confidence"))
    if not 0.0 <= confidence <= 1.0:
        problems.append(f"findings[{index}].confidence out of range: {confidence}")
        confidence = 0.0

    reason = _as_string(item.get("reason") or item.get("explanation"))
    if not reason:
        problems.append(f"findings[{index}] has no reason/explanation")

    extras = {name: item.get(name) for name in extra_fields if name in item}

    finding = ReasoningFinding(
        evidence_ids=evidence_ids,
        category=_as_string(item.get("category")),
        severity=severity,
        confidence=confidence,
        reason=reason,
        recommendation=_as_string(item.get("recommendation")),
        title=_as_string(item.get("title")),
        file=_as_string(item.get("file")),
        line=_as_int(item.get("line")),
        function=_as_string(item.get("function") or item.get("affected_function")),
        extras=extras,
    )
    return finding, problems


# -- task-specific wrappers -------------------------------------------------
BUSINESS_INTENT_FIELDS = ("verdict", "policy_id", "requirement", "affected_component",
                          "missing_control")
QUANTUM_CONTEXT_FIELDS = ("purpose", "migration_urgency", "migration_approach",
                          "affected_component", "business_impact",
                          "recommended_pqc_algorithm")


def parse_business_intent_response(text: str, *, model: str = "") -> ReasoningResponse:
    """Parse a business-intent comparison. Normalises the verdict enum and
    downgrades any verdict the model spelled in a way we do not recognise."""
    response = parse_reasoning_response(
        text, task="business_intent", model=model, require_evidence=True,
        extra_fields=BUSINESS_INTENT_FIELDS)

    for index, finding in enumerate(response.findings):
        raw_verdict = _as_string(finding.extras.get("verdict")).upper().replace(" ", "_")
        try:
            verdict = ComplianceVerdict(raw_verdict)
        except ValueError:
            response.problems.append(
                f"findings[{index}].verdict invalid: {raw_verdict!r}; "
                f"downgraded to INSUFFICIENT_EVIDENCE")
            verdict = ComplianceVerdict.INSUFFICIENT_EVIDENCE
        finding.extras["verdict"] = verdict.value
    return response


def parse_quantum_context_response(text: str, *, model: str = "") -> ReasoningResponse:
    """Parse a quantum contextual assessment, normalising migration urgency."""
    response = parse_reasoning_response(
        text, task="quantum_readiness", model=model, require_evidence=True,
        extra_fields=QUANTUM_CONTEXT_FIELDS)

    for index, finding in enumerate(response.findings):
        raw = _as_string(finding.extras.get("migration_urgency")).upper().replace(" ", "_")
        if not raw:
            continue
        try:
            urgency = MigrationUrgency(raw)
        except ValueError:
            response.problems.append(
                f"findings[{index}].migration_urgency invalid: {raw!r}")
            urgency = MigrationUrgency.MEDIUM
        finding.extras["migration_urgency"] = urgency.value
    return response


# ---------------------------------------------------------------------------
# Prompt-side schema descriptions
# ---------------------------------------------------------------------------
BASE_SCHEMA_INSTRUCTION = """Return exactly one JSON object, no prose, no markdown fences:
{
  "summary": "<one sentence>",
  "findings": [
    {
      "evidence_ids": ["E1"],
      "category": "<category>",
      "severity": "Critical|High|Medium|Low|Info",
      "confidence": 0.0-1.0,
      "reason": "<why, referring only to the supplied evidence>",
      "recommendation": "<concrete action>",
      "file": "<file from the evidence>",
      "line": <line from the evidence>,
      "function": "<function from the evidence>"
    }
  ]
}
Rules:
- Every finding MUST cite at least one evidence_id from the EVIDENCE list.
- Never invent evidence IDs, files, functions, line numbers or algorithms.
- If the evidence does not support a claim, return an empty findings array."""

BUSINESS_INTENT_SCHEMA_INSTRUCTION = BASE_SCHEMA_INSTRUCTION.replace(
    '"category": "<category>",',
    '"category": "business_intent",\n      '
    '"verdict": "COMPLIANT|VIOLATION|POTENTIAL_VIOLATION|INSUFFICIENT_EVIDENCE",\n      '
    '"policy_id": "<policy id from the POLICIES list>",\n      '
    '"missing_control": "<control the code does not implement, or \\"\\">",')

QUANTUM_SCHEMA_INSTRUCTION = BASE_SCHEMA_INSTRUCTION.replace(
    '"category": "<category>",',
    '"category": "quantum_readiness",\n      '
    '"purpose": "<what this crypto operation protects>",\n      '
    '"migration_urgency": "IMMEDIATE|HIGH|MEDIUM|LOW|NOT_REQUIRED",\n      '
    '"migration_approach": "<how to migrate this specific call site>",\n      '
    '"recommended_pqc_algorithm": "<NIST PQC algorithm>",\n      '
    '"affected_component": "<component name>",')
