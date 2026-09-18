"""
LLM Layer -- Strict Nemotron Response Parser
============================================
Decodes the JSON object required by Section 11 of
``guardian/llm/prompts/security_reviewer.md``.

The parser accepts minor transport formatting mistakes, such as wrapping
the JSON object in a markdown code fence, but it does not silently accept
schema drift. Missing required fields, invalid enum values, or malformed
finding objects are reported through ``parse_failed`` and ``parse_error``.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

log = logging.getLogger(__name__)

_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.S | re.I)
_ANY_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.S | re.I)
_SMART = {"\u201c": '"', "\u201d": '"', "\u2018": "'", "\u2019": "'"}

_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_POSTURES = {"Secure", "Acceptable", "At Risk", "Critical"}
_STATUSES = {"confirmed", "false_positive", "needs_manual_review"}
_FINDING_CONFIDENCE = {"High", "Medium", "Low"}

_REQUIRED_TOP_LEVEL = {
    "summary", "overall_posture", "severity", "confidence", "findings",
    "executive_summary", "business_impact", "technical_explanation",
    "recommendation", "secure_code", "owasp", "nist", "rmf", "cwe",
}
_REQUIRED_EXECUTIVE = {
    "posture_statement", "counts_by_severity", "highest_priority_risks",
    "immediate_remediation_priorities", "assumptions", "missing_context",
}
_REQUIRED_COUNTS = {"Critical", "High", "Medium", "Low", "Info"}
_REQUIRED_FINDING = {
    "finding_id", "rule_id", "title", "status", "severity", "confidence",
    "category", "cwe", "owasp", "nist", "file", "line_start", "line_end",
    "vulnerable_snippet", "technical_explanation", "source_to_sink",
    "attack_preconditions", "exploitation_scenario", "security_impact",
    "business_impact", "evidence", "reasoning", "remediation", "secure_code",
    "residual_risk", "verification", "assumptions",
}


@dataclass
class SecurityAnalysis:
    """Structured security-review result matching Section 11."""

    summary: str = ""
    overall_posture: str = ""
    severity: str = "Info"
    confidence: float = 0.0
    findings: list[dict] = field(default_factory=list)
    executive_summary: dict = field(default_factory=dict)
    business_impact: str = ""
    technical_explanation: str = ""
    recommendation: str = ""
    secure_code: str = ""
    owasp: str = ""
    nist: str = ""
    rmf: str = ""
    cwe: str = ""

    parse_failed: bool = False
    parse_error: str = ""
    raw_response: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def is_usable(self) -> bool:
        return not self.parse_failed and bool(self.summary or self.findings)


class ResponseParser:
    """Parse, normalize, and validate Nemotron's strict JSON response."""

    def parse(self, text: str) -> SecurityAnalysis:
        if not text or not text.strip():
            return SecurityAnalysis(parse_failed=True, parse_error="empty response",
                                    raw_response=text or "")

        cleaned = strip_json_markdown(text)
        data = self._extract_json(cleaned)
        if data is None:
            log.warning("Nemotron response did not contain a JSON object")
            return SecurityAnalysis(
                summary=cleaned.strip()[:2000],
                parse_failed=True,
                parse_error="no JSON object found",
                raw_response=text,
            )

        analysis = self._normalise(data, raw=text)
        errors = self._schema_errors(data, analysis)
        if errors:
            analysis.parse_failed = True
            analysis.parse_error = "; ".join(errors)
        return analysis

    def _extract_json(self, text: str) -> Optional[dict]:
        for candidate in self._candidates(text):
            for attempt in (candidate, self._repair(candidate)):
                try:
                    parsed = json.loads(attempt)
                except (TypeError, ValueError):
                    continue
                if isinstance(parsed, dict):
                    return parsed
        return None

    def _candidates(self, text: str) -> list[str]:
        out = [text.strip()]
        out.extend(m.group(1).strip() for m in _ANY_FENCE.finditer(text))
        balanced = self._balanced_object(text)
        if balanced:
            out.append(balanced)
        return out

    @staticmethod
    def _balanced_object(text: str) -> Optional[str]:
        start = text.find("{")
        if start == -1:
            return None
        depth, in_str, esc = 0, False, False
        for i in range(start, len(text)):
            ch = text[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        return None

    @staticmethod
    def _repair(text: str) -> str:
        for bad, good in _SMART.items():
            text = text.replace(bad, good)
        text = re.sub(r",\s*([}\]])", r"\1", text)
        text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
        return text

    def _normalise(self, data: dict, raw: str) -> SecurityAnalysis:
        findings = data.get("findings")
        if isinstance(findings, dict):
            findings = [findings]
        if not isinstance(findings, list):
            findings = []

        normalised_findings = [
            self._normalise_finding(f) for f in findings if isinstance(f, dict)
        ]
        executive_summary = self._normalise_executive(data.get("executive_summary"))

        return SecurityAnalysis(
            summary=self._string(data.get("summary")),
            overall_posture=self._string(data.get("overall_posture")),
            severity=self._severity(data.get("severity")),
            confidence=self._numeric_confidence(data.get("confidence")),
            findings=normalised_findings,
            executive_summary=executive_summary,
            business_impact=self._string(data.get("business_impact")),
            technical_explanation=self._string(data.get("technical_explanation")),
            recommendation=self._string(data.get("recommendation")),
            secure_code=self._string(data.get("secure_code")),
            owasp=self._string(data.get("owasp")),
            nist=self._string(data.get("nist")),
            rmf=self._string(data.get("rmf")),
            cwe=self._string(data.get("cwe")),
            raw_response=raw,
        )

    def _normalise_finding(self, finding: dict) -> dict:
        out: dict[str, Any] = {}
        for key in _REQUIRED_FINDING:
            value = finding.get(key)
            if key in {"line_start", "line_end"}:
                out[key] = self._integer(value)
            else:
                out[key] = self._string(value)
        out["severity"] = self._severity(out["severity"])
        out["confidence"] = self._title_enum(out["confidence"])
        out["status"] = out["status"].strip().lower()
        return out

    def _normalise_executive(self, value: Any) -> dict:
        value = value if isinstance(value, dict) else {}
        counts = value.get("counts_by_severity")
        counts = counts if isinstance(counts, dict) else {}
        return {
            "posture_statement": self._string(value.get("posture_statement")),
            "counts_by_severity": {
                severity: self._integer(counts.get(severity)) for severity in _REQUIRED_COUNTS
            },
            "highest_priority_risks": self._list(value.get("highest_priority_risks")),
            "immediate_remediation_priorities": self._list(
                value.get("immediate_remediation_priorities")
            ),
            "assumptions": self._list(value.get("assumptions")),
            "missing_context": self._list(value.get("missing_context")),
        }

    def _schema_errors(self, raw: dict, analysis: SecurityAnalysis) -> list[str]:
        errors: list[str] = []
        missing = sorted(_REQUIRED_TOP_LEVEL - set(raw))
        if missing:
            errors.append(f"missing top-level field(s): {', '.join(missing)}")

        if analysis.overall_posture not in _POSTURES:
            errors.append(f"invalid overall_posture: {analysis.overall_posture!r}")
        if analysis.severity not in _SEVERITIES:
            errors.append(f"invalid severity: {analysis.severity!r}")
        if not 0.0 <= analysis.confidence <= 1.0:
            errors.append(f"confidence outside 0.0-1.0: {analysis.confidence}")

        executive = raw.get("executive_summary")
        if not isinstance(executive, dict):
            errors.append("executive_summary must be an object")
        else:
            missing_exec = sorted(_REQUIRED_EXECUTIVE - set(executive))
            if missing_exec:
                errors.append(
                    "missing executive_summary field(s): " + ", ".join(missing_exec)
                )
            counts = executive.get("counts_by_severity")
            if not isinstance(counts, dict):
                errors.append("executive_summary.counts_by_severity must be an object")
            else:
                missing_counts = sorted(_REQUIRED_COUNTS - set(counts))
                if missing_counts:
                    errors.append(
                        "missing counts_by_severity field(s): " + ", ".join(missing_counts)
                    )

        raw_findings = raw.get("findings")
        if not isinstance(raw_findings, list):
            errors.append("findings must be an array")
            return errors

        for index, finding in enumerate(raw_findings):
            if not isinstance(finding, dict):
                errors.append(f"findings[{index}] must be an object")
                continue
            missing_finding = sorted(_REQUIRED_FINDING - set(finding))
            if missing_finding:
                errors.append(
                    f"findings[{index}] missing field(s): " + ", ".join(missing_finding)
                )
            status = str(finding.get("status", "")).strip().lower()
            if status not in _STATUSES:
                errors.append(f"findings[{index}].status invalid: {status!r}")
            severity = self._severity(finding.get("severity"))
            if severity not in _SEVERITIES:
                errors.append(f"findings[{index}].severity invalid: {severity!r}")
            confidence = self._title_enum(finding.get("confidence"))
            if confidence not in _FINDING_CONFIDENCE:
                errors.append(f"findings[{index}].confidence invalid: {confidence!r}")

        return errors

    @staticmethod
    def _string(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)):
            return ", ".join(str(item) for item in value)
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        return str(value)

    @staticmethod
    def _list(value: Any) -> list:
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    @staticmethod
    def _integer(value: Any) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _severity(value: Any) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        return {"Crit": "Critical", "Warning": "Medium", "Error": "High",
                "Informational": "Info"}.get(text.title(), text.title())

    @staticmethod
    def _title_enum(value: Any) -> str:
        return str(value or "").strip().title()

    @staticmethod
    def _numeric_confidence(value: Any) -> float:
        if value is None:
            return 0.0
        if isinstance(value, (int, float)):
            numeric = float(value)
            return round(numeric / 100.0, 3) if numeric > 1.0 else round(numeric, 3)
        text = str(value).strip().lower()
        word_map = {"very high": 0.95, "high": 0.85, "medium": 0.6,
                    "moderate": 0.6, "low": 0.3, "very low": 0.15}
        if text in word_map:
            return word_map[text]
        match = re.search(r"(\d+(?:\.\d+)?)", text)
        if not match:
            return 0.0
        numeric = float(match.group(1))
        return round(numeric / 100.0, 3) if numeric > 1.0 else round(numeric, 3)


def strip_json_markdown(text: str) -> str:
    """Remove markdown wrapping around a JSON object when present."""
    if not text:
        return ""
    match = _FENCE.match(text)
    if match:
        return match.group(1).strip()
    return text.strip()
