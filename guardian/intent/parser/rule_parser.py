"""
Strong Requirement -> Rule Parser Module
=======================================
Primary: Qwen2.5-3B-Instruct local natural-language requirement parser.
Fallback & Normalization: Deterministic rule parser & validator.

Decomposes requirements into structured components:
  1. Action     (verbs e.g. refund, transfer, encrypt, add item to cart)
  2. Condition  (thresholds/conditions e.g. amount > 50000, quantity > 0)
  3. Control    (demanded controls e.g. manager approval, inventory >= quantity)
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from guardian.intent.ingestion.document_loader import Requirement

log = logging.getLogger(__name__)

# Verb / Action extraction patterns for deterministic fallback.
ACTION_VERB_PATTERNS = re.compile(
    r"(?i)\b(refund|refunds|process_refund|transfer|transfers|encrypt\w*|decrypt\w*|"
    r"hashing|hash\w*|query|queries|database|delete\w*|purge\w*|mutate|audit\w*|log\w*|"
    r"authenticat\w*|approval|approve\w*|authoriz\w*|access\w*|login|logout|"
    r"register\w*|validat\w*|sanitiz\w*|verif\w*|store\w*|handl\w*|"
    r"transmit\w*|protect\w*|secur\w*|restrict\w*|limit\w*|"
    r"session\w*|password\w*|token\w*|secret\w*|upload\w*|download\w*|"
    r"deserializ\w*|command\w*|execut\w*|encod\w*|escap\w*|xml|xpath|outbound|request\w*|"
    r"path|file|error|exception|resource|dependency|dependencies|config\w*|default\w*|csrf|anti-forgery|"
    r"credential\w*|key|keys|privilege|permission\w*|object|idor|ownership)\b"
)

# Threshold / Condition extraction patterns for deterministic fallback.
NUMERIC_CONDITION_PATTERNS = re.compile(
    r"(?i)(\b(greater\s+than|exceeding|above|>|<|=|>=|<=)\s*\$?\s*[\d,]+|\b[\d,]+\s*(usd|dollars)?|\buser\s+input\b|\bexternal\b)"
)

# Demanded Control extraction patterns for deterministic fallback.
CONTROL_PATTERNS = re.compile(
    r"(?i)\b(manager\s+approval|authorization|authoriz\w*|authenticat\w*|"
    r"signoff|dual-control|sha-256|argon2id|bcrypt|md5|"
    r"parameterized|prepared\s+statement|audit\s+trail|audit\s+log|"
    r"rate\s+limit\w*|throttl\w*|rbac|permission\w*|access\s+control|"
    r"encrypt\w*|hash\w*|valid\w*|sanitiz\w*|escap\w*|"
    r"session\s+management|multi-factor|mfa|two-factor|2fa|"
    r"tls|ssl|https|csrf|secure\w*|allowlist|pinning|anti-forgery|secure\s+default\w*|"
    r"secret\s+store|environment|vault|least\s+privilege|ownership\s+check\w*)\b"
)


@dataclass
class ParsedRule:
    rule_id: str
    requirement_text: str
    source_file: str
    line_number: int
    action: str
    condition: str
    control: str
    rule_type: str  # "STRUCTURED" or "UNSTRUCTURED"
    priority: str = "Medium"
    title: str = ""
    evidence_terms: list[str] = field(default_factory=list)
    area: str = ""
    required_control: str = ""
    expected_implementation_behavior: str = ""
    violation_conditions: str = ""
    compliant_conditions: str = ""
    suggested_validation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "requirement_text": self.requirement_text,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "action": self.action,
            "condition": self.condition,
            "control": self.control,
            "rule_type": self.rule_type,
            "priority": self.priority,
            "title": self.title,
            "evidence_terms": self.evidence_terms,
            "area": self.area,
            "required_control": self.required_control,
            "expected_implementation_behavior": self.expected_implementation_behavior,
            "violation_conditions": self.violation_conditions,
            "compliant_conditions": self.compliant_conditions,
            "suggested_validation": self.suggested_validation,
        }


class RuleParser:
    """Parses Requirement objects into structured ParsedRule items.
    
    Primary parser: Local Qwen2.5-3B-Instruct.
    Validation & Fallback: Deterministic pattern matching.
    """

    def __init__(self, use_qwen: bool = True):
        self.use_qwen = use_qwen
        self._qwen_parser = None

    def _get_qwen_parser(self):
        if self._qwen_parser is None:
            try:
                from guardian.intent.parser.qwen_parser import QwenRuleParser
                self._qwen_parser = QwenRuleParser()
            except Exception as exc:
                log.warning("QwenRuleParser initialization notice: %s", exc)
                self._qwen_parser = False
        return self._qwen_parser if self._qwen_parser else None

    def parse_requirement(self, req: Requirement) -> ParsedRule:
        """Parse requirement into structured ParsedRule.
        
        Tries local Qwen2.5-3B-Instruct primary parser first; falls back to deterministic RuleParser.
        """
        # 1. Primary path: Local Qwen natural-language business rule parser
        if self.use_qwen:
            qwen = self._get_qwen_parser()
            if qwen:
                try:
                    qwen_data = qwen.parse_requirement(req)
                    if qwen_data:
                        return self.normalize_qwen_output(req, qwen_data)
                except Exception as exc:
                    log.warning("Qwen parser execution failed for %s, falling back to deterministic parser: %s", req.id, exc)

        # 2. Safety Net Fallback: Deterministic pattern matching
        return self._parse_requirement_deterministic(req)

    def normalize_qwen_output(self, req: Requirement, qwen_data: dict[str, Any]) -> ParsedRule:
        """Validate and normalize Qwen structured JSON output into canonical ParsedRule format."""
        action = str(qwen_data.get("action", "")).strip().lower() or "generic_action"
        condition = str(qwen_data.get("condition", "")).strip() or "none"
        control = str(qwen_data.get("control", "")).strip().lower() or "generic_control"

        raw_evidence = qwen_data.get("evidence_terms", [])
        evidence_terms: list[str] = []
        if isinstance(raw_evidence, list):
            evidence_terms = [str(term).strip().lower() for term in raw_evidence if str(term).strip()]
        if not evidence_terms and req.evidence_terms:
            evidence_terms = list(req.evidence_terms)

        is_structured = bool(
            (action and action != "generic_action")
            or (control and control != "generic_control")
            or (condition and condition != "none")
        )
        rule_type = "STRUCTURED" if is_structured else "UNSTRUCTURED"

        lower_text = req.text.lower()
        if req.severity:
            priority = "High" if req.severity.lower() in ("critical", "high") else "Medium"
        else:
            priority = "High" if ("critical" in lower_text or "must" in lower_text or "authoritative" in lower_text) else "Medium"

        return ParsedRule(
            rule_id=req.id,
            requirement_text=req.text,
            source_file=req.source,
            line_number=req.line_number,
            action=action,
            condition=condition,
            control=control,
            rule_type=rule_type,
            priority=priority,
            title=req.title,
            evidence_terms=evidence_terms,
            area=req.area,
            required_control=req.required_control,
            expected_implementation_behavior=req.expected_implementation_behavior,
            violation_conditions=req.violation_conditions,
            compliant_conditions=req.compliant_conditions,
            suggested_validation=req.suggested_validation,
        )

    def _parse_requirement_deterministic(self, req: Requirement) -> ParsedRule:
        """Deterministic pattern-matching safety net parser."""
        text = req.text
        lower_text = text.lower()

        # 1. Action extraction
        action_match = ACTION_VERB_PATTERNS.search(text)
        if action_match:
            action = action_match.group(0).lower()
        elif req.title:
            action = req.title.lower()
        elif req.evidence_terms:
            action = req.evidence_terms[0].lower()
        else:
            action = "generic_action"

        # 2. Condition extraction
        condition_match = NUMERIC_CONDITION_PATTERNS.search(text)
        condition = condition_match.group(0).strip() if condition_match else "none"

        # 3. Control extraction
        control_match = CONTROL_PATTERNS.search(text)
        if control_match:
            control = control_match.group(0).lower()
        elif req.evidence_terms:
            control = req.evidence_terms[-1].lower()
        else:
            control = "generic_control"

        # Rule type classification
        is_structured = bool(action_match or control_match or condition_match != "none")
        rule_type = "STRUCTURED" if is_structured else "UNSTRUCTURED"

        if req.severity:
            priority = "High" if req.severity.lower() in ("critical", "high") else "Medium"
        else:
            priority = "High" if ("50000" in lower_text or "critical" in lower_text or "must" in lower_text) else "Medium"

        return ParsedRule(
            rule_id=req.id,
            requirement_text=req.text,
            source_file=req.source,
            line_number=req.line_number,
            action=action,
            condition=condition,
            control=control,
            rule_type=rule_type,
            priority=priority,
            title=req.title,
            evidence_terms=list(req.evidence_terms),
            area=req.area,
            required_control=req.required_control,
            expected_implementation_behavior=req.expected_implementation_behavior,
            violation_conditions=req.violation_conditions,
            compliant_conditions=req.compliant_conditions,
            suggested_validation=req.suggested_validation,
        )

    def parse_all(self, requirements: list[Requirement]) -> list[ParsedRule]:
        """Parse a list of requirements into ParsedRule objects."""
        return [self.parse_requirement(r) for r in requirements]
