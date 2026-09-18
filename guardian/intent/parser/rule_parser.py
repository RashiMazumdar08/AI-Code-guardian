"""
Strong Requirement -> Rule Parser Module
=======================================
Decomposes requirements into 3 explicit components:
  1. Action     (verbs e.g. refund, transfer, encrypt, execute)
  2. Condition  (thresholds/conditions e.g. amount > 50000, user input)
  3. Control    (demanded controls e.g. manager approval, sha-256, parameterization)

Fallback: rule.type = "UNSTRUCTURED" if parsing cannot split cleanly.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from guardian.intent.ingestion.document_loader import Requirement

log = logging.getLogger(__name__)

# Verb / Action extraction patterns.
# NOTE: this started as a narrow whitelist tuned to one demo scenario
# (refunds/payments/manager-approval), which meant real-world security
# requirement documents (auth, secrets, access control, sessions, ...)
# never matched anything and silently fell back to "generic_action" /
# "generic_control" — i.e. every real rule looked unimplemented no matter
# what the scan actually found. Vocabulary broadened to cover general
# application-security requirement language.
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

# Threshold / Condition extraction patterns
NUMERIC_CONDITION_PATTERNS = re.compile(
    r"(?i)(\b(greater\s+than|exceeding|above|>|<|=|>=|<=)\s*\$?\s*[\d,]+|\b[\d,]+\s*(usd|dollars)?|\buser\s+input\b|\bexternal\b)"
)

# Demanded Control extraction patterns — broadened alongside the action
# patterns above so real security/business requirements resolve to an
# actual control instead of the "generic_control" placeholder.
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
        }


class RuleParser:
    """Parses Requirement objects into structured ParsedRule items."""

    def parse_requirement(self, req: Requirement) -> ParsedRule:
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

        # Priority calculation. Prefer the document's own stated severity
        # (structured rule-block documents carry one, e.g. "Critical"/
        # "High"/"Medium"/"Low") over guessing from keywords — a real,
        # author-assigned severity is more accurate than "does this text
        # happen to contain the word 'must'".
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
        )

    def parse_all(self, requirements: list[Requirement]) -> list[ParsedRule]:
        """Parse a list of requirements into ParsedRule objects."""
        return [self.parse_requirement(r) for r in requirements]
