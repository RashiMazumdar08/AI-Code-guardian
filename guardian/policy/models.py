"""
Structured Business Policies
============================
A business requirement written for humans:

    "Refunds above ₹50,000 require manager approval."

becomes a structure a analyzer can actually test against code:

    BusinessPolicy(
        action="refund",
        condition=Condition(field="amount", operator=">", value=50000),
        required_control=ControlType.AUTHORIZATION,
        control_detail="manager approval",
    )

This is the difference between the old engine and this one. Previously,
"business intent" meant keyword-overlap scoring between requirement text
and file names — which is why it produced the same verdict for a
repository that implements the control and one that does not. A policy
with an explicit action, condition and required control can be checked
against observed behaviour, and the check can be wrong in a way someone
can point at.

Policies keep `source_text` and `source_document` so every verdict traces
back to the sentence a human wrote.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class ControlType(str, Enum):
    """The kind of control a requirement demands."""

    AUTHORIZATION = "authorization"      # approval, role check, permission
    VALIDATION = "validation"            # input/range/format checks
    AUDIT = "audit"                      # logging, traceability, records
    ENCRYPTION = "encryption"            # data protection at rest/in transit
    RATE_LIMIT = "rate_limit"            # throttling, quotas
    SEGREGATION = "segregation"          # maker-checker, dual control
    WORKFLOW = "workflow"                # ordering/state transitions
    DATA_RETENTION = "data_retention"
    UNSPECIFIED = "unspecified"


class PolicyPriority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass(frozen=True)
class Condition:
    """A testable condition, e.g. `amount > 50000`."""

    field: str = ""
    operator: str = ""            # > >= < <= == != contains
    value: Optional[float] = None
    unit: str = ""                # currency/measure, e.g. "INR", "days"
    raw: str = ""                 # the phrase this came from

    @property
    def is_threshold(self) -> bool:
        return bool(self.field and self.operator and self.value is not None)

    def describe(self) -> str:
        if self.is_threshold:
            unit = f" {self.unit}" if self.unit else ""
            return f"{self.field} {self.operator} {self.value:g}{unit}"
        return self.raw

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BusinessPolicy:
    """One machine-checkable business rule."""

    action: str                                   # "refund", "transfer", "approve"
    required_control: ControlType = ControlType.UNSPECIFIED
    control_detail: str = ""                      # "manager approval"
    condition: Condition = field(default_factory=Condition)
    actor: str = ""                               # "manager", "admin", "system"
    subject: str = ""                             # "transaction", "loan"
    priority: PolicyPriority = PolicyPriority.HIGH
    negative: bool = False                        # "must NOT ..." style rule

    source_text: str = ""
    source_document: str = ""
    requirement_id: str = ""
    #: extra terms used to locate implementing code, e.g. {"refund","reversal"}
    keywords: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    policy_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if isinstance(self.required_control, str):
            try:
                self.required_control = ControlType(self.required_control)
            except ValueError:
                self.required_control = ControlType.UNSPECIFIED
        if isinstance(self.priority, str):
            try:
                self.priority = PolicyPriority(self.priority.title())
            except ValueError:
                self.priority = PolicyPriority.HIGH
        basis = (f"{self.action}|{self.required_control.value}|"
                 f"{self.condition.describe()}|{self.control_detail}|{self.requirement_id}")
        self.policy_id = "P" + hashlib.sha256(basis.encode()).hexdigest()[:10]

    # ------------------------------------------------------------------
    @property
    def is_checkable(self) -> bool:
        """True when the policy says enough to be tested against code.

        A requirement with no action, or no control to look for, is kept
        for the record but never produces a violation — claiming a
        violation of an untestable rule is exactly the fabrication this
        design exists to prevent.
        """
        return bool(self.action) and self.required_control is not ControlType.UNSPECIFIED

    def plain_english(self) -> str:
        parts = []
        if self.negative:
            parts.append(f"{(self.actor or 'the system').capitalize()} must NOT {self.action}")
        else:
            parts.append(f"{self.action.capitalize()}")
        if self.condition.is_threshold or self.condition.raw:
            parts.append(f"when {self.condition.describe()}")
        if self.control_detail:
            parts.append(f"requires {self.control_detail}")
        elif self.required_control is not ControlType.UNSPECIFIED:
            parts.append(f"requires a {self.required_control.value} control")
        return " ".join(parts).strip().rstrip(".") + "."

    def to_context_line(self) -> str:
        """Compact rendering for an LLM prompt."""
        bits = [f"{self.policy_id}: {self.plain_english()}"]
        bits.append(f"action={self.action}")
        bits.append(f"required_control={self.required_control.value}")
        if self.condition.is_threshold:
            bits.append(f"condition={self.condition.describe()}")
        if self.source_document:
            bits.append(f"source={self.source_document}")
        return " | ".join(bits)

    def search_terms(self) -> list[str]:
        """Terms used to locate the code that implements this policy."""
        terms = {self.action.lower()} | {k.lower() for k in self.keywords}
        if self.subject:
            terms.add(self.subject.lower())
        if self.condition.field:
            terms.add(self.condition.field.lower())
        return sorted(t for t in terms if len(t) > 2)

    def to_dict(self) -> dict:
        return {
            "policy_id": self.policy_id,
            "action": self.action,
            "required_control": self.required_control.value,
            "control_detail": self.control_detail,
            "condition": self.condition.to_dict(),
            "condition_text": self.condition.describe(),
            "actor": self.actor,
            "subject": self.subject,
            "priority": self.priority.value,
            "negative": self.negative,
            "plain_english": self.plain_english(),
            "checkable": self.is_checkable,
            "source_text": self.source_text,
            "source_document": self.source_document,
            "requirement_id": self.requirement_id,
            "keywords": self.keywords,
            "metadata": self.metadata,
        }


@dataclass
class PolicySet:
    """All policies extracted from a repository's requirement sources."""

    policies: list[BusinessPolicy] = field(default_factory=list)
    documents: list[str] = field(default_factory=list)
    unparsed_requirements: int = 0

    def __iter__(self):
        return iter(self.policies)

    def __len__(self) -> int:
        return len(self.policies)

    @property
    def checkable(self) -> list[BusinessPolicy]:
        return [p for p in self.policies if p.is_checkable]

    def by_control(self, control: ControlType) -> list[BusinessPolicy]:
        return [p for p in self.policies if p.required_control is control]

    def get(self, policy_id: str) -> Optional[BusinessPolicy]:
        return next((p for p in self.policies if p.policy_id == policy_id), None)

    def to_dict(self) -> dict:
        counts: dict[str, int] = {}
        for policy in self.policies:
            key = policy.required_control.value
            counts[key] = counts.get(key, 0) + 1
        return {
            "total": len(self.policies),
            "checkable": len(self.checkable),
            "unparsed_requirements": self.unparsed_requirements,
            "documents": self.documents,
            "by_control": counts,
            "policies": [p.to_dict() for p in self.policies],
        }
