"""
Requirement -> Structured Policy Extraction
===========================================
Turns requirement documents into `BusinessPolicy` objects.

Loading is delegated to the existing `RequirementLoader`
(`guardian.intent.legacy.loader`), which already handles TXT, MD, PDF,
DOCX, JSON, YAML, CSV and XLSX — that code works and is reused unchanged.
What is new is the *structuring* step: instead of scoring keyword overlap
between a requirement and a filename, each sentence is decomposed into
an action, a testable condition and the control it demands.

Extraction is deterministic. An optional Nemotron pass
(`enrich_with_llm`) can structure sentences the rules could not, but it
only ever *adds* policies from text the user supplied, and each one keeps
its `source_text` — so a policy is always traceable to a written
requirement, never invented.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from guardian.policy.models import (
    BusinessPolicy, Condition, ControlType, PolicyPriority, PolicySet,
)

log = logging.getLogger(__name__)

MIN_SENTENCE_LENGTH = 15

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
#: control keyword -> ControlType. Ordered by specificity at match time.
_CONTROL_PATTERNS: list[tuple[re.Pattern, ControlType, str]] = [
    (re.compile(r"(?i)\b(maker[\s\-]?checker|dual[\s\-]control|four[\s\-]eyes|"
                r"segregation of duties|two[\s\-]person)\b"),
     ControlType.SEGREGATION, "segregation of duties"),
    (re.compile(r"(?i)\b(approv\w*|authoriz\w*|authoris\w*|sign[\s\-]?off|"
                r"permission|consent|escalat\w*)\b"),
     ControlType.AUTHORIZATION, "approval/authorization"),
    (re.compile(r"(?i)\b(role|admin(?:istrator)?|manager|supervisor|officer|"
                r"privileg\w*|access control|rbac)\b"),
     ControlType.AUTHORIZATION, "role-based access control"),
    # Ownership/tenancy language is an access-control rule, not an audit one.
    # Checked before AUDIT because "records belonging to other customers"
    # contains the word "records".
    (re.compile(r"(?i)\b(belonging to (?:other|another|different)|"
                r"other (?:users?|customers?|accounts?|tenants?|patients?)|"
                r"another (?:user|customer|account|tenant|patient)|"
                r"own(?:ed)? by (?:other|another)|only (?:their|his|her) own|"
                r"cross[\s\-]tenant)\b"),
     ControlType.AUTHORIZATION, "object-level access control"),
    # Verb forms only. Bare "record"/"records" is usually a noun and made
    # every rule that mentions records look like an audit requirement.
    (re.compile(r"(?i)\b(audit\w*|log(?:ged|ging|s)?\b|recorded|recording|"
                r"trace\w*|traceab\w*|audit trail|journal\w*)\b"),
     ControlType.AUDIT, "audit logging"),
    (re.compile(r"(?i)\b(encrypt\w*|cipher|tls|ssl|at rest|in transit|"
                r"mask\w*|tokeniz\w*|redact\w*|hash\w*)\b"),
     ControlType.ENCRYPTION, "encryption/data protection"),
    (re.compile(r"(?i)\b(rate[\s\-]?limit\w*|throttl\w*|quota|per (?:second|minute|hour|day)|"
                r"maximum number of (?:requests|attempts))\b"),
     ControlType.RATE_LIMIT, "rate limiting"),
    (re.compile(r"(?i)\b(valid\w*|verif\w*|check\w*|mandatory|required field|"
                r"must (?:be|contain|match)|format|sanitis\w*|sanitiz\w*)\b"),
     ControlType.VALIDATION, "input validation"),
    (re.compile(r"(?i)\b(retain\w*|retention|purge|delete after|archiv\w*)\b"),
     ControlType.DATA_RETENTION, "data retention"),
    (re.compile(r"(?i)\b(before|after|prior to|following|workflow|state|"
                r"status|transition|sequence|step)\b"),
     ControlType.WORKFLOW, "workflow ordering"),
]

#: Business actions worth locating in code.
_ACTION_PATTERN = re.compile(
    r"(?i)\b(refund\w*|reversal|chargeback|transfer\w*|withdraw\w*|deposit\w*|"
    r"payment\w*|pay\b|charge\w*|settle\w*|disburse\w*|payout\w*|"
    r"approv\w*|reject\w*|cancel\w*|submit\w*|creat\w*|updat\w*|delet\w*|"
    r"issue\w*|generat\w*|export\w*|import\w*|upload\w*|download\w*|"
    r"login|logout|authenticat\w*|register\w*|onboard\w*|"
    r"order\w*|checkout|purchas\w*|ship\w*|cancel\w*|"
    r"loan\w*|credit\w*|debit\w*|invoice\w*|bill\w*|"
    r"access\w*|view\w*|read\w*|writ\w*|modif\w*|shar\w*|"
    r"prescrib\w*|discharg\w*|admit\w*)\b")

_ACTOR_PATTERN = re.compile(
    r"(?i)\b(manager|admin(?:istrator)?|supervisor|officer|approver|reviewer|"
    r"auditor|operator|customer|user|merchant|client|system|service|"
    r"teller|agent|employee|doctor|clinician|nurse)s?\b")

_SUBJECT_PATTERN = re.compile(
    r"(?i)\b(transaction|payment|refund|order|account|loan|claim|policy|invoice|"
    r"record|document|patient|prescription|user|customer|card|transfer)s?\b")

#: Numeric magnitude words used in Indian and Western business writing.
_MAGNITUDES = {
    "hundred": 100, "thousand": 1_000, "k": 1_000,
    "lakh": 100_000, "lakhs": 100_000, "lac": 100_000,
    "million": 1_000_000, "m": 1_000_000, "mn": 1_000_000,
    "crore": 10_000_000, "crores": 10_000_000,
    "billion": 1_000_000_000, "bn": 1_000_000_000,
}

_CURRENCY_SYMBOLS = {"₹": "INR", "$": "USD", "€": "EUR", "£": "GBP", "¥": "JPY"}

_COMPARATORS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(?:greater than or equal to|at least|no less than|minimum of)\b"), ">="),
    (re.compile(r"(?i)\b(?:less than or equal to|at most|no more than|up to|maximum of|not exceeding)\b"), "<="),
    (re.compile(r"(?i)\b(?:above|over|exceed(?:s|ing)?|greater than|more than|beyond|larger than)\b"), ">"),
    (re.compile(r"(?i)\b(?:below|under|less than|smaller than|fewer than)\b"), "<"),
    (re.compile(r"(?i)\b(?:equal to|equals|exactly)\b"), "=="),
]

_AMOUNT = re.compile(
    r"(?P<symbol>[₹$€£¥])?\s*(?:(?P<code>INR|USD|EUR|GBP|JPY|Rs\.?)\s*)?"
    r"(?P<number>\d[\d,]*(?:\.\d+)?)\s*"
    r"(?P<magnitude>hundred|thousand|lakhs?|lac|crores?|million|billion|k|m|mn|bn)?",
    re.I)

_NEGATIVE = re.compile(r"(?i)\b(must not|shall not|cannot|may not|never|"
                       r"is not allowed|is prohibited|forbidden|denied|blocked)\b")

_OBLIGATION = re.compile(r"(?i)\b(must|shall|should|require[sd]?|need[s]? to|"
                         r"has to|have to|mandatory|only)\b")

#: Deliberately excludes bare "for" — it introduces purpose ("for audit
#: purposes") far more often than a condition, and admitting it turned
#: every audit requirement into a bogus conditional policy.
_CONDITION_LEAD = re.compile(
    r"(?i)\b(?:if|when|where|whenever|in case of|provided that|unless|"
    r"above|below|over|under|exceeding|greater than|less than|more than|"
    r"at least|no more than|up to)\b")

#: Fields a condition can be about, mapped to the identifier a developer
#: is likely to have used. Used to locate the check in code.
_CONDITION_FIELDS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(?i)\b(amount|value|sum|total|price|balance|limit|"
                r"transaction size)\b"), "amount"),
    (re.compile(r"(?i)\b(quantity|count|number of|items)\b"), "quantity"),
    (re.compile(r"(?i)\b(age|years old)\b"), "age"),
    (re.compile(r"(?i)\b(duration|days|hours|minutes|period|retention)\b"), "duration"),
    (re.compile(r"(?i)\b(attempts|retries|requests)\b"), "attempts"),
    (re.compile(r"(?i)\b(score|rating|risk)\b"), "score"),
]

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?;])\s+|\n+")


# ---------------------------------------------------------------------------
@dataclass
class ExtractionStats:
    sentences_seen: int = 0
    policies_extracted: int = 0
    unstructured: int = 0


class PolicyExtractor:
    """Deterministic requirement -> policy structuring."""

    def __init__(self, *, min_sentence_length: int = MIN_SENTENCE_LENGTH) -> None:
        self.min_sentence_length = min_sentence_length
        self.stats = ExtractionStats()

    # ------------------------------------------------------------------
    def extract_from_sources(self, sources: Iterable[Path | str]) -> PolicySet:
        """Load requirement documents and structure them into policies."""
        policy_set = PolicySet()
        loader = self._loader()

        for source in sources:
            path = Path(source)
            policy_set.documents.append(str(path.name))
            requirements = []
            if loader is not None:
                try:
                    requirements = loader.load(path)
                except Exception as exc:  # noqa: BLE001 — one bad document, not a failed scan
                    log.warning("could not load requirements from %s: %s", path, exc)
            if not requirements:
                text = _read_text(path)
                if text:
                    requirements = [_PlainRequirement(source_id=path.name, content=text)]

            for requirement in requirements:
                policies = self.extract_from_requirement(requirement, str(path.name))
                if policies:
                    policy_set.policies.extend(policies)
                else:
                    policy_set.unparsed_requirements += 1

        policy_set.policies = _dedupe(policy_set.policies)
        self.stats.policies_extracted = len(policy_set.policies)
        return policy_set

    def extract_from_text(self, text: str, document: str = "inline") -> PolicySet:
        requirement = _PlainRequirement(source_id=document, content=text)
        policies = self.extract_from_requirement(requirement, document)
        return PolicySet(policies=_dedupe(policies), documents=[document])

    # ------------------------------------------------------------------
    def extract_from_requirement(self, requirement, document: str) -> list[BusinessPolicy]:
        """Structure one requirement (with its acceptance criteria)."""
        texts: list[str] = []
        content = getattr(requirement, "content", "") or ""
        title = getattr(requirement, "title", "") or ""
        if title:
            texts.append(title)
        texts.append(content)
        texts.extend(getattr(requirement, "acceptance_criteria", []) or [])

        requirement_id = str(getattr(requirement, "source_id", "") or document)

        policies: list[BusinessPolicy] = []
        for block in texts:
            for sentence in _sentences(block):
                self.stats.sentences_seen += 1
                policy = self.extract_from_sentence(sentence, document, requirement_id)
                if policy is not None:
                    policies.append(policy)
                else:
                    self.stats.unstructured += 1
        return policies

    # ------------------------------------------------------------------
    def extract_from_sentence(self, sentence: str, document: str = "",
                              requirement_id: str = "") -> Optional[BusinessPolicy]:
        """Structure one sentence, or return None when it states no rule."""
        text = sentence.strip()
        if len(text) < self.min_sentence_length:
            return None
        # A requirement states an obligation. Descriptive prose does not.
        if not _OBLIGATION.search(text) and not _NEGATIVE.search(text):
            return None

        action_match = _ACTION_PATTERN.search(text)
        if action_match is not None:
            action = _normalise_action(action_match.group(1))
            control_type, control_detail = self._extract_control(text, action_match)
        else:
            # Data-centric requirements ("Card numbers must be encrypted at
            # rest") name a subject and a control but no verb. They are still
            # testable, so key the policy on the subject rather than dropping it.
            control_type, control_detail = self._extract_control(
                text, re.match(r"", text))
            if control_type is ControlType.UNSPECIFIED:
                return None
            subject_match = _SUBJECT_PATTERN.search(text)
            noun = _leading_noun(text)
            action = (subject_match.group(1).lower() if subject_match
                      else noun)
            if not action:
                return None

        condition = self._extract_condition(text)
        actor = self._extract_actor(text)
        subject = self._extract_subject(text, action)

        return BusinessPolicy(
            action=action,
            required_control=control_type,
            control_detail=control_detail,
            condition=condition,
            actor=actor,
            subject=subject,
            priority=_priority_for(text, condition),
            negative=bool(_NEGATIVE.search(text)),
            source_text=text[:500],
            source_document=document,
            requirement_id=requirement_id,
            keywords=_keywords(action, subject, control_detail),
        )

    # ------------------------------------------------------------------
    def _extract_control(self, text: str,
                         action_match: re.Match) -> tuple[ControlType, str]:
        """Find the demanded control, ignoring the action verb itself.

        Without this exclusion, "refunds must be approved" and "approvals
        must be logged" would both classify as AUTHORIZATION, because the
        action verb 'approve' also matches the authorization vocabulary.
        """
        masked = (text[:action_match.start()] + " " * (action_match.end() - action_match.start())
                  + text[action_match.end():])
        for pattern, control, detail in _CONTROL_PATTERNS:
            match = pattern.search(masked)
            if match:
                return control, _control_detail(text, match.group(0), control, detail)
        # The action itself may be the control ("must be approved by a manager")
        for pattern, control, detail in _CONTROL_PATTERNS[:2]:
            match = pattern.search(text)
            if match:
                return control, _control_detail(text, match.group(0), control, detail)
        return ControlType.UNSPECIFIED, ""

    def _extract_condition(self, text: str) -> Condition:
        operator = ""
        raw = ""
        for pattern, symbol in _COMPARATORS:
            match = pattern.search(text)
            if match:
                operator = symbol
                raw = text[match.start():match.start() + 80].strip()
                break
        if not operator:
            lead = _CONDITION_LEAD.search(text)
            if lead:
                return Condition(raw=text[lead.start():lead.start() + 120].strip())
            return Condition()

        value, unit = _parse_amount(text[_position_after(text, operator):])
        field_name = "amount"
        for pattern, name in _CONDITION_FIELDS:
            if pattern.search(text):
                field_name = name
                break
        return Condition(field=field_name, operator=operator, value=value,
                         unit=unit, raw=raw)

    @staticmethod
    def _extract_actor(text: str) -> str:
        match = _ACTOR_PATTERN.search(text)
        return match.group(1).lower() if match else ""

    @staticmethod
    def _extract_subject(text: str, action: str) -> str:
        for match in _SUBJECT_PATTERN.finditer(text):
            candidate = match.group(1).lower()
            if candidate != action:
                return candidate
        return ""

    @staticmethod
    def _loader():
        try:
            from guardian.intent.legacy.loader import RequirementLoader
            return RequirementLoader()
        except Exception as exc:  # noqa: BLE001
            log.debug("RequirementLoader unavailable: %s", exc)
            return None


# ---------------------------------------------------------------------------
# LLM-assisted enrichment (optional, additive, always traceable)
# ---------------------------------------------------------------------------
POLICY_EXTRACTION_SCHEMA = """Return exactly one JSON object, no prose:
{
  "policies": [
    {
      "source_text": "<the exact requirement sentence you structured>",
      "action": "<single business action verb, e.g. refund>",
      "condition_field": "<amount|quantity|duration|attempts|age|score or \\"\\">",
      "condition_operator": "<> | >= | < | <= | == or \\"\\">",
      "condition_value": <number or null>,
      "required_control": "authorization|validation|audit|encryption|rate_limit|segregation|workflow|data_retention",
      "control_detail": "<short phrase, e.g. manager approval>",
      "actor": "<who performs or approves, or \\"\\">"
    }
  ]
}
Rules:
- Structure ONLY sentences present in the REQUIREMENTS text below.
- Copy source_text verbatim from that text. Never invent a requirement.
- Omit any sentence that does not state a testable rule."""


def enrich_with_llm(policy_set: PolicySet, raw_text: str, service,
                    *, max_chars: int = 6000) -> PolicySet:
    """Structure requirement sentences the rules could not.

    Only sentences whose text appears in `raw_text` are accepted, so the
    model can restructure what the user wrote but cannot add requirements
    they did not. Returns the input unchanged on any failure.
    """
    if service is None or not raw_text.strip():
        return policy_set

    from guardian.reasoning.gateway import ReasoningRequest
    from guardian.reasoning.schemas import extract_json

    already = {p.source_text.strip().lower() for p in policy_set.policies}
    request = ReasoningRequest(
        task="policy_extraction",
        instruction=("Structure the business requirements below into testable policies. "
                     "Skip any sentence already covered by the EXISTING POLICIES list."),
        schema_instruction=POLICY_EXTRACTION_SCHEMA,
        business_block=("EXISTING POLICIES:\n" +
                        "\n".join(f"- {p.source_text}" for p in policy_set.policies[:30])),
        evidence_block="REQUIREMENTS:\n" + raw_text[:max_chars],
        system_role=("You convert written business requirements into structured, "
                     "testable policies. You never invent requirements."),
    )
    result = service.reason(request)
    if not result.available or result.response is None:
        return policy_set

    data = extract_json(result.response.raw) or {}
    normalised_source = raw_text.lower()
    added = 0
    for item in data.get("policies", []) or []:
        if not isinstance(item, dict):
            continue
        source_text = str(item.get("source_text", "")).strip()
        if not source_text or source_text.lower() in already:
            continue
        # Grounding check: the model may only restructure text that exists.
        if _normalise_whitespace(source_text.lower())[:60] not in \
                _normalise_whitespace(normalised_source):
            log.info("discarded LLM policy not present in requirements: %.60s", source_text)
            continue
        action = str(item.get("action", "")).strip().lower()
        if not action:
            continue
        try:
            control = ControlType(str(item.get("required_control", "")).strip().lower())
        except ValueError:
            control = ControlType.UNSPECIFIED
        value = item.get("condition_value")
        condition = Condition(
            field=str(item.get("condition_field", "") or ""),
            operator=str(item.get("condition_operator", "") or ""),
            value=float(value) if isinstance(value, (int, float)) else None,
            raw=source_text[:120])
        policy_set.policies.append(BusinessPolicy(
            action=action, required_control=control,
            control_detail=str(item.get("control_detail", "") or ""),
            condition=condition, actor=str(item.get("actor", "") or ""),
            source_text=source_text[:500],
            source_document="llm-structured",
            metadata={"extracted_by": "nemotron"}))
        already.add(source_text.lower())
        added += 1

    if added:
        log.info("LLM structured %d additional requirement sentence(s)", added)
        policy_set.policies = _dedupe(policy_set.policies)
    return policy_set


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
@dataclass
class _PlainRequirement:
    source_id: str
    content: str
    title: str = ""
    acceptance_criteria: list = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.acceptance_criteria is None:
            self.acceptance_criteria = []


def _sentences(text: str) -> list[str]:
    if not text:
        return []
    out: list[str] = []
    for chunk in _SENTENCE_SPLIT.split(text):
        cleaned = chunk.strip().lstrip("-*•0123456789. \t")
        if cleaned:
            out.append(cleaned)
    return out


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _normalise_action(verb: str) -> str:
    verb = verb.lower()
    for suffix in ("ing", "ed", "es", "s"):
        if not verb.endswith(suffix) or len(verb) - len(suffix) < 4:
            continue
        stem = verb[: -len(suffix)]
        # "access" -> "acces" is not a stem; a doubled consonant at the cut
        # means the suffix was part of the word, not an inflection.
        if suffix in ("s", "es") and stem.endswith(("s", "x", "z")):
            continue
        verb = stem
        break
    return {"refun": "refund", "approv": "approve", "creat": "create",
            "updat": "update", "delet": "delete", "settl": "settle",
            "disburs": "disburse", "generat": "generate", "purchas": "purchase",
            "authenticat": "authenticate", "modif": "modify", "writ": "write",
            "issu": "issue", "cancell": "cancel", "reject": "reject",
            "shar": "share", "prescrib": "prescribe", "discharg": "discharge"}.get(verb, verb)


def _parse_amount(text: str) -> tuple[Optional[float], str]:
    match = _AMOUNT.search(text)
    if not match:
        return None, ""
    try:
        value = float(match.group("number").replace(",", ""))
    except (TypeError, ValueError):
        return None, ""
    magnitude = (match.group("magnitude") or "").lower()
    if magnitude in _MAGNITUDES:
        value *= _MAGNITUDES[magnitude]
    unit = ""
    symbol = match.group("symbol")
    code = match.group("code")
    if symbol:
        unit = _CURRENCY_SYMBOLS.get(symbol, "")
    elif code:
        unit = "INR" if code.lower().startswith("rs") else code.upper()
    return value, unit


def _position_after(text: str, operator: str) -> int:
    for pattern, symbol in _COMPARATORS:
        if symbol != operator:
            continue
        match = pattern.search(text)
        if match:
            return match.end()
    return 0


def _control_detail(text: str, keyword: str, control: ControlType,
                    default: str) -> str:
    """A short, readable control name.

    Slicing a window out of the sentence produced fragments like
    "R 50,000 require manager approval." in prompts and reports. Compose a
    clean phrase from the actor and the matched keyword instead, falling
    back to the control's canonical label.
    """
    keyword = keyword.strip().lower()
    actor_match = _ACTOR_PATTERN.search(text)
    actor = actor_match.group(1).lower() if actor_match else ""

    if control is ControlType.AUTHORIZATION:
        if any(marker in keyword for marker in
               ("belonging", "other", "another", "own", "cross")):
            return "object-level access control (ownership check)"
        if keyword.startswith(("approv", "sign", "consent", "escalat")):
            noun = "approval"
        elif keyword.startswith(("authoriz", "authoris", "permission")):
            noun = "authorization"
        elif keyword in ("role", "rbac", "access control", "privilege", "privileges"):
            noun = "role-based access control"
        else:
            noun = f"{keyword} check"
        return f"{actor} {noun}".strip() if actor else noun
    if control is ControlType.SEGREGATION:
        return "segregation of duties"
    if control is ControlType.AUDIT:
        return "audit logging"
    if control is ControlType.ENCRYPTION:
        return "encryption at rest" if "at rest" in text.lower() else \
            "encryption in transit" if "in transit" in text.lower() else "encryption"
    if control is ControlType.RATE_LIMIT:
        return "rate limiting"
    if control is ControlType.VALIDATION:
        return "input validation"
    return default


def _leading_noun(text: str) -> str:
    """First substantive word of a sentence, used when no verb is present."""
    for word in re.findall(r"[A-Za-z]{3,}", text):
        lowered = word.lower()
        if lowered not in {"all", "the", "any", "each", "every", "must", "shall",
                           "should", "and", "for", "not", "are", "was", "were"}:
            return lowered
    return ""


def _priority_for(text: str, condition: Condition) -> PolicyPriority:
    if re.search(r"(?i)\b(must not|shall not|never|prohibited|critical|"
                 r"regulatory|compliance|legal)\b", text):
        return PolicyPriority.CRITICAL
    if condition.is_threshold or re.search(r"(?i)\b(must|shall|only)\b", text):
        return PolicyPriority.HIGH
    return PolicyPriority.MEDIUM


def _keywords(action: str, subject: str, control_detail: str) -> list[str]:
    terms = {action}
    if subject:
        terms.add(subject)
    synonyms = {
        "refund": {"refund", "reversal", "chargeback", "credit_note"},
        "transfer": {"transfer", "remit", "send_money", "payout"},
        "approve": {"approve", "authorize", "authorise", "sign_off"},
        "withdraw": {"withdraw", "debit", "cash_out"},
        "pay": {"pay", "payment", "charge", "capture"},
        "login": {"login", "signin", "authenticate"},
        "order": {"order", "checkout", "purchase"},
    }
    terms |= synonyms.get(action, set())
    for word in re.findall(r"[A-Za-z]{4,}", control_detail or ""):
        terms.add(word.lower())
    return sorted(terms)


def _dedupe(policies: list[BusinessPolicy]) -> list[BusinessPolicy]:
    seen: dict[str, BusinessPolicy] = {}
    for policy in policies:
        existing = seen.get(policy.policy_id)
        if existing is None or len(policy.source_text) > len(existing.source_text):
            seen[policy.policy_id] = policy
    return list(seen.values())


def _normalise_whitespace(text: str) -> str:
    return " ".join(text.split())
