"""
Business Intent Engine — Rule Extractor (v4 Enhanced)
=======================================================
Changes from v3:
- Richer actor/action/condition/outcome extraction (more vocabulary)
- Deduplication of near-identical rules within one requirement
- plain_english is set on each rule at extraction time
- Acceptance criteria are each treated as an independent rule sentence
- Short sentences below MIN_LEN chars are skipped (reduces noise)
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Optional

from guardian.intent.legacy.models import BusinessRule, Requirement, RuleType

MIN_SENTENCE_LEN = 18   # skip trivial one-word or stub sentences

# ─── Extended keyword vocabulary ────────────────────────────────────────────

_AUTHZ_KW = re.compile(
    r"\b(only|must|shall|cannot|must not|not allowed|restricted to|"
    r"authoriz|permission|role|admin|manager|officer|verif|approved by|"
    r"granted to|require.*role|access.*control)\b", re.I)

_VALIDATION_KW = re.compile(
    r"\b(valid|invalid|reject|accept|must be|should be|format|required|"
    r"mandatory|max|min|limit|threshold|range|between|at least|no more than|"
    r"must contain|cannot be empty|non.?null|not null|positive)\b", re.I)

_AUDIT_KW = re.compile(
    r"\b(log|audit|record|track|monitor|notify|alert|history|trail|"
    r"evidence|timestamp|traceab)\b", re.I)

_WORKFLOW_KW = re.compile(
    r"\b(approv|reject|submit|review|escalat|workflow|step|stage|"
    r"status|transition|next.?state|before|after|following|prior to)\b", re.I)

_RATE_KW = re.compile(
    r"\b(rate.limit|throttl|per.second|per.minute|quota|max.*request|"
    r"concurrent|burst)\b", re.I)

# Actor vocabulary (expanded)
_ACTOR_PAT = re.compile(
    r"\b(admin(?:istrator)?|manager|user|merchant|customer|client|"
    r"system|service|api|officer|employee|vendor|partner|operator|"
    r"superuser|reviewer|approver|supervisor|loan.officer|teller|"
    r"verified\s+\w+|authenticated\s+\w+)\b", re.I)

# Action verbs (expanded)
_ACTION_PAT = re.compile(
    r"\b(approv[e]?|reject|submit|creat[e]?|updat[e]?|delet[e]?|access|"
    r"view|read|write|send|receiv[e]?|transfer|withdraw|deposit|"
    r"authenticat[e]?|authoriz[e]?|validat[e]?|process|log|audit|"
    r"generat[e]?|export|import|upload|download|cancel|refund|settl[e]?|"
    r"modif[y|ied]?|dispurs[e]?|disburse|allocat[e]?|calculat[e]?|"
    r"verif[y|ied]?|confirm|notify|alert|escalat[e]?|initiat[e]?|"
    r"close|open|lock|unlock|enable|disable|activate|deactivate)\b", re.I)

# Numeric constraint patterns  
_CONDITION_PAT = re.compile(
    r"(?:above|below|greater than|less than|more than|exceeding|"
    r"at least|up to|equal to|not more than|over|under|between|"
    r"minimum|maximum|limit of|threshold of|exceeds)\s+"
    r"(?:₹|Rs\.?|INR|USD|\$|€|GBP)?[\d,]+(?:\s*(?:lakh|crore|k|m|million|"
    r"thousand|hundred|billion))?", re.I)

# Outcome signals
_DENY_PAT  = re.compile(r"\b(must not|cannot|denied|rejected|blocked|forbidden|prohibited|not allowed)\b", re.I)
_ALLOW_PAT = re.compile(r"\b(must|shall|should|allowed|permitted|can|may|is able to)\b", re.I)
_AUDIT_OUTCOME_PAT = re.compile(r"\b(log|audit|record)\b", re.I)


def _classify_rule_type(text: str) -> RuleType:
    if _AUTHZ_KW.search(text):     return RuleType.AUTHORIZATION
    if _VALIDATION_KW.search(text): return RuleType.VALIDATION
    if _AUDIT_KW.search(text):     return RuleType.AUDIT
    if _WORKFLOW_KW.search(text):  return RuleType.WORKFLOW
    if _RATE_KW.search(text):      return RuleType.RATE_LIMIT
    return RuleType.GENERAL


def _extract_actor(sentence: str) -> str:
    m = _ACTOR_PAT.search(sentence)
    return m.group(0).strip() if m else "system"


def _extract_action(sentence: str) -> str:
    m = _ACTION_PAT.search(sentence)
    if not m:
        return sentence[:60].strip()
    rest = sentence[m.end():].strip().split()[:6]
    return (m.group(0) + " " + " ".join(rest)).strip()


def _extract_condition(sentence: str) -> str:
    m = _CONDITION_PAT.search(sentence)
    if m:
        return m.group(0).strip()
    m2 = re.search(r"\b(?:if|when|where|only if|provided that|whenever)\b(.{5,80})", sentence, re.I)
    if m2:
        return m2.group(1).strip().rstrip(".,;")
    return ""


def _extract_outcome(sentence: str) -> str:
    if _DENY_PAT.search(sentence):           return "Denied"
    if _AUDIT_OUTCOME_PAT.search(sentence):  return "Audit log written"
    if _ALLOW_PAT.search(sentence):          return "Allowed"
    return "Verified"


def _has_actionable_rule(sentence: str) -> bool:
    """Is this sentence long enough and verb-rich enough to encode a real rule?"""
    stripped = sentence.strip()
    if len(stripped) < 6:
        return False
    has_verb  = bool(_ACTION_PAT.search(stripped))
    has_modal = bool(re.search(
        r"\b(must|shall|should|only|cannot|not allowed|required|"
        r"verif|authoriz|approv|reject|may|needs? to)\b", stripped, re.I))
    # Full modal sentences
    if has_verb and has_modal:
        return True
    # Bare imperatives from AC columns (e.g. "Validate input", "Log audit events")
    if has_verb and len(stripped.split()) >= 2 and len(stripped) >= 8:
        return True
    return False


def _split_sentences(text: str) -> list[str]:
    raw = re.split(r"(?<=[.;!?])\s+|\n+", text)
    out = []
    for s in raw:
        s = s.strip()
        if not s:
            continue
        # also split on semicolons inline
        for part in re.split(r";\s*", s):
            part = part.strip()
            if part:
                out.append(part)
    return out


def _dedup_rules(rules: list[BusinessRule]) -> list[BusinessRule]:
    """Drop rules whose (action, actor) pair is identical to a previous one."""
    seen: set[tuple[str, str]] = set()
    out = []
    for r in rules:
        key = (r.action[:30].lower(), r.actor.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


# ─── Extractor base ─────────────────────────────────────────────────────────

class BaseExtractor(ABC):
    @abstractmethod
    def extract(self, requirement: Requirement) -> list[BusinessRule]: ...

    def extract_many(self, requirements: list[Requirement]) -> list[BusinessRule]:
        rules: list[BusinessRule] = []
        for req in requirements:
            rules.extend(self.extract(req))
        return rules


# ─── Rule-based extractor ────────────────────────────────────────────────────

class RuleBasedExtractor(BaseExtractor):
    """
    Pure regex + heuristic extractor — no external model dependency.
    Works offline, runs in milliseconds.
    """

    def extract(self, requirement: Requirement) -> list[BusinessRule]:
        rules: list[BusinessRule] = []

        # Process main content AND each acceptance criterion separately
        text_sources = [requirement.content] + requirement.acceptance_criteria

        for text in text_sources:
            for sentence in _split_sentences(text):
                if not _has_actionable_rule(sentence):
                    continue

                actor   = _extract_actor(sentence)
                action  = _extract_action(sentence)
                cond    = _extract_condition(sentence)
                outcome = _extract_outcome(sentence)
                rt      = _classify_rule_type(sentence)
                priority = (
                    "High"
                    if re.search(r"\b(critical|must|shall|mandatory|required)\b", sentence, re.I)
                    else "Medium"
                )

                rule = BusinessRule(
                    requirement_id=requirement.source_id,
                    actor=actor,
                    action=action,
                    condition=cond,
                    expected_outcome=outcome,
                    rule_type=rt,
                    priority=priority,
                    source_text=sentence,
                )
                rules.append(rule)

        return _dedup_rules(rules)


# ─── spaCy extractor (model-enhanced when available) ────────────────────────

class SpacyExtractor(BaseExtractor):

    def __init__(self, nlp):
        self._nlp      = nlp
        self._fallback = RuleBasedExtractor()

    def _actor_from_doc(self, doc) -> str:
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG"):
                return ent.text
        for token in doc:
            if token.dep_ in ("nsubj", "nsubjpass"):
                return token.text
        return _extract_actor(doc.text)

    def _action_from_doc(self, doc) -> str:
        for token in doc:
            if token.pos_ == "VERB" and token.dep_ in ("ROOT", "relcl", "advcl"):
                children = [c.text for c in token.children if c.dep_ in ("dobj", "pobj", "attr")]
                return (token.lemma_ + " " + " ".join(children)).strip()
        return _extract_action(doc.text)

    def extract(self, requirement: Requirement) -> list[BusinessRule]:
        rules: list[BusinessRule] = []
        text_sources = [requirement.content] + requirement.acceptance_criteria

        for text in text_sources:
            for sentence in _split_sentences(text):
                if not _has_actionable_rule(sentence):
                    continue
                try:
                    doc    = self._nlp(sentence[:500])
                    actor  = self._actor_from_doc(doc)
                    action = self._action_from_doc(doc)
                except Exception:
                    actor  = _extract_actor(sentence)
                    action = _extract_action(sentence)

                rule = BusinessRule(
                    requirement_id=requirement.source_id,
                    actor=actor,
                    action=action,
                    condition=_extract_condition(sentence),
                    expected_outcome=_extract_outcome(sentence),
                    rule_type=_classify_rule_type(sentence),
                    priority="High" if re.search(r"\b(critical|must|shall)\b", sentence, re.I) else "Medium",
                    source_text=sentence,
                )
                rules.append(rule)

        return _dedup_rules(rules)


# ─── Factory ─────────────────────────────────────────────────────────────────

def create_extractor(prefer_spacy: bool = True) -> BaseExtractor:
    if prefer_spacy:
        try:
            import spacy
            nlp = spacy.load("en_core_web_sm")
            return SpacyExtractor(nlp)
        except Exception:
            pass
        try:
            import spacy
            nlp = spacy.blank("en")
            return SpacyExtractor(nlp)
        except Exception:
            pass
    return RuleBasedExtractor()
