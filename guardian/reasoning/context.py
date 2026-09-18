"""
Evidence Selection & Context Packing
====================================
Turns the evidence store into the smallest context that can answer one
reasoning question.

This module is the enforcement point for "never send the whole
repository". The gateway only accepts pre-rendered blocks, and the only
sanctioned way to produce them is here — which means adding a new
reasoning task cannot accidentally introduce a repository dump.

Selection strategy:

  * start from the evidence that *defines* the task (crypto usages for
    quantum, behavioural evidence for a business policy);
  * pull in a bounded number of *related* items — same file, same
    function, same tag — because a lone evidence item rarely explains
    itself;
  * render as one compact line per item, never the raw snippet;
  * attach a source excerpt only when explicitly asked for, capped to a
    window around the relevant line.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Optional

from guardian.core.context import AnalysisContext
from guardian.evidence.models import Evidence, EvidenceType
from guardian.ust.models import USTFile, USTNodeType

log = logging.getLogger(__name__)

MAX_EVIDENCE_ITEMS = 40
MAX_RELATED_PER_ITEM = 6
MAX_SNIPPET_LINES = 40
MAX_UST_LINES = 30


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------
def select_related(store, seed: Iterable[Evidence], *,
                   limit: int = MAX_EVIDENCE_ITEMS,
                   types: Optional[Iterable[EvidenceType]] = None) -> list[Evidence]:
    """Expand a seed set with evidence sharing its file, symbol or tags."""
    seed_list = list(seed)
    chosen: dict[str, Evidence] = {e.id or e.fingerprint: e for e in seed_list}
    wanted_types = set(types) if types else None

    for item in seed_list:
        if len(chosen) >= limit:
            break
        neighbours = [n for n in store.by_file(item.file)
                      if (n.id or n.fingerprint) not in chosen]
        if wanted_types:
            neighbours = [n for n in neighbours if n.type in wanted_types]
        # prefer evidence in the same function, then the closest lines
        neighbours.sort(key=lambda n: (n.symbol != item.symbol, abs(n.line - item.line)))
        for neighbour in neighbours[:MAX_RELATED_PER_ITEM]:
            if len(chosen) >= limit:
                break
            chosen[neighbour.id or neighbour.fingerprint] = neighbour

    return list(chosen.values())[:limit]


def select_for_crypto_asset(context: AnalysisContext, crypto_evidence: Evidence,
                            limit: int = 12) -> list[Evidence]:
    """Evidence needed to reason about one cryptographic call site."""
    related = context.evidence.search(files=[crypto_evidence.file], limit=limit * 2)
    ranked = sorted(
        (e for e in related if e.id != crypto_evidence.id),
        key=lambda e: (
            0 if e.type in (EvidenceType.API_ENDPOINT, EvidenceType.DATABASE_OPERATION,
                            EvidenceType.AUTHORIZATION_CHECK) else 1,
            abs(e.line - crypto_evidence.line),
        ))
    return [crypto_evidence] + ranked[:limit - 1]


def select_for_policy(context: AnalysisContext, behaviour: Iterable[Evidence],
                      limit: int = 20) -> list[Evidence]:
    """Evidence needed to judge one business policy."""
    seed = list(behaviour)[:limit]
    return select_related(context.evidence, seed, limit=limit,
                          types=(EvidenceType.BEHAVIOR, EvidenceType.MISSING_CONTROL,
                                 EvidenceType.AUTHORIZATION_CHECK,
                                 EvidenceType.API_ENDPOINT,
                                 EvidenceType.DATABASE_OPERATION,
                                 EvidenceType.CODE_STRUCTURE))


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
def render_evidence(items: Iterable[Evidence], *, limit: int = MAX_EVIDENCE_ITEMS) -> str:
    """One line per evidence item — IDs, locations and facts, no source."""
    lines: list[str] = []
    for item in list(items)[:limit]:
        if not item.id:
            continue      # unpublished evidence has no citable ID
        line = item.to_context_line()
        if item.description:
            line += f"\n    {item.description[:300]}"
        lines.append(f"- {line}")
    return "\n".join(lines)


def render_ust_context(ust_file: Optional[USTFile], *, around_line: int = 0,
                       function_name: str = "", limit: int = MAX_UST_LINES) -> str:
    """Structural facts about the relevant function, from the UST.

    This is what lets the model reason about *behaviour* — which calls
    happen, whether an authorization check exists, what the parameters
    are — without reading the file.
    """
    if ust_file is None:
        return ""

    target = None
    if function_name:
        target = next((f for f in ust_file.functions() if f.name == function_name), None)
    if target is None and around_line:
        target = ust_file.function_at(around_line)

    lines: list[str] = [f"file: {ust_file.path} ({ust_file.language}, "
                        f"parsed by {ust_file.parser})"]
    if ust_file.imports:
        lines.append(f"imports: {', '.join(ust_file.imports[:15])}")

    if target is None:
        for node in ust_file.nodes[:limit]:
            lines.append(f"  {node.describe()}")
        return "\n".join(lines[:limit + 2])

    lines.append(f"function: {target.symbol or target.name}"
                 f"({', '.join(target.parameters)})"
                 f"  [lines {target.span.start_line}-{target.span.end_line}]")

    body = [n for n in ust_file.nodes
            if n.enclosing_function == target.name and n is not target]
    has_authz = any("authorization_check" in n.business_tags for n in body)
    lines.append(f"  authorization checks in this function: "
                 f"{'yes' if has_authz else 'none found'}")

    for node in body[:limit]:
        detail = node.describe()
        markers = []
        if node.security_tags:
            markers.append("/".join(node.security_tags))
        if node.crypto_tags:
            markers.append("/".join(t for t in node.crypto_tags if t != "crypto"))
        if node.business_tags:
            markers.append("/".join(node.business_tags))
        if node.data_flow.get("tainted"):
            markers.append("TAINTED")
        if node.control_flow.get("in_conditional"):
            markers.append("inside conditional")
        lines.append(f"  {detail}" + (f"  <{'; '.join(markers)}>" if markers else ""))

    return "\n".join(lines)


def render_snippet(context: AnalysisContext, file: str, line: int,
                   window: int = 8, max_lines: int = MAX_SNIPPET_LINES) -> str:
    """A bounded source window. Used sparingly — the UST block is usually
    a better and much smaller answer to "what does this code do"."""
    if not file:
        return ""
    path = Path(context.repository.root) / file
    text = context.repository.read(path)
    if not text:
        return ""
    lines = text.splitlines()
    start = max(0, line - window - 1)
    end = min(len(lines), line + window)
    window_lines = lines[start:end][:max_lines]
    numbered = [f"{start + i + 1:>5}| {content}" for i, content in enumerate(window_lines)]
    return "\n".join(numbered)


def render_business_context(context: AnalysisContext, *, policies: Iterable = (),
                            domain: str = "") -> str:
    """Domain verdict + the policies relevant to this task."""
    parts: list[str] = []
    if domain:
        parts.append(f"detected business domain: {domain}")
    policy_lines = []
    for policy in list(policies)[:15]:
        text = getattr(policy, "to_context_line", None)
        policy_lines.append(f"- {text()}" if callable(text) else f"- {policy}")
    if policy_lines:
        parts.append("POLICIES:\n" + "\n".join(policy_lines))
    return "\n".join(parts)


def evidence_id_set(items: Iterable[Evidence]) -> set[str]:
    """The IDs a model is permitted to cite for this task."""
    return {item.id for item in items if item.id}
