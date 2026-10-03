import sys
import os
import re
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.abspath("."))

from guardian.intent.ingestion.document_loader import DocumentLoader
from guardian.intent.parser.rule_parser import RuleParser
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.agents.business.agent import _STOP_WORDS

_COMMON_PROG_WORDS = {
    "able", "available", "never", "have", "has", "had", "one", "two", "three", "using", "used", "uses", "use",
    "appropriate", "strategy", "operation", "operations", "protected", "check", "checking", "checks", "checked",
    "update", "updates", "updating", "updated", "become", "becomes", "must", "shall", "should", "could", "may",
    "can", "will", "would", "make", "makes", "making", "take", "takes", "taking", "get", "gets", "getting",
    "set", "sets", "setting", "return", "returns", "returning", "call", "calls", "calling", "create", "creates",
    "creating", "process", "processes", "processing", "run", "runs", "running", "execute", "executes", "executing",
    "value", "values", "data", "type", "types", "item", "items", "list", "lists", "array", "arrays", "object",
    "objects", "string", "strings", "number", "numbers", "boolean", "code", "function", "method", "class", "module",
    "package", "service", "handler", "manager", "helper", "util", "utils", "file", "files", "path", "paths",
    "name", "names", "id", "ids", "api", "v1", "v2", "backend", "frontend", "src", "component", "components",
    "route", "endpoint", "tree", "json", "scan", "agentic", "traceability", "state", "curated", "defaultdata",
    "mindmap", "generic_action", "generic_control", "generic", "action", "control", "status", "score", "matched",
    "title", "area", "rule_id", "policy_id", "requirement", "expected", "behavior", "conditions", "suggested",
    "validation", "what", "why", "how", "none", "null", "undefined", "true", "false", "review", "detected", "target",
    "report", "reports", "download", "scans", "scan", "server", "client", "supplied", "applicable"
}

_EXTENDED_STOP_WORDS = _STOP_WORDS | _COMMON_PROG_WORDS

def test_extract_concept_groups(f: dict):
    text_parts = [
        str(f.get("original_requirement") or f.get("rule") or f.get("title") or ""),
        str(f.get("expected_implementation_behavior") or ""),
        str(f.get("violation_conditions") or ""),
        str(f.get("compliant_conditions") or ""),
        str(f.get("area") or ""),
        str(f.get("required_control") or ""),
    ]
    combined = " ".join(text_parts).lower()
    words = [w for w in re.findall(r"[a-z0-9_]{3,}", combined) if w not in _EXTENDED_STOP_WORDS and not w.isdigit()]

    pairs = []
    seen = set()
    for i in range(len(words)):
        for j in range(i + 1, min(i + 6, len(words))):
            w1, w2 = words[i], words[j]
            if w1 != w2:
                pair = tuple(sorted([w1, w2]))
                if pair not in seen:
                    seen.add(pair)
                    pairs.append(pair)
    return pairs

def test_rank_workspace_candidates(f: dict[str, Any], ws_profiles: list[Any]) -> list[Any]:
    concept_pairs = test_extract_concept_groups(f)
    single_keywords = [w for w in re.findall(r"[a-z0-9_]{3,}", " ".join([
        str(f.get("original_requirement") or ""),
        str(f.get("title") or ""),
        str(f.get("area") or "")
    ]).lower()) if w not in _EXTENDED_STOP_WORDS and not w.isdigit()]

    if not concept_pairs and not single_keywords:
        return []

    policy_act = str(f.get("matched_action") or f.get("action") or "").lower()
    policy_ctrl = str(f.get("matched_control") or f.get("control") or "").lower()
    source_f = str(f.get("source_file") or f.get("file") or "").lower()
    is_frontend_policy = any("frontend" in x or ".tsx" in x or ".jsx" in x or ".ts" in x or ".js" in x for x in (policy_act, policy_ctrl, source_f))

    scored_candidates = []
    for wp in ws_profiles:
        wp_file_lower = wp.file.lower()
        if not is_frontend_policy and (wp_file_lower.startswith("frontend/") or "/components/" in wp_file_lower or wp_file_lower.endswith((".tsx", ".jsx", ".ts", ".js"))):
            continue

        blob = f"{wp.file} {wp.function_name} {wp.code_snippet}".lower()
        has_infra_term = any(infra in blob for infra in ["embedder", "chatbot", "vector_store", "ollama", "openai", "langchain", "llm", "tokenizer", "rag", "embeddings", "embedding"])
        if has_infra_term:
            continue

        blob_words = set(re.findall(r"[a-z0-9_]{3,}", blob))

        fn_lower = wp.function_name.lower()
        matched_act_str = str(f.get("matched_action") or f.get("action") or "").lower()
        matched_fn_str = str(f.get("matched_function") or f.get("function") or "").lower()
        is_exact_matched_fn = bool(
            (matched_act_str and matched_act_str not in ("generic_action", "n/a", "none") and (matched_act_str in fn_lower or fn_lower in matched_act_str)) or
            (matched_fn_str and matched_fn_str not in ("n/a", "none", "unknown") and (matched_fn_str in fn_lower or fn_lower in matched_fn_str))
        )

        pair_hits = sum(1 for w1, w2 in concept_pairs if w1 in blob_words and w2 in blob_words)
        single_hits = sum(1 for kw in single_keywords if kw in blob_words)

        if not is_exact_matched_fn:
            if concept_pairs and pair_hits < 1:
                continue
            if not concept_pairs and single_hits < 2:
                continue

        fn_hits = sum(1 for kw in single_keywords if kw in fn_lower)
        score = (10.0 if is_exact_matched_fn else 0.0) + (pair_hits * 5.0) + (single_hits * 1.0) + (fn_hits * 2.0) + (getattr(wp, "business_score", 0.0) * 0.1)
        if score > 0:
            scored_candidates.append((score, wp))

    scored_candidates.sort(key=lambda x: x[0], reverse=True)
    return [cand for _, cand in scored_candidates[:2]]

pdf_path = Path("data/business_docs/DV_Bookshop_Business_Rules.pdf")
loader = DocumentLoader(docs_dir=pdf_path.parent)
reqs = loader.extract_actionable_requirements()
parser = RuleParser()
rules = parser.parse_all(reqs)

ws_profiles = RuleMatcher._profiles_from_workspace(Path.cwd())

for rule in rules:
    f = {
        "rule_id": rule.rule_id,
        "title": rule.title,
        "original_requirement": rule.requirement_text,
        "expected_implementation_behavior": rule.expected_implementation_behavior,
        "violation_conditions": rule.violation_conditions,
        "compliant_conditions": rule.compliant_conditions,
        "area": rule.area,
        "required_control": rule.required_control or rule.control,
        "matched_action": "generic_action",
        "matched_control": "generic_control",
        "evidence_terms": rule.evidence_terms,
    }
    pairs = test_extract_concept_groups(f)
    cands = test_rank_workspace_candidates(f, ws_profiles)
    print(f"=== {rule.rule_id}: {rule.title} ===")
    print("Concept Pairs:", pairs[:6])
    print(f"Candidates ({len(cands)}):")
    for c in cands:
        print(f"  - {c.file}:{c.line} ({c.function_name})")
    print()
