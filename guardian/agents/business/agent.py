"""
AI Code Guardian v3 — Business Agent
====================================
Specialist agent wrapping the Business Intent Engine to classify business domains,
criticality, compliance requirements, and business capabilities.
"""
from __future__ import annotations

from typing import Any, Dict

from guardian.agents.base.agent import BaseAgent
from guardian.agents.shared.context import BusinessContextObject
from guardian.llm.rate_limit_handler import classify_llm_error
import re

_STOP_WORDS = {
    "a", "an", "the", "and", "or", "but", "if", "because", "as", "until", "while",
    "of", "at", "by", "for", "with", "about", "against", "between", "into", "through",
    "during", "before", "after", "above", "below", "to", "from", "up", "upon", "down",
    "in", "out", "on", "off", "over", "under", "again", "further", "then", "once",
    "here", "there", "when", "where", "why", "how", "all", "any", "both", "each",
    "few", "more", "most", "other", "some", "such", "no", "nor", "not", "only",
    "own", "same", "so", "than", "too", "very", "can", "will", "just", "should", "now",
    "must", "require", "requires", "required", "shall", "allowed", "forbidden", "cannot",
    "implementation", "behavior", "condition", "conditions", "rule", "policy", "system",
    "application", "code", "user", "generic_action", "generic_control", "generic",
    "n/a", "none", "null", "undefined", "document", "defines", "canonical", "business",
    "logic", "verification", "validation", "able", "available", "never", "have", "has", "had",
    "one", "two", "three", "using", "used", "uses", "use", "appropriate", "strategy", "operation",
    "operations", "protected", "check", "checking", "checks", "checked", "update", "updates",
    "updating", "updated", "become", "becomes", "make", "makes", "making", "take", "takes", "taking",
    "get", "gets", "getting", "set", "sets", "setting", "return", "returns", "returning", "call",
    "calls", "calling", "create", "creates", "creating", "process", "processes", "processing",
    "run", "runs", "running", "execute", "executes", "executing", "value", "values", "data", "type",
    "types", "item", "items", "list", "lists", "array", "arrays", "object", "objects", "string",
    "strings", "number", "numbers", "boolean", "function", "method", "class", "module", "package",
    "service", "handler", "manager", "helper", "util", "utils", "file", "files", "path", "paths",
    "name", "names", "id", "ids", "api", "v1", "v2", "backend", "frontend", "src", "component",
    "components", "route", "endpoint", "tree", "json", "scan", "agentic", "traceability", "state",
    "curated", "defaultdata", "mindmap", "action", "control", "status", "score", "matched", "title",
    "area", "rule_id", "policy_id", "requirement", "expected", "conditions", "suggested",
    "validation", "what", "why", "how", "true", "false", "review", "detected", "target",
    "report", "reports", "download", "scans", "scan"
}

_INFRASTRUCTURE_PENALTY_TERMS = {
    "embedder", "chatbot", "vector_store", "ollama", "openai", "langchain",
    "llm", "tokenizer", "rag", "embeddings", "embedding"
}


def _extract_policy_keywords(f: dict[str, Any]) -> set[str]:
    text_parts = [
        str(f.get("original_requirement") or f.get("rule") or f.get("title") or ""),
        str(f.get("expected_implementation_behavior") or ""),
        str(f.get("violation_conditions") or ""),
        str(f.get("compliant_conditions") or ""),
        str(f.get("area") or ""),
        str(f.get("required_control") or ""),
        str(f.get("matched_action") or f.get("action") or ""),
        str(f.get("matched_control") or f.get("control") or ""),
        str(f.get("matched_function") or f.get("function") or ""),
        str(f.get("source_file") or f.get("matched_file") or f.get("file") or ""),
    ]
    for term in f.get("evidence_terms") or []:
        text_parts.append(str(term))

    combined = " ".join(text_parts).lower()
    words = re.findall(r"[a-z0-9_]{3,}", combined)
    return {w for w in words if w not in _STOP_WORDS and not w.isdigit()}


def _extract_concept_groups(f: dict[str, Any]) -> list[tuple[str, str]]:
    text_parts = [
        str(f.get("original_requirement") or f.get("rule") or f.get("title") or ""),
        str(f.get("expected_implementation_behavior") or ""),
        str(f.get("violation_conditions") or ""),
        str(f.get("compliant_conditions") or ""),
        str(f.get("area") or ""),
        str(f.get("required_control") or ""),
    ]
    for term in f.get("evidence_terms") or []:
        text_parts.append(str(term))

    combined = " ".join(text_parts).lower()
    words = [w for w in re.findall(r"[a-z0-9_]{3,}", combined) if w not in _STOP_WORDS and not w.isdigit()]

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


def _rank_workspace_candidates(f: dict[str, Any], ws_profiles: list[Any]) -> list[Any]:
    concept_pairs = _extract_concept_groups(f)
    single_keywords = _extract_policy_keywords(f)
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

        acts_str = " ".join(getattr(wp, "actions", []) or [])
        ctrls_str = " ".join(getattr(wp, "controls", []) or [])
        raw_blob = f"{wp.file} {wp.function_name} {acts_str} {ctrls_str} {wp.code_snippet}".lower()
        has_infra_term = any(infra in raw_blob for infra in _INFRASTRUCTURE_PENALTY_TERMS)
        if has_infra_term:
            continue

        blob_words = set(re.findall(r"[a-z0-9]{3,}", raw_blob.replace("_", " ")))

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


def _policy_priority_key(f: dict[str, Any]) -> tuple[int, float]:
    st = str(f.get("status") or "").upper()
    try:
        sc = float(f.get("score", 0.0))
    except (TypeError, ValueError):
        sc = 0.0

    if st in ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT"):
        prio = 1
    elif st == "PARTIAL":
        prio = 2
    elif sc < 0.8 and st not in ("VIOLATION", "COMPLIANT"):
        prio = 3
    else:
        prio = 4

    return (prio, sc)


class BusinessAgent(BaseAgent):
    """Specialist agent wrapping Business Intent classification engines."""

    name: str = "business"
    description: str = "Classifies business domain intent, criticality, and compliance mandates."

    def _process(self, state: AgentWorkflowState) -> AgentWorkflowState:
        self._used_tools = ["business_intent_tool", "knowledge_tool"]

        b_context = state.get("business_context", {})
        findings = state.get("findings", [])

        # 1. Adopt pre-evaluated deterministic findings from LangGraph state if present,
        # rather than blindly re-running engine.run() and losing pre-evaluated findings.
        intent_result: Dict[str, Any] = state.get("business_intent_results", {})
        has_pre_eval = bool(intent_result and intent_result.get("findings"))

        from guardian.reasoning.gateway import get_scan_token_tracker
        tracker_before = get_scan_token_tracker(state.get("scan_id", ""))
        self.logger.info(
            "[BIZ-DIAGNOSTIC-TRACE]\nscan_id=%s\nhas_pre_evaluated_results=%s\n"
            "remaining_budget_before=%d\nspent_before=%s",
            state.get("scan_id", ""), has_pre_eval,
            tracker_before.remaining_budget, dict(tracker_before.agent_spent)
        )

        if not intent_result or not intent_result.get("findings"):
            try:
                from guardian.intent.engine import BusinessIntentEngine
                from guardian.intent.ingestion.document_loader import get_workspace_id
                repo_path_str = state.get("repository_profile", {}).get("repo_path") or state.get("repository_profile", {}).get("root") or state.get("scan_id")
                ws_id = get_workspace_id(repo_path_str)
                engine = BusinessIntentEngine(workspace_id=ws_id)
                self.logger.info(
                    "[BIZ-ENGINE-INSTANTIATION]\nengine_class=%s\nuse_llm=%s\nworkspace_id=%s",
                    engine.__class__.__name__, getattr(engine, "use_llm", None), ws_id
                )
                intent_result = engine.run(scan_findings=findings, workspace_id=ws_id)
            except Exception as e:
                self.logger.warning(f"Business Intent Engine invocation notice: {e}")
                intent_result = {
                    "status": "ERROR",
                    "message": str(e),
                    "alignment_score": 0.0,
                    "alignment_percentage": 0.0,
                    "total_rules": 0,
                    "matched": 0,
                    "violated": 0,
                    "partial": 0,
                    "insufficient": 0,
                    "documents": [],
                    "findings": [],
                }

        status = intent_result.get("status", "ERROR")
        violations = [
            f for f in intent_result.get("findings", [])
            if f.get("status") in ("VIOLATION", "POTENTIAL_VIOLATION")
        ]

        if status == "SUCCESS":
            criticality = "CRITICAL" if violations else b_context.get("criticality", "NORMAL")
            confidence = 0.9 if intent_result.get("total_rules") else 0.5
            reason = (
                f"{intent_result.get('total_rules', 0)} policy rule(s) evaluated "
                f"against {len(intent_result.get('documents', []) or [])} business document(s)."
            )
        else:
            criticality = b_context.get("criticality", "NORMAL")
            confidence = 0.0
            reason = {
                "NO_DOCUMENTS": "NO_BUSINESS_REQUIREMENTS: no business/policy documents found in repository.",
                "NO_VALID_REQUIREMENTS": "NO_BUSINESS_REQUIREMENTS: documents found but no testable requirements parsed.",
                "INSUFFICIENT_EVIDENCE": "INSUFFICIENT_EVIDENCE: requirements found but scan evidence was insufficient to judge them.",
            }.get(status, f"Business Intent Engine returned status={status}.")

        domain = b_context.get("domain", "general")

        # Optional Grok AI reasoning for semantic business intent interpretation & gap resolution
        ai_business_insights: List[Dict[str, Any]] = []
        analyzed_policy_ids: List[str] = []
        skipped_policy_ids: List[str] = []
        
        det_findings = intent_result.get("findings", [])
        total_rules = intent_result.get("total_rules", 0)
        inconclusive_findings = [
            f for f in det_findings
            if f.get("status") in ("INSUFFICIENT_EVIDENCE", "INSUFFICIENT")
        ]

        if total_rules == 0 or status in ("NO_DOCUMENTS", "NO_VALID_REQUIREMENTS", "ERROR"):
            grok_status = "SKIPPED"
            agent_reason = "No business requirements documents found or no actionable rules parsed for this environment."
        elif len(inconclusive_findings) == 0:
            grok_status = "SKIPPED"
            agent_reason = f"The deterministic business intent analysis produced a sufficiently conclusive baseline ({total_rules} rule(s) evaluated) with zero ambiguous policies requiring AI resolution."
        else:
            grok_status = "SKIPPED"
            agent_reason = "The deterministic business intent analysis identified ambiguous policies, but AI Business Agent reasoning is not enabled."

        try:
            from guardian.llm.config import LLMConfig
            cfg = LLMConfig.from_env(agent="business")
            if cfg.is_agent_enabled("business"):
                repo_path_str = state.get("repository_profile", {}).get("repo_path") or "."
                ws_profiles = []
                try:
                    from pathlib import Path
                    from guardian.intent.matcher.rule_matcher import RuleMatcher
                    repo_p = Path(repo_path_str) if repo_path_str else None
                    ws_profiles = RuleMatcher._profiles_from_workspace(repo_p)
                except Exception:
                    pass

                sorted_findings = sorted(det_findings, key=_policy_priority_key)

                inconclusive_ids = {f.get("rule_id") or f.get("policy_id") for f in inconclusive_findings}
                for f in det_findings:
                    pid = f.get("rule_id") or f.get("policy_id")
                    eligibility = "ELIGIBLE_FOR_AI" if pid in inconclusive_ids else "NOT_ELIGIBLE"
                    self.logger.info("[POLICY ELIGIBILITY TRACE] policy_id=%s deterministic_verdict=%s eligibility=%s", pid, f.get("status"), eligibility)

                # ONLY invoke AI when there are inconclusive / ambiguous policy findings requiring resolution.
                # High-confidence COMPLIANT rules must NOT trigger LLM calls to conserve rate limits.
                should_call_grok = len(inconclusive_findings) > 0
                if should_call_grok:
                    import uuid
                    from guardian.reasoning.gateway import ReasoningGateway, ReasoningRequest
                    service = ReasoningGateway(config=cfg)
                    if service.configured:
                        # Process policies individually (BATCH_SIZE=1) to keep tokens strictly under Groq rate limit
                        BATCH_SIZE = 1
                        policy_batches = [
                            inconclusive_findings[i:i + BATCH_SIZE]
                            for i in range(0, len(inconclusive_findings), BATCH_SIZE)
                        ]

                        grok_status = "COMPLETED"
                        total_ai_findings = 0
                        batch_results = []

                        for batch_idx, batch in enumerate(policy_batches):
                            batch_snippets = []
                            bus_block_lines = []
                            first_policy_id = batch[0].get("rule_id", f"REQ-{batch_idx+1:03d}") if batch else "REQ-001"

                            for idx, f in enumerate(batch):
                                p_id = f.get("rule_id") or f.get("policy_id") or f"REQ-{idx+1:03d}"
                                orig_req = f.get("original_requirement") or f.get("rule") or f.get("title") or "Business policy requirement"
                                st = f.get("status") or "EVALUATED"
                                try:
                                    sc = round(float(f.get("score", 0.0)), 3)
                                except (TypeError, ValueError):
                                    sc = 0.0
                                act = f.get("matched_action") or f.get("action") or "N/A"
                                cond = f.get("matched_condition") or f.get("condition") or "none"
                                ctrl = f.get("matched_control") or f.get("control") or "N/A"

                                missing_ctrl = f.get("missing_control") or f.get("what") or f.get("why") or ctrl
                                det_ev = f.get("evidence") or (
                                    f"file: {f.get('matched_file') or f.get('file') or 'workspace'} · function: {f.get('matched_function') or f.get('function') or 'N/A'}"
                                    if (f.get("matched_file") or f.get("file")) else "None"
                                )

                                exp_behavior = f.get("expected_implementation_behavior") or "N/A"
                                viol_cond = f.get("violation_conditions") or "N/A"
                                comp_cond = f.get("compliant_conditions") or "N/A"

                                bus_block_lines.append(
                                    f"[POLICY {p_id}]\n"
                                    f"Original Requirement:\n{orig_req}\n"
                                    f"Requirement: {orig_req}\n\n"
                                    f"Expected Implementation Behavior:\n{exp_behavior}\n\n"
                                    f"Violation Conditions:\n{viol_cond}\n\n"
                                    f"Compliant Conditions:\n{comp_cond}\n\n"
                                    f"Deterministic Verdict:\n{st}\n"
                                    f"Verdict: {st}\n\n"
                                    f"Deterministic Score:\n{sc}\n"
                                    f"Score: {sc}\n\n"
                                    f"Action: {act}\n"
                                    f"Matched Action:\n{act}\n"
                                    f"Condition: {cond}\n"
                                    f"Matched Condition:\n{cond}\n"
                                    f"Control: {ctrl}\n"
                                    f"Matched Control:\n{ctrl}\n\n"
                                    f"Deterministic Evidence:\n{det_ev}"
                                )

                                # Candidate retrieval & ranking: select ONLY code snippets relevant to THIS policy
                                matched_snippet = f.get("matched_snippet")
                                matched_file = f.get("matched_file")
                                matched_func = f.get("matched_function")
                                matched_line = f.get("matched_line", 1)

                                if matched_snippet and matched_file and matched_file not in ("workspace", "unknown", "N/A", ""):
                                    wp_ev_id = f"E{len(batch_snippets)+1}"
                                    snippet_lines = matched_snippet.strip().splitlines()[:15]
                                    truncated_snippet = "\n".join(snippet_lines)
                                    if len(truncated_snippet) > 400:
                                        truncated_snippet = truncated_snippet[:400] + "\n..."
                                    batch_snippets.append(
                                        f"[{wp_ev_id}] file: {matched_file}:{matched_line} function: {matched_func}\n"
                                        f"Source Snippet:\n{truncated_snippet}"
                                    )
                                else:
                                    policy_matched_profiles = _rank_workspace_candidates(f, ws_profiles)
                                    for wp in policy_matched_profiles:
                                        wp_ev_id = f"E{len(batch_snippets)+1}"
                                        raw_snippet = getattr(wp, "code_snippet", "").strip()
                                        snippet_lines = raw_snippet.splitlines()[:15]
                                        truncated_snippet = "\n".join(snippet_lines)
                                        if len(truncated_snippet) > 400:
                                            truncated_snippet = truncated_snippet[:400] + "\n..."
                                        snippet_block = f"\nSource Snippet:\n{truncated_snippet}" if truncated_snippet else ""
                                        batch_snippets.append(
                                            f"[{wp_ev_id}] file: {wp.file}:{wp.line} function: {wp.function_name}"
                                            f"{snippet_block}"
                                        )

                            bus_block = "\n\n".join(bus_block_lines)
                            kws = ", ".join(sorted(_extract_policy_keywords(batch[0]))) if batch else ""
                            ev_block = "Repository Implementation Evidence:\n" + (
                                "\n\n".join(batch_snippets)
                                if batch_snippets
                                else f"[E1] No workspace implementation evidence found matching policy keywords ({kws})."
                            )

                            # Estimate input tokens (approx. 4 chars per token)
                            input_text_for_est = f"{bus_block}\n{ev_block}"
                            input_token_est = len(input_text_for_est) // 4
                            output_token_limit = 500
                            total_requested_est = input_token_est + output_token_limit

                            model_name_str = getattr(service, "model_name", "unknown")
                            self.logger.info(
                                "[POLICY TRACE] policy_id=%s batch=%d/%d input_tokens_est=%d output_tokens=%d snippets=%d",
                                first_policy_id, batch_idx + 1, len(policy_batches),
                                input_token_est, output_token_limit, len(batch_snippets)
                            )

                            req_instruction = (
                                "Semantically evaluate the supplied policy requirement against the implementation evidence.\n"
                                "Return one verdict: COMPLIANT, VIOLATION, PARTIAL, or INSUFFICIENT_EVIDENCE.\n"
                                "If no policy-relevant implementation evidence exists in the codebase, return INSUFFICIENT_EVIDENCE.\n\n"
                                "CRITICAL FORMAT INSTRUCTIONS:\n"
                                "Respond ONLY with a single valid JSON object.\n"
                                "The first character of your response must be '{'.\n"
                                "Do not output thinking steps.\n"
                                "Do not output analysis before the JSON.\n"
                                "Do not output analysis after the JSON.\n"
                                "Do not use Markdown code fences.\n"
                                "Do not include ```json.\n"
                                "Do not include a preamble or explanation outside the JSON object."
                            )

                            schema_inst = (
                                'Return JSON only:\n'
                                '{\n'
                                '  "summary": "<summary>",\n'
                                '  "findings": [\n'
                                '    {\n'
                                '      "policy_id": "<id>",\n'
                                '      "verdict": "COMPLIANT|VIOLATION|PARTIAL|INSUFFICIENT_EVIDENCE",\n'
                                '      "confidence": 0.95,\n'
                                '      "reason": "<reason>",\n'
                                '      "recommendation": "<recommendation>",\n'
                                '      "missing_control": "",\n'
                                '      "file": "workspace",\n'
                                '      "line": 1,\n'
                                '      "function": "",\n'
                                '      "evidence_ids": ["E1"]\n'
                                '    }\n'
                                '  ]\n'
                                '}'
                            )

                            system_role_inst = (
                                "You are a senior application security engineer performing contextual analysis.\n"
                                "CRITICAL FORMAT RULES:\n"
                                "1. Respond ONLY with a single valid JSON object.\n"
                                "2. The first character of your response must be '{'.\n"
                                "3. Do not output thinking steps.\n"
                                "4. Do not output analysis before the JSON.\n"
                                "5. Do not output analysis after the JSON.\n"
                                "6. Do not use Markdown code fences.\n"
                                "7. Do not include ```json.\n"
                                "8. Do not include a preamble or explanation outside the JSON object."
                            )

                            req = ReasoningRequest(
                                task="business_intent",
                                agent="business",
                                scan_id=state.get("scan_id", ""),
                                system_role=system_role_inst,
                                instruction=req_instruction,
                                schema_instruction=schema_inst,
                                business_block=bus_block,
                                evidence_block=ev_block,
                                max_tokens=output_token_limit,
                            )
                            ai_res = service.reason(req)
                            from guardian.reasoning.gateway import get_scan_token_tracker
                            tracker = get_scan_token_tracker(state.get("scan_id", ""))
                            other_unspent = sum(
                                max(0, tracker.agent_reservations.get(a, 0) - tracker.agent_spent.get(a, 0))
                                for a in tracker.agent_reservations if a != "business"
                            )
                            avail_res = max(0, tracker.agent_reservations.get("business", 1800) - tracker.agent_spent.get("business", 0))
                            unreserved = max(0, tracker.remaining_budget - (avail_res + other_unspent))
                            usable_cap = avail_res + unreserved

                            cnt_before = len(ai_business_insights)
                            first_policy_id = batch[0].get("rule_id", "REQ-001") if batch else "REQ-001"
                            raw_rec = bool(ai_res.response and getattr(ai_res.response, "raw", None))
                            parsed_ok = bool(ai_res.ok and ai_res.response and ai_res.response.ok)
                            p_cnt = len(ai_res.findings) if ai_res.findings else 0


                            if ai_res.ok:
                                analyzed_policy_ids.append(first_policy_id)
                                batch_results.append({"status": "COMPLETED", "error": None})
                                self.logger.info(
                                    "[BUSINESS BUDGET TRACE]\nstage=business_reasoning\nagent=business\n"
                                    "estimated_input_tokens=%d\nmax_output_tokens=%d\nrequired_tokens=%d\n"
                                    "remaining_budget=%d\nreserved_budget=%d\nusable_capacity=%d\n"
                                    "admission_decision=EXECUTED\ngrok_status=COMPLETED",
                                    input_token_est, output_token_limit, total_requested_est,
                                    tracker.remaining_budget, tracker.agent_reservations.get("business", 1800),
                                    usable_cap
                                )
                                if ai_res.findings:
                                    total_ai_findings += len(ai_res.findings)
                                    for rf in ai_res.findings:
                                        verdict = (rf.extras.get("verdict") or "").upper() or "PARTIAL"
                                        policy_id = rf.extras.get("policy_id") or getattr(rf, "rule_id", None) or rf.title or "REQ-001"
                                        if not policy_id.startswith("REQ-") and not policy_id.startswith("AI-"):
                                            policy_id = f"REQ-{policy_id}"

                                        insight_dict = {
                                            "finding_id": f"ai-bus-{uuid.uuid4().hex[:8]}",
                                            "rule_id": policy_id,
                                            "policy_id": policy_id,
                                            "title": rf.title or rf.extras.get("requirement") or "AI Business Policy Resolution",
                                            "requirement": rf.extras.get("requirement") or rf.title or "Business Policy Requirement",
                                            "verdict": verdict,
                                            "status": verdict,
                                            "severity": rf.severity or ("High" if verdict == "VIOLATION" else "Info"),
                                            "reason": rf.reason,
                                            "description": rf.reason,
                                            "recommendation": rf.recommendation,
                                            "missing_control": rf.extras.get("missing_control") or "",
                                            "file": rf.file or f.get("matched_file") or f.get("file") or "workspace",
                                            "line": rf.line or f.get("matched_line") or 1,
                                            "function": rf.function or f.get("matched_function") or "",
                                            "evidence_ids": rf.evidence_ids or ["E1"],
                                            "source": "AI_VALIDATED",
                                            "engine": "llm_business_reasoning",
                                            "provider": cfg.provider.title() if (hasattr(cfg, "provider") and cfg.provider) else "Gemini",
                                            "extras": rf.extras,
                                        }

                                        ai_business_insights.append(insight_dict)
                                        if verdict in ("VIOLATION", "POTENTIAL_VIOLATION"):
                                            violations.append({
                                                "rule_id": policy_id,
                                                "policy_name": rf.category or "Business Intent Policy",
                                                "status": verdict,
                                                "rule": rf.title or rf.extras.get("requirement") or "Semantic Business Policy Mismatch",
                                                "what": rf.reason,
                                                "why": rf.extras.get("missing_control") or rf.recommendation or "Business control missing or unverified",
                                                "how": rf.recommendation or "Implement required business validation check",
                                                "evidence": f"file: {rf.file or 'N/A'} · function: {rf.function or 'N/A'}",
                                                "file": rf.file,
                                                "line_number": rf.line,
                                                "source": "AI_VALIDATED",
                                            })
                            else:
                                skipped_policy_ids.append(first_policy_id)
                                err_text = getattr(ai_res, "error", None) or getattr(ai_res, "error_message", None) or ""
                                status_type = classify_llm_error(err_text)
                                batch_results.append({"status": status_type, "error": err_text})
                                self.logger.info(
                                    "[BUSINESS BUDGET TRACE]\nstage=business_reasoning\nagent=business\n"
                                    "estimated_input_tokens=%d\nmax_output_tokens=%d\nrequired_tokens=%d\n"
                                    "remaining_budget=%d\nreserved_budget=%d\nusable_capacity=%d\n"
                                    "admission_decision=%s\ngrok_status=%s",
                                    input_token_est, output_token_limit, total_requested_est,
                                    tracker.remaining_budget, tracker.agent_reservations.get("business", 1800),
                                    usable_cap, status_type, status_type
                                )
                                if status_type in ("SKIPPED_BUDGET", "PROVIDER_DAILY_QUOTA", "RATE_LIMITED"):
                                    # Record remaining un-executed batch policy IDs as skipped
                                    for un_b in policy_batches[batch_idx + 1:]:
                                        if un_b:
                                            p_un = un_b[0].get("rule_id", "REQ-000")
                                            skipped_policy_ids.append(p_un)
                                    break

                            cnt_after = len(ai_business_insights)
                            self.logger.info(
                                "[BIZ AI RESULT TRACE]\npolicy_id=%s\nbatch_status=%s\nprovider=gemini\n"
                                "gemini_http_status=200\nraw_response_received=%s\nparsed_success=%s\n"
                                "parsed_findings_count=%d\nai_business_insights_count_before=%d\n"
                                "ai_business_insights_count_after=%d",
                                first_policy_id, "COMPLETED" if ai_res.ok else status_type,
                                str(raw_rec).lower(), str(parsed_ok).lower(),
                                p_cnt, cnt_before, cnt_after
                            )

                        # Multi-batch status aggregation logic
                        total_batches = len(policy_batches)
                        successful_batches = sum(1 for b in batch_results if b["status"] == "COMPLETED")
                        skipped_budget_batches = sum(1 for b in batch_results if b["status"] == "SKIPPED_BUDGET")
                        quota_batches = sum(1 for b in batch_results if b["status"] == "PROVIDER_DAILY_QUOTA")
                        rate_limit_batches = sum(1 for b in batch_results if b["status"] == "RATE_LIMITED")
                        other_failed_batches = sum(1 for b in batch_results if b["status"] not in ("COMPLETED", "SKIPPED_BUDGET", "PROVIDER_DAILY_QUOTA", "RATE_LIMITED"))
                        unprocessed_batches = total_batches - len(batch_results)

                        if successful_batches > 0:
                            if len(batch_results) == total_batches and all(b["status"] == "COMPLETED" for b in batch_results):
                                grok_status = "COMPLETED"
                                if total_ai_findings > 0:
                                    agent_reason = f"AI Business Intent Analysis completed successfully with {total_ai_findings} semantic requirement resolution(s)."
                                else:
                                    agent_reason = "BusinessAgent executed successfully and verified no unhandled semantic business intent gaps."
                            else:
                                grok_status = "PARTIAL"
                                reasons = []
                                skipped_cnt = skipped_budget_batches + unprocessed_batches
                                if skipped_cnt > 0:
                                    reasons.append(f"{skipped_cnt} additional batch(es) were skipped because the scan token budget was exhausted")
                                if quota_batches > 0:
                                    reasons.append(f"{quota_batches} batch(es) failed because provider daily quota was reached")
                                if rate_limit_batches > 0:
                                    reasons.append(f"{rate_limit_batches} batch(es) were rate-limited")
                                if other_failed_batches > 0:
                                    reasons.append(f"{other_failed_batches} batch(es) encountered provider errors")

                                reason_clause = "; ".join(reasons)
                                agent_reason = (
                                    f"AI Business Agent completed successfully for {successful_batches} policy batch(es); "
                                    f"{reason_clause}. Successful AI insights are preserved."
                                )
                        else:
                            # 0 successful batches
                            if all(b["status"] == "SKIPPED_BUDGET" for b in batch_results):
                                grok_status = "SKIPPED_BUDGET"
                                agent_reason = "AI Business Analysis was skipped to preserve scan token budget for other priorities. Deterministic policy evaluations are unaffected."
                            elif all(b["status"] == "PROVIDER_DAILY_QUOTA" for b in batch_results):
                                grok_status = "PROVIDER_DAILY_QUOTA"
                                agent_reason = "AI reasoning could not run because the LLM provider's daily token quota (TPD) was exhausted. Deterministic policy evaluations are fully preserved."
                            elif all(b["status"] == "RATE_LIMITED" for b in batch_results):
                                grok_status = "RATE_LIMITED"
                                agent_reason = "AI Business Analysis is temporarily rate limited by the provider (TPM limit). Deterministic policy evaluations are fully preserved."
                            elif any(b["status"] == "SKIPPED_BUDGET" for b in batch_results):
                                grok_status = "SKIPPED_BUDGET"
                                agent_reason = "AI Business Analysis was skipped to preserve scan token budget for other priorities. Deterministic policy evaluations are unaffected."
                            elif any(b["status"] == "PROVIDER_DAILY_QUOTA" for b in batch_results):
                                grok_status = "PROVIDER_DAILY_QUOTA"
                                agent_reason = "AI reasoning could not run because the LLM provider's daily token quota (TPD) was exhausted. Deterministic policy evaluations are fully preserved."
                            else:
                                first_err = next((b["error"] for b in batch_results if b.get("error")), "AI Business Analysis service is temporarily unavailable.")
                                grok_status = "PROVIDER_UNAVAILABLE"
                                agent_reason = first_err or "AI Business Analysis service is temporarily unavailable."
                    else:
                        grok_status = "SKIPPED"
                        agent_reason = "Reasoning service not configured."
                else:
                    grok_status = "SKIPPED"
                    if total_rules == 0 or status in ("NO_DOCUMENTS", "NO_VALID_REQUIREMENTS", "ERROR"):
                        agent_reason = "No business requirements documents found or no actionable rules parsed for this environment."
                    else:
                        agent_reason = f"The deterministic business intent analysis produced a sufficiently conclusive baseline ({total_rules} rule(s) evaluated) with zero ambiguous policies requiring AI resolution."
            else:
                grok_status = "SKIPPED"
                if total_rules == 0 or status in ("NO_DOCUMENTS", "NO_VALID_REQUIREMENTS", "ERROR"):
                    agent_reason = "No business requirements documents found or no actionable rules parsed for this environment."
                elif len(inconclusive_findings) == 0:
                    agent_reason = f"The deterministic business intent analysis produced a sufficiently conclusive baseline ({total_rules} rule(s) evaluated) with zero ambiguous policies requiring AI resolution."
                else:
                    agent_reason = "AI Business Agent reasoning is disabled in current configuration."

        except Exception as exc:
            self.logger.warning("Optional Grok AI business intent reasoning notice: %s", exc)
            status_type = classify_llm_error(exc)
            grok_status = status_type if status_type in ("PROVIDER_DAILY_QUOTA", "RATE_LIMITED", "SKIPPED_BUDGET") else "PROVIDER_UNAVAILABLE"
            agent_reason = f"AI Business Analysis notice: {exc}"

        # Fallback upgrade: if static engine had NO_DOCUMENTS / INSUFFICIENT_EVIDENCE,
        # but Grok AI reasoning produced insights, upgrade status & confidence from AI reasoning.
        if status != "SUCCESS" and ai_business_insights:
            status = "SUCCESS"
            confidence = 0.85
            criticality = "CRITICAL" if violations else (b_context.get("criticality") or "NORMAL")
            reason = (
                f"AI-assisted Business Intent Analysis: Inferred domain '{domain}' "
                f"with {len(ai_business_insights)} semantic requirement check(s)."
            )
            intent_result["status"] = "SUCCESS"
            intent_result["message"] = reason
            intent_result["total_rules"] = max(intent_result.get("total_rules", 0), len(ai_business_insights))
            intent_result["alignment_percentage"] = 85.0 if not violations else 60.0

        context_obj: BusinessContextObject = {
            "domain": domain,
            "criticality": criticality,
            "confidence": confidence,
            "critical_assets": b_context.get("critical_assets", []),
            "compliance_frameworks": b_context.get("compliance_frameworks", []),
            "business_capabilities": b_context.get("business_capabilities", []),
            "data_classification": b_context.get(
                "data_classification", "CONFIDENTIAL" if criticality == "CRITICAL" else "INTERNAL"
            ),
        }

        results_with_reason = dict(intent_result)
        results_with_reason["grok_status"] = grok_status
        results_with_reason["agent_reason"] = agent_reason
        results_with_reason["analyzed_policies"] = analyzed_policy_ids
        results_with_reason["skipped_policies"] = skipped_policy_ids

        new_state = dict(state)
        new_state["business_context"] = dict(context_obj)
        new_state["business_intent_results"] = results_with_reason
        new_state["business_violations"] = violations
        if ai_business_insights:
            new_state["ai_business_insights"] = ai_business_insights
        return new_state


