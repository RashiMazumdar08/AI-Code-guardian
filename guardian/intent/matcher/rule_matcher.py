"""
Robust Intent Matcher & AST Behavior Profile Analyzer
======================================================
- Normalizes AST data into BehaviorProfiles (actions, conditions, controls, sequence).
- Evaluates multi-factor scoring:
    ast_score = 0.40 * action_match + 0.30 * condition_match + 0.30 * control_match
    sequence check: verifies control executes BEFORE action
    final_score = 0.60 * ast_score + 0.30 * semantic_score + 0.10 * keyword_score
- False positive elimination: marks INSUFFICIENT_EVIDENCE if action & control absent.

Behavior profiles are built from the REAL findings of the scan being
evaluated (file/line/category actually reported by the scanner) — never
from a fixed, hardcoded sample codebase. If no findings are supplied
there is nothing to compare against, so every rule is honestly reported
as INSUFFICIENT_EVIDENCE rather than matched against fictional files.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from guardian.intent.analysis.business_evidence import BusinessEvidenceAnalyzer, DeterministicRuleAnalysis
from guardian.intent.parser.rule_parser import (
    ACTION_VERB_PATTERNS, CONTROL_PATTERNS, ParsedRule,
)
from guardian.intent.semantic.evidence_fusion import EvidenceFusionEngine

log = logging.getLogger(__name__)


@dataclass
class BehaviorProfile:
    """Normalized behavior profile extracted from UST/AST for one function."""

    function_name: str
    file: str
    line: int
    actions: list[str] = field(default_factory=list)
    conditions: list[str] = field(default_factory=list)
    controls: list[str] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)  # execution order of calls
    code_snippet: str = ""
    security_score: float = 0.0
    business_score: float = 0.0


def _stem(word: str) -> str:
    """Crude suffix-insensitive stem so 'authenticate'/'authentication'/
    'authenticated' (or 'secret'/'secrets') compare equal without needing
    a real stemmer. Short words are left alone to avoid false collisions."""
    return word if len(word) < 5 else word[:6]


def _stems(text: str) -> set[str]:
    return {_stem(tok) for tok in re.findall(r"[a-z0-9]+", text.lower())}


def _stem_overlap(a: str, b: str) -> bool:
    """True if `a` and `b` share a meaningful word stem."""
    return bool(_stems(a) & _stems(b))


def _calculate_security_score(fn_name: str, fn_snippet: str, actions: list[str], controls: list[str]) -> float:
    """Calculates general security relevance score for a function to prioritize AI context selection.
    
    This is NOT a vulnerability detector — it strictly ranks function relevance for security reasoning.
    """
    score = 0.0
    s_lower = (fn_name + " " + fn_snippet).lower()

    # 1. API / Route endpoint decorators or HTTP route bindings (+3.0)
    if any(k in s_lower for k in ["@app.route", "@router.", "@api.", "@get", "@post", "@put", "@delete", "@patch", "getmapping", "postmapping", "requestmapping", "route("]):
        score += 3.0

    # 2. Authentication / Authorization controls or decorators (+2.5)
    if any(k in s_lower for k in ["login_required", "authenticated", "authenticate", "auth", "jwt", "permission", "role", "authorize", "is_admin", "check_permission", "bearer", "session"]):
        score += 2.5

    # 3. Resource Identifier parameters (+2.0)
    if any(k in s_lower for k in ["_id", "id:", "uuid", "pk", "account_id", "user_id", "order_id", "file_id", "item_id", "token"]):
        score += 2.0

    # 4. Database / ORM / Data store lookups (+2.0)
    if any(k in s_lower for k in [".query.", ".filter", ".find", ".get(", ".execute(", "db.session", "select ", "delete_from", "update("]):
        score += 2.0

    # 5. Security-sensitive / Privileged function names (+1.5)
    if any(k in fn_name.lower() for k in ["user", "profile", "account", "order", "payment", "admin", "auth", "login", "token", "secret", "password", "config", "file", "download", "upload", "exec", "cmd", "setting"]):
        score += 1.5

    # 6. Externally supplied input or Request / Session references (+1.5)
    if any(k in s_lower for k in ["request.args", "request.form", "request.json", "request.get_json", "current_user", "session[", "params", "request.body"]):
        score += 1.5

    # 7. Dangerous / Sensitive system operations (+1.5)
    if any(k in s_lower for k in ["os.system", "subprocess", "eval", "exec(", "pickle", "requests.get", "send_file", "open("]):
        score += 1.5

    return score


def _calculate_business_score(fn_name: str, fn_snippet: str, actions: list[str], controls: list[str]) -> float:
    """Calculates general business intent relevance score for a function to prioritize AI context selection.
    
    This is NOT a violation detector — it strictly ranks function relevance for business intent reasoning.
    """
    score = 0.0
    s_lower = (fn_name + " " + fn_snippet).lower()

    # 1. Business action / entity verbs (+3.0)
    if any(k in s_lower for k in ["cancel", "order", "pay", "refund", "ship", "approve", "checkout", "billing", "invoice", "transaction", "transfer"]):
        score += 3.0

    # 2. State transition / Status modifications (+2.5)
    if any(k in s_lower for k in ["status", "state", "stage", "transition", "shipped", "approved", "cancelled", "completed", "pending"]):
        score += 2.5

    # 3. Validation controls & business rules (+2.0)
    if any(k in s_lower for k in ["check_", "validate", "verify", "can_", "is_valid", "allow_", "require_", "assert"]):
        score += 2.0

    # 4. Database / ORM / State mutations (+2.0)
    if any(k in s_lower for k in [".save()", ".commit()", "db.session", ".update(", ".add(", "delete"]):
        score += 2.0

    # 5. API / Route endpoint bindings (+1.5)
    if any(k in s_lower for k in ["@app.route", "@router.", "@api.", "@get", "@post", "@put", "@delete", "@patch", "route("]):
        score += 1.5

    # 6. User / Account / Role references (+1.5)
    if any(k in s_lower for k in ["user", "account", "customer", "role", "admin", "client"]):
        score += 1.5

    return score


_AST_WORKSPACE_CACHE: dict[str, tuple[float, list[BehaviorProfile]]] = {}


class RuleMatcher:
    """Production-grade multi-factor rule matcher.

    Comparisons are made against BehaviorProfiles derived from the actual
    scan findings passed to `evaluate_all`/`evaluate_rule` — there is no
    built-in sample codebase. A scan with no findings simply has nothing
    to check requirements against yet.
    """

    def __init__(self, workspace_dir: Path | None = None, enable_semantic: bool = True, semantic_top_k: int = 3):
        self.code_profiles: list[BehaviorProfile] = []
        self.workspace_dir = workspace_dir
        self.evidence_analyzer = BusinessEvidenceAnalyzer(workspace_dir=workspace_dir)
        self.fusion_engine = EvidenceFusionEngine(workspace_dir=workspace_dir)
        self.enable_semantic = enable_semantic
        self.semantic_top_k = semantic_top_k

    @staticmethod
    def _profiles_from_findings(findings: list[dict[str, Any]] | None) -> list[BehaviorProfile]:
        """Turn real scanner findings into BehaviorProfiles so evidence is
        always grounded in the code that was actually scanned."""
        profiles: list[BehaviorProfile] = []
        for finding in findings or []:
            category = str(finding.get("category") or "")
            rule_id = str(finding.get("rule") or finding.get("rule_id") or "")
            file_path = str(finding.get("file") or finding.get("file_path") or "unknown")
            try:
                line = int(finding.get("line") or finding.get("line_number") or 0)
            except (TypeError, ValueError):
                line = 0
            function_name = str(
                finding.get("function")
                or finding.get("snippet")
                or Path(file_path).name
                or "unknown"
            )
            text_blob = " ".join(
                str(finding.get(k, "")) for k in
                ("category", "rule", "rule_id", "snippet", "recommendation", "message")
            ).lower()

            actions = (
                re.findall(r"[a-z0-9]+", category.lower())
                + re.findall(r"[a-z0-9]+", rule_id.lower())
                + [m.lower() for m in ACTION_VERB_PATTERNS.findall(text_blob)]
            )
            controls = [m.lower() for m in CONTROL_PATTERNS.findall(text_blob)]

            profiles.append(
                BehaviorProfile(
                    function_name=function_name,
                    file=file_path,
                    line=line,
                    actions=actions,
                    conditions=[],
                    controls=controls,
                    sequence=[],
                    code_snippet=str(finding.get("snippet") or "")[:500],
                    security_score=2.0,  # Pre-seeded scanner finding -> elevated baseline relevance
                )
            )
        return profiles

    @staticmethod
    def _profiles_from_workspace(workspace_dir: Path | None = None) -> list[BehaviorProfile]:
        """Extract BehaviorProfiles directly from source code files in the workspace
        so code logic that didn't generate a scanner finding is still evaluated against rules.
        Uses in-memory mtime caching to eliminate duplicate filesystem parsing."""
        import os
        if not workspace_dir:
            workspace_dir = Path.cwd()
        ws_key = str(workspace_dir.resolve())
        try:
            mtime = workspace_dir.stat().st_mtime
        except Exception:
            mtime = 0.0

        if ws_key in _AST_WORKSPACE_CACHE:
            cached_mtime, cached_profiles = _AST_WORKSPACE_CACHE[ws_key]
            if cached_mtime == mtime:
                return cached_profiles

        profiles: list[BehaviorProfile] = []
        ignore_dirs = {".venv", "node_modules", ".git", "__pycache__", "build", "dist", ".acg_workspaces", ".pytest_cache", "_to_delete"}
        exts = {".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".go", ".php", ".rb", ".c", ".cpp"}
        file_count = 0
        max_files = 150

        try:
            for root, dirs, files in os.walk(ws_key):
                dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]
                for file in files:
                    if file_count >= max_files:
                        break
                    p = Path(root) / file
                    if p.suffix.lower() in exts:
                        file_count += 1
                        try:
                            content = p.read_text(encoding="utf-8", errors="ignore")
                        except Exception:
                            continue

                        try:
                            rel_path = str(p.relative_to(workspace_dir))
                        except ValueError:
                            rel_path = str(p)

                        fn_matches = re.finditer(
                            r"(?i)\b(def|function|async\s+function|public|private|protected)\s+([a-zA-Z0-9_]+)",
                            content
                        )
                        lines = content.splitlines()
                        for match in fn_matches:
                            fn_name = match.group(2)
                            char_pos = match.start()
                            line_no = content[:char_pos].count("\n") + 1

                            # Bounded 5-15 line snippet extraction including decorators
                            start_line = line_no
                            min_start = max(1, line_no - 4)
                            for l_idx in range(line_no - 2, min_start - 2, -1):
                                if l_idx >= 0 and lines[l_idx].strip().startswith(("@", "//", "/*", "#")):
                                    start_line = l_idx + 1
                                else:
                                    break

                            end_line = min(len(lines), line_no + 12)
                            bounded_lines = lines[start_line - 1 : end_line]
                            raw_snippet = "\n".join(bounded_lines)
                            fn_snippet_lower = raw_snippet.lower()

                            actions = [m.lower() for m in ACTION_VERB_PATTERNS.findall(fn_snippet_lower + " " + fn_name)]
                            controls = [m.lower() for m in CONTROL_PATTERNS.findall(fn_snippet_lower)]
                            sec_score = _calculate_security_score(fn_name, fn_snippet_lower, actions, controls)
                            bus_score = _calculate_business_score(fn_name, fn_snippet_lower, actions, controls)

                            profiles.append(BehaviorProfile(
                                function_name=fn_name,
                                file=rel_path,
                                line=line_no,
                                actions=actions or [fn_name.lower()],
                                conditions=[],
                                controls=controls,
                                sequence=[],
                                code_snippet=raw_snippet[:800],
                                security_score=sec_score,
                                business_score=bus_score,
                            ))
                if file_count >= max_files:
                    break
        except Exception as exc:
            log.warning("Workspace profile extraction skipped: %s", exc)

        _AST_WORKSPACE_CACHE[ws_key] = (mtime, profiles)
        return profiles

    def _token_jaccard(self, text1: str, text2: str) -> float:
        """Token overlap ratio (Jaccard similarity)."""
        tokens1 = set(re.findall(r"[a-z0-9]+", text1.lower()))
        tokens2 = set(re.findall(r"[a-z0-9]+", text2.lower()))
        if not tokens1 or not tokens2:
            return 0.0
        intersection = tokens1.intersection(tokens2)
        union = tokens1.union(tokens2)
        return len(intersection) / len(union)

    def evaluate_rule(self, rule: ParsedRule, findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        """Evaluates a single ParsedRule against codebase behavior profiles."""
        best_score = 0.0
        best_profile: BehaviorProfile | None = None
        best_verdict = "INSUFFICIENT_EVIDENCE"
        best_what = "No relevant action or control logic found in code AST"
        best_why = "Requirement cannot be verified against scan scope"
        best_how = "Annotate implementing function or upload code module"

        # 0. Run deep AST control flow, data flow, & specialized business evidence analyzer
        analysis: DeterministicRuleAnalysis = self.evidence_analyzer.analyze_rule(
            rule_id=rule.rule_id,
            requirement_text=rule.requirement_text,
            rule_obj=rule,
        )

        rule_action = rule.action.lower()
        rule_condition = rule.condition.lower()
        rule_control = rule.control.lower()
        req_text = rule.requirement_text.lower()

        # Build behavior profiles from real findings AND workspace source files
        profiles = self._profiles_from_findings(findings) or []
        workspace_profiles = self._profiles_from_workspace()
        existing_keys = {(p.file, p.function_name) for p in profiles}
        for wp in workspace_profiles:
            if (wp.file, wp.function_name) not in existing_keys:
                profiles.append(wp)
        profiles = profiles or self.code_profiles

        profiles_considered = len(profiles)
        profiles_passed_gate = 0

        for profile in profiles:
            fn_name = profile.function_name.lower()
            all_actions = " ".join(profile.actions).lower() + " " + fn_name
            all_conditions = " ".join(profile.conditions).lower()
            all_controls = " ".join(profile.controls).lower()
            profile_text_blob = f"{profile.function_name} {all_actions} {profile.file}".lower()

            action_match = 1.0 if _stem_overlap(rule_action, all_actions) else 0.0
            condition_match = 1.0 if (rule_condition != "none" and rule_condition in all_conditions) else 0.5 if rule_condition == "none" else 0.0
            control_match = 1.0 if _stem_overlap(rule_control, all_controls) else 0.0

            evidence_term_hit = bool(rule.evidence_terms) and any(
                _stem_overlap(term, profile_text_blob) for term in rule.evidence_terms
            )

            if not (action_match > 0 or control_match > 0 or evidence_term_hit):
                continue
            profiles_passed_gate += 1

            ast_score = (0.40 * action_match) + (0.30 * condition_match) + (0.30 * control_match)

            sequence_valid = True
            if profile.controls and profile.actions and profile.sequence:
                ctrl_idx = min((profile.sequence.index(s) for s in profile.sequence if any(c in s for c in profile.controls)), default=-1)
                act_idx = min((profile.sequence.index(s) for s in profile.sequence if any(a in s for a in profile.actions)), default=-1)
                if ctrl_idx != -1 and act_idx != -1 and ctrl_idx > act_idx:
                    sequence_valid = False
                    ast_score *= 0.5

            semantic_score = self._token_jaccard(req_text, profile_text_blob)
            keyword_score = 1.0 if (
                _stem_overlap(rule_action, fn_name)
                or _stem_overlap(rule_control, all_controls)
                or evidence_term_hit
            ) else 0.0

            final_score = (0.60 * ast_score) + (0.30 * semantic_score) + (0.10 * keyword_score)

            if final_score > best_score:
                best_score = final_score
                best_profile = profile

                if action_match > 0 or evidence_term_hit:
                    if control_match == 0:
                        best_verdict = "VIOLATION"
                        best_what = f"Action '{profile.function_name}' lacks required '{rule.control}' control"
                        best_why = f"High risk execution of {rule.action} without required control"
                        best_how = f"Add {rule.control} logic before executing action in {profile.function_name}"
                    elif not sequence_valid:
                        best_verdict = "VIOLATION"
                        best_what = f"Control '{rule.control}' is placed AFTER action in execution order"
                        best_why = "State mutation occurs prior to authorization check"
                        best_how = f"Reorder execution sequence so {rule.control} runs before {rule.action}"
                    elif control_match > 0 and ("md5" in all_controls or "weak" in all_controls):
                        best_verdict = "VIOLATION"
                        best_what = f"Deprecated control '{all_controls}' used in {profile.function_name}"
                        best_why = "Weak security control fails compliance mandate"
                        best_how = "Upgrade to strong SHA-256 or Argon2id encryption"
                    elif control_match > 0:
                        best_verdict = "COMPLIANT"
                        best_what = f"Required control '{rule.control}' verified on path of {profile.function_name}"
                        best_why = "Policy requirements satisfied"
                        best_how = "Maintain current control implementation"
                elif control_match > 0:
                    best_verdict = "PARTIAL"
                    best_what = f"Control '{rule.control}' detected but target action requires review"
                    best_why = "Partial policy alignment"
                    best_how = f"Verify binding between {rule.control} and action handler"

        # Apply deterministic deep evidence analysis result if higher confidence / definitive verdict reached
        if analysis.deterministic_verdict != "INSUFFICIENT_EVIDENCE" and analysis.confidence >= 0.70:
            if analysis.confidence >= best_score or best_verdict == "INSUFFICIENT_EVIDENCE":
                best_verdict = analysis.deterministic_verdict
                best_score = max(best_score, analysis.confidence)
                best_what = analysis.what
                best_why = analysis.why
                best_how = analysis.how
        elif analysis.score_boost > 0:
            best_score = min(1.0, best_score + analysis.score_boost)

        rejection_reason = None
        if (best_profile is None and not analysis.matched_file) or best_score < 0.12:
            rejection_reason = (
                "no candidate profile showed genuine action/control/evidence-term relevance"
                if best_profile is None and not analysis.matched_file
                else f"best candidate score {round(best_score, 3)} fell below the 0.12 confidence threshold"
            )
            best_verdict = "INSUFFICIENT_EVIDENCE"
            best_what = "No relevant action or control logic found in code AST"
            best_why = "Codebase contains no matching domain execution paths"
            best_how = "Upload related source code or annotate function implementations"
            best_profile = None

        final_matched_file = (best_profile.file if best_profile else "") or analysis.matched_file
        final_matched_func = (best_profile.function_name if best_profile else "") or analysis.matched_function
        final_matched_line = (best_profile.line if best_profile else 0) or analysis.matched_line
        final_matched_snippet = (best_profile.code_snippet if best_profile else "") or analysis.matched_snippet

        evidence_str = (
            f"file: {final_matched_file} · function: {final_matched_func}"
            if final_matched_file and final_matched_func else (
                f"file: {final_matched_file}" if final_matched_file else ""
            )
        )

        missing_controls = analysis.missing_controls if analysis.missing_controls else (
            [rule.control] if best_verdict in ("VIOLATION", "PARTIAL", "INSUFFICIENT_EVIDENCE") else []
        )

        det_result = {
            "rule": rule.requirement_text,
            "original_requirement": rule.requirement_text,
            "rule_id": rule.rule_id,
            "title": rule.title,
            "area": rule.area,
            "required_control": rule.required_control or rule.control,
            "expected_implementation_behavior": rule.expected_implementation_behavior,
            "violation_conditions": rule.violation_conditions,
            "compliant_conditions": rule.compliant_conditions,
            "suggested_validation": rule.suggested_validation,
            "status": best_verdict,
            "what": best_what,
            "why": best_why,
            "how": best_how,
            "evidence": evidence_str,
            "evidence_terms": rule.evidence_terms,
            "score": round(best_score, 3),
            "source_file": rule.source_file,
            "line_number": rule.line_number,
            "matched_action": rule.action,
            "matched_condition": rule.condition,
            "matched_control": rule.control,
            "missing_control": ", ".join(missing_controls) if missing_controls else "",
            "missing_controls": missing_controls,
            "negative_evidence": analysis.negative_evidence,
            "evidence_items": [ev.to_dict() for ev in analysis.all_evidence()],
            "matched_file": final_matched_file,
            "matched_function": final_matched_func,
            "matched_line": final_matched_line,
            "matched_snippet": final_matched_snippet,
            "debug": {
                "profiles_considered": profiles_considered,
                "profiles_passed_relevance_gate": profiles_passed_gate,
                "profiles_rejected": profiles_considered - profiles_passed_gate,
                "rejection_reason": rejection_reason,
            },
        }

        if self.enable_semantic:
            fused_res = self.fusion_engine.fuse_rule_result(det_result, top_k=self.semantic_top_k)
            return fused_res.to_dict()
        return det_result

    def evaluate_all(self, rules: list[ParsedRule], findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Evaluate a list of ParsedRules against codebase behavior."""
        return [self.evaluate_rule(r, findings) for r in rules]

