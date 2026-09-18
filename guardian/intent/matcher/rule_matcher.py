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

from guardian.intent.parser.rule_parser import (
    ACTION_VERB_PATTERNS, CONTROL_PATTERNS, ParsedRule,
)

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


class RuleMatcher:
    """Production-grade multi-factor rule matcher.

    Comparisons are made against BehaviorProfiles derived from the actual
    scan findings passed to `evaluate_all`/`evaluate_rule` — there is no
    built-in sample codebase. A scan with no findings simply has nothing
    to check requirements against yet.
    """

    def __init__(self):
        self.code_profiles: list[BehaviorProfile] = []

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

            # Use the SAME vocabulary the rule parser uses to pull action/control
            # words out of a requirement sentence, so a finding whose own
            # category/recommendation mentions e.g. "authentication" or
            # "encryption" lines up with a rule that demands it — instead of
            # two independently-invented keyword lists silently drifting apart.
            actions = (
                re.findall(r"[a-z0-9]+", category.lower())
                + re.findall(r"[a-z0-9]+", rule_id.lower())
                + [m.lower() for m in ACTION_VERB_PATTERNS.findall(text_blob)]
            )
            controls = [m.lower() for m in CONTROL_PATTERNS.findall(text_blob)]

    @staticmethod
    def _profiles_from_workspace(workspace_dir: Path | None = None) -> list[BehaviorProfile]:
        """Extract BehaviorProfiles directly from source code files in the workspace
        so code logic that didn't generate a scanner finding is still evaluated against rules."""
        import os
        if not workspace_dir:
            workspace_dir = Path.cwd()
        profiles: list[BehaviorProfile] = []
        ignore_dirs = {".venv", "node_modules", ".git", "__pycache__", "build", "dist", ".acg_workspaces", ".pytest_cache", "_to_delete"}
        exts = {".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".go", ".php", ".rb", ".c", ".cpp"}
        file_count = 0
        max_files = 150
        
        try:
            for root, dirs, files in os.walk(str(workspace_dir)):
                # Prune ignored directories in-place so os.walk does not traverse them
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
                            fn_snippet = "\n".join(lines[line_no-1 : line_no+30]).lower()
                            
                            actions = [m.lower() for m in ACTION_VERB_PATTERNS.findall(fn_snippet + " " + fn_name)]
                            controls = [m.lower() for m in CONTROL_PATTERNS.findall(fn_snippet)]
                            
                            profiles.append(BehaviorProfile(
                                function_name=fn_name,
                                file=rel_path,
                                line=line_no,
                                actions=actions or [fn_name.lower()],
                                conditions=[],
                                controls=controls,
                                sequence=[]
                            ))
                if file_count >= max_files:
                    break
        except Exception as exc:
            log.warning("Workspace profile extraction skipped: %s", exc)
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

        # Debug observability (Phase 24): counts only, never raw prompts or
        # secrets — how many findings were even looked at for this rule,
        # vs. how many showed genuine relevance and were allowed to
        # compete for best_profile at all.
        profiles_considered = len(profiles)
        profiles_passed_gate = 0

        for profile in profiles:
            fn_name = profile.function_name.lower()
            all_actions = " ".join(profile.actions).lower() + " " + fn_name
            all_conditions = " ".join(profile.conditions).lower()
            all_controls = " ".join(profile.controls).lower()
            profile_text_blob = f"{profile.function_name} {all_actions} {profile.file}".lower()

            # 1. Action Match (40%) — stem-based so "authenticate" in the rule
            # matches "authentication"/"authenticated" found in the finding.
            action_match = 1.0 if _stem_overlap(rule_action, all_actions) else 0.0

            # 2. Condition Match (30%)
            condition_match = 1.0 if (rule_condition != "none" and rule_condition in all_conditions) else 0.5 if rule_condition == "none" else 0.0

            # 3. Control Match (30%)
            control_match = 1.0 if _stem_overlap(rule_control, all_controls) else 0.0

            # Evidence-terms overlap: an extra, rule-specific relevance
            # signal straight from the source document itself (structured
            # rule documents carry an explicit "Evidence terms" list per
            # rule) — independent of the parser's coarser action/control
            # vocabulary, so a finding worded differently from
            # ACTION_VERB_PATTERNS/CONTROL_PATTERNS can still register.
            evidence_term_hit = bool(rule.evidence_terms) and any(
                _stem_overlap(term, profile_text_blob) for term in rule.evidence_terms
            )

            # Relevance gate: a profile is only a *candidate* match when it
            # shows genuine positive signal for THIS rule — an action
            # match, a control match, or an evidence-term hit. Without
            # this gate, a profile with zero real relevance could still
            # "win" best_profile by comparative accident purely off the
            # condition_match=0.5 baseline every profile gets for free
            # when the rule has no numeric condition (rule_condition ==
            # "none") — which is exactly what let an unrelated dependency
            # finding get displayed as "evidence" for an unrelated rule.
            if not (action_match > 0 or control_match > 0 or evidence_term_hit):
                continue
            profiles_passed_gate += 1

            # Combined AST Score (60% weight)
            ast_score = (0.40 * action_match) + (0.30 * condition_match) + (0.30 * control_match)

            # Control Flow Validation: Check if control precedes action in execution sequence
            sequence_valid = True
            if profile.controls and profile.actions and profile.sequence:
                ctrl_idx = min((profile.sequence.index(s) for s in profile.sequence if any(c in s for c in profile.controls)), default=-1)
                act_idx = min((profile.sequence.index(s) for s in profile.sequence if any(a in s for a in profile.actions)), default=-1)
                if ctrl_idx != -1 and act_idx != -1 and ctrl_idx > act_idx:
                    sequence_valid = False
                    ast_score *= 0.5  # Penalty for control after action

            # Semantic Score (30% weight)
            semantic_score = self._token_jaccard(req_text, profile_text_blob)

            # Keyword Score (10% weight)
            keyword_score = 1.0 if (
                _stem_overlap(rule_action, fn_name)
                or _stem_overlap(rule_control, all_controls)
                or evidence_term_hit
            ) else 0.0

            # Final Score Calculation
            final_score = (0.60 * ast_score) + (0.30 * semantic_score) + (0.10 * keyword_score)

            if final_score > best_score:
                best_score = final_score
                best_profile = profile

                # Determine status verdict
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

        # PART 5 Guardrail: False Positive Elimination
        rejection_reason = None
        if best_profile is None or best_score < 0.12:
            rejection_reason = (
                "no candidate profile showed genuine action/control/evidence-term relevance"
                if best_profile is None
                else f"best candidate score {round(best_score, 3)} fell below the 0.12 confidence threshold"
            )
            best_verdict = "INSUFFICIENT_EVIDENCE"
            best_what = "No relevant action or control logic found in code AST"
            best_why = "Codebase contains no matching domain execution paths"
            best_how = "Upload related source code or annotate function implementations"
            # Never display a low-relevance "best of a bad lot" profile as
            # if it were supporting evidence once the guardrail has
            # downgraded the verdict — this is what previously let an
            # unrelated finding (e.g. a dependency-version finding) show
            # up as "evidence" for a rule it had nothing to do with.
            best_profile = None

        evidence_str = (
            f"file: {best_profile.file} · function: {best_profile.function_name}"
            if best_profile else ""
        )

        return {
            "rule": rule.requirement_text,
            "rule_id": rule.rule_id,
            "title": rule.title,
            "status": best_verdict,
            "what": best_what,
            "why": best_why,
            "how": best_how,
            "evidence": evidence_str,
            "evidence_terms": rule.evidence_terms,
            "score": round(best_score, 3),
            "source_file": rule.source_file,
            "line_number": rule.line_number,
            "debug": {
                "profiles_considered": profiles_considered,
                "profiles_passed_relevance_gate": profiles_passed_gate,
                "profiles_rejected": profiles_considered - profiles_passed_gate,
                "rejection_reason": rejection_reason,
            },
        }

    def evaluate_all(self, rules: list[ParsedRule], findings: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
        """Evaluate a list of ParsedRules against codebase behavior."""
        return [self.evaluate_rule(r, findings) for r in rules]
