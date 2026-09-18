"""
Business Intent Engine — Public API (v4)
==========================================
    from guardian.intent.legacy import BusinessIntentEngine

    engine = BusinessIntentEngine()
    report, findings = engine.analyze(
        requirements_source="Jira_User_Stories.xlsx",
        code_directory="./src",
        policy_path="Company_Security_Policy.md",   # optional
    )

    print(report.narrative)           # plain-English summary
    for f in findings:
        print(f.snippet)              # the rule in plain English
        print(f.recommendation)       # WHAT / WHY / HOW block
"""
from guardian.intent.legacy.models import (
    BusinessRule, BusinessAlignmentReport,
    Requirement, RuleMatch, MatchStatus, RuleType,
)
from guardian.intent.legacy.loader import RequirementLoader
from guardian.intent.legacy.extractor import create_extractor, BaseExtractor
from guardian.intent.legacy.matcher import KeywordMatcher, DirectoryMatcher, BaseMatcher
from guardian.intent.legacy.scorer import BusinessIntentScorer
from guardian.core.models import Finding

from pathlib import Path
from typing import Union, Optional


class BusinessIntentEngine:

    def __init__(
        self,
        extractor: Optional[BaseExtractor]     = None,
        matcher:   Optional[BaseMatcher]       = None,
        scorer:    Optional[BusinessIntentScorer] = None,
    ):
        self._loader    = RequirementLoader()
        self._extractor = extractor or create_extractor()
        self._matcher_impl = matcher   # stored; DirectoryMatcher created in analyze()
        self._scorer    = scorer or BusinessIntentScorer()

    def analyze(
        self,
        requirements_source: Union[str, Path, dict, list],
        code_directory:      Union[str, Path],
        policy_path:         Optional[Union[str, Path]] = None,
    ) -> tuple[BusinessAlignmentReport, list[Finding]]:
        """
        Full pipeline: load → extract → match → score → findings.
        """
        requirements = self._load(requirements_source)
        rules = self._extractor.extract_many(requirements)

        if not rules:
            empty = BusinessAlignmentReport(
                alignment_score=100.0, rule_coverage=1.0,
                total_rules=0, matched=0, partial=0, not_implemented=0, violated=0,
            )
            return empty, []

        # Build DirectoryMatcher with optional policy file
        policy = Path(policy_path) if policy_path else None
        matcher_impl = self._matcher_impl or KeywordMatcher(
            (policy.read_text(encoding="utf-8", errors="ignore") if policy and policy.exists() else "")
        )
        dir_matcher = DirectoryMatcher(matcher_impl, policy_path=policy)
        matches = dir_matcher.match_against_directory(rules, Path(code_directory))

        report   = self._scorer.score(matches, requirements)
        findings = self._scorer.to_findings(report)
        return report, findings

    def _load(self, source: Union[str, Path, dict, list]) -> list[Requirement]:
        if isinstance(source, list):
            out = []
            for item in source:
                out.extend(self._loader.load(item))
            return out
        return self._loader.load(source)
