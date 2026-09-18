"""
Report View Model
==================
The normalization + validation + plain-English presentation layer between
raw backend data (curated AgentWorkflowState / the deterministic ScanPipeline
report dict) and the Agentic/Unified HTML reports
(guardian/reporting/agentic_html_reporter.py).

This module exists because of one non-negotiable rule (AI Code Guardian
v2.1.0 report-redesign spec, Section 2 -- "DO NOT INVENT INFORMATION"):
nothing in a rendered report may be a value this module did not receive
from real backend data. Every function below either (a) passes a real
field through untouched, (b) reshapes/groups/dedupes real fields without
changing their meaning, (c) maps a real, closed-vocabulary value (a
category string from data/rules/Security_Rules.json, an IAC category from
guardian/infrastructure/rules.py, or a `reachability` value the
ThreatSimulationAgent actually emits) to a plain-English sentence, or
(d) substitutes one of the small set of literal fallback strings below when
data is missing or malformed -- never a generated, computed, or guessed
substitute.

THE DETERMINISTIC SCANNER REMAINS THE SOURCE OF TECHNICAL TRUTH. Business
logic (grouping, deduping, path normalization, plain-English mapping) lives
here, in Python -- never inline in the HTML templates (Section 19).

Real field shapes this module reads (ground truth, re-confirmed against the
current codebase rather than assumed):
  - backend/app/api/v1/agentic_scan.py::_curated_state / _STATE_KEYS --
    the `agentic` dict passed into every function below.
  - backend/app/api/v1/agentic_scan.py::_adopt_deterministic_report /
    _deterministic_baseline -- the `deterministic` report dict shape
    (report["scan"]["findings"], report["scan"]["by_severity"], etc.),
    the same shape backend/app/api/v1/scans.py stores in _SCANS_STORE.
  - frontend/src/components/agentic-scan/types.ts -- FindingItem,
    BusinessIntentFinding, AttackPathItem, PatchItem, ValidationResultItem,
    CorrelatedChainItem, RiskScores (mirrors the Python side exactly; kept
    in lockstep across both codebases throughout this project).
  - data/rules/Security_Rules.json -- the ONLY real SEC-* rule_id/category
    vocabulary this scanner produces (SEC-001..SEC-010).
  - guardian/infrastructure/rules.py -- the real IAC-* rule_id/category
    vocabulary (IAC-DKR-*, IAC-CMP-*, IAC-K8S-*, IAC-TF-*, IAC-CI-*).
Categories outside both lists (e.g. from a language this scanner adds
later, or business-rule categories a user's own uploaded document defines)
are NOT assumed to not exist -- they fall back to their own real category
text (see plain_english_category()) rather than an invented explanation.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Mandated fallback phrasing (Section 2's exact required wording -- never
# reworded, never replaced with a computed substitute).
# ---------------------------------------------------------------------------
IMPACT_UNKNOWN = "Impact could not be determined from the available evidence."
NO_ATTACK_PATH = "Agentic analysis could not establish a reliable attack path."
EVIDENCE_NEEDS_REVIEW = "Evidence available — technical details require review."
# Used by executive_summary() ONLY when there is genuinely no findings data
# of any kind to judge repository security status against (neither a full
# deterministic report dict nor any agentic-adopted finding) -- distinct
# from, and never confused with, the old "this report does not include a
# deterministic scan" wording, which was shown even when the agentic run
# WAS grounded in a real deterministic scan (see agentic_html_reporter.py's
# header banner vs. this string -- that contradiction is what this
# constant replaces).
SECURITY_STATUS_UNKNOWN = "Repository security status could not be determined from the available evidence."
# Used by the Business Impact section/Agent Execution Overview when the
# BusinessAgent genuinely had no business context to reason over (real
# status NO_DOCUMENTS/NO_VALID_REQUIREMENTS from guardian/intent/engine.py,
# surfaced verbatim via guardian/agents/business/agent.py's agent_reason) --
# never shown when business documents WERE supplied but simply produced no
# violations, which is a different, real outcome.
NO_BUSINESS_CONTEXT = "Business impact could not be determined because no business requirements were available for this scan."
# Used when the ArchitectureAgent's trust_boundaries list is genuinely empty
# (guardian/agents/architecture/agent.py derives it from real detected
# endpoints/entry points/database layers; an empty list is itself a real
# result, not a missing one) -- never replaced with an invented boundary.
NO_TRUST_BOUNDARY = (
    "No trust boundary crossing was identified from the repository's "
    "detected entry points, API endpoints, or database layers."
)
# Verdict-card redesign (master report redesign task, Section 20/21):
# every conceptual traceability hop this report promises to show
# (Finding -> Evidence -> Agent -> Risk -> Remediation -> Validation) is
# always rendered, even when the underlying data doesn't have that hop --
# in which case this literal string is shown, never a fabricated value or
# a silently-dropped row.
TRACE_UNAVAILABLE = "Traceability unavailable for this step."

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

REMEDIATION_STATUS_ORDER = ["VALIDATED", "PROPOSED", "PENDING REVIEW", "REJECTED"]

# Plain-English remediation status vocabulary (Section: "Remediation status
# vocabulary") -- one short, honest explanation per real status this module
# already computes in group_patches_by_status()/REMEDIATION_STATUS_ORDER,
# plus the zero-patches case ("NOT GENERATED", used by both HTML reporters
# when a finding/report has no proposed patch at all). Never claims "Fixed"
# -- that word is not used anywhere in this vocabulary.
REMEDIATION_STATUS_EXPLANATION: Dict[str, str] = {
    "NOT GENERATED": "No remediation has been applied.",
    "PROPOSED": "A possible fix has been generated.",
    "PENDING REVIEW": "The fix has not been verified yet.",
    "VALIDATED": "The proposed fix passed the available validation checks.",
    "REJECTED": "The proposed fix did not pass validation and should not be treated as a confirmed fix.",
}


def remediation_status_explanation(status: Optional[str]) -> str:
    return REMEDIATION_STATUS_EXPLANATION.get(str(status or "").upper(), "")


# Severity explanations (Section: "Severity must be explained") -- the
# exact, fixed wording for each real severity this scanner assigns; never
# exaggerated, never computed from anything other than the severity key
# itself.
SEVERITY_EXPLANATION: Dict[str, str] = {
    "critical": "Immediate attention recommended. This issue could have a severe security impact.",
    "high": "High priority. Exploitation could cause significant security impact.",
    "medium": "Moderate risk. The issue should be addressed, but its impact is generally more limited.",
    "low": "Lower risk. Address as part of normal security improvements.",
}


def severity_explanation(severity: Optional[str]) -> str:
    return SEVERITY_EXPLANATION.get(str(severity or "").strip().lower(), "")


# Verdict states (Section 6) -- the report's plain-English Repository
# Security Status vocabulary. Deliberately does NOT include, imply, or
# derive any source-control workflow decision: no such policy
# configuration exists anywhere in this codebase (re-verified against
# guardian/policies/manager.py -- policy violations carry a severity and a
# rule, never a workflow-blocking flag). AI Code Guardian does not decide
# what a developer should do with their source-control workflow; these
# labels answer only "how secure is this repository based on the
# available evidence?"
VERDICT_LABELS = {
    "critical": "CRITICAL RISK",
    "needs_review": "NEEDS ATTENTION",
    "high_risk": "HIGH RISK",
    "validation_failed": "VALIDATION FAILED",
    "low_risk": "LOW RISK",
    "pass": "SECURE",
    "unknown": "INSUFFICIENT EVIDENCE",
}

# ---------------------------------------------------------------------------
# Plain-English presentation mapping (Section 15). Keyed on the REAL,
# closed-vocabulary category strings this codebase's deterministic scanners
# actually produce (data/rules/Security_Rules.json + guardian/infrastructure/
# rules.py). This is a presentation-only lookup: it never writes back into
# or alters the underlying category/rule_id/severity values themselves --
# every caller keeps the real value alongside the plain-English sentence.
# ---------------------------------------------------------------------------
_CATEGORY_PLAIN_ENGLISH: Dict[str, str] = {
    # data/rules/Security_Rules.json (SEC-001..SEC-010)
    "sql injection": "An attacker could manipulate a database query by injecting unexpected input.",
    "xss": "An attacker could inject a script that runs in another user's browser session.",
    "csrf": "An attacker could trick a logged-in user's browser into submitting a request they did not intend.",
    "hardcoded secret": "A password, API key, or token is stored directly in source code instead of a secret store.",
    "weak crypto": "A cryptographic algorithm or setting used here is no longer considered safe.",
    "broken authentication": "A weakness in login or session handling could let an attacker bypass authentication.",
    "path traversal": "An attacker could reach files outside the intended directory by manipulating a file path.",
    "ssrf": "An attacker could make the server send requests to an internal or unintended destination.",
    "insecure deserialization": "Untrusted data is being deserialized, which can lead to code execution or object injection.",
    "sensitive logging": "Sensitive data may be written to logs where anyone with log access could read it.",
    # guardian/infrastructure/rules.py (IAC-*)
    "root container": "The container is configured to run as the root user, widening the blast radius of a compromise.",
    "exposed secret": "A credential is written directly into a configuration or infrastructure file.",
    "unpinned base image": "The base image is not pinned to a specific version, so what gets built can silently change.",
    "curl-pipe-shell": "A script is downloaded and executed directly without verifying it first.",
    "privileged container": "The container runs with elevated host-level privileges.",
    "host network access": "The container shares the host's network namespace, removing normal network isolation.",
    "privilege escalation": "The container is allowed to gain more privileges than its starting process had.",
    "open security group": "A network rule allows traffic in from anywhere on the internet.",
    "public storage bucket": "The storage bucket is configured to be publicly readable.",
    "weak ci pipeline": "A CI workflow checks out and runs pull-request code in a context that can access secrets.",
    # guardian/engines/security.py (the taint-analysis engine) and the
    # per-language plugins (guardian/scanner/javascript, rust, etc.) --
    # confirmed by re-running the real ScanPipeline against this
    # repository, not assumed from the SEC-*/IAC-* lists above alone.
    "command injection": "An attacker could get the application to run an arbitrary operating-system command.",
    "code injection": "Untrusted input is passed somewhere that can execute it as code.",
    "eval injection": "User-influenced input reaches eval() or a similar dynamic-execution function.",
    "insecure random": "A non-cryptographic random number generator is used somewhere security-sensitive.",
    # Not a code vulnerability -- the Business Agent's own finding-shaped
    # wrapper around a business-rule mismatch (guardian/engines/
    # business_intent.py). Kept here so plain_english_category() never
    # falls through to a bare "Business Intent Violation." for it.
    "business intent violation": "Code behavior does not match a requirement stated in the uploaded business rules.",
}

_REACHABILITY_PLAIN_ENGLISH: Dict[str, str] = {
    "direct": "An external request can reach the affected component directly.",
    "indirect": "The path depends on internal code or additional access. (Inferred path — not a confirmed one.)",
}

# Section 12 -- what each agent actually does, in plain English, keyed on
# the real internal agent names (guardian/orchestrator + GRAPH_LABELS in
# frontend/src/components/agentic-scan/types.ts). An agent name outside
# this map falls back to its own raw name rather than an invented action.
_AGENT_ACTION_ENGLISH: Dict[str, str] = {
    "planner": "Planned which specialist agents this run needed, and in what order.",
    "repository": "Mapped the repository's structure and dependencies.",
    "security": "Reviewed the deterministic findings for additional security context.",
    "business": "Compared code behavior against the uploaded business rules.",
    "architecture": "Analyzed how components in the repository connect to one another.",
    "dependency": "Reviewed declared and transitive dependencies for known risk.",
    "threat_simulation": "Modeled plausible attack paths for reachable findings.",
    "policy": "Checked findings against configured policy requirements.",
    "risk_fusion": "Combined technical, business, and threat signals into a composite risk score.",
    "patch": "Generated proposed code fixes for eligible findings.",
    "validation": "Checked proposed patches for grounding and syntax correctness.",
}

_AGENT_LABELS: Dict[str, str] = {
    "planner": "Planner", "repository": "Repository", "security": "Security",
    "business": "Business", "architecture": "Architecture", "dependency": "Dependency",
    "threat_simulation": "Threat Simulation", "policy": "Policy",
    "risk_fusion": "Risk Fusion", "patch": "Patch Generation", "validation": "Validation",
}


def plain_english_category(category: Optional[str]) -> str:
    """A one-sentence, plain-English explanation of a finding category.
    Falls back to the real category string itself (never a placeholder)
    when the category isn't one of this scanner's known SEC-*/IAC-*
    categories -- e.g. a category a future language scanner introduces."""
    key = str(category or "").strip().lower()
    return _CATEGORY_PLAIN_ENGLISH.get(key, "") or (f"{category}." if category else IMPACT_UNKNOWN)


def plain_english_reachability(reachability: Optional[str]) -> str:
    key = str(reachability or "").strip().lower()
    return _REACHABILITY_PLAIN_ENGLISH.get(key, "")


def plain_english_agent_action(agent_name: Optional[str]) -> str:
    return _AGENT_ACTION_ENGLISH.get(str(agent_name or ""), "")


def agent_label(agent_name: Optional[str]) -> str:
    return _AGENT_LABELS.get(str(agent_name or ""), str(agent_name or "Agent"))


# ---------------------------------------------------------------------------
# Path normalization (Section 5 / 14) -- never show a raw local filesystem
# path (e.g. C:\Users\...\Temp\guardian_github_repos\...) in a report;
# always show a repository-relative path.
# ---------------------------------------------------------------------------
_CLONE_MARKER_RE = re.compile(r"guardian_github_repos[\\/][^\\/]+[\\/]", re.IGNORECASE)


def normalize_path(path: Optional[str], repo_root: Optional[str] = None) -> str:
    if not path:
        return ""
    p = str(path).replace("\\", "/")
    root = str(repo_root or "").replace("\\", "/").rstrip("/")
    if root and p.startswith(root):
        return p[len(root):].lstrip("/") or p
    # Strip everything up to and including a known temp-clone marker
    # (…/guardian_github_repos/<repo>/…) even when repo_root wasn't
    # available to this call -- keep only what comes AFTER the clone
    # root, never the local machine's temp-directory prefix.
    m = _CLONE_MARKER_RE.search(p)
    if m:
        return p[m.end():]
    # Last resort: still looks like an absolute local path (drive letter or
    # leading slash) -- never show the full local path, keep only the
    # trailing segments so the file is still identifiable.
    if re.match(r"^[A-Za-z]:/", p) or p.startswith("/"):
        parts = [seg for seg in p.split("/") if seg]
        return "/".join(parts[-3:]) if len(parts) > 3 else "/".join(parts)
    return p


# ---------------------------------------------------------------------------
# Data-quality validation (Section 14) -- malformed records never reach the
# HTML with an invented replacement; they render EVIDENCE_NEEDS_REVIEW
# instead, and invalid "target assets" like a bare "/" are dropped.
# ---------------------------------------------------------------------------
_INVALID_TARGET_ASSETS = {"", "/", ".", "none", "null", "n/a"}


def is_valid_finding(f: Any) -> bool:
    return isinstance(f, dict) and bool(f.get("finding_id") or f.get("rule_id"))


def is_valid_attack_path(p: Any) -> bool:
    return isinstance(p, dict) and bool(p.get("finding_id")) and bool(p.get("entry_point") or p.get("target_file"))


def is_valid_target_asset(asset: Any) -> bool:
    return str(asset or "").strip().lower() not in _INVALID_TARGET_ASSETS


# ---------------------------------------------------------------------------
# Findings grouped by severity (Section 5) -- cards, not a flat table.
# ---------------------------------------------------------------------------
def group_findings_by_severity(
    findings: List[Dict[str, Any]], repo_root: Optional[str] = None
) -> "list[Tuple[str, List[Dict[str, Any]]]]":
    """Returns [(severity_key, [normalized finding dict, ...]), ...] in
    SEVERITY_ORDER, skipping empty severities. Any severity value outside
    the known 5 is kept under its own (real) key, appended at the end --
    never silently dropped or relabeled."""
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings or []:
        if not is_valid_finding(f):
            continue
        sev_key = str(f.get("severity") or "info").strip().lower()
        item = dict(f)
        item["_display_file"] = normalize_path(f.get("file") or f.get("file_path"), repo_root)
        item["_display_line"] = f.get("line") if f.get("line") is not None else f.get("line_number")
        item["_plain_category"] = plain_english_category(f.get("category"))
        buckets.setdefault(sev_key, []).append(item)

    ordered: List[Tuple[str, List[Dict[str, Any]]]] = []
    for key in SEVERITY_ORDER:
        if buckets.get(key):
            ordered.append((key, buckets.pop(key)))
    # Any remaining (non-standard) severity keys, in the order encountered.
    for key, items in buckets.items():
        if items:
            ordered.append((key, items))
    return ordered


# ---------------------------------------------------------------------------
# Attack paths -- top 3 prominent, remainder grouped/deduped (Section 7).
# Grouping key: (attack_vector, target_file) -- e.g. every "vulnerable
# dependency" path against the same manifest collapses into one group
# instead of N nearly-identical rows, while each group still preserves
# every original finding_id it covers (never dropped, only visually
# collapsed) for traceability.
# ---------------------------------------------------------------------------
def top_and_grouped_attack_paths(
    attack_paths: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    valid = [p for p in (attack_paths or []) if is_valid_attack_path(p)]
    # Rank by exploitability (real field) so "top 3" means highest real
    # exploitability, not just insertion order.
    ranked = sorted(valid, key=lambda p: (p.get("exploitability") or 0), reverse=True)
    top = ranked[:3]
    rest = ranked[3:]

    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    order: List[Tuple[str, str]] = []
    for p in rest:
        key = (str(p.get("attack_vector") or ""), str(p.get("target_file") or ""))
        if key not in groups:
            groups[key] = {
                "attack_vector": p.get("attack_vector"),
                "target_file": p.get("target_file"),
                "entry_point": p.get("entry_point"),
                "reachability": p.get("reachability"),
                "finding_ids": [],
                "max_exploitability": 0,
            }
            order.append(key)
        g = groups[key]
        fid = p.get("finding_id")
        if fid and fid not in g["finding_ids"]:
            g["finding_ids"].append(fid)
        g["max_exploitability"] = max(g["max_exploitability"], p.get("exploitability") or 0)

    grouped = [groups[k] for k in order]
    return top, grouped


# ---------------------------------------------------------------------------
# Business Intent -- business language first (Section 8). Never invents a
# revenue/fraud/compliance consequence; `why`/`what` are the real matcher
# output, `score` is a real match-confidence (0-1), not a fabricated
# severity.
# ---------------------------------------------------------------------------
def normalize_business_violation(v: Dict[str, Any], repo_root: Optional[str] = None) -> Dict[str, Any]:
    out = dict(v)
    out["_headline"] = v.get("why") or v.get("what") or v.get("rule") or "Business rule requires review."
    out["_display_file"] = normalize_path(v.get("source_file"), repo_root)
    out["_evidence"] = v.get("evidence") or EVIDENCE_NEEDS_REVIEW
    return out


# ---------------------------------------------------------------------------
# Remediation grouped by real status (Section 10). VALIDATED only when a
# real ValidationResultItem says PASSED; PENDING REVIEW only when a patch
# exists but hasn't been checked yet; REJECTED only on a real REJECTED
# validation status. "Ready to Apply" is a synonym this module applies
# ONLY to the VALIDATED group -- never attached to PROPOSED/PENDING.
# ---------------------------------------------------------------------------
def group_patches_by_status(
    patches: List[Dict[str, Any]], validation_results: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    validation_by_patch = {v.get("patch_id"): v for v in (validation_results or []) if isinstance(v, dict)}
    groups: Dict[str, List[Dict[str, Any]]] = {k: [] for k in REMEDIATION_STATUS_ORDER}
    for p in patches or []:
        if not isinstance(p, dict):
            continue
        v = validation_by_patch.get(p.get("patch_id"))
        raw_status = str(p.get("validation_status") or "PENDING").upper()
        if raw_status == "PASSED" or (v and v.get("status") == "PASSED"):
            status = "VALIDATED"
        elif raw_status == "REJECTED" or (v and v.get("status") == "REJECTED"):
            status = "REJECTED"
        elif v is not None:
            # A validation record exists but didn't pass/reject cleanly --
            # still real data, shown for review rather than assumed OK.
            status = "PENDING REVIEW"
        else:
            status = "PROPOSED"
        item = dict(p)
        item["_validation"] = v
        groups[status].append(item)
    return groups


# ---------------------------------------------------------------------------
# Evidence traceability as a FIXED conceptual chain per finding (master
# report redesign, Section 20): Finding -> Evidence -> Agent -> Risk ->
# Remediation -> Validation. Every one of the 6 hops is always returned;
# a hop this finding genuinely has no real data for shows TRACE_UNAVAILABLE
# rather than being silently dropped (the previous behavior) or filled with
# a guess.
# ---------------------------------------------------------------------------
def build_traceability_chain(
    finding: Dict[str, Any],
    evidence_mapping: Dict[str, List[str]],
    patches_by_finding: Dict[str, List[Dict[str, Any]]],
    validated_patch_ids: set,
    risk_by_finding: Optional[Dict[str, Dict[str, Any]]] = None,
    rejected_patch_ids: Optional[set] = None,
) -> List[Dict[str, str]]:
    fid = finding.get("finding_id", "")
    ev_ids = evidence_mapping.get(fid) or finding.get("evidence_ids") or (
        [finding["evidence_id"]] if finding.get("evidence_id") else []
    )
    patches = patches_by_finding.get(fid, [])
    risk = (risk_by_finding or {}).get(fid)
    rejected_patch_ids = rejected_patch_ids or set()

    hops: List[Dict[str, str]] = [
        {"label": "Finding", "value": finding.get("rule_id") or fid or TRACE_UNAVAILABLE},
        {"label": "Evidence", "value": ", ".join(str(e) for e in ev_ids) if ev_ids else TRACE_UNAVAILABLE},
        {"label": "Agent", "value": "Security Agent — correlated" if fid in evidence_mapping else TRACE_UNAVAILABLE},
    ]
    if risk and risk.get("exploitability") is not None:
        hops.append({"label": "Risk", "value": f"exploitability {risk['exploitability']:.2f}"})
    else:
        hops.append({"label": "Risk", "value": TRACE_UNAVAILABLE})
    hops.append({
        "label": "Remediation",
        "value": f"{len(patches)} patch(es) proposed" if patches else TRACE_UNAVAILABLE,
    })
    if any(p.get("patch_id") in validated_patch_ids for p in patches):
        hops.append({"label": "Validation", "value": "Validation PASSED"})
    elif any(p.get("patch_id") in rejected_patch_ids for p in patches):
        hops.append({"label": "Validation", "value": "Validation REJECTED"})
    else:
        hops.append({"label": "Validation", "value": TRACE_UNAVAILABLE})
    return hops


# ---------------------------------------------------------------------------
# Risk Fusion -- plain-English "why is risk high" (Section 9). Explains
# each REAL score dimension already on risk_scores; never computes or
# shows a "risk after patch" number, since that isn't produced anywhere in
# the backend.
# ---------------------------------------------------------------------------
def risk_dimension_explanations(risk_scores: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    if not risk_scores:
        return []
    rs = risk_scores
    out: List[Dict[str, str]] = []

    def _band(v: Optional[float]) -> str:
        if v is None:
            return "unknown"
        try:
            v = float(v)
        except (TypeError, ValueError):
            return "unknown"
        if v >= 7:
            return "high"
        if v >= 4:
            return "moderate"
        return "low"

    tech = rs.get("technical_risk_score")
    if tech is not None:
        band = _band(tech)
        out.append({
            "dimension": "Technical",
            "score": tech,
            "explanation": {
                "high": "Driven by the severity and number of unresolved deterministic findings.",
                "moderate": "Some deterministic findings remain unresolved, but severity is mixed.",
                "low": "Few or low-severity deterministic findings remain unresolved.",
            }.get(band, IMPACT_UNKNOWN),
        })
    biz = rs.get("business_risk_score")
    if biz is not None:
        band = _band(biz)
        out.append({
            "dimension": "Business",
            "score": biz,
            "explanation": {
                "high": "Findings touch code the Business Agent flagged as high business criticality.",
                "moderate": "Some affected code carries moderate business criticality.",
                "low": "Affected code carries low business criticality, per the Business Agent's mapping.",
            }.get(band, IMPACT_UNKNOWN),
        })
    threat = rs.get("threat_risk_score")
    if threat is not None:
        band = _band(threat)
        out.append({
            "dimension": "Threat",
            "score": threat,
            "explanation": {
                "high": "The Threat Simulation Agent modeled directly reachable attack paths against these findings.",
                "moderate": "The Threat Simulation Agent modeled some indirect or partially reachable attack paths.",
                "low": "The Threat Simulation Agent found limited or no reachable attack paths.",
            }.get(band, IMPACT_UNKNOWN),
        })
    policy = rs.get("policy_risk_score")
    if policy is not None:
        band = _band(policy)
        out.append({
            "dimension": "Policy",
            "score": policy,
            "explanation": {
                "high": "Multiple configured policy requirements are violated by current findings.",
                "moderate": "At least one configured policy requirement is violated.",
                "low": "No or few configured policy requirements are violated.",
            }.get(band, IMPACT_UNKNOWN),
        })
    return out


# ---------------------------------------------------------------------------
# Executive Summary -- answers the 4 mandated questions (Section 3) using
# only real counts already computed elsewhere in this module; never an
# independent narrative.
# ---------------------------------------------------------------------------
def executive_summary(
    deterministic: Optional[Dict[str, Any]],
    agentic: Dict[str, Any],
    critical: int,
    high: int,
    patches_by_status: Dict[str, List[Dict[str, Any]]],
    unresolved_violations: int,
    has_findings_data: bool = True,
) -> Dict[str, str]:
    # Q1: Is the repository secure?
    #
    # Bug fixed here: this used to key off `deterministic is not None` --
    # i.e. whether the CALLER happened to pass the full deterministic
    # report dict (only true for the Unified Report). A plain Agentic
    # Report never passes it, even though the agentic run always adopts a
    # real deterministic scan's findings (see backend/app/api/v1/
    # agentic_scan.py::_adopt_deterministic_report) and the report header
    # prominently names that scan_id -- so the Agentic Report contradicted
    # itself: "Source deterministic scan: scan_1" in the header banner,
    # "This report does not include a deterministic scan..." right below
    # it in the Executive Summary. `critical`/`high` are now computed by
    # the caller from whichever real source is available (the full
    # deterministic report OR agentic["findings"], the same adopted
    # findings the rest of this report already reasons over -- see
    # agentic_html_reporter.py), and `has_findings_data` says whether
    # either of those actually produced real counts. Only when NEITHER
    # exists is the repository's security status genuinely undeterminable.
    if has_findings_data:
        if critical > 0:
            is_safe = f"Needs attention — {critical} Critical finding(s) are unresolved."
        elif high > 0:
            is_safe = f"Needs attention — {high} High-severity finding(s) are unresolved."
        else:
            is_safe = "No Critical or High-severity deterministic findings are unresolved."
    else:
        is_safe = SECURITY_STATUS_UNKNOWN

    # Q2: What matters most?
    if critical > 0:
        matters_most = f"{critical} Critical-severity finding(s) — these are the highest-priority items in this scan."
    elif high > 0:
        matters_most = f"{high} High-severity finding(s) — the highest-priority items in this scan."
    elif unresolved_violations > 0:
        matters_most = f"{unresolved_violations} business rule violation(s) flagged by the Business Agent."
    else:
        matters_most = "No Critical or High-severity findings were identified in this scan."

    # Q3: What could happen if exploited?
    attack_paths = agentic.get("attack_paths") or []
    valid_paths = [p for p in attack_paths if is_valid_attack_path(p)]
    if valid_paths:
        direct = [p for p in valid_paths if str(p.get("reachability", "")).lower() == "direct"]
        if direct:
            could_happen = f"{len(direct)} directly reachable attack path(s) were modeled by the Threat Simulation Agent."
        else:
            could_happen = f"{len(valid_paths)} attack path(s) were modeled, all requiring indirect or additional access."
    else:
        could_happen = NO_ATTACK_PATH

    # Q4: What should be fixed first?
    validated = patches_by_status.get("VALIDATED") or []
    proposed = patches_by_status.get("PROPOSED") or []
    if validated:
        fix_first = f"{len(validated)} validated patch(es) are ready to apply."
    elif proposed:
        fix_first = f"{len(proposed)} proposed patch(es) await validation."
    elif critical > 0 or high > 0:
        fix_first = "Address the Critical/High findings above first; no automated patch has been generated yet."
    else:
        fix_first = "No outstanding remediation is required based on the data in this report."

    return {
        "security_status_summary": is_safe,
        "what_matters_most": matters_most,
        "what_could_happen": could_happen,
        "what_to_fix_first": fix_first,
    }


# ---------------------------------------------------------------------------
# Real per-finding severity counts from a raw findings list -- used when the
# caller has agentic["findings"] (always the real adopted deterministic
# findings, see backend/app/api/v1/agentic_scan.py::_adopt_deterministic_
# report) but not the full deterministic report dict, e.g. for a plain
# Agentic Report. Same counting logic group_findings_by_severity() already
# uses, just returning counts instead of grouped items.
# ---------------------------------------------------------------------------
def severity_counts_from_findings(findings: Optional[List[Dict[str, Any]]]) -> Dict[str, int]:
    counts: Dict[str, int] = {k: 0 for k in SEVERITY_ORDER}
    for f in findings or []:
        if not is_valid_finding(f):
            continue
        sev = str(f.get("severity") or "info").strip().lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Section 2/12 -- real, data-derived per-agent conclusions for the Agent
# Execution Overview, replacing the old static _AGENT_ACTION_ENGLISH lookup
# (which showed the identical sentence whether an agent found nothing or
# found ten things -- exactly the "generic empty agent card" complaint).
# Every branch below reads a real field a specific agent (guardian/agents/
# <name>/agent.py, re-verified against the current code) actually writes to
# AgentWorkflowState; an agent this function doesn't special-case, or one
# whose real fields are empty/absent, falls back to the static plain-
# English description -- never a fabricated count.
# ---------------------------------------------------------------------------
def agent_key_conclusion(agent_name: Optional[str], agentic: Dict[str, Any]) -> str:
    name = str(agent_name or "")
    findings = agentic.get("findings") or []

    if name == "repository":
        ctx = agentic.get("repository_context") or {}
        ep, apis = len(ctx.get("entry_points") or []), len(ctx.get("public_apis") or [])
        if ep or apis:
            return f"Mapped {ep} entry point(s) and {apis} public API endpoint(s)."
        return "No repository structure could be mapped."

    if name == "security":
        n = len(findings)
        return (
            f"Adopted {n} deterministic finding(s) from the scanner; performed no re-scan."
            if n else "No deterministic findings were available to adopt."
        )

    if name == "business":
        results = agentic.get("business_intent_results") or {}
        reason = results.get("agent_reason")
        return reason or plain_english_agent_action(name)

    if name == "architecture":
        ctx = agentic.get("architecture_context") or {}
        sb, tb = len(ctx.get("service_boundaries") or []), len(ctx.get("trust_boundaries") or [])
        if tb:
            return f"Mapped {sb} service boundary(ies) and {tb} trust boundary(ies)."
        if sb:
            return f"Mapped {sb} service boundary(ies); {NO_TRUST_BOUNDARY[0].lower()}{NO_TRUST_BOUNDARY[1:]}"
        return "No architectural boundaries were derived for this repository."

    if name == "dependency":
        ctx = agentic.get("dependency_context") or {}
        total, vuln = ctx.get("total_dependencies") or 0, ctx.get("vulnerable_dependencies_count") or 0
        if total:
            return f"Parsed {total} declared dependency(ies); flagged {vuln} with a finding."
        return "No dependency manifests were found to analyze."

    if name == "threat_simulation":
        paths = [p for p in (agentic.get("attack_paths") or []) if is_valid_attack_path(p)]
        if paths:
            return f"Modeled {len(paths)} attack path(s) grounded in {len(findings)} adopted finding(s)."
        return "No finding met the criteria for a modeled attack path (reachable entry point or Critical/High severity)."

    if name == "policy":
        res = agentic.get("policy_results") or {}
        if not res:
            return plain_english_agent_action(name)
        n = res.get("total_violations", 0)
        return (f"Evaluated findings against active policy packs; found {n} violation(s)." if n
                else "Evaluated findings against active policy packs; no violations found.")

    if name == "risk_fusion":
        risk = agentic.get("risk_scores") or {}
        score = risk.get("composite_risk_score")
        if score is None:
            return "No composite risk score was produced."
        level = risk.get("risk_level")
        return f"Computed a composite risk score of {score}/10 ({str(level).title() if level else 'unrated'})."

    if name == "patch":
        patches = agentic.get("patches") or []
        if not patches:
            return "No patches were proposed (no eligible findings, or patch generation was not part of this run)."
        files = len({p.get("affected_file") for p in patches if p.get("affected_file")})
        return f"Proposed {len(patches)} patch(es) across {files} file(s)."

    if name == "validation":
        results = agentic.get("validation_results") or []
        if not results:
            return "No patches were available to validate."
        passed = sum(1 for v in results if v.get("status") == "PASSED")
        rejected = sum(1 for v in results if v.get("status") == "REJECTED")
        return f"Validated {len(results)} patch(es): {passed} passed, {rejected} rejected."

    return plain_english_agent_action(name)


# ---------------------------------------------------------------------------
# Section 12 -- Business Agent gating. Distinguishes "no business context
# was ever supplied" from "context was supplied and produced zero
# violations" -- two different real outcomes the old code collapsed into
# one empty-state message. Both `status` and `agent_reason` are real fields
# guardian/agents/business/agent.py already computes from the real
# BusinessIntentEngine result -- never inferred here.
# ---------------------------------------------------------------------------
def business_section_state(agentic: Dict[str, Any]) -> Dict[str, Any]:
    results = agentic.get("business_intent_results") or {}
    status = str(results.get("status") or "").upper()
    return {
        "status": status,
        "no_context": status in ("NO_DOCUMENTS", "NO_VALID_REQUIREMENTS"),
        "reason": results.get("agent_reason") or "",
        "violations": agentic.get("business_violations") or [],
    }


# ---------------------------------------------------------------------------
# Per-finding lookups (Section 1) -- real PolicyAgent/ThreatSimulationAgent/
# RiskFusionAgent/PatchGenerationAgent/BusinessAgent output, each indexed by
# the field that actually links it back to a finding. Field names below
# (policy_name, rule_name, finding_id, source_file, patch_id, ...) are
# re-confirmed against guardian/policies/manager.py::evaluate_findings,
# guardian/agents/threat_simulation/agent.py, guardian/evidence/
# correlation.py's chain shape, and guardian/agents/patch/models.py --
# never guessed.
# ---------------------------------------------------------------------------
def policy_violations_by_finding(policy_results: Optional[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for v in (policy_results or {}).get("violations") or []:
        if isinstance(v, dict) and v.get("finding_id"):
            out.setdefault(v["finding_id"], []).append(v)
    return out


def attack_paths_by_finding(attack_paths: Optional[List[Dict[str, Any]]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for p in attack_paths or []:
        if is_valid_attack_path(p) and p.get("finding_id") not in out:
            out[p["finding_id"]] = p
    return out


def chains_by_finding(correlated_findings: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for c in (correlated_findings or {}).get("chains") or []:
        if isinstance(c, dict) and c.get("finding_id"):
            out.setdefault(c["finding_id"], c)
    return out


def business_violations_by_file(violations: Optional[List[Dict[str, Any]]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for v in violations or []:
        sf = isinstance(v, dict) and v.get("source_file")
        if sf:
            out.setdefault(sf, []).append(v)
    return out


def patches_by_finding_with_validation(
    patches: Optional[List[Dict[str, Any]]], validation_results: Optional[List[Dict[str, Any]]]
) -> Dict[str, Dict[str, Any]]:
    validation_by_patch = {v.get("patch_id"): v for v in (validation_results or []) if isinstance(v, dict)}
    out: Dict[str, Dict[str, Any]] = {}
    for p in patches or []:
        fid = isinstance(p, dict) and p.get("finding_id")
        if fid and fid not in out:
            item = dict(p)
            item["_validation"] = validation_by_patch.get(p.get("patch_id"))
            out[fid] = item
    return out


# ---------------------------------------------------------------------------
# Architecture -- real, file-grounded per-finding context (previously the
# ArchitectureAgent's output was never connected to individual findings at
# all). Only ties an architecture fact to a finding when there is a real,
# checkable connection: whether the finding's own file is one of the
# ArchitectureAgent's real critical_components (entry points detected by
# guardian/discovery/repo_detector.py's content-signature regex). Trust
# boundaries are repository-wide, not finding-specific, so they are always
# surfaced honestly labeled as repo-level context rather than implied to be
# about this one finding -- never a guessed file<->boundary link the data
# doesn't support.
# ---------------------------------------------------------------------------
def architecture_analysis_for_finding(
    finding: Dict[str, Any],
    arch_ctx: Optional[Dict[str, Any]],
    repo_root: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not arch_ctx:
        return None
    display_file = normalize_path(finding.get("file") or finding.get("file_path"), repo_root)
    raw_file = str(finding.get("file") or finding.get("file_path") or "")
    critical_components = [c for c in (arch_ctx.get("critical_components") or []) if c]
    is_critical = bool(display_file) and any(
        display_file == str(c) or raw_file.endswith(str(c)) or display_file.endswith(str(c))
        for c in critical_components
    )
    trust_boundaries = arch_ctx.get("trust_boundaries") or []
    if not is_critical and not trust_boundaries:
        return None  # nothing real to say about this finding architecturally
    out: Dict[str, Any] = {"is_critical_component": is_critical, "trust_boundaries": trust_boundaries}
    if not trust_boundaries:
        out["trust_boundaries_note"] = NO_TRUST_BOUNDARY
    return out


# ---------------------------------------------------------------------------
# Section 1 -- one finding's full cross-agent analysis. Every part is either
# the finding's own real field, or a lookup into another agent's real
# per-finding output; a part with nothing real is simply left out of the
# returned dict (rather than filled with a placeholder), so the HTML layer
# can render "only include a sub-section if real evidence exists" directly
# off which keys are present.
# ---------------------------------------------------------------------------
def build_finding_analysis(
    finding: Dict[str, Any],
    repo_root: Optional[str],
    attack_by_finding: Dict[str, Dict[str, Any]],
    chain_by_finding: Dict[str, Dict[str, Any]],
    biz_by_file: Dict[str, List[Dict[str, Any]]],
    policy_by_finding: Dict[str, List[Dict[str, Any]]],
    patch_by_finding: Dict[str, Dict[str, Any]],
    arch_ctx: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    fid = finding.get("finding_id", "")
    display_file = normalize_path(finding.get("file") or finding.get("file_path"), repo_root)
    out: Dict[str, Any] = {
        "finding_id": fid,
        "rule_id": finding.get("rule_id") or fid,
        "severity": str(finding.get("severity") or "info"),
        "category": finding.get("category"),
        "plain_category": plain_english_category(finding.get("category")),
        "display_file": display_file,
        "display_line": finding.get("line") if finding.get("line") is not None else finding.get("line_number"),
    }
    path = attack_by_finding.get(fid)
    if path:
        out["attack_path"] = path
    chain = chain_by_finding.get(fid)
    if chain:
        out["risk_correlation"] = chain
    biz = biz_by_file.get(display_file) or biz_by_file.get(finding.get("file") or finding.get("file_path") or "")
    if biz:
        out["business_violations"] = biz
    pol = policy_by_finding.get(fid)
    if pol:
        out["policy_violations"] = pol
    patch = patch_by_finding.get(fid)
    if patch:
        out["patch"] = patch
    arch = architecture_analysis_for_finding(finding, arch_ctx, repo_root)
    if arch:
        out["architecture"] = arch
    return out


# ---------------------------------------------------------------------------
# Risk band label (Section 16) -- "3.77/10 — Medium" instead of a bare
# number. Same thresholds risk_dimension_explanations() already uses
# internally, exposed as a standalone function so the Verdict card and the
# Risk Fusion section both label the SAME score with the SAME word, never
# two independently-computed bands.
# ---------------------------------------------------------------------------
def risk_band_label(score: Optional[float]) -> str:
    if score is None:
        return ""
    try:
        v = float(score)
    except (TypeError, ValueError):
        return ""
    if v >= 7:
        return "High"
    if v >= 4:
        return "Medium"
    return "Low"


# ---------------------------------------------------------------------------
# Verdict (Section 5/6) -- a single, conclusion-first Repository Security
# Status for the report header. Every branch reads a real, already-computed
# signal (severity counts, real patch/validation outcomes, RiskFusionAgent's
# own real composite risk_level) and is checked in a fixed priority order so
# the same input always produces the same verdict. Never derives a
# source-control approval/workflow claim of any kind: no such policy
# configuration exists anywhere in this codebase (re-verified against
# guardian/policies/manager.py). AI Code Guardian does not decide what a
# developer should do with their source-control workflow -- this answers
# only "how secure is this repository based on the available evidence?"
# (NEEDS ATTENTION / CRITICAL RISK / HIGH RISK / etc, see VERDICT_LABELS).
# ---------------------------------------------------------------------------
def compute_verdict(
    has_findings_data: bool,
    total_findings: int,
    critical: int,
    high: int,
    patches_by_status: Dict[str, List[Dict[str, Any]]],
    risk_level: Optional[str],
) -> Dict[str, str]:
    if not has_findings_data:
        return {"key": "unknown", "label": VERDICT_LABELS["unknown"], "tone": "neutral"}
    if total_findings == 0:
        return {"key": "pass", "label": VERDICT_LABELS["pass"], "tone": "good"}
    if critical > 0:
        return {"key": "critical", "label": VERDICT_LABELS["critical"], "tone": "bad"}
    if high > 0:
        return {"key": "needs_review", "label": VERDICT_LABELS["needs_review"], "tone": "warn"}
    validated = len(patches_by_status.get("VALIDATED") or [])
    rejected = len(patches_by_status.get("REJECTED") or [])
    still_pending = len(patches_by_status.get("PROPOSED") or []) + len(patches_by_status.get("PENDING REVIEW") or [])
    # Section 3's mandated example: 3 patches proposed, all 3 rejected, zero
    # validated and zero still pending -> a real, distinct failure state,
    # never silently reported as "no automated patch has been generated".
    if rejected > 0 and validated == 0 and still_pending == 0:
        return {"key": "validation_failed", "label": VERDICT_LABELS["validation_failed"], "tone": "bad"}
    if str(risk_level or "").lower() in ("high", "critical"):
        return {"key": "high_risk", "label": VERDICT_LABELS["high_risk"], "tone": "warn"}
    return {"key": "low_risk", "label": VERDICT_LABELS["low_risk"], "tone": "good"}


# ---------------------------------------------------------------------------
# The single highest-priority finding this report leads with (Section 5's
# Verdict card THE ISSUE). Highest severity first, then highest real
# attack-path exploitability as a tie-breaker among same-severity findings
# -- a real, deterministic ranking rule, never an arbitrary "pick the
# first one". Returns the same shape build_finding_analysis() already
# produces for the Findings Analyzed cards, so the Verdict card can never
# describe this finding differently than its own card does further down
# the report.
# ---------------------------------------------------------------------------
def top_priority_finding_analysis(
    findings: List[Dict[str, Any]],
    repo_root: Optional[str],
    attack_by_finding: Dict[str, Dict[str, Any]],
    chain_by_finding: Dict[str, Dict[str, Any]],
    biz_by_file: Dict[str, List[Dict[str, Any]]],
    policy_by_finding: Dict[str, List[Dict[str, Any]]],
    patch_by_finding: Dict[str, Dict[str, Any]],
    arch_ctx: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    valid = [f for f in (findings or []) if is_valid_finding(f)]
    if not valid:
        return None
    sev_rank = {k: i for i, k in enumerate(SEVERITY_ORDER)}

    def _key(f: Dict[str, Any]) -> Tuple[int, float]:
        sev = str(f.get("severity") or "info").strip().lower()
        path = attack_by_finding.get(f.get("finding_id", ""))
        exploit = (path or {}).get("exploitability") or 0
        return (sev_rank.get(sev, len(SEVERITY_ORDER)), -exploit)

    top = sorted(valid, key=_key)[0]
    return build_finding_analysis(
        top, repo_root, attack_by_finding, chain_by_finding, biz_by_file, policy_by_finding, patch_by_finding, arch_ctx,
    )


# ---------------------------------------------------------------------------
# Verdict card narrative (Section 5) -- THE ISSUE / WHAT AGENTS DETERMINED /
# THE CATCH (limitation) / RECOMMENDED NEXT STEP. Every sentence is composed
# from fields already present on `top_finding` (itself real agent output,
# see top_priority_finding_analysis) or the verdict's own real key --
# nothing here independently judges severity or invents a conclusion the
# underlying data doesn't support.
# ---------------------------------------------------------------------------
def verdict_narrative(
    verdict: Dict[str, str],
    top_finding: Optional[Dict[str, Any]],
    business_no_context: bool,
) -> Dict[str, str]:
    if verdict["key"] == "unknown":
        return {
            "issue": SECURITY_STATUS_UNKNOWN,
            "agents_determined": "No agentic analysis could be evaluated for this run.",
            "limitation": "No deterministic findings or agentic output were available to this report.",
            "next_step": "Run a deterministic scan and an agentic analysis pass before reviewing this report.",
        }
    if verdict["key"] == "pass" or not top_finding:
        return {
            "issue": "No deterministic findings were adopted into this agentic run.",
            "agents_determined": "The agentic layer had no findings to analyze.",
            "limitation": "",
            "next_step": "No action required based on the data in this report.",
        }

    sev_label = SEVERITY_LABEL.get(top_finding["severity"].lower(), top_finding["severity"])
    loc = top_finding["display_file"] + (
        f":{top_finding['display_line']}" if top_finding.get("display_line") is not None else ""
    )
    issue = f"{sev_label}-severity finding ({top_finding['rule_id']}) was detected at {loc}. {top_finding['plain_category']}"

    path = top_finding.get("attack_path")
    limitation = ""
    if path:
        basis = str(path.get("exploitability_basis") or "")
        confirmed = "deterministic taint analysis" in basis
        reach_plain = plain_english_reachability(str(path.get("reachability") or "")) or IMPACT_UNKNOWN
        agents_determined = (
            f"The Threat Simulation Agent {'confirmed a real attack path' if confirmed else 'modeled a potential attack path'}: {reach_plain}"
        )
        if not confirmed:
            limitation = (
                "The data flow from source to sink was not confirmed by the deterministic taint engine — "
                "this path is heuristic (entry-point matching), not an observed data flow."
            )
    else:
        agents_determined = "The Threat Simulation Agent did not model a reachable attack path for this finding."

    if business_no_context:
        limitation = (limitation + " " if limitation else "") + NO_BUSINESS_CONTEXT

    patch = top_finding.get("patch")
    if patch:
        v = patch.get("_validation")
        if v and v.get("status") == "PASSED":
            next_step = "A validated patch is available for this finding — review and apply it."
        elif v and v.get("status") == "REJECTED":
            reason = "; ".join(str(i) for i in (v.get("issues") or [])) or "see Remediation for detail"
            next_step = f"A proposed patch was rejected during validation ({reason}) — a grounded fix still needs to be written."
        else:
            next_step = "A patch has been proposed for this finding but has not yet completed validation."
    else:
        next_step = "Confirm the finding manually and implement a grounded fix; no patch has been generated for it yet."

    return {"issue": issue, "agents_determined": agents_determined, "limitation": limitation, "next_step": next_step}
