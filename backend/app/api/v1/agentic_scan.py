"""
Agentic Scan API Endpoint
=========================
THE DETERMINISTIC SCANNER (guardian.core.pipeline.ScanPipeline) IS THE
SOURCE OF TECHNICAL TRUTH. The agentic layer is PURELY an enrichment layer
over deterministic scan evidence -- it is NEVER an independent scan.

This endpoint always adopts an existing deterministic scan (by scan_id,
from GET /api/v1/scans) -- its real findings/evidence, produced by
guardian.core.pipeline.ScanPipeline and already sitting in
backend/app/api/v1/scans.py's _SCANS_STORE -- and hands them to the real
LangGraph multi-agent workflow (guardian.orchestrator.workflow.
OrchestratorWorkflow) as a shared evidence store for reasoning/enrichment:
business-intent interpretation, threat/attack-path simulation, policy
evaluation, cross-domain risk fusion, remediation generation, and patch
validation.

There is no "full scan" mode and no clone+scan fallback. If scan_id is
missing or does not match an existing deterministic scan, this endpoint
refuses to run with: "Deterministic scan required. Run scan in IDE
Workspace first." The agent graph never re-clones, re-scans, or
independently detects vulnerabilities -- findings/evidence entering it are
always genuine ScanPipeline output, adopted, not duplicated or invented.

Downstream, this module streams the ACTUAL execution state over
Server-Sent Events:

  - planner / per-agent started & completed events, published by the
    existing EventBus (guardian.orchestrator.events) exactly as BaseAgent
    already emits them -- no second/parallel event system.
  - a full AgentWorkflowState snapshot after every LangGraph superstep
    (via compiled_graph.stream(..., stream_mode="values")).
  - SKIPPED markers for agents the execution plan (structural skip, e.g.
    scan_mode="security_only") or the runtime routing (conditional skip,
    e.g. no findings for patch generation) genuinely did not run -- derived
    from execution_plan / completed_agents, never fabricated.
  - a "deterministic_baseline" summary (from the real scan) and an
    "agentic_summary" (from real runtime state) so the UI can show the two
    result domains side by side without inventing numbers.

This module reads backend/app/api/v1/scans.py's _SCANS_STORE (read-only,
to adopt an existing scan) but never writes to it, and never touches any
other existing endpoint -- /scans and its UI stay exactly as they were.

v2.1.0 Phase 2 -- structured AgenticAnalysisResult contract
-------------------------------------------------------------
_build_agentic_analysis_result() already existed as the stable, bucketed
read model between LangGraph and every frontend consumer (see its own
docstring below) -- Phase 2 did not need to invent this from scratch
(Critical Rule #1: verify the real implementation before assuming
something is missing). Recon against the v2.1.0 spec's conceptual
AgenticAnalysisResult shape found four real gaps, closed below:
  - "repository": the profile this run was seeded with (previously only
    reachable via the separate deterministic scan record).
  - "errors": the run's failure, if any, in the same {stage, error} list
    shape the deterministic report already uses -- previously only a bare
    string on the outer envelope, not part of the stable result contract.
  - "evidence_traceability": reuses report_view_model.build_traceability_
    chain() -- the exact Finding -> Evidence -> Agent -> Remediation ->
    Validation chain logic the Agentic/Unified HTML reports already use,
    rather than a second implementation of the same chain-building logic
    living only in the reporters.
  - "execution_summary": the same real counts already computed by
    _agentic_summary() (kept, unchanged, as the sibling "agentic_summary"
    field for backward compatibility), now also nested inside "result"
    under the name the spec's contract uses.
None of these compute, infer, or invent a value -- every one is a
pass-through or reuse of something already real elsewhere in this
module. `run.agentic_run_id` / `run.base_scan_id` are kept as-is rather
than renamed to the spec's literal "agentic_scan_id" -- they are the same
identifiers, already the contract every frontend consumer reads, and
Critical Rule #1 rules out a breaking rename with no functional gain.
"""
from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

try:
    from pydantic import ConfigDict  # pydantic v2
    _PYDANTIC_V2 = True
except ImportError:  # pragma: no cover — pydantic v1 environments
    _PYDANTIC_V2 = False

from guardian.orchestrator.events import EventBus, PlannerCompleted, TaskCompleted, TaskScheduled
from guardian.orchestrator.planner import FULL_AGENT_ORDER
from guardian.orchestrator.state import create_initial_state
from guardian.orchestrator.workflow import OrchestratorWorkflow
from guardian.reporting import report_view_model as rvm

# Read-only: the exact in-memory store backend/app/api/v1/scans.py already
# populates from real ScanPipeline runs. We only ever read from it (to
# adopt an existing scan's findings/evidence) -- never write to it, so
# /scans and its UI are completely unaffected by this module.
from backend.app.api.v1.scans import _SCANS_STORE as _DETERMINISTIC_SCANS_STORE

logger = logging.getLogger("guardian.api.agentic_scan")

router = APIRouter(prefix="/agentic-scan", tags=["agentic-scan"])

# The error the deterministic-first flow returns whenever there is no valid
# deterministic scan to enrich. Exact wording matters -- the frontend keys
# off this string.
NO_DETERMINISTIC_SCAN_ERROR = "Deterministic scan required. Run scan in IDE Workspace first."

# The real, coded LangGraph topology -- built from the same ordered agent
# list the graph builder itself uses (guardian/orchestrator/planner.py::
# FULL_AGENT_ORDER), so the graph the UI draws can never drift from what
# guardian/orchestrator/langgraph_flow.py actually wires up. Each optional
# node's conditional edge target, when it's skipped, is the next node in
# this same order (see _route_after_* / _next_planned_node in
# langgraph_flow.py) -- so this consecutive-pairs edge list is the real
# static shape of the graph, not an approximation drawn for the UI.
GRAPH_NODES: List[str] = ["planner"] + list(FULL_AGENT_ORDER)
GRAPH_EDGES: List[List[str]] = [[GRAPH_NODES[i], GRAPH_NODES[i + 1]] for i in range(len(GRAPH_NODES) - 1)]

# In-memory run store: scan_id -> {status, log, queues, state, error, ...}
_SCANS: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()


class AgenticScanRequest(BaseModel):
    scan_id: str = Field(
        ..., description="Existing deterministic scan_id (from GET /api/v1/scans) whose findings/evidence "
                          "the agentic layer will reason over. Required -- the agentic layer never scans "
                          "independently.",
    )
    scan_mode: str = Field("full_scan", description="Agentic execution plan: 'full_scan' or 'security_only'.")


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value, default=str)
        return value
    except Exception:
        return str(value)


# Whitelisted, JSON-safe view of AgentWorkflowState for the UI. Deliberately
# excludes "messages" (LangChain message objects, not relevant to a scan
# run) but otherwise passes through every field the required UI panels need:
# execution plan/trace, per-domain agent contexts, findings, evidence,
# business-intent results/violations, dependency context, risk scores,
# patches, and validation results.
_STATE_KEYS = [
    "scan_id", "scan_mode", "active_agent", "current_task",
    "completed_agents", "pending_agents", "execution_plan",
    "agent_trace", "execution_metrics",
    "repository_context", "business_context", "business_intent_results",
    "business_violations", "security_context", "architecture_context",
    "dependency_context", "threat_context", "policy_results",
    "correlated_findings", "attack_paths", "exploitability",
    "findings", "evidence", "risk_scores",
    "patches", "git_diff", "remediation_summary", "developer_explanation",
    "validation_report", "validation_results", "validation_confidence",
    "grounding_report",
]


def _curated_state(state: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _json_safe(state.get(k)) for k in _STATE_KEYS if k in state}


def _evidence_traceability(curated: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Finding -> Evidence -> Agent -> Remediation -> Validation chains,
    one per finding that has more than a bare "Finding" hop. Reuses
    report_view_model.build_traceability_chain() -- the exact same logic
    guardian/reporting/agentic_html_reporter.py's Evidence Traceability
    section already runs -- rather than a second implementation of chain-
    building living only in the reporters (Critical Rule #1). Real IDs
    only; a finding with nothing real to trace is omitted, never padded.
    """
    findings = curated.get("findings") or []
    evidence_mapping = (curated.get("correlated_findings") or {}).get("evidence_mapping") or {}
    patches_by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for p in (curated.get("patches") or []):
        patches_by_finding.setdefault(p.get("finding_id", ""), []).append(p)
    validated_patch_ids = {
        v.get("patch_id") for v in (curated.get("validation_results") or []) if v.get("status") == "PASSED"
    }
    chains: List[Dict[str, Any]] = []
    for f in findings:
        if not rvm.is_valid_finding(f):
            continue
        hops = rvm.build_traceability_chain(f, evidence_mapping, patches_by_finding, validated_patch_ids)
        if len(hops) < 2:
            continue
        chains.append({"finding_id": f.get("finding_id", ""), "hops": hops})
    return chains


# ---------------------------------------------------------------------------
# AgenticAnalysisResult -- the canonical read model
# ---------------------------------------------------------------------------
# A single, explicitly-bucketed reshaping of `_curated_state()`'s output
# (itself a whitelisted, JSON-safe view of the real AgentWorkflowState --
# see guardian/orchestrator/state.py). This is the ONE contract every
# frontend consumer (Security tab, Business Intent tab, Agentic Scan tab,
# Reports) should read from, instead of each tab independently parsing raw
# curated state fields by name. It never computes, infers, or invents a
# value -- every field here is a straight pass-through of something
# `_curated_state()` already exposes, or a reuse of an existing helper
# (_agentic_summary, report_view_model.build_traceability_chain) -- this
# function only groups those fields by which part of the workflow
# produced them (see AI_CODE_GUARDIAN v2.1.0 architecture doc, section 10).
#
# `run` carries the two identifiers the whole system is scoped by:
#   - agentic_run_id: this agentic run's own id (the "scan_id" this module
#     generates as f"agentic_{uuid4()...}" -- see start_agentic_scan below)
#   - base_scan_id: the DETERMINISTIC scan_id it adopted (record["source_
#     scan_id"]) -- the technical source of truth this run is enriching.
# Every consumer that reads a result should confirm result.run.base_scan_id
# matches the deterministic scan currently on screen before displaying it
# (see frontend's agenticMatchesCurrentScan) -- this function does not
# enforce that itself, it just always includes both ids so callers can.
#
# v2.1.0 Part 18 -- typed Pydantic contract
# -------------------------------------------------------------------------
# _build_agentic_analysis_result() already produced the right SHAPE (see
# above); the real remaining gap (Critical Rule #1: verify before assuming
# something is missing) was that the shape existed only as an untyped
# Dict[str, Any] -- nothing validated that a given bucket actually matched
# the contract every frontend consumer depends on, and FastAPI/OpenAPI had
# no schema for it. The models below type the contract's own top-level
# buckets; the genuinely dynamic, scanner/LangGraph-shaped content inside
# them (individual findings, evidence, patches, ...) stays Dict[str, Any]/
# List[Dict[str, Any]] deliberately -- freezing THAT to a rigid schema
# would break the moment any engine or agent adds a field, for no real
# safety benefit (those payloads already round-trip through the JSON-safe
# `_curated_state()` whitelist above).
#
# _build_agentic_analysis_result() still returns a plain dict, unchanged,
# so every existing caller (record["result"] storage, the SSE `_emit(...,
# result=...)` calls below, which json.dumps() it, and GET /{scan_id}'s
# response) keeps working exactly as before -- it now builds that dict BY
# validating an AgenticAnalysisResult instance first, then dumping it back
# to a dict, so a shape drift raises a real pydantic ValidationError
# instead of silently shipping a malformed contract to the frontend.
def _model_to_dict(model: BaseModel) -> Dict[str, Any]:
    """pydantic v1/v2 compatible dict export (mode="json" under v2 so enum/
    datetime-like values serialize the same way json.dumps(default=str)
    elsewhere in this module already treats them)."""
    if _PYDANTIC_V2:
        return model.model_dump(mode="json")
    return model.dict()  # pydantic v1


class RunInfo(BaseModel):
    agentic_run_id: str
    base_scan_id: Optional[str] = None
    status: Optional[str] = None
    scan_mode: Optional[str] = None
    started_at: Optional[float] = None


class ExecutionProgress(BaseModel):
    """v2.1.0 Part 22 -- real per-run progress derived from genuine state,
    never a fabricated percentage. `stage` is the human-readable node
    currently executing (or the terminal state once the run finishes);
    `percent` is completed/(planned total) once the planner has produced
    an execution_plan, else None -- there is nothing real to divide by
    before that, so this reports "unknown", not a fake 0%."""
    stage: Optional[str] = None
    percent: Optional[float] = None
    completed_count: int = 0
    planned_count: Optional[int] = None


class ExecutionInfo(BaseModel):
    active_agent: Optional[str] = None
    current_task: Optional[str] = None
    completed_agents: List[str] = Field(default_factory=list)
    pending_agents: List[str] = Field(default_factory=list)
    execution_plan: Optional[Dict[str, Any]] = None
    agent_trace: List[Dict[str, Any]] = Field(default_factory=list)
    execution_metrics: Optional[Dict[str, Any]] = None
    progress: ExecutionProgress = Field(default_factory=ExecutionProgress)


class DeterministicContext(BaseModel):
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)


class SecurityEnrichment(BaseModel):
    correlated_findings: Dict[str, Any] = Field(default_factory=dict)
    attack_paths: List[Dict[str, Any]] = Field(default_factory=list)
    exploitability: Optional[Any] = None
    security_context: Dict[str, Any] = Field(default_factory=dict)


class BusinessAnalysis(BaseModel):
    violations: List[Dict[str, Any]] = Field(default_factory=list)
    results: Optional[Any] = None


class ThreatAnalysis(BaseModel):
    threat_context: Dict[str, Any] = Field(default_factory=dict)
    attack_paths: List[Dict[str, Any]] = Field(default_factory=list)


class RiskFusion(BaseModel):
    risk_scores: Optional[Dict[str, Any]] = None
    correlated_chains: List[Any] = Field(default_factory=list)
    evidence_mapping: Dict[str, Any] = Field(default_factory=dict)


class Remediation(BaseModel):
    patches: List[Dict[str, Any]] = Field(default_factory=list)
    remediation_summary: Optional[Any] = None
    git_diff: Optional[Any] = None
    developer_explanation: Optional[Any] = None


class Validation(BaseModel):
    results: List[Dict[str, Any]] = Field(default_factory=list)
    report: Optional[Any] = None
    confidence: Optional[Any] = None
    grounding_report: Optional[Any] = None


class EvidenceTraceabilityChain(BaseModel):
    finding_id: str
    hops: List[Dict[str, Any]] = Field(default_factory=list)


class ErrorEntry(BaseModel):
    stage: str
    error: str


class AgenticAnalysisResult(BaseModel):
    """The typed v2.1.0 contract. Every field mirrors, 1:1, a bucket
    _build_agentic_analysis_result() already produced as a dict -- see the
    module-level docstring's "v2.1.0 Phase 2" note for where each bucket's
    content actually comes from. Extra keys are tolerated (`extra="allow"`
    under pydantic v2 below) rather than rejected, so this contract can
    only ever be additive against older records already in `_SCANS`."""
    if _PYDANTIC_V2:
        model_config = ConfigDict(extra="allow")
    else:  # pragma: no cover — pydantic v1
        class Config:
            extra = "allow"

    run: RunInfo
    repository: Dict[str, Any] = Field(default_factory=dict)
    execution: ExecutionInfo
    deterministic_context: DeterministicContext
    security_enrichment: SecurityEnrichment
    business_analysis: BusinessAnalysis
    architecture_analysis: Dict[str, Any] = Field(default_factory=dict)
    dependency_analysis: Dict[str, Any] = Field(default_factory=dict)
    threat_analysis: ThreatAnalysis
    policy_analysis: Dict[str, Any] = Field(default_factory=dict)
    risk_fusion: RiskFusion
    remediation: Remediation
    validation: Validation
    evidence_traceability: List[EvidenceTraceabilityChain] = Field(default_factory=list)
    execution_summary: Dict[str, Any] = Field(default_factory=dict)
    errors: List[ErrorEntry] = Field(default_factory=list)


def _execution_progress(curated: Dict[str, Any]) -> Dict[str, Any]:
    """Real progress, never fabricated -- see ExecutionProgress above.
    `planned_count` comes from the planner's own execution_plan.agent_order
    (the same real list _run_agentic_scan already uses to detect skipped
    agents, see "structurally_skipped" below) plus 1 for the planner node
    itself, since `completed_agents` also includes "planner" once it's
    done (see on_planner_completed's _emit in _run_agentic_scan)."""
    completed = curated.get("completed_agents") or []
    plan = curated.get("execution_plan") or {}
    planned_agents = plan.get("agent_order") or []
    planned_count = (len(planned_agents) + 1) if planned_agents else None  # +1 for "planner"
    percent = None
    if planned_count:
        percent = round(min(len(completed), planned_count) / planned_count * 100, 1)
    stage = curated.get("active_agent") or (completed[-1] if completed else None)
    return {
        "stage": stage,
        "percent": percent,
        "completed_count": len(completed),
        "planned_count": planned_count,
    }


def _build_agentic_analysis_result(
    scan_id: str, record: Dict[str, Any], curated: Dict[str, Any]
) -> Dict[str, Any]:
    correlated = curated.get("correlated_findings") or {}
    model = AgenticAnalysisResult(
        run={
            "agentic_run_id": scan_id,
            "base_scan_id": record.get("source_scan_id"),
            "status": record.get("status"),
            "scan_mode": record.get("scan_mode"),
            "started_at": record.get("started_at"),
        },
        # The repository profile this run was seeded with (see
        # _adopt_deterministic_report below) -- stored on `record` once at
        # adoption time, not part of AgentWorkflowState itself, so every
        # consumer of `result` can show which repository/language/
        # frameworks this run analyzed without a second lookup against the
        # separate deterministic scan record.
        repository=record.get("repository_profile") or {},
        execution={
            "active_agent": curated.get("active_agent"),
            "current_task": curated.get("current_task"),
            "completed_agents": curated.get("completed_agents", []),
            "pending_agents": curated.get("pending_agents", []),
            "execution_plan": curated.get("execution_plan"),
            "agent_trace": curated.get("agent_trace", []),
            "execution_metrics": curated.get("execution_metrics"),
            # v2.1.0 Part 22 -- real stage/percent-complete, see
            # _execution_progress() above. Additive: every existing
            # consumer of "execution" already ignores unknown sibling keys.
            "progress": _execution_progress(curated),
        },
        # Deterministic evidence/findings AS ADOPTED into this agentic run
        # (guardian.core.pipeline.ScanPipeline output, never re-detected --
        # see _adopt_deterministic_report below). Included here, scoped
        # under its own bucket, so cross-cutting views (Evidence
        # Traceability) don't need a second raw-state field lookup.
        deterministic_context={
            "findings": curated.get("findings", []),
            "evidence": curated.get("evidence", []),
        },
        security_enrichment={
            "correlated_findings": correlated,
            "attack_paths": curated.get("attack_paths", []),
            "exploitability": curated.get("exploitability"),
            "security_context": curated.get("security_context") or {},
        },
        business_analysis={
            "violations": curated.get("business_violations", []),
            "results": curated.get("business_intent_results"),
        },
        architecture_analysis=curated.get("architecture_context") or {},
        dependency_analysis=curated.get("dependency_context") or {},
        threat_analysis={
            "threat_context": curated.get("threat_context") or {},
            "attack_paths": curated.get("attack_paths", []),
        },
        policy_analysis=curated.get("policy_results") or {},
        risk_fusion={
            "risk_scores": curated.get("risk_scores"),
            "correlated_chains": correlated.get("chains", []),
            "evidence_mapping": correlated.get("evidence_mapping") or {},
        },
        remediation={
            "patches": curated.get("patches", []),
            "remediation_summary": curated.get("remediation_summary"),
            "git_diff": curated.get("git_diff"),
            "developer_explanation": curated.get("developer_explanation"),
        },
        validation={
            "results": curated.get("validation_results", []),
            "report": curated.get("validation_report"),
            "confidence": curated.get("validation_confidence"),
            "grounding_report": curated.get("grounding_report"),
        },
        # Real Finding -> Evidence -> Agent -> Remediation -> Validation
        # chains -- see _evidence_traceability() above. Empty list, never
        # fabricated hops, when there is nothing real to trace yet.
        evidence_traceability=_evidence_traceability(curated),
        # Same computation as the sibling top-level "agentic_summary" field
        # returned by GET /{scan_id} (kept for backward compatibility) --
        # nested here too under the v2.1.0 contract's name, not a second
        # implementation.
        execution_summary=_agentic_summary(curated),
        # {stage, error} shape, matching the deterministic report's own
        # "errors" list (guardian/reporting/html_reporter.py's Partial
        # Results section) so both report types can be handled uniformly.
        # Empty unless this run's record actually recorded a failure.
        errors=([{"stage": "workflow", "error": record["error"]}] if record.get("error") else []),
    )
    # Validated via the typed AgenticAnalysisResult model above, then
    # dumped straight back to a dict -- every existing caller (record
    # storage, the SSE _emit(...) calls, GET /{scan_id}) keeps receiving
    # exactly the same plain-dict shape it always has.
    return _model_to_dict(model)


def _emit(scan_id: str, event_type: str, **data: Any) -> None:
    with _LOCK:
        record = _SCANS.get(scan_id)
        if not record:
            return
        evt = {"type": event_type, "ts": time.time(), **data}
        record["log"].append(evt)
        for q in list(record["queues"]):
            q.put(evt)


# ---------------------------------------------------------------------------
# Deterministic -> agentic adoption
#
# The two Finding/Evidence shapes in this codebase:
#   - canonical (guardian.core.models.Finding / guardian.evidence.models.
#     Evidence): what ScanPipeline actually produces -- file/line/
#     evidence_ids(list)/id.
#   - legacy (what several specialist agents -- threat_simulation, patch,
#     evidence correlation, policy, chat, grounding -- were originally
#     built to read): file_path/line_number/evidence_id(single)/finding_id
#     on the evidence side.
#
# Rather than rewriting every one of those consumers, every finding/
# evidence dict handed to the agent graph below carries BOTH sets of keys,
# so real deterministic data flows through unmodified logic on both sides
# instead of being duplicated, re-detected, or invented.
# ---------------------------------------------------------------------------

def _canonical_finding_with_aliases(f: Dict[str, Any]) -> Dict[str, Any]:
    """A real ScanPipeline Finding.to_dict(), plus legacy alias keys."""
    out = dict(f)
    evidence_ids = f.get("evidence_ids") or []
    out.setdefault("file_path", f.get("file", ""))
    out.setdefault("line_number", f.get("line", 0))
    out.setdefault("evidence_id", evidence_ids[0] if evidence_ids else "")
    out.setdefault("title", f.get("category") or f.get("rule_id") or "Finding")
    out.setdefault("description", f.get("recommendation") or f.get("reason") or "")
    return out


def _canonical_evidence_with_aliases(e: Dict[str, Any], finding_id_by_evidence_id: Dict[str, str]) -> Dict[str, Any]:
    """A real ScanPipeline Evidence.to_dict(), plus legacy alias keys."""
    out = dict(e)
    eid = e.get("id", "")
    out.setdefault("evidence_id", eid)
    out.setdefault("code_snippet", e.get("snippet", ""))
    out.setdefault("engine", e.get("source", ""))
    out.setdefault("finding_id", finding_id_by_evidence_id.get(eid, ""))
    return out


def _deterministic_baseline(scan_result: Dict[str, Any], unified_risk: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Real counts straight from ScanResult.to_dict() -- never fabricated."""
    by_severity: Dict[str, int] = scan_result.get("by_severity", {}) or {}

    def _count(*names: str) -> int:
        return sum(v for k, v in by_severity.items() if k.lower() in names)

    baseline = {
        "total_findings": scan_result.get("total_findings", 0),
        "critical": _count("critical"),
        "high": _count("high"),
        "medium": _count("medium"),
        "low": _count("low"),
        "info": _count("info"),
        "by_severity": by_severity,
        "by_category": scan_result.get("by_category", {}) or {},
        "funnel_metrics": scan_result.get("funnel_metrics", {}) or {},
    }
    # guardian.core.unified_risk.UnifiedRiskReport -- a DIFFERENT scale from
    # the agentic composite_risk_score (0-100, higher is BETTER, vs the
    # agent graph's 0-10 where higher is WORSE). Included so the UI can
    # show the deterministic security posture score alongside the agentic
    # composite risk, clearly labeled with its own scale -- never collapsed
    # into a single number, since the two are not directly comparable.
    if unified_risk:
        baseline["deterministic_overall_risk_score"] = unified_risk.get("overall_risk_score")
        baseline["deterministic_security_score"] = unified_risk.get("security_score")
    return baseline


def _adopt_deterministic_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Turns a real ScanPipeline report dict (the same shape stored in
    backend/app/api/v1/scans.py's _SCANS_STORE) into the repository
    profile / findings / evidence the agent graph consumes, plus the
    deterministic baseline counts for the UI's Overview and Baseline-vs-
    Agentic panels. Does NOT re-detect anything -- every finding and
    evidence item below is exactly what the deterministic scanner found.
    """
    scan_result = report.get("scan", {}) or {}
    raw_findings = scan_result.get("findings", []) or []
    raw_evidence = report.get("evidence_items", []) or []

    ev_to_finding: Dict[str, str] = {}
    for f in raw_findings:
        fid = f.get("finding_id", "")
        for eid in (f.get("evidence_ids") or []):
            ev_to_finding.setdefault(eid, fid)

    findings = [_canonical_finding_with_aliases(f) for f in raw_findings]
    evidence = [_canonical_evidence_with_aliases(e, ev_to_finding) for e in raw_evidence]

    profile = dict(report.get("repository", {}) or {})
    profile["repo_path"] = report.get("target", "") or profile.get("root", "")

    return {
        "repository_profile": profile,
        "findings": findings,
        "evidence": evidence,
        "baseline": _deterministic_baseline(scan_result, report.get("unified_risk")),
    }


def _agentic_summary(last_state: Dict[str, Any]) -> Dict[str, Any]:
    """Real counts pulled from actual AgentWorkflowState after the graph
    finishes -- the agentic-enrichment side of the Overview/Baseline-vs-
    Agentic comparison. Every number here is len()/lookup of genuine
    runtime state, never a fabricated or placeholder value."""
    correlated = last_state.get("correlated_findings") or {}
    business_violations = last_state.get("business_violations") or []
    attack_paths = last_state.get("attack_paths") or []
    policy_results = last_state.get("policy_results") or {}
    policy_violations = policy_results.get("violations") or [] if isinstance(policy_results, dict) else []
    patches = last_state.get("patches") or []
    validation_report = last_state.get("validation_report") or {}
    validated_count = validation_report.get("passed_count", 0) if isinstance(validation_report, dict) else 0
    risk_scores = last_state.get("risk_scores") or {}

    return {
        "correlated_risks": correlated.get("total_correlated", 0) if isinstance(correlated, dict) else 0,
        "business_violations": len(business_violations),
        "attack_paths": len(attack_paths),
        "policy_violations": len(policy_violations),
        "remediation_proposals": len(patches),
        "validated_patches": validated_count,
        "unified_risk_score": risk_scores.get("composite_risk_score") if isinstance(risk_scores, dict) else None,
        "risk_level": risk_scores.get("risk_level") if isinstance(risk_scores, dict) else None,
    }


def _run_agentic_scan(scan_id: str, source_scan_id: str, scan_mode: str) -> None:
    record = _SCANS[scan_id]
    # The real moment execution begins -- the thread has now actually been
    # scheduled and started running, as distinct from "queued" above (when
    # the record existed but this function body hadn't executed yet).
    with _LOCK:
        record["status"] = "running"
    try:
        det_report = _DETERMINISTIC_SCANS_STORE.get(source_scan_id)
        if not det_report:
            raise ValueError(NO_DETERMINISTIC_SCAN_ERROR)
        _emit(scan_id, "workflow.adopting", source_scan_id=source_scan_id)
        adopted = _adopt_deterministic_report(det_report)

        profile = adopted["repository_profile"]
        findings = adopted["findings"]
        evidence = adopted["evidence"]
        baseline = adopted["baseline"]

        with _LOCK:
            record["deterministic_baseline"] = baseline
            # See _build_agentic_analysis_result's "repository" bucket --
            # stashed on the record (not AgentWorkflowState) so it survives
            # every snapshot without inflating the LangGraph state itself.
            record["repository_profile"] = profile
        _emit(
            scan_id, "workflow.adopted", source_scan_id=source_scan_id,
            total_findings=len(findings), total_evidence=len(evidence), baseline=baseline,
        )
        _emit(
            scan_id, "workflow.profiled", primary_language=profile.get("primary_language"),
            total_files=profile.get("total_files"), frameworks=profile.get("frameworks"),
        )

        bus = EventBus()
        scheduled: set = set()
        planner_t0 = 0.0  # set immediately before the graph is invoked, below

        def on_scheduled(evt: TaskScheduled) -> None:
            scheduled.add(evt.agent_name)
            _emit(scan_id, "agent.started", agent=evt.agent_name, task=evt.task_name)

        def on_completed(evt: TaskCompleted) -> None:
            _emit(
                scan_id, "agent.completed", agent=evt.agent_name,
                duration=evt.duration, status=evt.status, error=evt.error,
            )

        # PlannerAgent is not a BaseAgent subclass (its job is to decide what
        # the rest of the graph even runs) so it doesn't go through
        # TaskScheduled/TaskCompleted -- it publishes its own PlannerCompleted
        # event instead. Wire that into the same started/completed vocabulary
        # the UI graph expects, using real wall-clock timing.
        def on_planner_completed(evt: PlannerCompleted) -> None:
            scheduled.add("planner")
            _emit(scan_id, "agent.completed", agent="planner",
                  duration=time.perf_counter() - planner_t0, status="success", error="")

        bus.subscribe(TaskScheduled, on_scheduled)
        bus.subscribe(TaskCompleted, on_completed)
        bus.subscribe(PlannerCompleted, on_planner_completed)

        # Fresh OrchestratorWorkflow (fresh agent instances + event bus) per
        # scan run -- no shared mutable state across concurrent scans.
        wf = OrchestratorWorkflow(event_bus=bus)

        initial_state = create_initial_state(
            scan_id=scan_id, repository_profile=profile, scan_mode=scan_mode,
            findings=findings, evidence=evidence,
        )
        config = {"configurable": {"thread_id": scan_id}}

        _emit(scan_id, "workflow.started", scan_mode=scan_mode)
        # Planner always runs first -- it starts the instant the graph is
        # invoked below, so mark it RUNNING now (its "completed" pairs with
        # the real PlannerCompleted event above).
        planner_t0 = time.perf_counter()
        _emit(scan_id, "agent.started", agent="planner", task="Builds the conditional execution plan for this scan.")

        plan_emitted = False
        last_state: Dict[str, Any] = dict(initial_state)

        for state in wf.compiled_graph.stream(initial_state, config=config, stream_mode="values"):
            last_state = state
            curated = _curated_state(state)
            result = _build_agentic_analysis_result(scan_id, record, curated)
            with _LOCK:
                record["state"] = curated
                record["result"] = result

            # Cooperative cancellation: checked once per real LangGraph
            # superstep (i.e. after whichever agent just finished), not on
            # a timer -- so "cancelled" always lands on a genuine execution
            # boundary, never mid-agent. See POST /{scan_id}/cancel below.
            if record.get("cancel_requested"):
                with _LOCK:
                    record["status"] = "cancelled"
                _emit(scan_id, "workflow.cancelled",
                      reason="Cancelled by user request.",
                      completed_agents=curated.get("completed_agents", []))
                return

            plan = state.get("execution_plan") or {}
            if plan and not plan_emitted:
                plan_emitted = True
                planned = set(plan.get("agent_order", []))
                structurally_skipped = [
                    n for n in GRAPH_NODES
                    if n not in planned and n not in ("planner", "repository")
                ]
                _emit(scan_id, "planner.completed", execution_plan=plan)
                for n in structurally_skipped:
                    _emit(scan_id, "agent.skipped", agent=n,
                          reason=plan.get("reason") or "not part of this scan mode's execution plan")

            _emit(scan_id, "state.snapshot", state=curated, result=result)

        # Anything the plan included but the live conditional routing never
        # actually invoked (e.g. "patch" when risk_fusion found zero
        # findings to remediate) genuinely never ran -- mark it SKIPPED
        # instead of leaving the UI showing it stuck at WAITING forever.
        plan = last_state.get("execution_plan") or {}
        for n in plan.get("agent_order", []):
            if n not in scheduled and n not in ("planner", "repository"):
                _emit(scan_id, "agent.skipped", agent=n,
                      reason="planned but not executed at runtime (e.g. no findings to act on)")

        final_curated = _curated_state(last_state)
        summary = _agentic_summary(last_state)
        with _LOCK:
            record["status"] = "completed"
            record["state"] = final_curated
            record["agentic_summary"] = summary
            # Rebuild with the now-"completed" status so result.run.status
            # reflects the final state, not "running" from mid-stream.
            final_result = _build_agentic_analysis_result(scan_id, record, final_curated)
            record["result"] = final_result
        _emit(
            scan_id, "workflow.completed",
            total_findings=len(findings),
            total_patches=len(last_state.get("patches", []) or []),
            deterministic_baseline=baseline,
            agentic_summary=summary,
            result=final_result,
        )
    except Exception as e:
        logger.exception("Agentic scan %s failed: %s", scan_id, e)
        with _LOCK:
            record["status"] = "error"
            record["error"] = str(e)
            # Rebuild `result` too (if a partial one exists) so a consumer
            # reading result.errors after a failure sees it there as well
            # as on the outer envelope's bare "error" string.
            if record.get("state"):
                record["result"] = _build_agentic_analysis_result(scan_id, record, record["state"])
        _emit(scan_id, "workflow.failed", error=str(e))
    finally:
        _emit(scan_id, "stream.end")


@router.post("/start")
async def start_agentic_scan(request: AgenticScanRequest):
    # Deterministic-first, no exceptions: the agentic layer is purely an
    # enrichment layer and never scans independently. A missing or unknown
    # scan_id is refused outright -- no clone+scan fallback exists.
    if not request.scan_id or request.scan_id not in _DETERMINISTIC_SCANS_STORE:
        raise HTTPException(status_code=404, detail=NO_DETERMINISTIC_SCAN_ERROR)

    scan_id = f"agentic_{uuid.uuid4().hex[:12]}"
    _SCANS[scan_id] = {
        # "queued" is real, not fabricated: the record exists and has been
        # accepted, but the background thread hasn't begun executing yet
        # (thread scheduling is genuinely asynchronous -- see the "status"
        # flip to "running" at the very top of _run_agentic_scan below,
        # which is the actual moment execution starts). There is no
        # separate work queue in this single-process implementation, so
        # CREATED and QUEUED (per the AI_CODE_GUARDIAN v2.1.0 lifecycle)
        # are the same real moment here; "queued" is used for both.
        "status": "queued",
        "log": [],
        "queues": [],
        "state": {},
        "result": None,
        "error": None,
        "source_scan_id": request.scan_id,
        "scan_mode": request.scan_mode,
        "started_at": time.time(),
        "deterministic_baseline": None,
        "agentic_summary": None,
        "repository_profile": None,
        # Cooperative cancellation flag -- checked between LangGraph
        # supersteps in the stream loop below. A Python thread can't be
        # force-killed safely, so cancellation is real but not instant: it
        # takes effect at the next state the graph yields, same as how the
        # UI already only ever shows real per-superstep progress.
        "cancel_requested": False,
    }
    thread = threading.Thread(
        target=_run_agentic_scan,
        args=(scan_id, request.scan_id, request.scan_mode),
        daemon=True,
    )
    thread.start()
    return {"scan_id": scan_id, "source_scan_id": request.scan_id, "graph": {"nodes": GRAPH_NODES, "edges": GRAPH_EDGES}}


@router.get("")
async def list_agentic_scans():
    return [
        {
            "scan_id": sid, "status": r["status"],
            "source_scan_id": r.get("source_scan_id"),
            "scan_mode": r.get("scan_mode"), "started_at": r.get("started_at"),
            "deterministic_baseline": r.get("deterministic_baseline"),
            "agentic_summary": r.get("agentic_summary"),
        }
        for sid, r in _SCANS.items()
    ]


@router.get("/{scan_id}")
async def get_agentic_scan(scan_id: str):
    record = _SCANS.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Agentic scan '{scan_id}' not found.")
    return {
        "scan_id": scan_id,
        "status": record["status"],
        "source_scan_id": record.get("source_scan_id"),
        "error": record.get("error"),
        "state": record.get("state", {}),
        # AgenticAnalysisResult -- see _build_agentic_analysis_result above.
        # The canonical, bucketed read model; "state" is kept for backward
        # compatibility with panels not yet migrated to read "result".
        "result": record.get("result"),
        "log": record.get("log", []),
        "deterministic_baseline": record.get("deterministic_baseline"),
        "agentic_summary": record.get("agentic_summary"),
        "graph": {"nodes": GRAPH_NODES, "edges": GRAPH_EDGES},
    }


@router.post("/{scan_id}/cancel")
async def cancel_agentic_scan(scan_id: str):
    """
    Requests cancellation of an in-flight agentic run. This is real,
    cooperative cancellation, not an instant kill -- a Python thread can't
    be safely force-terminated mid-agent, so this only sets a flag that
    the run loop (_run_agentic_scan, above) checks once per real LangGraph
    superstep (i.e. right after whichever agent just finished). The run
    transitions to "cancelled" at that next boundary and stops there --
    completed_agents up to that point stay exactly what they really are,
    nothing further is fabricated as having run.

    Refuses (409) if the run has already reached a terminal state
    (completed/error/cancelled) -- there is nothing left to cancel.
    """
    record = _SCANS.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Agentic scan '{scan_id}' not found.")
    with _LOCK:
        status = record["status"]
        if status not in ("queued", "running"):
            raise HTTPException(
                status_code=409,
                detail=f"Cannot cancel: agentic scan '{scan_id}' is already '{status}'.",
            )
        record["cancel_requested"] = True
    return {"scan_id": scan_id, "status": "cancel_requested"}


@router.get("/{scan_id}/stream")
async def stream_agentic_scan(scan_id: str):
    record = _SCANS.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Agentic scan '{scan_id}' not found.")

    q: "queue.Queue[Dict[str, Any]]" = queue.Queue()
    with _LOCK:
        for evt in record["log"]:
            q.put(evt)
        record["queues"].append(q)

    async def event_generator():
        try:
            while True:
                try:
                    evt = await asyncio.to_thread(q.get, True, 30)
                except queue.Empty:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(evt, default=str)}\n\n"
                if evt.get("type") == "stream.end":
                    break
        finally:
            with _LOCK:
                if q in record["queues"]:
                    record["queues"].remove(q)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
