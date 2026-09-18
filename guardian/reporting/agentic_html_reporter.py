"""
Agentic / Unified HTML Report
==============================
A self-contained HTML renderer for the LangGraph agentic analysis
(guardian/orchestrator + guardian/agents), independent of and never
imported by guardian/reporting/pdf_reporter.py or any other existing
deterministic reporter. Nothing here touches those files or the
`registry.reporter(...)` plugin system they're registered under -- this
is a separate, additive rendering path called only from the
`/api/v1/reports/agentic-download` endpoint (backend/app/api/v1/reports.py).

This report answers "how secure is this repository based on what was
actually analyzed?" -- it never renders a source-control workflow/approval
decision. The Repository Security Status badge (see _verdict_section) is
computed by guardian.reporting.report_view_model.compute_verdict(), the
SAME function the Security Report and the Reports page use.

v2.1.0 report redesign
-----------------------
This file no longer reads raw curated-state fields directly. Every section
below is built from guardian.reporting.report_view_model -- the
normalization + validation + plain-English presentation layer between raw
backend data and this HTML. That module documents, and this file enforces,
the one rule the whole redesign exists for:

    THE DETERMINISTIC SCANNER REMAINS THE SOURCE OF TECHNICAL TRUTH.
    Nothing rendered here may be a value the backend did not actually
    produce. Missing or malformed data renders one of a small, fixed set
    of honest fallback sentences (report_view_model.IMPACT_UNKNOWN /
    NO_ATTACK_PATH / EVIDENCE_NEEDS_REVIEW) -- never an invented
    replacement.

Three strict labels are used throughout and never combined:
  [DETECTED]  -- straight from guardian.core.pipeline.ScanPipeline.
  [ANALYZED]  -- an agent's interpretation of DETECTED evidence.
  [VALIDATED] -- a patch a real ValidationAgent run actually confirmed.

Two modes, both produced by the same function:
  - render_agentic_report_html(agentic)                -> Agentic Report:
    agent-focused sections only. Deliberately does NOT render the full
    deterministic findings list (Section 13) -- it stays agent-execution,
    business, threat, risk, remediation, validation, and traceability.
  - render_agentic_report_html(agentic, deterministic)  -> Unified Report:
    the above, PLUS the full "Deterministic Security Findings" section,
    grouped by severity as cards (not a flat table) -- the complete
    DETECTED -> ANALYZED -> PRIORITIZED -> REMEDIATED -> VALIDATED story.
"""
from __future__ import annotations

import html
from datetime import datetime
from typing import Any, Dict, List, Optional

from guardian.reporting import report_view_model as rvm

_SEV_COLOR = {
    "critical": "#f4374a", "high": "#ff8a3d",
    "medium": "#f5c451", "low": "#4ade80", "info": "#8e8e9a",
}

_STATUS_COLOR = {
    "validated": ("#4ade80", "rgba(74,222,128,.12)"), "passed": ("#4ade80", "rgba(74,222,128,.12)"),
    "proposed": ("#8e8e9a", "rgba(142,142,154,.16)"), "pending review": ("#f5c451", "rgba(245,196,81,.12)"),
    "pending": ("#f5c451", "rgba(245,196,81,.12)"), "rejected": ("#f4374a", "rgba(244,55,74,.12)"),
    "completed": ("#4ade80", "rgba(74,222,128,.12)"), "success": ("#4ade80", "rgba(74,222,128,.12)"),
    "running": ("#ff8a3d", "rgba(255,138,61,.12)"), "failed": ("#f4374a", "rgba(244,55,74,.12)"),
    "error": ("#f4374a", "rgba(244,55,74,.12)"), "skipped": ("#8e8e9a", "rgba(142,142,154,.16)"),
    "waiting": ("#8e8e9a", "rgba(142,142,154,.16)"),
}


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _badge(status: str) -> str:
    key = str(status or "").lower()
    fg, bg = _STATUS_COLOR.get(key, ("#8e8e9a", "rgba(142,142,154,.16)"))
    return f"<span class='badge' style='color:{fg};background:{bg};border:1px solid {fg}33'>{_e(status or 'unknown')}</span>"


def _sev_badge(sev: str) -> str:
    key = str(sev or "").lower()
    color = _SEV_COLOR.get(key, "#8e8e9a")
    return f"<span class='badge' style='color:#0a0a0f;background:{color}'>{_e(sev or 'Unknown').upper()}</span>"


def _label(kind: str) -> str:
    """[DETECTED] / [ANALYZED] / [VALIDATED] -- the report's one strict
    origin vocabulary (Section 6). Never combined with, or substituted for,
    each other."""
    text, cls = {
        "detected": ("DETECTED", "lbl-detected"),
        "analyzed": ("ANALYZED", "lbl-analyzed"),
        "validated": ("VALIDATED", "lbl-validated"),
    }[kind]
    return f"<span class='origin {cls}'>{text}</span>"


def _empty(message: str) -> str:
    return f"<p class='empty'>{_e(message)}</p>"


# Section 16: "avoid showing 100+ rows by default". Nothing is ever
# dropped from the underlying data -- only the RENDERED list is capped,
# with an honest "+N more" note naming exactly how many were held back.
def _cap(items: List[Any], limit: int = 24) -> "tuple[List[Any], int]":
    if len(items) <= limit:
        return items, 0
    return items[:limit], len(items) - limit


def _more_note(remaining: int, noun: str) -> str:
    if remaining <= 0:
        return ""
    return f"<p class='more-note'>+ {remaining} more {noun} not shown above (full detail is in the JSON/SARIF export).</p>"


# ---------------------------------------------------------------------------
# Section 8/9: a patch's real diff -- guardian/agents/patch/models.py's
# PatchProposal.git_diff when the agent produced one, otherwise a real
# before/after from original_snippet/suggested_replacement (the same two
# fields the diff was generated from). Neither is ever synthesized here --
# if both are empty, this renders nothing (never a fabricated diff).
# ---------------------------------------------------------------------------
def _patch_diff_html(patch: Dict[str, Any]) -> str:
    git_diff = (patch.get("git_diff") or "").strip()
    if git_diff:
        return f"<pre class='diff'><code>{_e(git_diff)}</code></pre>"
    before, after = patch.get("original_snippet") or "", patch.get("suggested_replacement") or ""
    if before or after:
        return (
            "<div class='diff-before-after'>"
            f"<pre class='diff diff-before'><code>- {_e(before) or '(empty)'}</code></pre>"
            f"<pre class='diff diff-after'><code>+ {_e(after) or '(empty)'}</code></pre>"
            "</div>"
        )
    return ""


# ---------------------------------------------------------------------------
# Section 5/6/7: VERDICT -- the conclusion-first hero card that replaces the
# old TL;DR banner + plain Q&A Executive Summary as the report's lead. Every
# field is composed by report_view_model.compute_verdict() /
# verdict_narrative() from real, already-computed signals (severity counts,
# real patch/validation outcomes, RiskFusionAgent's own composite score) --
# this function only lays the pieces out. Stats shown are only ones that
# actually exist in the data (Section 7: never a fabricated zero).
# ---------------------------------------------------------------------------
def _verdict_section(
    verdict: Dict[str, str],
    narrative: Dict[str, str],
    critical: int,
    high: int,
    direct_attack_paths: int,
    total_attack_paths: int,
    risk_scores: Dict[str, Any],
    patches_by_status: Dict[str, List[Dict[str, Any]]],
    has_findings_data: bool,
) -> str:
    stats: List[str] = []
    if has_findings_data:
        stats.append(f"<div class='vstat'><span class='vnum'>{_e(critical)}</span><span class='vlbl'>Critical Findings</span></div>")
        stats.append(f"<div class='vstat'><span class='vnum'>{_e(high)}</span><span class='vlbl'>High Findings</span></div>")
    if total_attack_paths:
        stats.append(f"<div class='vstat'><span class='vnum'>{_e(total_attack_paths)}</span><span class='vlbl'>Attack Path(s) Modeled</span></div>")
    score = risk_scores.get("composite_risk_score")
    if score is not None:
        band = rvm.risk_band_label(score)
        stats.append(f"<div class='vstat'><span class='vnum'>{_e(score)}/10</span><span class='vlbl'>Overall Risk{f' — {_e(band)}' if band else ''}</span></div>")
    validated_n = len(patches_by_status.get("VALIDATED") or [])
    rejected_n = len(patches_by_status.get("REJECTED") or [])
    if validated_n or rejected_n:
        stats.append(f"<div class='vstat'><span class='vnum'>{_e(validated_n)}</span><span class='vlbl'>Patches Validated</span></div>")
        stats.append(f"<div class='vstat'><span class='vnum'>{_e(rejected_n)}</span><span class='vlbl'>Patches Rejected</span></div>")
    stats_html = f"<div class='vstats'>{''.join(stats)}</div>" if stats else ""

    limitation_html = (
        f"<div class='vrow'><div class='vrow-label'>THE CATCH</div><div class='vrow-body'>{_e(narrative['limitation'])}</div></div>"
        if narrative.get("limitation") else ""
    )

    return f"""
    <section class="verdict verdict-{_e(verdict['tone'])}">
      <div class="verdict-badge">{_e(verdict['label'])}</div>
      {stats_html}
      <div class="vrow"><div class="vrow-label">THE ISSUE</div><div class="vrow-body">{_e(narrative['issue'])}</div></div>
      <div class="vrow"><div class="vrow-label">WHAT AGENTS DETERMINED</div><div class="vrow-body">{_e(narrative['agents_determined'])}</div></div>
      {limitation_html}
      <div class="vrow"><div class="vrow-label">RECOMMENDED NEXT STEP</div><div class="vrow-body">{_e(narrative['next_step'])}</div></div>
    </section>
    """


# ---------------------------------------------------------------------------
# Section 3 (legacy): the original 4-question Executive Summary. Kept, not
# deleted -- every one of these answers is still real, independently-useful
# detail -- but demoted to a collapsed <details> beneath the new Verdict
# card, which is now the report's actual conclusion-first lead.
# ---------------------------------------------------------------------------
def _executive_summary_section(summary: Dict[str, str]) -> str:
    rows = [
        ("Is the repository secure?", summary["security_status_summary"]),
        ("What matters most?", summary["what_matters_most"]),
        ("What could happen if this is exploited?", summary["what_could_happen"]),
        ("What should be fixed first?", summary["what_to_fix_first"]),
    ]
    cards = "".join(
        f"<div class='qa-card'><div class='q'>{_e(q)}</div><div class='a'>{_e(a)}</div></div>"
        for q, a in rows
    )
    return f"""
    <section class="exec-qa-section">
      <h2>💡 Executive Summary (Plain English)</h2>
      <p class="sub">Key conclusions derived from real scanner findings and agentic security analysis.</p>
      <div class="qa-grid">{cards}</div>
    </section>
    """


# ---------------------------------------------------------------------------
# Section 8: compact visual agent pipeline -- replaces the old grid of 10
# large expandable agent cards as the report's primary "how did the agents
# work" view. Each step's status/contribution comes from the same real
# per-agent trace + rvm.agent_key_conclusion() the old cards used; the full
# technical detail (runtime, tools, errors) still exists, just moved to the
# Agent Execution Metrics table under a <details> further down rather than
# repeated here.
# ---------------------------------------------------------------------------
_PIPELINE_STEPS = [
    ("repository", "Repository"), ("security", "Security"), ("business", "Business"),
    ("architecture", "Architecture"), ("dependency", "Dependency"), ("threat_simulation", "Threat"),
    ("policy", "Policy"), ("risk_fusion", "Risk Fusion"), ("patch", "Remediation"), ("validation", "Validation"),
]


def _agent_status(agent: str, trace_by_agent: Dict[str, Dict[str, Any]], completed: set) -> str:
    t = trace_by_agent.get(agent)
    if t:
        return "failed" if (t.get("result") or {}).get("status") == "error" else "completed"
    if agent in completed:
        return "completed"
    return "skipped"


_STATUS_ICON = {"completed": "✓", "failed": "✗", "skipped": "—"}


def _pipeline_section(agentic: Dict[str, Any]) -> str:
    trace = agentic.get("agent_trace", []) or []
    trace_by_agent = {t.get("agent_name"): t for t in trace if isinstance(t, dict)}
    completed = set(agentic.get("completed_agents") or [])
    plan = agentic.get("execution_plan") or {}
    order = set(plan.get("agent_order") or trace_by_agent.keys())

    steps = []
    for agent, label in _PIPELINE_STEPS:
        # repository/security always run; the rest only when actually
        # planned (guardian/orchestrator/langgraph_flow.py's conditional
        # routing) or present in the real trace -- an agent that was never
        # planned and never ran is SKIPPED, not silently omitted.
        if agent not in ("repository", "security") and agent not in order and agent not in trace_by_agent:
            status = "skipped"
        else:
            status = _agent_status(agent, trace_by_agent, completed)
        contribution = rvm.agent_key_conclusion(agent, agentic) or "Ran as part of this agentic analysis."
        steps.append(f"""
        <div class="pstep pstep-{status}">
          <div class="pstep-head"><span class="pstep-icon">{_STATUS_ICON[status]}</span><span class="pstep-name">{_e(label)}</span></div>
          <p class="pstep-body">{_e(contribution)}</p>
        </div>""")

    return f"""
    <section>
      <h2>Agent Execution Pipeline {_label("analyzed")}</h2>
      <p class="sub">What each agent actually contributed to this run, in execution order. Full runtime/tooling
      detail is in Agent Execution Metrics below.</p>
      <div class="pipeline">{"".join(steps)}</div>
    </section>
    """


# ---------------------------------------------------------------------------
# Deterministic findings, grouped by severity as cards (Unified Report only)
# ---------------------------------------------------------------------------
def _deterministic_section(deterministic: Dict[str, Any], repo_root: str) -> str:
    scan = deterministic.get("scan", {}) or {}
    raw_findings = scan.get("findings", []) or []
    target = deterministic.get("target") or (deterministic.get("repository") or {}).get("root", "")
    groups = rvm.group_findings_by_severity(raw_findings, repo_root)

    if not groups:
        body = _empty("No deterministic findings in this scan.")
    else:
        sections = []
        for sev_key, items in groups:
            label = rvm.SEVERITY_LABEL.get(sev_key, sev_key.title())
            visible, remaining = _cap(items, limit=24)
            cards = "".join(
                f"""<div class="finding-card sev-{_e(sev_key)}">
                  <div class="finding-head">
                    <span class="fid">{_e(f.get('rule_id') or f.get('finding_id') or '')}</span>
                    {_sev_badge(f.get('severity'))}
                  </div>
                  <p class="plain">{_e(f['_plain_category'])}</p>
                  <p class="loc"><code>{_e(f['_display_file'])}{':' + str(f['_display_line']) if f.get('_display_line') is not None else ''}</code></p>
                  {f"<p class='rec'><b>Recommendation:</b> {_e(f.get('recommendation'))}</p>" if f.get('recommendation') else ''}
                </div>"""
                for f in visible
            )
            sections.append(
                f"<h3>{_e(label)} ({len(items)}) {_label('detected')}</h3><div class='finding-grid'>{cards}</div>"
                f"{_more_note(remaining, 'findings')}"
            )
        body = "".join(sections)

    return f"""
    <section>
      <h2>Deterministic Security Findings {_label("detected")}</h2>
      <p class="sub">Source of technical truth: guardian.core.pipeline.ScanPipeline. Target: <code>{_e(target)}</code>
      &middot; {_e(scan.get('total_findings', len(raw_findings)))} finding(s), grouped by severity.</p>
      {body}
    </section>
    """


# ---------------------------------------------------------------------------
# Section 9/11: Agent Execution Metrics -- the real per-agent runtime/
# status/findings-consumed numbers, kept in full (nothing removed from the
# old Agent Execution Overview cards is lost -- see the compact pipeline
# above for the plain-English contribution, this table for the technical
# detail) but now rendered inside a <details>, not front-and-center, per
# the redesign's "communicate visually, keep technical detail available
# without dominating the report" requirement. Status is taken from the real
# per-agent trace record, never assumed "success" just because the graph
# node executed -- an agent absent from agent_trace (structurally or
# conditionally skipped, see guardian/orchestrator/langgraph_flow.py) is
# shown as SKIPPED, not silently omitted. Never exposes secrets, tokens, or
# local filesystem paths -- only runtime, tool names, and error text, all of
# which are already scrubbed to repository-relative form elsewhere in this
# module.
# ---------------------------------------------------------------------------
def _agent_execution_metrics_section(agentic: Dict[str, Any]) -> str:
    trace = agentic.get("agent_trace", []) or []
    plan = agentic.get("execution_plan") or {}
    trace_by_agent = {t.get("agent_name"): t for t in trace if isinstance(t, dict)}
    planned = list(plan.get("agent_order") or []) or list(trace_by_agent.keys())
    completed = set(agentic.get("completed_agents") or [])

    if not planned and not trace:
        return f"<details class='detail-block'><summary>View Agent Execution Metrics</summary>{_empty('No agent execution recorded.')}</details>"

    rows = []
    for agent in ["planner"] + [a for a in planned if a != "planner"]:
        t = trace_by_agent.get(agent)
        if t:
            status = "error" if (t.get("result") or {}).get("status") == "error" else "success"
            ms = (t.get("execution_time") or 0) * 1000
            time_str = f"{ms:.1f}ms" if ms < 10 else f"{ms:.0f}ms"
            evidence_n = len(t.get("evidence_ids") or [])
            errors = "; ".join(t.get("errors") or []) or "—"
        elif agent in completed:
            status, time_str, evidence_n, errors = "success", "—", 0, "—"
        else:
            status, time_str, evidence_n, errors = "skipped", "—", 0, "—"
        rows.append(
            f"<tr><td>{_e(rvm.agent_label(agent))}</td><td>{_badge(status)}</td><td>{_e(time_str)}</td>"
            f"<td>{_e(evidence_n)}</td><td>{_e(errors)}</td></tr>"
        )

    plan_line = ""
    if plan:
        order = plan.get("agent_order") or []
        plan_line = (
            f"<p class='sub'>Execution plan: priority=<b>{_e(plan.get('priority'))}</b>, "
            f"confidence=<b>{_e(plan.get('confidence'))}</b>, order={_e(' → '.join(order))}</p>"
        )

    return f"""
    <details class="detail-block">
      <summary>View Agent Execution Metrics</summary>
      {plan_line}
      <p class="sub">Runtime is real wall-clock time measured around each agent's execution
      (guardian/agents/base/agent.py) -- these agents make no LLM calls, so a sub-millisecond runtime is a real,
      fast, deterministic step, not an unmeasured placeholder. SKIPPED means the planner's execution plan (or a
      live routing decision, e.g. no findings to patch) genuinely did not run that agent.</p>
      <table><thead><tr><th>Agent</th><th>Status</th><th>Runtime</th><th>Evidence Produced</th><th>Errors</th></tr></thead>
      <tbody>{''.join(rows)}</tbody></table>
    </details>
    """


# ---------------------------------------------------------------------------
# Section 1/2/17: Findings Analyzed -- the report's core, finding-centric
# section. For every Critical/High finding this run adopted, shows exactly
# what each agent actually produced for it: a missing sub-section means
# that agent genuinely produced nothing for this finding, never that it was
# omitted from the report. Medium/Low/Info findings are counted, not
# individually expanded, for the same "avoid 100+ rows" reason _cap()
# already applies elsewhere in this file -- their real data (if any) is
# still reachable via Evidence Traceability / the deterministic findings
# list.
# ---------------------------------------------------------------------------
def _finding_analysis_card(fa: Dict[str, Any]) -> str:
    sev_lower = fa["severity"].lower()
    high_pri = sev_lower in ("critical", "high")
    loc = f"{fa['display_file']}{':' + str(fa['display_line']) if fa.get('display_line') is not None else ''}"
    # EXPANDED by default (Section 21): header, Deterministic Evidence,
    # Threat Analysis for High/Critical, Remediation status line.
    expanded = [f"""
      <div class="finding-head">
        <span class="fid">{_e(fa['rule_id'])}</span>
        {_sev_badge(fa['severity'])}
      </div>
      <p class="plain"><b>Deterministic Evidence:</b> {_e(fa['plain_category'])} <code>{_e(loc)}</code></p>
      <p class="plain sub"><b>How serious is it?</b> {_e(rvm.severity_explanation(fa['severity']) or rvm.IMPACT_UNKNOWN)}</p>
    """]

    path = fa.get("attack_path")
    if path:
        plain = rvm.plain_english_reachability(str(path.get("reachability") or "")) or rvm.IMPACT_UNKNOWN
        basis = str(path.get("exploitability_basis") or "")
        scenario = path.get("exploit_scenario") or ""
        confirmed = "deterministic taint analysis" in basis
        path_tag = "<span class='tag tag-confirmed'>Confirmed</span>" if confirmed else "<span class='tag tag-heuristic'>⚠ Potential / Heuristic Path</span>"
        expanded.append(f"""
        <p class="plain"><b>Threat Analysis:</b> {path_tag} {_e(plain)}
          <span class="sub">({_e(path.get('entry_point', '?'))} &rarr; {_e(path.get('attack_vector', '?'))} &rarr; {_e(path.get('target_file', '?'))},
          exploitability {(path.get('exploitability') or 0):.2f}{f" &mdash; {_e(basis)}" if basis else ""})</span></p>""")
        if scenario:
            expanded.append(f"<p class='plain sub'><b>Exploit Scenario:</b> {_e(scenario)}</p>")
        elif not confirmed:
            expanded.append("<p class='plain sub'><b>Exploit Scenario:</b> Data flow from the entry point to this finding was NOT confirmed.</p>")
    elif high_pri:
        expanded.append(f"<p class='plain sub'><b>Threat Analysis:</b> {_e(rvm.NO_ATTACK_PATH)}</p>")

    patch = fa.get("patch")
    if patch:
        v = patch.get("_validation")
        real_status = "VALIDATED" if (v and v.get("status") == "PASSED") else ("REJECTED" if (v and v.get("status") == "REJECTED") else "PROPOSED")
        status = "VALIDATED" if real_status == "VALIDATED" else ("REJECTED" if real_status == "REJECTED" else "PROPOSED (Not Validated)")
        explanation = rvm.remediation_status_explanation(real_status)
        expanded.append(f"""
        <p class="plain"><b>Remediation:</b> {_badge(status)} patch at
          <code>{_e(patch.get('affected_file', ''))}:{_e(patch.get('affected_lines', ''))}</code>
          {f"&mdash; {_e(patch.get('explanation'))}" if patch.get('explanation') else ''}</p>
        {f"<p class='plain sub'>{_e(explanation)}</p>" if explanation else ''}""")
    elif high_pri:
        expanded.append(
            f"<p class='plain sub'><b>Remediation:</b> {_badge('NOT GENERATED')} "
            f"{_e(rvm.remediation_status_explanation('NOT GENERATED'))}</p>"
        )

    # COLLAPSED by default (Section 21): Architecture, Business, Policy,
    # Risk detail, patch diff, validation technical detail. Only rendered
    # at all when there is real content for at least one of them.
    collapsed: List[str] = []

    arch = fa.get("architecture")
    if arch:
        tb = arch.get("trust_boundaries") or []
        arch_bits = []
        if arch.get("is_critical_component"):
            arch_bits.append("this file is one of the repository's detected critical entry points/auth modules")
        if tb:
            arch_bits.append(f"repository-wide trust boundaries: {', '.join(_e(b) for b in tb)}")
        elif arch.get("trust_boundaries_note"):
            arch_bits.append(_e(arch["trust_boundaries_note"]))
        if arch_bits:
            collapsed.append(f"<p class='plain'><b>Architecture Analysis:</b> {'; '.join(arch_bits)}.</p>")

    chain = fa.get("risk_correlation")
    if chain:
        collapsed.append(f"""
        <p class="plain"><b>Risk Fusion:</b> correlated as &ldquo;{_e(chain.get('title') or chain.get('chain_id', ''))}&rdquo;
          &middot; business criticality: {_e(chain.get('business_criticality', '') or 'unknown')}
          &middot; exploitability: {(chain.get('exploitability') or 0):.2f}
          &middot; {_e(len(chain.get('policy_violations') or []))} policy violation(s) attached.</p>""")

    biz = fa.get("business_violations")
    if biz:
        lines = "; ".join(_e(v.get("why") or v.get("what") or v.get("rule") or "Business rule flagged.") for v in biz[:3])
        collapsed.append(f"<p class='plain'><b>Business Impact:</b> {lines}</p>")

    pol = fa.get("policy_violations")
    if pol:
        names = ", ".join(_e(v.get("rule_name") or v.get("policy_name") or "policy") for v in pol[:5])
        collapsed.append(f"<p class='plain'><b>Policy Analysis:</b> violates {names}.</p>")

    if patch:
        v = patch.get("_validation")
        diff_html = _patch_diff_html(patch)
        if diff_html:
            collapsed.append(diff_html)
        if v:
            reason = ""
            status = "VALIDATED" if v.get("status") == "PASSED" else ("REJECTED" if v.get("status") == "REJECTED" else str(v.get("status") or ""))
            if status == "REJECTED" and v.get("issues"):
                reason = f" Reason: {_e('; '.join(str(i) for i in v['issues']))}"
            collapsed.append(f"""
            <p class="sub"><b>Validation:</b> grounded={'yes' if v.get('grounding_passed') else 'no'},
              syntax valid={'yes' if v.get('syntax_valid') else 'no'}, result={_e(v.get('status', ''))}.{reason}</p>""")
        else:
            collapsed.append("<p class='sub'><b>Validation:</b> NOT VALIDATED — no validation record exists for this patch yet.</p>")

    collapsed_html = (
        f"<details class='fa-detail'><summary>Architecture / Business / Policy / Risk / Patch detail</summary>{''.join(collapsed)}</details>"
        if collapsed else ""
    )

    return f"<div class='finding-card fa-card sev-{_e(sev_lower)}'>{''.join(expanded)}{collapsed_html}</div>"


def _findings_analyzed_section(agentic: Dict[str, Any], repo_root: str) -> str:
    findings = [f for f in (agentic.get("findings") or []) if rvm.is_valid_finding(f)]
    if not findings:
        return f"<section><h2>Findings Analyzed {_label('analyzed')}</h2>{_empty('No deterministic findings were adopted into this agentic run.')}</section>"

    attack_by_f = rvm.attack_paths_by_finding(agentic.get("attack_paths") or [])
    chains_by_f = rvm.chains_by_finding(agentic.get("correlated_findings") or {})
    biz_by_file = rvm.business_violations_by_file(agentic.get("business_violations") or [])
    policy_by_f = rvm.policy_violations_by_finding(agentic.get("policy_results") or {})
    patches_by_f = rvm.patches_by_finding_with_validation(agentic.get("patches") or [], agentic.get("validation_results") or [])
    arch_ctx = agentic.get("architecture_context") or {}

    high_pri = [f for f in findings if str(f.get("severity", "")).lower() in ("critical", "high")]
    other_count = len(findings) - len(high_pri)

    visible, remaining = _cap(high_pri, limit=20)
    cards = "".join(
        _finding_analysis_card(rvm.build_finding_analysis(f, repo_root, attack_by_f, chains_by_f, biz_by_file, policy_by_f, patches_by_f, arch_ctx))
        for f in visible
    )
    body = cards if cards else _empty("No Critical/High findings were adopted into this run.")
    other_note = (
        f"<p class='sub'>{other_count} additional Medium/Low/Info finding(s) were adopted but are not individually "
        f"expanded here -- see Deterministic Security Findings / Evidence Traceability for detail on each.</p>"
        if other_count else ""
    )

    return f"""
    <section>
      <h2>Findings Analyzed {_label("analyzed")}</h2>
      <p class="sub">Every Critical/High finding this run adopted, with exactly what each agent actually produced
      for it -- a missing sub-section below means that agent genuinely produced nothing for this finding, not that
      it was left out of the report.</p>
      <div class="finding-analysis-list">{body}</div>
      {_more_note(remaining, 'Critical/High findings')}
      {other_note}
    </section>
    """


# ---------------------------------------------------------------------------
# Policy Analysis -- real PolicyAgent output (guardian/policies/manager.py).
# ---------------------------------------------------------------------------
def _policy_section(agentic: Dict[str, Any]) -> str:
    policy = agentic.get("policy_results") or {}
    if not policy:
        return f"<section><h2>Policy Analysis {_label('analyzed')}</h2>{_empty('PolicyAgent did not run, or produced no result, for this scan.')}</section>"

    violations = policy.get("violations") or []
    passed = policy.get("passed_policies") or []
    failed = policy.get("failed_policies") or []
    visible, remaining = _cap(violations, limit=30)
    rows = "".join(
        f"<tr><td>{_e(v.get('finding_id', ''))}</td><td>{_e(v.get('policy_name', ''))}</td>"
        f"<td>{_e(v.get('rule_id', ''))} &middot; {_e(v.get('rule_name', ''))}</td>"
        f"<td>{_sev_badge(v.get('severity', ''))}</td></tr>"
        for v in visible
    )
    return f"""
    <section>
      <h2>Policy Analysis {_label("analyzed")}</h2>
      <p class="sub">{_e(policy.get('total_violations', len(violations)))} violation(s) &middot;
      {_e(len(failed))} failed / {_e(len(passed))} passed policy pack(s) (active packs evaluated by PolicyAgent:
      {_e(', '.join(passed + failed) or '—')}).</p>
      {f"<table><thead><tr><th>Finding</th><th>Policy</th><th>Rule</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>" if violations else _empty('No policy violations found.')}
      {_more_note(remaining, 'violations')}
    </section>
    """


# ---------------------------------------------------------------------------
# Section 8: Business Intent -- business language first, no invented
# revenue/fraud/compliance consequence.
# ---------------------------------------------------------------------------
def _business_section(agentic: Dict[str, Any], repo_root: str) -> str:
    # Section 12: distinguish "no business context was ever supplied" from
    # "context was supplied and produced zero violations" -- two different
    # real BusinessAgent outcomes the old code collapsed into one identical
    # empty-state message.
    biz_state = rvm.business_section_state(agentic)
    violations = biz_state["violations"]
    if not violations:
        message = rvm.NO_BUSINESS_CONTEXT if biz_state["no_context"] else "No business intent violations detected."
        if biz_state["no_context"] and biz_state["reason"]:
            message = f"{rvm.NO_BUSINESS_CONTEXT} ({biz_state['reason']})"
        return f"<section><h2>Business Impact {_label('analyzed')}</h2>{_empty(message)}</section>"

    visible, remaining = _cap(violations, limit=24)
    cards = []
    for v in visible:
        nv = rvm.normalize_business_violation(v, repo_root)
        loc = f"<code>{_e(nv['_display_file'])}{':' + str(v.get('line_number')) if v.get('line_number') is not None else ''}</code>" if nv["_display_file"] else ""
        confidence = v.get("score")
        cards.append(f"""
        <div class="business-card">
          <div class="business-head">
            {_badge(v.get('status', ''))}
            <span class="rule">{_e(v.get('rule') or v.get('rule_id') or '')}</span>
          </div>
          <p class="plain">{_e(nv['_headline'])}</p>
          {f"<p class='loc'>{loc}</p>" if loc else ''}
          <p class="evidence">{_e(nv['_evidence'])}</p>
          {f"<p class='sub'>Match confidence: {confidence:.0%}</p>" if isinstance(confidence, (int, float)) else ''}
        </div>""")

    return f"""
    <section>
      <h2>Business Impact {_label("analyzed")}</h2>
      <p class="sub">Compared against the business rules document uploaded for this repository. Every line below
      is the matcher's real output -- there is no invented revenue, fraud, or compliance consequence attached.</p>
      <div class="business-grid">{''.join(cards)}</div>
      {_more_note(remaining, 'violations')}
    </section>
    """


# ---------------------------------------------------------------------------
# Section 7: Threat & Attack Paths -- top 3 prominent, remainder grouped.
# ---------------------------------------------------------------------------
def _threat_section(agentic: Dict[str, Any]) -> str:
    paths = agentic.get("attack_paths", []) or []
    top, grouped = rvm.top_and_grouped_attack_paths(paths)

    if not top and not grouped:
        return f"<section><h2>Threat &amp; Attack Paths {_label('analyzed')}</h2>{_empty(rvm.NO_ATTACK_PATH)}</section>"

    top_cards = []
    for p in top:
        reach = str(p.get("reachability") or "")
        plain = rvm.plain_english_reachability(reach) or rvm.IMPACT_UNKNOWN
        basis = str(p.get("exploitability_basis") or "")
        confirmed = "deterministic taint analysis" in basis
        tag = "<span class='tag tag-confirmed'>Confirmed</span>" if confirmed else "<span class='tag tag-heuristic'>⚠ Potential / Heuristic Path</span>"
        limitation = "" if confirmed else "<p class='sub'>Data flow from the entry point to this sink was not confirmed — this path is inferred from entry-point/severity heuristics.</p>"
        top_cards.append(f"""
        <div class="attack-card">
          {tag}
          <div class="chain">
            <span class="hop">{_e(p.get('entry_point', '?'))}</span>
            <span class="arrow">&rarr;</span>
            <span class="hop hop-mid">{_e(p.get('attack_vector', '?'))}</span>
            <span class="arrow">&rarr;</span>
            <span class="hop hop-target">{_e(p.get('target_file', '?'))}</span>
          </div>
          <p class="plain">{_e(plain)}</p>
          <p class="sub">Exploitability: <b>{(p.get('exploitability') or 0):.2f}</b> &middot; Finding: <b>{_e(p.get('finding_id', ''))}</b></p>
          {limitation}
        </div>""")

    grouped_rows = "".join(
        f"<tr><td>{_e(g.get('attack_vector'))}</td><td><code>{_e(g.get('target_file'))}</code></td>"
        f"<td>{_e(g.get('reachability'))}</td><td>{_e(', '.join(g.get('finding_ids') or []))}</td>"
        f"<td>{(g.get('max_exploitability') or 0):.2f}</td></tr>"
        for g in grouped
    )
    grouped_html = ""
    if grouped:
        grouped_html = f"""
        <details class="detail-block">
          <summary>View all attack paths ({len(grouped)} additional group(s), deduplicated by vector + target)</summary>
          <p class="sub">Repetitive paths against the same target (e.g. multiple findings via the same vulnerable
          dependency) are grouped here; every original finding_id is preserved for traceability.</p>
          <table><thead><tr><th>Vector</th><th>Target</th><th>Reachability</th><th>Finding IDs</th><th>Max Exploitability</th></tr></thead>
          <tbody>{grouped_rows}</tbody></table>
        </details>
        """

    return f"""
    <section>
      <h2>Threat &amp; Attack Paths {_label("analyzed")}</h2>
      <p class="sub">Top {len(top)} path(s) by exploitability, modeled by the Threat Simulation Agent over real
      deterministic findings.</p>
      <div class="attack-grid">{''.join(top_cards)}</div>
      {grouped_html}
    </section>
    """


# ---------------------------------------------------------------------------
# Section 9: Risk Fusion -- plain-English "why is risk high" per dimension.
# ---------------------------------------------------------------------------
def _risk_section(
    agentic: Dict[str, Any], critical: int, high: int, direct_attack_paths: int,
    policy_violations: int, business_no_context: bool,
) -> str:
    risk = agentic.get("risk_scores") or {}
    correlated = agentic.get("correlated_findings") or {}
    if not risk:
        return f"<section><h2>Risk Fusion {_label('analyzed')}</h2>{_empty('RiskFusionAgent has not produced a composite score.')}</section>"

    score = risk.get("composite_risk_score")
    band = rvm.risk_band_label(score)
    dims = rvm.risk_dimension_explanations(risk)
    dim_cards = "".join(
        f"""<div class="risk-card">
          <div class="risk-head"><span class="num">{d['score']:.1f}</span><span class="lbl">{_e(d['dimension'])}</span></div>
          <p class="plain">{_e(d['explanation'])}</p>
        </div>"""
        for d in dims
    )

    # Section 16 -- "why this risk level", each bullet a real, checkable
    # signal already computed elsewhere in this report; ✓ marks a signal
    # that IS present/known, ⚠ marks one that's missing/uncertain -- never
    # an independently-judged good/bad label.
    why_bullets: List[str] = []
    if critical > 0:
        why_bullets.append(f"<li class='why-yes'>✓ {critical} Critical-severity deterministic finding(s)</li>")
    elif high > 0:
        why_bullets.append(f"<li class='why-yes'>✓ {high} High-severity deterministic finding(s)</li>")
    if direct_attack_paths:
        why_bullets.append(f"<li class='why-yes'>✓ {direct_attack_paths} directly reachable attack path(s) modeled</li>")
    if business_no_context:
        why_bullets.append(f"<li class='why-warn'>⚠ Business context unavailable</li>")
    if policy_violations:
        why_bullets.append(f"<li class='why-yes'>✓ {policy_violations} configured policy violation(s)</li>")
    elif not business_no_context:
        why_bullets.append("<li class='why-yes'>✓ No policy violations</li>")
    why_html = f"<ul class='why-list'>{''.join(why_bullets)}</ul>" if why_bullets else ""

    chains = correlated.get("chains") or []
    chain_row_parts = []
    for c in chains:
        target_asset = c.get("target_asset", "")
        target_cell = _e(target_asset) if rvm.is_valid_target_asset(target_asset) else "<span class='empty'>—</span>"
        chain_row_parts.append(
            f"<tr><td>{_e(c.get('title') or c.get('chain_id', ''))}</td><td>{_e(c.get('finding_id', ''))}</td>"
            f"<td>{target_cell}</td>"
            f"<td>{_sev_badge(c.get('business_criticality', ''))}</td>"
            f"<td>{(c.get('exploitability') or 0):.2f}</td>"
            f"<td>{_e(len(c.get('policy_violations') or []))}</td></tr>"
        )
    chain_rows = "".join(chain_row_parts)

    return f"""
    <section>
      <h2>Risk Fusion {_label("analyzed")}</h2>
      <p class="risk-overall"><span class="risk-overall-num">{_e(score)}/10</span>{f" — {_e(band)}" if band else ""}</p>
      <p class="sub">Level: {_badge(risk.get('risk_level', ''))} &middot; confidence: {_e(risk.get('confidence_score'))}</p>
      <h3>Why this risk level?</h3>
      {why_html}
      <details class="detail-block">
        <summary>Risk dimension detail &amp; correlated risks</summary>
        <div class="risk-grid">{dim_cards}</div>
        <h3>Correlated Risks ({_e(correlated.get('total_correlated', 0))})</h3>
        {f"<table><thead><tr><th>Risk</th><th>Finding ID</th><th>Target Asset</th><th>Business Criticality</th><th>Exploitability</th><th>Policy Violations</th></tr></thead><tbody>{chain_rows}</tbody></table>" if chains else _empty("No correlated risk chains produced.")}
      </details>
    </section>
    """


# ---------------------------------------------------------------------------
# Section 10: Remediation, grouped VALIDATED / PROPOSED / PENDING REVIEW /
# REJECTED with counts. "Ready to Apply" appears ONLY on VALIDATED.
# ---------------------------------------------------------------------------
def _remediation_section(agentic: Dict[str, Any]) -> str:
    patches = agentic.get("patches", []) or []
    validation_results = agentic.get("validation_results", []) or []
    groups = rvm.group_patches_by_status(patches, validation_results)

    if not patches:
        return (
            f"<section><h2>Remediation {_label('analyzed')}</h2>{_badge('NOT GENERATED')} "
            f"{_empty(rvm.remediation_status_explanation('NOT GENERATED') + ' (No findings to remediate, or PatchGenerationAgent did not run.)')}</section>"
        )

    count_line = " &middot; ".join(f"{status}: <b>{len(items)}</b>" for status, items in groups.items())

    blocks = []
    for status in rvm.REMEDIATION_STATUS_ORDER:
        items = groups.get(status) or []
        if not items:
            continue
        status_explanation = rvm.remediation_status_explanation(status)
        rows = []
        for p in items:
            v = p.get("_validation")
            ready = " <span class='ready'>Ready to Apply</span>" if status == "VALIDATED" else ""
            diff_html = _patch_diff_html(p)
            reason_html = ""
            if v and status == "REJECTED" and v.get("issues"):
                reason_html = f"<p class='sub'><b>Why?</b> {_e('; '.join(str(i) for i in v['issues']))}</p>"
            # Plain-language status first; raw grounding/syntax data kept as
            # a clearly separate, secondary "technical validation details"
            # line rather than being the reader's first signal.
            technical_validation = (
                f"<p class='sub'><b>Technical validation details:</b> grounded={'yes' if v.get('grounding_passed') else 'no'} "
                f"&middot; syntax valid={'yes' if v.get('syntax_valid') else 'no'} &middot; result={_e(v.get('status', ''))}</p>"
                if v else "<p class='sub'><b>Technical validation details:</b> no validation record exists for this patch yet.</p>"
            )
            display_status = "PROPOSED (Not Validated)" if status == "PROPOSED" else status
            rows.append(f"""
            <div class="patch-card">
              <div class="patch-head">
                <span class="fid">{_e(p.get('finding_id', ''))}</span>
                {_badge(display_status)}{ready}
              </div>
              <p class="loc"><code>{_e(p.get('affected_file', ''))}:{_e(p.get('affected_lines', ''))}</code></p>
              {f"<p class='sub'>{_e(status_explanation)}</p>" if status_explanation else ''}
              {f"<p class='plain'>{_e(p.get('explanation'))}</p>" if p.get('explanation') else ''}
              {diff_html}
              {reason_html}
              {technical_validation}
            </div>""")
        label = _label("validated") if status == "VALIDATED" else _label("analyzed")
        blocks.append(f"<h3>{_e(status)} ({len(items)}) {label}</h3><div class='patch-grid'>{''.join(rows)}</div>")

    return f"""
    <section>
      <h2>Remediation {_label("analyzed")}</h2>
      <p class="sub">{count_line}. A patch is only labeled VALIDATED when a real ValidationAgent run actually
      confirmed it -- everything else is honestly shown as proposed, pending, or rejected.</p>
      {''.join(blocks)}
    </section>
    """


# ---------------------------------------------------------------------------
# Section 11: Evidence Traceability as a visual timeline per finding.
# ---------------------------------------------------------------------------
def _traceability_section(agentic: Dict[str, Any]) -> str:
    findings = agentic.get("findings", []) or []
    evidence_mapping = (agentic.get("correlated_findings") or {}).get("evidence_mapping") or {}
    patches_by_finding: Dict[str, List[Dict[str, Any]]] = {}
    for p in (agentic.get("patches") or []):
        patches_by_finding.setdefault(p.get("finding_id", ""), []).append(p)
    validated_patch_ids = {
        v.get("patch_id") for v in (agentic.get("validation_results") or []) if v.get("status") == "PASSED"
    }
    rejected_patch_ids = {
        v.get("patch_id") for v in (agentic.get("validation_results") or []) if v.get("status") == "REJECTED"
    }
    risk_by_finding = rvm.attack_paths_by_finding(agentic.get("attack_paths") or [])

    rows = []
    for f in findings:
        if not rvm.is_valid_finding(f):
            continue
        # Section 20: a fixed 6-hop conceptual chain, always rendered --
        # every hop is either real or TRACE_UNAVAILABLE, never dropped.
        hops = rvm.build_traceability_chain(
            f, evidence_mapping, patches_by_finding, validated_patch_ids,
            risk_by_finding=risk_by_finding, rejected_patch_ids=rejected_patch_ids,
        )
        hop_html = "".join(
            f"<div class='hop{' hop-unavailable' if h['value'] == rvm.TRACE_UNAVAILABLE else ''}'>"
            f"<span class='hop-label'>{_e(h['label'])}</span><span class='hop-value'>{_e(h['value'])}</span></div>"
            + ("<span class='hop-arrow'>&rarr;</span>" if i < len(hops) - 1 else "")
            for i, h in enumerate(hops)
        )
        rows.append(f"<div class='timeline-row'>{hop_html}</div>")

    visible_rows, remaining = _cap(rows, limit=30)
    body = "".join(visible_rows) if visible_rows else _empty("No findings to trace.")
    return f"""
    <section>
      <h2>Evidence Traceability {_label("analyzed")}</h2>
      <p class="sub">Each finding traced through the fixed chain Finding &rarr; Evidence &rarr; Agent &rarr; Risk
      &rarr; Remediation &rarr; Validation. Every hop is either a real id/value or explicitly marked
      &ldquo;Traceability unavailable for this step&rdquo; -- never a guessed or dropped hop.</p>
      <div class="timeline">{body}</div>
      {_more_note(remaining, 'traced findings')}
    </section>
    """


# ---------------------------------------------------------------------------
# Final Recommendations -- rule-based only, derived from the real counts
# already shown above.
# ---------------------------------------------------------------------------
def _recommendations_section(
    deterministic: Optional[Dict[str, Any]], critical: int, high: int,
    unresolved_violations: int, groups: Dict[str, List[Dict[str, Any]]],
    has_findings_data: bool = True, direct_attack_paths: int = 0,
) -> str:
    items: List[str] = []
    if has_findings_data:
        if critical > 0:
            items.append(f"<li><b>Address immediately:</b> {_e(critical)} Critical deterministic finding(s) are unresolved.</li>")
        elif high > 0:
            items.append(f"<li><b>Needs review:</b> {_e(high)} High-severity deterministic finding(s) present.</li>")
        else:
            items.append("<li><b>No Critical/High deterministic findings</b> in this scan.</li>")
    if unresolved_violations:
        items.append(f"<li><b>Review business impact:</b> {_e(unresolved_violations)} business requirement(s) flagged as violated or potentially violated.</li>")
    # Section 5: attack paths are real, actionable data on their own --
    # previously unrepresented here, so a run with modeled attack paths but
    # no patches/violations yet would fall through to the empty-state
    # message below even though there was real data to act on.
    if direct_attack_paths:
        items.append(f"<li><b>Prioritize reachable attack paths:</b> {_e(direct_attack_paths)} directly reachable attack path(s) were modeled by the Threat Simulation Agent.</li>")
    proposed = len(groups.get("PROPOSED") or []) + len(groups.get("PENDING REVIEW") or [])
    validated = len(groups.get("VALIDATED") or [])
    if proposed:
        items.append(f"<li><b>Verify remaining patches:</b> {_e(proposed)} proposed patch(es) have not passed validation yet.</li>")
    if validated and not proposed:
        items.append(f"<li>All proposed patch(es) that reached validation passed ({_e(validated)}).</li>")
    if not items:
        items.append("<li>No findings or violations to act on based on the data in this report.</li>")

    return f"""
    <section>
      <h2>Final Recommendations</h2>
      <p class="sub">Derived only from the real counts above -- not a generated narrative.</p>
      <ul class="reco">{''.join(items)}</ul>
    </section>
    """


_CSS = """
:root{--bg:#0a0a0f;--panel:#111118;--panel2:#15151d;--border:rgba(255,255,255,.08);
  --text:#f4f4f8;--sub:#8e8e9a;--orange:#ff5400;--orange-dim:rgba(255,84,0,.14)}
*{box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;margin:0;padding:2.5rem;color:var(--text);background:var(--bg)}
h1{margin:0 0 .3rem;color:var(--orange);font-size:1.6rem}
h2{margin:2.4rem 0 .6rem;font-size:1.1rem;border-bottom:1px solid var(--border);padding-bottom:.5rem;color:var(--text)}
h3{margin:1.4rem 0 .5rem;font-size:.92rem;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
section{margin-bottom:.5rem}
.sub{color:var(--sub);margin:.3rem 0 1rem;line-height:1.6;font-size:.85rem}
code{font-size:.78rem;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:4px;color:#d8d8e0}
.empty{color:#5c5c68;font-style:italic;font-size:.85rem}
.badge{font-size:.68rem;padding:3px 9px;border-radius:10px;font-weight:700;white-space:nowrap;text-transform:uppercase;letter-spacing:.03em}
.origin{font-size:.62rem;font-weight:700;letter-spacing:.06em;padding:3px 9px;border-radius:10px;margin-left:.5rem;text-transform:uppercase;vertical-align:middle}
.lbl-detected{color:#5eb8ff;background:rgba(94,184,255,.12);border:1px solid rgba(94,184,255,.3)}
.lbl-analyzed{color:#c99bff;background:rgba(201,155,255,.12);border:1px solid rgba(201,155,255,.3)}
.lbl-validated{color:#4ade80;background:rgba(74,222,128,.12);border:1px solid rgba(74,222,128,.3)}
.ready{font-size:.68rem;font-weight:700;color:#4ade80;margin-left:.5rem;text-transform:uppercase;letter-spacing:.03em}

.qa-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.9rem}
.qa-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:1rem 1.2rem}
.qa-card .q{font-size:.78rem;font-weight:700;color:var(--orange);text-transform:uppercase;letter-spacing:.02em;margin-bottom:.4rem}
.qa-card .a{font-size:.92rem;line-height:1.5}

.finding-analysis-list{display:flex;flex-direction:column;gap:.7rem;margin-bottom:.6rem}
.fa-card p{margin:.35rem 0}
.diff{font-size:.76rem;line-height:1.5;background:#090a0d;border:1px solid var(--border);border-radius:8px;padding:.6rem .8rem;overflow-x:auto;margin:.4rem 0;white-space:pre-wrap;word-break:break-word}
.diff-before-after{display:flex;flex-direction:column;gap:.3rem}
.diff-before{border-left:3px solid #f4374a;color:#ff8a95}
.diff-after{border-left:3px solid #4ade80;color:#7ee6a0}
.finding-grid,.attack-grid,.agent-grid,.business-grid,.risk-grid,.patch-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:.8rem;margin-bottom:.6rem}
.finding-card,.attack-card,.agent-card,.business-card,.risk-card,.patch-card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.9rem 1.1rem}
.finding-card.sev-critical{border-left:3px solid #f4374a}
.finding-card.sev-high{border-left:3px solid #ff8a3d}
.finding-card.sev-medium{border-left:3px solid #f5c451}
.finding-card.sev-low{border-left:3px solid #4ade80}
.finding-head,.agent-head,.business-head,.patch-head{display:flex;align-items:center;justify-content:space-between;gap:.5rem;margin-bottom:.4rem;flex-wrap:wrap}
.fid,.agent-name,.rule{font-weight:700;font-size:.85rem}
.plain{font-size:.86rem;line-height:1.5;margin:.3rem 0}
.loc{margin:.3rem 0}
.rec,.evidence{font-size:.82rem;color:var(--sub);margin:.3rem 0}
.err{color:#f4374a;font-size:.8rem}
details{margin-top:.4rem}
details summary{cursor:pointer;font-size:.75rem;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}

.chain{display:flex;align-items:center;flex-wrap:wrap;gap:.4rem;font-size:.85rem;margin-bottom:.5rem}
.hop{padding:3px 9px;border-radius:6px;background:rgba(255,255,255,.06)}
.hop-mid{color:var(--sub)}
.hop-target{background:rgba(201,155,255,.12);color:#c99bff}
.arrow{color:#5c5c68}

.risk-head{display:flex;align-items:baseline;gap:.5rem;margin-bottom:.3rem}
.risk-head .num{font-size:1.4rem;font-weight:700;color:var(--orange)}
.risk-head .lbl{font-size:.75rem;color:var(--sub);text-transform:uppercase}

.timeline{display:flex;flex-direction:column;gap:.5rem}
.timeline-row{display:flex;align-items:center;flex-wrap:wrap;gap:.4rem;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.55rem .8rem;font-size:.8rem}
.hop-label{color:var(--sub);text-transform:uppercase;font-size:.62rem;letter-spacing:.03em;margin-right:.3rem}
.hop-value{color:var(--text);font-weight:600}
.hop-arrow{color:#5c5c68}

table{border-collapse:collapse;width:100%;font-size:.82rem;margin-top:.4rem;background:var(--panel);border-radius:8px;overflow:hidden}
th,td{border-bottom:1px solid var(--border);padding:.5rem .65rem;text-align:left;vertical-align:top}
th{background:var(--panel2);color:var(--sub);font-size:.72rem;text-transform:uppercase;letter-spacing:.02em}

.reco{padding-left:1.2rem;line-height:1.8;font-size:.9rem}
.footer{margin-top:3rem;color:#5c5c68;font-size:.75rem;border-top:1px solid var(--border);padding-top:1.2rem;line-height:1.6}
.header-banner{background:var(--orange-dim);border:1px solid rgba(255,84,0,.3);border-radius:10px;padding:.9rem 1.2rem;margin:1rem 0 1.6rem}
.header-banner .num{color:var(--orange);font-weight:700}
.more-note{color:#5c5c68;font-size:.78rem;font-style:italic;margin-top:.4rem}

.tldr{font-size:1.05rem;font-weight:700;letter-spacing:.01em;padding:.9rem 1.3rem;border-radius:10px;margin:1.1rem 0}
.tldr-bad{background:rgba(244,55,74,.14);color:#ff8a95;border:1px solid rgba(244,55,74,.4)}
.tldr-warn{background:rgba(245,196,81,.14);color:#f5c451;border:1px solid rgba(245,196,81,.4)}
.tldr-good{background:rgba(74,222,128,.14);color:#4ade80;border:1px solid rgba(74,222,128,.4)}
.tldr-neutral{background:rgba(255,255,255,.06);color:var(--text);border:1px solid var(--border)}

/* --- Verdict card (Section 5/6/7) --- */
.verdict{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:1.3rem 1.5rem;margin:1.2rem 0 1.6rem}
.verdict-bad{border-color:rgba(244,55,74,.5)}
.verdict-warn{border-color:rgba(245,196,81,.5)}
.verdict-good{border-color:rgba(74,222,128,.5)}
.verdict-neutral{border-color:var(--border)}
.verdict-badge{display:inline-block;font-size:.95rem;font-weight:800;letter-spacing:.04em;padding:.4rem 1rem;border-radius:8px;margin-bottom:1rem}
.verdict-bad .verdict-badge{background:rgba(244,55,74,.16);color:#ff8a95}
.verdict-warn .verdict-badge{background:rgba(245,196,81,.16);color:#f5c451}
.verdict-good .verdict-badge{background:rgba(74,222,128,.16);color:#4ade80}
.verdict-neutral .verdict-badge{background:rgba(255,255,255,.08);color:var(--text)}
.vstats{display:flex;flex-wrap:wrap;gap:1.6rem;margin-bottom:1.1rem;padding-bottom:1.1rem;border-bottom:1px solid var(--border)}
.vstat{display:flex;flex-direction:column}
.vstat .vnum{font-size:1.3rem;font-weight:700;color:var(--text)}
.vstat .vlbl{font-size:.68rem;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
.vrow{margin:.7rem 0}
.vrow-label{font-size:.68rem;font-weight:700;color:var(--sub);text-transform:uppercase;letter-spacing:.05em;margin-bottom:.15rem}
.vrow-body{font-size:.95rem;line-height:1.55}

/* --- Compact agent pipeline (Section 8) --- */
.pipeline{display:flex;flex-wrap:wrap;gap:.6rem}
.pstep{flex:1 1 150px;min-width:150px;background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:.7rem .8rem}
.pstep-completed{border-left:3px solid #4ade80}
.pstep-failed{border-left:3px solid #f4374a}
.pstep-skipped{border-left:3px solid #5c5c68;opacity:.6}
.pstep-head{display:flex;align-items:center;gap:.4rem;margin-bottom:.3rem}
.pstep-icon{font-weight:800}
.pstep-completed .pstep-icon{color:#4ade80}
.pstep-failed .pstep-icon{color:#f4374a}
.pstep-skipped .pstep-icon{color:#5c5c68}
.pstep-name{font-weight:700;font-size:.82rem}
.pstep-body{font-size:.74rem;color:var(--sub);line-height:1.4;margin:0}

/* --- Heuristic vs confirmed tags (Section 12/19/33) --- */
.tag{display:inline-block;font-size:.62rem;font-weight:700;letter-spacing:.03em;padding:2px 8px;border-radius:8px;text-transform:uppercase;margin-bottom:.3rem}
.tag-confirmed{background:rgba(74,222,128,.14);color:#4ade80}
.tag-heuristic{background:rgba(245,196,81,.14);color:#f5c451}

/* --- Risk "why" bullets (Section 16) --- */
.risk-overall{margin:.2rem 0 0}
.risk-overall-num{font-size:1.6rem;font-weight:800;color:var(--orange)}
.why-list{list-style:none;padding:0;margin:.4rem 0 1rem;display:flex;flex-direction:column;gap:.3rem;font-size:.86rem}
.why-yes{color:#7ee6a0}
.why-warn{color:#f5c451}

/* --- Collapsible detail blocks (Sections 9/21) --- */
.detail-block{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:.8rem 1.1rem;margin:.8rem 0}
.detail-block summary{cursor:pointer;font-size:.82rem;font-weight:600;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
.detail-block[open] summary{margin-bottom:.6rem}
.fa-detail{margin-top:.5rem}
.fa-detail summary{cursor:pointer;font-size:.72rem;color:var(--sub);text-transform:uppercase;letter-spacing:.03em}
.hop-unavailable .hop-value{color:#5c5c68;font-style:italic;font-weight:400}

@media print{
  /* Redefine the theme tokens themselves -- since every section below
     reads color/background through var(--text)/--sub/--panel/--border/
     --panel2, this alone re-themes the whole document for print without
     needing a second, easy-to-miss override per element (the bug a first
     pass at this left: headings inherited var(--text)'s near-white color
     against the print override's white background, so h2/h3 were nearly
     invisible on a printed/PDF page). */
  :root{--bg:#fff;--panel:#fff;--panel2:#f2f2f2;--border:#ccc;--text:#111;--sub:#555;--orange:#d94600;--orange-dim:#fff1e8}
  body{padding:1rem}
  .qa-card,.finding-card,.attack-card,.agent-card,.business-card,.risk-card,.patch-card,.timeline-row,table{box-shadow:none}
  code{background:#f2f2f2;color:#333}
  .tldr-bad{background:#fdecec;color:#b71c1c;border-color:#e59}
  .tldr-warn{background:#fff8e1;color:#8a6100;border-color:#e5c366}
  .tldr-good{background:#e8f5e9;color:#1b5e20;border-color:#8fce9a}
  .tldr-neutral{background:#f2f2f2;color:#333;border-color:#ccc}
  .lbl-detected{color:#01579b;background:#e1f5fe}
  .lbl-analyzed{color:#6a1b9a;background:#f3e5f5}
  .lbl-validated{color:#1b5e20;background:#e8f5e9}
  .hop-target{color:#6a1b9a;background:#f3e5f5}
  .verdict-bad .verdict-badge{background:#fdecec;color:#b71c1c}
  .verdict-warn .verdict-badge{background:#fff8e1;color:#8a6100}
  .verdict-good .verdict-badge{background:#e8f5e9;color:#1b5e20}
  .verdict-neutral .verdict-badge{background:#f2f2f2;color:#333}
  .tag-confirmed{background:#e8f5e9;color:#1b5e20}
  .tag-heuristic{background:#fff8e1;color:#8a6100}
  /* Print/PDF export is non-interactive -- expand every <details> so
     collapsed content is never silently missing from the printed page
     (Section 26: preserve important sections, attack paths, tables). */
  details{page-break-inside:avoid}
  details summary{display:none}
  details>*{display:block !important}
  section,.finding-card,.attack-card,.pstep,.verdict{page-break-inside:avoid}
}
"""


def render_agentic_report_html(
    agentic: Dict[str, Any],
    deterministic: Optional[Dict[str, Any]] = None,
    deterministic_scan_id: Optional[str] = None,
) -> str:
    """Renders the Agentic Report (deterministic=None) or the Unified
    Report (deterministic provided). `agentic` is the curated
    AgentWorkflowState-shaped dict the frontend already holds after a run
    completes (see useAgenticScan.ts); `deterministic` is the same report
    dict backend/app/api/v1/scans.py stores in _SCANS_STORE.

    `deterministic_scan_id` is the scan_id of the deterministic scan that
    fed the agentic run. Surfaced prominently in the header of both reports
    so the report itself proves the agentic layer reasoned over real,
    traceable findings rather than an independent analysis.
    """
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    title = "Unified Security & Agentic Report" if deterministic else "Agentic Analysis Report"
    scan_id = agentic.get("scan_id", "—")
    det_scan_id = deterministic_scan_id or agentic.get("source_scan_id") or agentic.get("scan_id") or "—"

    repo_root = ""
    if deterministic:
        repo_root = (deterministic.get("repository") or {}).get("root", "") or deterministic.get("target", "") or ""

    # ---- shared derived data (computed once, reused by exec summary + sections) ----
    scan = (deterministic or {}).get("scan", {}) or {}
    agentic_findings = agentic.get("findings") or []
    if deterministic:
        by_sev = {str(k).lower(): v for k, v in (scan.get("by_severity", {}) or {}).items()}
    else:
        # Plain Agentic Report: no full deterministic report dict was
        # passed, but agentic["findings"] is always the same real
        # deterministic findings this run adopted (see backend/app/api/v1/
        # agentic_scan.py::_adopt_deterministic_report) -- use those real
        # counts instead of treating "no full report dict" as "no findings
        # data at all" (the bug behind the old "This report does not
        # include a deterministic scan..." contradiction, see
        # report_view_model.executive_summary's docstring comment).
        by_sev = rvm.severity_counts_from_findings(agentic_findings)
    critical = by_sev.get("critical", 0) or 0
    high = by_sev.get("high", 0) or 0
    # A genuinely clean run (Security Agent ran and adopted zero findings --
    # a real, confirmed "SECURE" result) must be distinguishable from a run
    # this report has no data about at all (SECURITY_STATUS_UNKNOWN). An empty
    # `findings` list can't tell the two apart on its own -- backend/app/
    # api/v1/agentic_scan.py::_STATE_KEYS always includes "findings" in the
    # curated state (defaulting to []), so its mere presence doesn't prove
    # an agent actually ran. Whether ANY agent execution was recorded
    # (agent_trace/completed_agents) is the real signal that findings data
    # exists to reason over, even when that data is a genuine empty list.
    has_findings_data = bool(deterministic) or bool(agentic_findings) or bool(agentic.get("agent_trace")) or bool(agentic.get("completed_agents"))
    total_findings = sum(by_sev.values()) if has_findings_data else 0

    violations = agentic.get("business_violations", []) or []
    unresolved_violations = len([v for v in violations if str(v.get("status", "")).upper() in ("VIOLATION", "POTENTIAL_VIOLATION")])
    business_no_context = rvm.business_section_state(agentic)["no_context"]

    patches = agentic.get("patches", []) or []
    validation_results = agentic.get("validation_results", []) or []
    patch_groups = rvm.group_patches_by_status(patches, validation_results)

    valid_attack_paths = [p for p in (agentic.get("attack_paths") or []) if rvm.is_valid_attack_path(p)]
    total_attack_paths = len(valid_attack_paths)
    direct_attack_paths = len([p for p in valid_attack_paths if str(p.get("reachability", "")).lower() == "direct"])

    policy_violation_count = (agentic.get("policy_results") or {}).get("total_violations") or 0

    summary = rvm.executive_summary(
        deterministic, agentic, critical, high, patch_groups, unresolved_violations,
        has_findings_data=has_findings_data,
    )
    risk_scores = agentic.get("risk_scores") or {}
    risk_level = risk_scores.get("risk_level")

    # ---- Verdict (Section 5/6): the conclusion-first lead ----
    verdict = rvm.compute_verdict(has_findings_data, total_findings, critical, high, patch_groups, risk_level)
    attack_by_f = rvm.attack_paths_by_finding(agentic.get("attack_paths") or [])
    chains_by_f = rvm.chains_by_finding(agentic.get("correlated_findings") or {})
    biz_by_file = rvm.business_violations_by_file(agentic.get("business_violations") or [])
    policy_by_f = rvm.policy_violations_by_finding(agentic.get("policy_results") or {})
    patches_by_f = rvm.patches_by_finding_with_validation(patches, validation_results)
    arch_ctx = agentic.get("architecture_context") or {}
    top_finding = rvm.top_priority_finding_analysis(
        agentic_findings, repo_root, attack_by_f, chains_by_f, biz_by_file, policy_by_f, patches_by_f, arch_ctx,
    )
    narrative = rvm.verdict_narrative(verdict, top_finding, business_no_context)

    deterministic_html = _deterministic_section(deterministic, repo_root) if deterministic else ""

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>AI Code Guardian — {_e(title)}</title><style>{_CSS}</style></head><body>
<h1>AI Code Guardian — {_e(title)}</h1>
<p class="sub">Generated {_e(generated_at)}</p>
<div class="header-banner">
  <span class="num">Source Deterministic Scan: {_e(det_scan_id)}</span> &middot;
  <span class="num">Agentic Analysis Run: {_e(scan_id)}</span>
  <p class="sub" style="margin:.4rem 0 0">Every finding referenced below was produced by that deterministic scan
  (guardian.core.pipeline.ScanPipeline) -- the agentic layer reasons over these exact results, it does not
  independently detect vulnerabilities. One deterministic scan may have multiple agentic analysis runs; this
  report reflects exactly one of each, never a mix.</p>
</div>
{_verdict_section(verdict, narrative, critical, high, direct_attack_paths, total_attack_paths, risk_scores, patch_groups, has_findings_data)}
{_executive_summary_section(summary)}
{deterministic_html}
{_pipeline_section(agentic)}
{_findings_analyzed_section(agentic, repo_root)}
{_threat_section(agentic)}
{_business_section(agentic, repo_root)}
{_policy_section(agentic)}
{_risk_section(agentic, critical, high, direct_attack_paths, policy_violation_count, business_no_context)}
{_remediation_section(agentic)}
{_traceability_section(agentic)}
{_recommendations_section(deterministic, critical, high, unresolved_violations, patch_groups, has_findings_data=has_findings_data, direct_attack_paths=direct_attack_paths)}
{_agent_execution_metrics_section(agentic)}
<div class="footer">
  THE DETERMINISTIC SCANNER IS THE SOURCE OF TECHNICAL TRUTH. The agentic layer (LangGraph multi-agent
  workflow) reasons over real deterministic findings and evidence to produce the sections above -- it does
  not re-detect vulnerabilities. [DETECTED] = straight from the scanner. [ANALYZED] = an agent's
  interpretation of that evidence. [VALIDATED] = a patch a real validation run confirmed. Generated by
  AI Code Guardian.
</div>
</body></html>"""
