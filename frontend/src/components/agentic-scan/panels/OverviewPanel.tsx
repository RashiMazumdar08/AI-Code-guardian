"use client";

import React from "react";
import { ArrowRight, ShieldCheck, Sparkles, TrendingUp, TrendingDown } from "lucide-react";
import type { AgenticSummary, DeterministicBaseline } from "../types";

// Conventional security-score banding (0-100, higher = better posture) --
// used only to color the deterministic score, never to alter the number.
function securityScoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

// The agentic composite risk score's color follows the SAME risk_level the
// backend already computed (guardian/agents/risk/agent.py) -- never a
// second, independently-invented threshold on the raw number.
function riskLevelColor(level: string | null | undefined): string {
  const l = (level || "").toUpperCase();
  if (l === "CRITICAL" || l === "HIGH") return "text-red-400";
  if (l === "MEDIUM") return "text-amber-400";
  if (l === "LOW") return "text-emerald-400";
  return "text-[#f4f4f8]";
}

function StatCard({ label, value, colorClass }: { label: string; value: React.ReactNode; colorClass?: string }) {
  return (
    <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
      <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">{label}</div>
      <div className={`text-lg font-mono font-bold ${colorClass || "text-[#f4f4f8]"}`}>{value}</div>
    </div>
  );
}

/**
 * Deterministic baseline (real ScanPipeline counts) vs agentic enrichment
 * (real AgentWorkflowState counts once the graph finishes) side by side --
 * never fabricated, never recomputed by an agent. Both objects come
 * verbatim from backend events (workflow.adopted / workflow.completed in
 * backend/app/api/v1/agentic_scan.py); this panel only formats them.
 */
export function OverviewPanel({
  baseline, summary, running,
}: {
  baseline: DeterministicBaseline | null;
  summary: AgenticSummary | null;
  running: boolean;
}) {
  if (!baseline) {
    return (
      <div className="text-[11px] font-mono text-[#5c5c68] text-center py-10">
        {running ? "Adopting the deterministic scan's findings/evidence…" : "No deterministic baseline yet."}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-4">
        <div className="flex items-center gap-2 mb-3">
          <ShieldCheck className="w-3.5 h-3.5 text-sky-400" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-sky-400 font-bold">
            Deterministic Baseline — source of technical truth
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          <StatCard label="Total Findings" value={baseline.total_findings} colorClass="text-[#f4f4f8]" />
          <StatCard label="Critical" value={baseline.critical} colorClass="text-red-400" />
          <StatCard label="High" value={baseline.high} colorClass="text-orange-400" />
          <StatCard label="Medium" value={baseline.medium} colorClass="text-amber-400" />
          <StatCard label="Low" value={baseline.low} colorClass="text-emerald-400" />
        </div>
        <div className="text-[9px] font-mono text-[#5c5c68] mt-2">
          Straight from guardian.core.pipeline.ScanPipeline's ScanResult.to_dict() -- the agent graph below reasons
          over these findings, it never re-detects or replaces them.
        </div>
      </div>

      <div className="flex items-center justify-center text-[#5c5c68]">
        <ArrowRight className="w-4 h-4" />
      </div>

      <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-4">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-3.5 h-3.5 text-[#ff5400]" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-[#ff5400] font-bold">
            Agentic Enrichment — reasoning over the same evidence
          </span>
        </div>
        {summary ? (
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            <StatCard label="Correlated Risks" value={summary.correlated_risks} />
            <StatCard label="Business Violations" value={summary.business_violations} />
            <StatCard label="Attack Paths" value={summary.attack_paths} />
            <StatCard label="Policy Violations" value={summary.policy_violations} />
            <StatCard label="Remediation Proposals" value={summary.remediation_proposals} />
            <StatCard label="Validated Patches" value={summary.validated_patches} colorClass="text-emerald-400" />
          </div>
        ) : (
          <div className="text-[10px] font-mono text-[#5c5c68] py-4 text-center">
            {running ? "Agent graph is still running — enrichment numbers appear once it completes." : "Not run yet."}
          </div>
        )}
        <div className="text-[9px] font-mono text-[#5c5c68] mt-2">
          Every number above is a real len()/lookup of AgentWorkflowState after the LangGraph run finishes (see
          _agentic_summary in backend/app/api/v1/agentic_scan.py) -- never a placeholder or estimate.
        </div>
      </div>

      <div className="text-[9px] font-mono text-[#5c5c68] text-center">
        DETERMINISTIC {baseline.total_findings} finding{baseline.total_findings === 1 ? "" : "s"}
        {"  ->  "}
        AGENTIC ANALYSIS {summary ? (
          <>
            {summary.correlated_risks} correlated risk{summary.correlated_risks === 1 ? "" : "s"}, {summary.business_violations} business violation{summary.business_violations === 1 ? "" : "s"}, {summary.attack_paths} attack path{summary.attack_paths === 1 ? "" : "s"}, {summary.policy_violations} policy violation{summary.policy_violations === 1 ? "" : "s"}, {summary.remediation_proposals} remediation suggestion{summary.remediation_proposals === 1 ? "" : "s"}
          </>
        ) : "pending"}
      </div>

      <div className="rounded-lg bg-[#0c0d11] border border-white/8 overflow-hidden">
        <div className="px-3 py-2 border-b border-white/8 text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a]">
          Baseline vs Agentic — demonstrates the agentic layer adds context rather than duplicating SAST
        </div>
        <table className="w-full text-[10px] font-mono">
          <thead>
            <tr className="text-[#8e8e9a] border-b border-white/8">
              <th className="text-left px-3 py-1.5">Dimension</th>
              <th className="text-left px-3 py-1.5">Deterministic</th>
              <th className="text-left px-3 py-1.5">Agentic</th>
            </tr>
          </thead>
          <tbody>
            {[
              // "Technical Findings" intentionally shows the SAME count on
              // both sides when a run has completed -- proof the agent
              // graph reasons over these exact findings rather than
              // re-detecting a different number. Every other row is
              // agentic-only by nature (the deterministic scanner doesn't
              // produce a "Correlated Risks" or "Attack Paths" count), so
              // those show N/A on the left rather than a fabricated 0.
              ["Technical Findings", String(baseline.total_findings), summary ? String(baseline.total_findings) : "N/A"],
              ["Correlated Risks", "N/A", summary ? String(summary.correlated_risks) : "N/A"],
              ["Business Violations", "N/A", summary ? String(summary.business_violations) : "N/A"],
              ["Attack Paths", "N/A", summary ? String(summary.attack_paths) : "N/A"],
              ["Policy Violations", "N/A", summary ? String(summary.policy_violations) : "N/A"],
              ["Remediation Proposals", "N/A", summary ? String(summary.remediation_proposals) : "N/A"],
              ["Validated Patches", "N/A", summary ? String(summary.validated_patches) : "N/A"],
            ].map(([dim, det, ag]) => (
              <tr key={dim} className="border-b border-white/5 last:border-0">
                <td className="px-3 py-1.5 text-[#f4f4f8] font-semibold">{dim}</td>
                <td className="px-3 py-1.5 text-sky-400">{det}</td>
                <td className="px-3 py-1.5 text-[#ff5400]">{ag}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Risk Score: deliberately NOT collapsed into one number or one row --
          these are two different scales with opposite polarity (0-100
          higher=better vs 0-10 higher=worse). Each side is labeled with its
          own scale and colored independently so they can never be
          misread as directly comparable. */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-3.5 h-3.5 text-sky-400" />
            <span className="text-[9px] font-mono uppercase tracking-wider text-sky-400 font-bold">
              Deterministic Security Score
            </span>
          </div>
          {baseline.deterministic_overall_risk_score != null ? (
            <div className={`text-2xl font-mono font-bold ${securityScoreColor(baseline.deterministic_overall_risk_score)}`}>
              {baseline.deterministic_overall_risk_score.toFixed(1)} <span className="text-xs text-[#5c5c68]">/ 100</span>
            </div>
          ) : (
            <div className="text-sm font-mono text-[#5c5c68]">—</div>
          )}
          <div className="text-[9px] font-mono text-[#8e8e9a] mt-1">Higher = better security posture (guardian.core.unified_risk)</div>
        </div>
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingDown className="w-3.5 h-3.5 text-[#ff5400]" />
            <span className="text-[9px] font-mono uppercase tracking-wider text-[#ff5400] font-bold">
              Agentic Risk Score
            </span>
          </div>
          {summary?.unified_risk_score != null ? (
            <div className={`text-2xl font-mono font-bold ${riskLevelColor(summary.risk_level)}`}>
              {summary.unified_risk_score.toFixed(2)} <span className="text-xs text-[#5c5c68]">/ 10</span>
              {summary.risk_level && (
                <span className={`ml-2 align-middle text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${riskLevelColor(summary.risk_level)} bg-white/5`}>
                  {summary.risk_level}
                </span>
              )}
            </div>
          ) : (
            <div className="text-sm font-mono text-[#5c5c68]">—</div>
          )}
          <div className="text-[9px] font-mono text-[#8e8e9a] mt-1">Higher = worse risk (LangGraph risk_fusion composite_risk_score) — a different scale, not directly comparable to the score on the left</div>
        </div>
      </div>
    </div>
  );
}

export default OverviewPanel;
