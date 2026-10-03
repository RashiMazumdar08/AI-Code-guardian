"use client";

import React from "react";
import { ArrowRight, ShieldCheck, Sparkles, TrendingUp, TrendingDown } from "lucide-react";
import type { AgenticSummary, DeterministicBaseline } from "../types";

// Conventional security-score banding (0-100, higher = better posture) --
// used only to color the deterministic score, never to alter the number.
function securityScoreColor(score: number): string {
  if (score >= 80) return "text-emerald-600";
  if (score >= 50) return "text-amber-600";
  return "text-rose-600";
}

function riskLevelColor(level: string | null | undefined): string {
  const l = (level || "").toUpperCase();
  if (l === "CRITICAL" || l === "HIGH") return "text-rose-600";
  if (l === "MEDIUM") return "text-amber-600";
  if (l === "LOW") return "text-emerald-600";
  return "text-[#111827]";
}

function StatCard({ label, value, colorClass }: { label: string; value: React.ReactNode; colorClass?: string }) {
  return (
    <div className="rounded-lg bg-slate-50 border border-[#DCE5F0] p-3">
      <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">{label}</div>
      <div className={`text-lg font-mono font-bold ${colorClass || "text-[#111827]"}`}>{value}</div>
    </div>
  );
}

/**
 * Deterministic baseline vs agentic enrichment side by side.
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
      <div className="text-[11px] font-mono text-slate-500 text-center py-10">
        {running ? "Adopting the deterministic scan's findings/evidence…" : "No deterministic baseline yet."}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4">
        <div className="flex items-center gap-2 mb-3">
          <ShieldCheck className="w-3.5 h-3.5 text-blue-600" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-blue-600 font-bold">
            Deterministic Baseline — source of technical truth
          </span>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
          <StatCard label="Total Findings" value={baseline.total_findings} colorClass="text-[#111827]" />
          <StatCard label="Critical" value={baseline.critical} colorClass="text-rose-600" />
          <StatCard label="High" value={baseline.high} colorClass="text-amber-600" />
          <StatCard label="Medium" value={baseline.medium} colorClass="text-yellow-600" />
          <StatCard label="Low" value={baseline.low} colorClass="text-blue-600" />
        </div>
        <div className="text-[9px] font-mono text-slate-500 mt-2">
          Straight from guardian.core.pipeline.ScanPipeline's ScanResult.to_dict() -- the agent graph below reasons
          over these findings, it never re-detects or replaces them.
        </div>
      </div>

      <div className="flex items-center justify-center text-slate-400">
        <ArrowRight className="w-4 h-4" />
      </div>

      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span className="text-[10px] font-mono uppercase tracking-wider text-blue-600 font-bold">
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
            <StatCard label="Validated Patches" value={summary.validated_patches} colorClass="text-emerald-600" />
          </div>
        ) : (
          <div className="text-[10px] font-mono text-slate-500 py-4 text-center">
            {running ? "Agent graph is still running — enrichment numbers appear once it completes." : "Not run yet."}
          </div>
        )}
        <div className="text-[9px] font-mono text-slate-500 mt-2">
          Every number above is a real len()/lookup of AgentWorkflowState after the LangGraph run finishes (see
          _agentic_summary in backend/app/api/v1/agentic_scan.py) -- never a placeholder or estimate.
        </div>
      </div>

      <div className="text-[9px] font-mono text-slate-500 text-center">
        DETERMINISTIC {baseline.total_findings} finding{baseline.total_findings === 1 ? "" : "s"}
        {"  ->  "}
        AGENTIC ANALYSIS {summary ? (
          <>
            {summary.correlated_risks} correlated risk{summary.correlated_risks === 1 ? "" : "s"}, {summary.business_violations} business violation{summary.business_violations === 1 ? "" : "s"}, {summary.attack_paths} attack path{summary.attack_paths === 1 ? "" : "s"}, {summary.policy_violations} policy violation{summary.policy_violations === 1 ? "" : "s"}, {summary.remediation_proposals} remediation suggestion{summary.remediation_proposals === 1 ? "" : "s"}
          </>
        ) : "pending"}
      </div>

      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm overflow-hidden">
        <div className="px-3 py-2 border-b border-[#DCE5F0] text-[9px] font-mono uppercase tracking-wider text-slate-500 bg-slate-50">
          Baseline vs Agentic — demonstrates the agentic layer adds context rather than duplicating SAST
        </div>
        <table className="w-full text-[10px] font-mono">
          <thead>
            <tr className="text-slate-500 border-b border-[#DCE5F0] bg-slate-50">
              <th className="text-left px-3 py-1.5 font-semibold">Dimension</th>
              <th className="text-left px-3 py-1.5 font-semibold">Deterministic</th>
              <th className="text-left px-3 py-1.5 font-semibold">Agentic</th>
            </tr>
          </thead>
          <tbody>
            {[
              ["Technical Findings", String(baseline.total_findings), summary ? String(baseline.total_findings) : "N/A"],
              ["Correlated Risks", "N/A", summary ? String(summary.correlated_risks) : "N/A"],
              ["Business Violations", "N/A", summary ? String(summary.business_violations) : "N/A"],
              ["Attack Paths", "N/A", summary ? String(summary.attack_paths) : "N/A"],
              ["Policy Violations", "N/A", summary ? String(summary.policy_violations) : "N/A"],
              ["Remediation Proposals", "N/A", summary ? String(summary.remediation_proposals) : "N/A"],
              ["Validated Patches", "N/A", summary ? String(summary.validated_patches) : "N/A"],
            ].map(([dim, det, ag]) => (
              <tr key={dim} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/50">
                <td className="px-3 py-1.5 text-[#111827] font-semibold">{dim}</td>
                <td className="px-3 py-1.5 text-blue-600 font-bold">{det}</td>
                <td className="px-3 py-1.5 text-blue-600 font-bold">{ag}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingUp className="w-3.5 h-3.5 text-blue-600" />
            <span className="text-[9px] font-mono uppercase tracking-wider text-blue-600 font-bold">
              Deterministic Security Score
            </span>
          </div>
          {baseline.deterministic_overall_risk_score != null ? (
            <div className={`text-2xl font-mono font-bold ${securityScoreColor(baseline.deterministic_overall_risk_score)}`}>
              {baseline.deterministic_overall_risk_score.toFixed(1)} <span className="text-xs text-slate-400">/ 100</span>
            </div>
          ) : (
            <div className="text-sm font-mono text-slate-400">—</div>
          )}
          <div className="text-[9px] font-mono text-slate-500 mt-1">Higher = better security posture (guardian.core.unified_risk)</div>
        </div>
        <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4">
          <div className="flex items-center gap-2 mb-2">
            <TrendingDown className="w-3.5 h-3.5 text-blue-600" />
            <span className="text-[9px] font-mono uppercase tracking-wider text-blue-600 font-bold">
              Agentic Risk Score
            </span>
          </div>
          {summary?.unified_risk_score != null ? (
            <div className={`text-2xl font-mono font-bold ${riskLevelColor(summary.risk_level)}`}>
              {summary.unified_risk_score.toFixed(2)} <span className="text-xs text-slate-400">/ 10</span>
              {summary.risk_level && (
                <span className={`ml-2 align-middle text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${riskLevelColor(summary.risk_level)} bg-slate-100`}>
                  {summary.risk_level}
                </span>
              )}
            </div>
          ) : (
            <div className="text-sm font-mono text-slate-400">—</div>
          )}
          <div className="text-[9px] font-mono text-slate-500 mt-1">Higher = worse risk (LangGraph risk_fusion composite_risk_score) — a different scale, not directly comparable to the score on the left</div>
        </div>
      </div>
    </div>
  );
}

export default OverviewPanel;
