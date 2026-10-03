"use client";

import React, { useState } from "react";
import type { AgenticAnalysisResult } from "../types";

function Bar({ label, value, weight, contribution, max = 10, colorClass }: {
  label: string; value: number; weight: number; contribution: number; max?: number; colorClass: string;
}) {
  const pct = Math.min(100, (value / max) * 100);
  return (
    <div>
      <div className="flex items-center justify-between text-[10px] font-mono mb-1">
        <span className="text-slate-600">{label} <span className="text-slate-400">(weight {weight})</span></span>
        <span className="text-[#111827] font-semibold">
          {value.toFixed(2)} / {max} <span className="text-slate-400">→ contributes {contribution.toFixed(2)}</span>
        </span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-100 overflow-hidden">
        <div className={`h-full ${colorClass} rounded-full transition-all duration-500`} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

const RISK_LEVEL_COLOR: Record<string, string> = {
  CRITICAL: "text-rose-700 bg-rose-50 border border-rose-200",
  HIGH: "text-amber-700 bg-amber-50 border border-amber-200",
  MEDIUM: "text-yellow-700 bg-yellow-50 border border-yellow-200",
  LOW: "text-emerald-700 bg-emerald-50 border border-emerald-200",
};

/**
 * Composite risk score breakdown from RiskFusionAgent.
 */
export function RiskPanel({ result }: { result: AgenticAnalysisResult | null }) {
  const risk = result?.risk_fusion.risk_scores;
  const [showContributors, setShowContributors] = useState(false);

  if (!risk) {
    return <div className="text-[11px] font-mono text-slate-500 text-center py-10">RiskFusionAgent hasn't produced a composite score yet.</div>;
  }

  const techContribution = risk.technical_risk_score * 0.35;
  const bizContribution = risk.business_risk_score * 0.25;
  const threatContribution = risk.threat_risk_score * 0.20 * risk.reachability_weight;
  const policyContribution = risk.policy_risk_score * 0.20;

  const findings = result?.deterministic_context.findings || [];
  const highOrCritical = findings.filter((f) => ["high", "critical"].includes((f.severity || "").toLowerCase()));

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">Unified / Composite Risk</div>
            <div className="text-2xl font-mono font-bold text-blue-600">{risk.composite_risk_score.toFixed(2)} / 10</div>
          </div>
          <span className={`text-[10px] font-mono font-bold uppercase px-2.5 py-1 rounded ${RISK_LEVEL_COLOR[risk.risk_level] || ""}`}>
            {risk.risk_level}
          </span>
        </div>
        <div className="text-[9px] font-mono text-slate-500 mt-2">
          consensus confidence: {risk.confidence_score} · reachability weight: {risk.reachability_weight}
        </div>
      </div>

      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4 space-y-3">
        <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">
          Formula: Technical(×0.35) + Business(×0.25) + Threat(×0.20×reachability) + Policy(×0.20) = Unified Risk
        </div>
        <Bar label="Technical Risk" value={risk.technical_risk_score} weight={0.35} contribution={techContribution} colorClass="bg-blue-500" />
        <Bar label="Business Risk" value={risk.business_risk_score} weight={0.25} contribution={bizContribution} colorClass="bg-purple-500" />
        <Bar label="Threat Risk" value={risk.threat_risk_score} weight={0.20} contribution={threatContribution} colorClass="bg-rose-500" />
        <Bar label="Policy Risk" value={risk.policy_risk_score} weight={0.20} contribution={policyContribution} colorClass="bg-amber-500" />
        <div className="flex items-center justify-between text-[10px] font-mono pt-2 border-t border-[#DCE5F0]">
          <span className="text-slate-600">Sum of contributions</span>
          <span className="text-[#111827] font-bold">
            {(techContribution + bizContribution + threatContribution + policyContribution).toFixed(2)} / 10
          </span>
        </div>
      </div>

      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-4">
        <button
          onClick={() => setShowContributors((v) => !v)}
          className="text-[10px] font-mono font-bold text-slate-600 hover:text-[#111827] uppercase tracking-wide"
        >
          {showContributors ? "▾" : "▸"} Contributing findings ({highOrCritical.length} high/critical of {findings.length} total)
        </button>
        {showContributors && (
          <div className="mt-3 space-y-1.5 max-h-64 overflow-y-auto">
            {findings.length === 0 && <div className="text-[10px] font-mono text-slate-400">No findings.</div>}
            {findings.map((f) => (
              <div key={f.finding_id} className="flex items-center justify-between text-[10px] font-mono px-2 py-1 rounded bg-slate-50 border border-[#DCE5F0]">
                <span className="text-[#111827]">{f.rule_id} — {f.file_path}:{f.line_number}</span>
                <span className="text-slate-500 font-semibold">{f.severity}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export default RiskPanel;
