"use client";

import React, { useState } from "react";
import { GitMerge, ShieldCheck, AlertCircle, Building2, FileCheck, Layers, Lightbulb } from "lucide-react";
import type { CorrelatedChainItem, RiskScores, WorkflowStatus } from "../agentic-scan/types";

export interface AIRiskCorrelationSectionProps {
  chains: CorrelatedChainItem[];
  riskScores?: RiskScores;
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  onViewFinding?: (findingId: string) => void;
}

export function AIRiskCorrelationSection({
  chains, riskScores, workflowStatus, hasRunForThisScan, onViewFinding,
}: AIRiskCorrelationSectionProps) {
  const [open, setOpen] = useState(true);
  const isRunning = workflowStatus === "starting" || workflowStatus === "running";

  return (
    <div className="rounded-xl bg-[#12131a] border border-violet-500/30 overflow-hidden shadow-lg shadow-violet-950/20">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3.5 bg-gradient-to-r from-violet-950/30 via-transparent to-transparent hover:bg-white/4 transition-colors text-left"
      >
        <div className="flex items-center gap-2.5">
          <span className="text-[9px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/40 shadow-[0_0_10px_rgba(139,92,246,0.2)]">
            AI RISK FUSION
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-[#f4f4f8]">
                AI Risk Correlation — Real-World Business Impact
              </span>
            </div>
            <p className="text-[10.5px] font-sans text-[#8e8e9a] mt-0.5">
              Connects code flaws to business consequences—showing what customer data, systems, or compliance rules are threatened.
            </p>
          </div>
        </div>
        <span className="text-xs font-mono text-violet-400 font-bold px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20">
          {open ? "▾ Hide" : "▸ Show"}
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-violet-500/15 pt-3 space-y-4">
          {/* Explainer Callout */}
          <div className="p-3 rounded-lg bg-violet-500/10 border border-violet-500/25 flex items-start gap-2.5 text-[11px] font-sans text-violet-200">
            <Lightbulb className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
            <div>
              Technical bugs don't exist in a vacuum. This section answers: <i>"If this code gets hacked, what real-world assets (customer databases, payment systems) break, and what security laws do we breach?"</i>
            </div>
          </div>

          {!hasRunForThisScan && !isRunning && (
            <div className="text-center py-6 bg-[#0c0d11] rounded-xl border border-white/5 space-y-2">
              <Layers className="w-8 h-8 text-violet-400/60 mx-auto" />
              <p className="text-xs font-sans text-[#8e8e9a]">
                Run AI Scan above to compute real-world business asset risk and policy violation reports.
              </p>
            </div>
          )}

          {isRunning && (
            <div className="text-xs font-mono text-violet-300 py-6 text-center bg-[#0c0d11] rounded-xl border border-white/5">
              AI Agent Calculating Real-World Business Impact &amp; Compliance Risk…
            </div>
          )}

          {hasRunForThisScan && !isRunning && (
            <>
              {/* Layman Risk Gauges Banner */}
              {typeof riskScores?.composite_risk_score === "number" && (
                <div className="p-3.5 rounded-xl bg-[#0c0d11] border border-violet-500/20 grid grid-cols-1 sm:grid-cols-3 gap-3 font-sans">
                  {/* Composite Score Card */}
                  <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-violet-500/20 border border-violet-500/40 flex flex-col items-center justify-center text-violet-300 shrink-0 font-mono">
                      <span className="text-xs font-bold">{riskScores.composite_risk_score.toFixed(1)}</span>
                      <span className="text-[7px] text-[#8e8e9a]">/10</span>
                    </div>
                    <div>
                      <div className="text-[9.5px] text-[#8e8e9a] font-bold uppercase">Overall Business Danger</div>
                      <div className="text-xs font-bold text-[#f4f4f8] flex items-center gap-1.5">
                        <span>Total Risk Rating</span>
                        {riskScores.risk_level && (
                          <span className="text-[8px] uppercase px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30 font-mono">
                            {riskScores.risk_level}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Technical Risk Card */}
                  {typeof riskScores.technical_risk_score === "number" && (
                    <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-sky-500/20 border border-sky-500/40 flex flex-col items-center justify-center text-sky-300 shrink-0 font-mono">
                        <span className="text-xs font-bold">{riskScores.technical_risk_score.toFixed(1)}</span>
                        <span className="text-[7px] text-[#8e8e9a]">/10</span>
                      </div>
                      <div>
                        <div className="text-[9.5px] text-[#8e8e9a] font-bold uppercase">Code Flaw Severity</div>
                        <div className="text-xs font-bold text-[#f4f4f8]">Programming Bug Level</div>
                      </div>
                    </div>
                  )}

                  {/* Business Risk Card */}
                  {typeof riskScores.business_risk_score === "number" && (
                    <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-amber-500/20 border border-amber-500/40 flex flex-col items-center justify-center text-amber-300 shrink-0 font-mono">
                        <span className="text-xs font-bold">{riskScores.business_risk_score.toFixed(1)}</span>
                        <span className="text-[7px] text-[#8e8e9a]">/10</span>
                      </div>
                      <div>
                        <div className="text-[9.5px] text-[#8e8e9a] font-bold uppercase">Data &amp; Asset Value at Risk</div>
                        <div className="text-xs font-bold text-[#f4f4f8]">Valuable System Exposure</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Layman Correlated Chain Cards */}
              <div className="space-y-2.5">
                <div className="text-[11px] font-sans font-bold text-[#f4f4f8] flex items-center gap-1.5">
                  <GitMerge className="w-3.5 h-3.5 text-violet-400" />
                  <span>Real-World Business Impact Stories ({chains.length}):</span>
                </div>

                {chains.length === 0 ? (
                  <div className="text-[11px] font-sans text-[#8e8e9a] text-center py-4 bg-[#0c0d11] rounded-lg border border-white/5">
                    No business risk chains generated for this run.
                  </div>
                ) : (
                  chains.map((c) => (
                    <div key={c.chain_id} className="rounded-xl bg-[#0c0d11] border border-white/10 hover:border-violet-500/30 transition-all p-3.5 space-y-2.5 shadow-md">
                      {/* Title Header */}
                      <div className="flex items-center justify-between gap-2 flex-wrap border-b border-white/5 pb-2">
                        <div className="flex items-center gap-2">
                          <GitMerge className="w-4 h-4 text-violet-300 shrink-0" />
                          <span className="text-xs font-sans font-bold text-[#f4f4f8]">
                            Impact Chain: {c.title || c.chain_id}
                          </span>
                        </div>
                        <span className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                          c.business_criticality === "CRITICAL" || c.business_criticality === "HIGH"
                            ? "bg-red-500/15 text-red-400 border-red-500/30"
                            : "bg-amber-500/15 text-amber-300 border-amber-500/30"
                        }`}>
                          Business Importance: {c.business_criticality}
                        </span>
                      </div>

                      {/* 3 Pillars Layman Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px] font-sans">
                        {/* Pillar 1: Code Flaw */}
                        <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 space-y-1">
                          <div className="text-[9.5px] text-[#8e8e9a] font-bold uppercase flex items-center gap-1">
                            <AlertCircle className="w-3 h-3 text-amber-400 shrink-0" />
                            <span>1. The Code Mistake</span>
                          </div>
                          <div>
                            {onViewFinding ? (
                              <button onClick={() => onViewFinding(c.finding_id)} className="text-violet-300 hover:text-violet-200 font-bold underline decoration-dotted underline-offset-2">
                                Finding {c.finding_id}
                              </button>
                            ) : (
                              <b className="text-[#f4f4f8]">{c.finding_id}</b>
                            )}
                          </div>
                          {typeof c.exploitability === "number" && (
                            <div className="text-[9.5px] text-[#8e8e9a]">
                              Hacker Success Chance: <b className="text-[#f4f4f8]">{(c.exploitability * 100).toFixed(0)}%</b>
                            </div>
                          )}
                        </div>

                        {/* Pillar 2: Target Business Asset */}
                        <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 space-y-1">
                          <div className="text-[9.5px] text-[#8e8e9a] font-bold uppercase flex items-center gap-1">
                            <Building2 className="w-3 h-3 text-sky-400 shrink-0" />
                            <span>2. System / Data In Danger</span>
                          </div>
                          <div className="text-[#f4f4f8] font-bold truncate" title={c.target_asset}>
                            {c.target_asset || "Core Business Server"}
                          </div>
                        </div>

                        {/* Pillar 3: Policy & Compliance Breach */}
                        <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 space-y-1">
                          <div className="text-[9.5px] text-[#8e8e9a] font-bold uppercase flex items-center gap-1">
                            <FileCheck className="w-3 h-3 text-red-400 shrink-0" />
                            <span>3. Security Rules &amp; Laws Broken</span>
                          </div>
                          {c.policy_violations && c.policy_violations.length > 0 ? (
                            <div className="text-[10px] font-mono text-red-300 font-semibold truncate" title={c.policy_violations.join(", ")}>
                              {c.policy_violations.join(", ")}
                            </div>
                          ) : (
                            <div className="text-[10px] text-[#8e8e9a] italic">Standard Company Security Rules</div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

export default AIRiskCorrelationSection;


