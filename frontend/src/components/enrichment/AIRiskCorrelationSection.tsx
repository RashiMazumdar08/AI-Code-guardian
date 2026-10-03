"use client";

import React, { useState, useEffect } from "react";
import { GitMerge, ShieldCheck, AlertCircle, Building2, FileCheck, Layers, Lightbulb, ChevronLeft, ChevronRight } from "lucide-react";
import type { CorrelatedChainItem, RiskScores, WorkflowStatus } from "../agentic-scan/types";

export interface AIRiskCorrelationSectionProps {
  chains: CorrelatedChainItem[];
  riskScores?: RiskScores;
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  onViewFinding?: (findingId: string) => void;
}

function getPageNumbers(current: number, total: number): (number | string)[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  if (current <= 3) {
    return [1, 2, 3, 4, "...", total];
  }
  if (current >= total - 2) {
    return [1, "...", total - 3, total - 2, total - 1, total];
  }
  return [1, "...", current - 1, current, current + 1, "...", total];
}

export function AIRiskCorrelationSection({
  chains, riskScores, workflowStatus, hasRunForThisScan, onViewFinding,
}: AIRiskCorrelationSectionProps) {
  const [open, setOpen] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const isRunning = workflowStatus === "starting" || workflowStatus === "running";

  const PAGE_SIZE = 4;

  useEffect(() => {
    setCurrentPage(1);
  }, [chains]);

  const totalChains = (chains || []).length;
  const totalPages = Math.max(1, Math.ceil(totalChains / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const startIndex = (safePage - 1) * PAGE_SIZE;
  const endIndex = Math.min(startIndex + PAGE_SIZE, totalChains);
  const displayedChains = (chains || []).slice(startIndex, endIndex);

  return (
    <div className="rounded-2xl bg-white border border-slate-200 shadow-sm overflow-hidden">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-5 py-4 bg-[#EEF4FF] hover:bg-[#E8F0FF] transition-colors text-left border-b border-slate-200"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center shadow-xs shrink-0">
            <GitMerge className="w-5 h-5 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[12px] font-sans font-semibold uppercase tracking-[0.04em] px-2.5 py-0.5 rounded-full bg-[#EEF4FF] text-[#2563EB] border border-blue-200">
                AI RISK FUSION
              </span>
              <h2 className="text-[16px] font-bold text-slate-900 leading-[1.4] tracking-tight">
                AI Risk Correlation &amp; Business Impact
              </h2>
            </div>
            <p className="text-[14px] font-sans font-normal text-slate-600 mt-1 leading-[1.5]">
              Connects code flaws to business consequences—showing what customer data, systems, or compliance rules are threatened.
            </p>
          </div>
        </div>
        <span className="text-[14px] font-sans font-semibold text-[#2563EB] px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-[#EEF4FF] transition shadow-xs">
          {open ? "▾ Hide Panel" : "▸ Expand Panel"}
        </span>
      </button>

      {open && (
        <div className="px-4 pb-4 pt-3 space-y-4 bg-white">
          {/* Explainer Callout */}
          <div className="p-3 rounded-lg bg-blue-50/60 border border-blue-100 flex items-start gap-2.5 text-[14px] font-sans font-normal text-slate-700 leading-[1.5]">
            <Lightbulb className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
            <div>
              Technical bugs don't exist in a vacuum. This section answers: <i>"If this code gets hacked, what real-world assets (customer databases, payment systems) break, and what security laws do we breach?"</i>
            </div>
          </div>

          {!hasRunForThisScan && !isRunning && (
            <div className="text-center py-6 bg-slate-50 rounded-xl border border-slate-200 space-y-2">
              <Layers className="w-8 h-8 text-slate-400 mx-auto" />
              <p className="text-xs font-sans text-slate-600">
                Run AI Scan above to compute real-world business asset risk and policy violation reports.
              </p>
            </div>
          )}

          {isRunning && (
            <div className="text-xs font-mono text-blue-600 py-6 text-center bg-slate-50 rounded-xl border border-slate-200">
              AI Agent Calculating Real-World Business Impact &amp; Compliance Risk…
            </div>
          )}

          {hasRunForThisScan && !isRunning && (
            <>
              {/* Layman Risk Gauges Banner */}
              {typeof riskScores?.composite_risk_score === "number" && (
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 grid grid-cols-1 sm:grid-cols-3 gap-3 font-sans">
                  {/* Composite Score Card */}
                  <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-sm flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-blue-50 border border-blue-200 flex flex-col items-center justify-center text-blue-700 shrink-0 font-mono">
                      <span className="text-xs font-bold">{riskScores.composite_risk_score.toFixed(1)}</span>
                      <span className="text-[7px] text-slate-500">/10</span>
                    </div>
                    <div>
                      <div className="text-[9.5px] text-slate-500 font-bold uppercase">Overall Business Danger</div>
                      <div className="text-xs font-bold text-slate-900 flex items-center gap-1.5">
                        <span>Total Risk Rating</span>
                        {riskScores.risk_level && (
                          <span className="text-[8px] uppercase px-1.5 py-0.2 rounded bg-amber-50 text-amber-700 border border-amber-200 font-mono">
                            {riskScores.risk_level}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Technical Risk Card */}
                  {typeof riskScores.technical_risk_score === "number" && (
                    <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-sm flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-sky-50 border border-sky-200 flex flex-col items-center justify-center text-sky-700 shrink-0 font-mono">
                        <span className="text-xs font-bold">{riskScores.technical_risk_score.toFixed(1)}</span>
                        <span className="text-[7px] text-slate-500">/10</span>
                      </div>
                      <div>
                        <div className="text-[9.5px] text-slate-500 font-bold uppercase">Code Flaw Severity</div>
                        <div className="text-xs font-bold text-slate-900">Programming Bug Level</div>
                      </div>
                    </div>
                  )}

                  {/* Business Risk Card */}
                  {typeof riskScores.business_risk_score === "number" && (
                    <div className="p-2.5 rounded-lg bg-white border border-slate-200 shadow-sm flex items-center gap-3">
                      <div className="w-10 h-10 rounded-lg bg-amber-50 border border-amber-200 flex flex-col items-center justify-center text-amber-700 shrink-0 font-mono">
                        <span className="text-xs font-bold">{riskScores.business_risk_score.toFixed(1)}</span>
                        <span className="text-[7px] text-slate-500">/10</span>
                      </div>
                      <div>
                        <div className="text-[9.5px] text-slate-500 font-bold uppercase">Data &amp; Asset Value at Risk</div>
                        <div className="text-xs font-bold text-slate-900">Valuable System Exposure</div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Layman Correlated Chain Cards */}
              <div className="space-y-2.5">
                <div className="text-[11px] font-sans font-bold text-slate-900 flex items-center gap-1.5">
                  <GitMerge className="w-3.5 h-3.5 text-blue-600" />
                  <span>Real-World Business Impact Stories ({totalChains}):</span>
                </div>

                {totalChains === 0 ? (
                  <div className="text-[11px] font-sans text-slate-500 text-center py-4 bg-slate-50 rounded-lg border border-slate-200">
                    No business risk chains generated for this run.
                  </div>
                ) : (
                  displayedChains.map((c) => (
                    <div key={c.chain_id} className="rounded-xl bg-slate-50 border border-slate-200 hover:border-blue-300 transition-all p-3.5 space-y-2.5 shadow-sm">
                      {/* Title Header */}
                      <div className="flex items-center justify-between gap-2 flex-wrap border-b border-slate-200 pb-2">
                        <div className="flex items-center gap-2">
                          <GitMerge className="w-4 h-4 text-blue-600 shrink-0" />
                          <span className="text-xs font-sans font-bold text-slate-900">
                            Impact Chain: {c.title || c.chain_id}
                          </span>
                        </div>
                        <span className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                          c.business_criticality === "CRITICAL" || c.business_criticality === "HIGH"
                            ? "bg-red-50 text-red-700 border-red-200"
                            : "bg-amber-50 text-amber-700 border-amber-200"
                        }`}>
                          Business Importance: {c.business_criticality}
                        </span>
                      </div>

                      {/* 3 Pillars Layman Grid */}
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px] font-sans">
                        {/* Pillar 1: Code Flaw */}
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1 shadow-sm">
                          <div className="text-[9.5px] text-slate-500 font-bold uppercase flex items-center gap-1">
                            <AlertCircle className="w-3 h-3 text-amber-600 shrink-0" />
                            <span>1. The Code Mistake</span>
                          </div>
                          <div>
                            {onViewFinding ? (
                              <button onClick={() => onViewFinding(c.finding_id)} className="text-blue-600 hover:text-blue-700 font-bold underline decoration-dotted underline-offset-2">
                                Finding {c.finding_id}
                              </button>
                            ) : (
                              <b className="text-slate-900">{c.finding_id}</b>
                            )}
                          </div>
                          {typeof c.exploitability === "number" && (
                            <div className="text-[9.5px] text-slate-500">
                              Hacker Success Chance: <b className="text-slate-900">{(c.exploitability * 100).toFixed(0)}%</b>
                            </div>
                          )}
                        </div>

                        {/* Pillar 2: Target Business Asset */}
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1 shadow-sm">
                          <div className="text-[9.5px] text-slate-500 font-bold uppercase flex items-center gap-1">
                            <Building2 className="w-3 h-3 text-sky-600 shrink-0" />
                            <span>2. System / Data In Danger</span>
                          </div>
                          <div className="text-slate-900 font-bold truncate" title={c.target_asset}>
                            {c.target_asset || "Core Business Server"}
                          </div>
                        </div>

                        {/* Pillar 3: Policy & Compliance Breach */}
                        <div className="p-2.5 rounded-lg bg-white border border-slate-200 space-y-1 shadow-sm">
                          <div className="text-[9.5px] text-slate-500 font-bold uppercase flex items-center gap-1">
                            <FileCheck className="w-3 h-3 text-red-600 shrink-0" />
                            <span>3. Security Rules &amp; Laws Broken</span>
                          </div>
                          {c.policy_violations && c.policy_violations.length > 0 ? (
                            <div className="text-[10px] font-mono text-red-700 font-semibold truncate" title={c.policy_violations.join(", ")}>
                              {c.policy_violations.join(", ")}
                            </div>
                          ) : (
                            <div className="text-[10px] text-slate-500 italic">Standard Company Security Rules</div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}

                {/* Pagination Bar */}
                {totalChains > PAGE_SIZE && (
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 pb-1 px-3 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono">
                    <div className="text-slate-500">
                      Showing <span className="text-slate-900 font-bold">{startIndex + 1}–{endIndex}</span> of{" "}
                      <span className="text-slate-900 font-bold">{totalChains}</span> impact stories
                    </div>

                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                        disabled={safePage === 1}
                        className="px-2.5 py-1 rounded bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-[11px] font-semibold flex items-center gap-1 shadow-sm"
                      >
                        <ChevronLeft className="w-3.5 h-3.5" /> Previous
                      </button>

                      <div className="flex items-center gap-1 px-1">
                        {getPageNumbers(safePage, totalPages).map((p, idx) => {
                          if (p === "...") {
                            return (
                              <span key={`ellipsis-${idx}`} className="px-1 text-slate-400 font-mono text-xs select-none">
                                ...
                              </span>
                            );
                          }
                          const pageNum = p as number;
                          return (
                            <button
                              key={pageNum}
                              onClick={() => setCurrentPage(pageNum)}
                              className={`w-7 h-7 rounded text-[11px] font-mono font-bold flex items-center justify-center transition-all ${
                                pageNum === safePage
                                  ? "bg-blue-600 text-white border border-blue-600 shadow-sm"
                                  : "bg-white text-slate-600 hover:text-slate-900 hover:bg-slate-100 border border-slate-200"
                              }`}
                            >
                              {pageNum}
                            </button>
                          );
                        })}
                      </div>

                      <button
                        onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                        disabled={safePage === totalPages}
                        className="px-2.5 py-1 rounded bg-white border border-slate-200 text-slate-700 hover:bg-slate-100 disabled:opacity-40 disabled:cursor-not-allowed transition-colors text-[11px] font-semibold flex items-center gap-1 shadow-sm"
                      >
                        Next <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
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


