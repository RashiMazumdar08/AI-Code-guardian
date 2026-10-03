"use client";

import React, { useState } from "react";
import {
  Sparkles,
  Play,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  ChevronRight,
  Briefcase,
  ShieldCheck,
  FileCode,
} from "lucide-react";
import type { WorkflowStatus } from "../agentic-scan/types";

export interface AIBusinessAnalysisSectionProps {
  aiBusinessInsights?: any[];
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  agenticScanId?: string | null;
  sourceScanId?: string | null;
  grokStatus?: string | null;
  businessAgentReason?: string | null;
  onRunAgentic: () => void;
}

export default function AIBusinessAnalysisSection({
  aiBusinessInsights = [],
  workflowStatus,
  hasRunForThisScan,
  agenticScanId,
  sourceScanId,
  grokStatus,
  businessAgentReason,
  onRunAgentic,
}: AIBusinessAnalysisSectionProps) {
  const [open, setOpen] = useState(true);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);

  const isRunningForThisTarget =
    workflowStatus === "starting" || workflowStatus === "running";

  const activeInsight = React.useMemo(() => {
    if (!aiBusinessInsights || aiBusinessInsights.length === 0) return null;
    return aiBusinessInsights[selectedIndex] || aiBusinessInsights[0];
  }, [aiBusinessInsights, selectedIndex]);

  return (
    <div className="rounded-2xl bg-white border border-slate-200 overflow-hidden shadow-sm space-y-0">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-5 py-4 bg-[#EEF4FF] hover:bg-[#E8F0FF] transition-colors text-left border-b border-slate-200"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center shadow-xs shrink-0">
            <Sparkles className="w-5 h-5 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-xs font-semibold uppercase tracking-wider px-2.5 py-0.5 rounded-full bg-[#EEF4FF] text-[#2563EB] border border-blue-200">
                BUSINESS AGENT
              </span>
              <h2 className="text-lg md:text-xl font-bold text-slate-900 tracking-tight">
                AI Business Intent Analysis
              </h2>
            </div>
            <p className="text-sm text-slate-600 mt-1">
              Semantic requirement gap detection, workflow/state transition validation &amp; missing control discovery
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold text-[#2563EB] px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-[#EEF4FF] transition shadow-xs">
            {open ? "▾ Hide Panel" : "▸ Expand Panel"}
          </span>
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 border-t border-slate-200 space-y-4 pt-4 bg-white">
          {/* Explainer Callout */}
          <div className="p-3.5 rounded-xl bg-blue-50 border border-blue-200 flex items-start gap-2.5 text-xs text-blue-900 leading-relaxed">
            <Lightbulb className="w-4 h-4 text-[#2563EB] shrink-0 mt-0.5" />
            <div>
              While deterministic rules establish baseline requirement matching, the LangGraph Business Agent performs AI semantic gap analysis over codebase AST candidates to identify missing approval steps, unhandled business conditions, and state transition gaps.
            </div>
          </div>

          {/* Un-run Banner State */}
          {!hasRunForThisScan && !isRunningForThisTarget && (
            <div className="my-2 p-5 rounded-xl bg-[#F8FAFC] border border-slate-200 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-blue-50 border border-blue-200 flex items-center justify-center mx-auto text-[#2563EB]">
                <Sparkles className="w-5 h-5 animate-pulse" />
              </div>
              <div className="max-w-md mx-auto">
                <h4 className="text-sm font-semibold text-slate-900 uppercase tracking-wide">
                  Enrich Codebase with Business Agent AI Reasoning
                </h4>
                <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                  Run an AI Agentic Scan to perform AI semantic analysis over business logic evidence and discover unhandled policy rules.
                </p>
              </div>
              <button
                onClick={onRunAgentic}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-xs font-semibold uppercase tracking-wide bg-[#2563EB] text-white hover:bg-[#1D4ED8] transition-colors shadow-sm"
              >
                <Play className="w-3.5 h-3.5 fill-current" /> Run AI Agentic Scan
              </button>
            </div>
          )}

          {/* Running State */}
          {isRunningForThisTarget && (
            <div className="pt-4 flex items-center gap-2 text-xs font-medium text-[#2563EB] py-6 justify-center">
              <Loader2 className="w-4 h-4 animate-spin text-[#2563EB]" />
              Business Agent analyzing codebase candidate profiles &amp; requirements via AI reasoning…
            </div>
          )}

          {/* Completed State */}
          {hasRunForThisScan && !isRunningForThisTarget && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-500 font-mono">
                <span>
                  agentic run: {agenticScanId || "—"} · grounded in deterministic scan: {sourceScanId || "—"}
                </span>
                {grokStatus === "SKIPPED" && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-sky-50 text-sky-700 border border-sky-200">
                    SKIPPED (Conclusive Baseline)
                  </span>
                )}
                {grokStatus === "SKIPPED_BUDGET" && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                    SKIPPED (Token Budget Limit)
                  </span>
                )}
                {grokStatus === "PROVIDER_DAILY_QUOTA" && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                    DAILY QUOTA EXHAUSTED
                  </span>
                )}
                {grokStatus === "RATE_LIMITED" && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                    RATE LIMITED (Per-Minute Limit)
                  </span>
                )}
                {grokStatus === "COMPLETED" && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    COMPLETED
                  </span>
                )}
                {(grokStatus === "PARTIAL" || grokStatus === "COMPLETED_WITH_SKIPS") && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                    COMPLETED (PARTIAL)
                  </span>
                )}
                {(grokStatus === "FAILED" || grokStatus === "UNAVAILABLE" || grokStatus === "PROVIDER_UNAVAILABLE") && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                    {aiBusinessInsights.length > 0 ? "COMPLETED (PARTIAL)" : "SERVICE UNAVAILABLE"}
                  </span>
                )}
              </div>

              {/* If AI Business Insights exist, show them regardless of whether later batches hit provider limits */}
              {aiBusinessInsights.length > 0 ? (
                <div className="space-y-3">
                  {businessAgentReason && (grokStatus === "PARTIAL" || grokStatus === "COMPLETED_WITH_SKIPS" || grokStatus === "PROVIDER_UNAVAILABLE" || grokStatus === "RATE_LIMITED" || grokStatus === "SKIPPED_BUDGET" || businessAgentReason.includes("skipped") || businessAgentReason.includes("notice")) && (
                    <div className="p-3.5 rounded-xl bg-amber-50 border border-amber-200 flex items-start gap-2.5 text-xs text-amber-900 leading-relaxed">
                      <AlertTriangle className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
                      <div>{businessAgentReason}</div>
                    </div>
                  )}
                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                    {/* Left List of AI Business Insights (5 cols) */}
                    <div className="lg:col-span-5 rounded-2xl bg-slate-50 border border-slate-200 flex flex-col overflow-hidden shadow-sm">
                      <div className="px-3.5 py-2.5 bg-slate-100 border-b border-slate-200 flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                          AI Insights ({aiBusinessInsights.length})
                        </span>
                        <span className="text-xs font-semibold text-[#2563EB]">
                          AI Analyzed
                        </span>
                      </div>

                      <div className="divide-y divide-slate-200 max-h-[320px] overflow-y-auto p-2 space-y-1">
                        {aiBusinessInsights.map((insight, idx) => {
                          const isSelected = selectedIndex === idx;
                          const verdict = (insight.verdict || insight.extras?.verdict || "VIOLATION").toUpperCase();
                          const isViolation = verdict.includes("VIOLATION");
                          const isInsufficient = verdict.includes("INSUFFICIENT") || verdict.includes("PARTIAL");

                          const badgeClass = isViolation
                            ? "bg-red-50 text-red-700 border-red-200"
                            : isInsufficient
                            ? "bg-amber-50 text-amber-700 border-amber-200"
                            : "bg-emerald-50 text-emerald-700 border-emerald-200";

                          return (
                            <div
                              key={idx}
                              onClick={() => setSelectedIndex(idx)}
                              className={`p-3 rounded-xl cursor-pointer transition relative ${
                                isSelected
                                  ? "bg-blue-50 border border-blue-300 shadow-sm"
                                  : "bg-white border border-slate-200 hover:bg-slate-100"
                              }`}
                            >
                              <div className="flex items-start justify-between gap-1.5">
                                <div className="space-y-1 min-w-0">
                                  <div className="flex items-center gap-1.5">
                                    <span className={`px-1.5 py-0.5 rounded font-mono font-bold text-[10px] uppercase border ${badgeClass}`}>
                                      {verdict}
                                    </span>
                                    <span className="text-xs font-mono text-[#2563EB] font-bold truncate">
                                      {insight.policy_id || insight.extras?.policy_id || `AI-BUS-${idx + 1}`}
                                    </span>
                                  </div>
                                  <h5 className="text-xs font-semibold text-slate-900 truncate">
                                    {insight.title || insight.category || "Business Intent Insight"}
                                  </h5>
                                </div>
                                <ChevronRight className={`w-3.5 h-3.5 flex-shrink-0 transition ${isSelected ? "text-[#2563EB]" : "text-slate-400"}`} />
                              </div>

                              <div className="mt-1.5 flex items-center justify-between text-xs text-slate-500">
                                <span className="truncate max-w-[170px] font-mono text-slate-600">
                                  {insight.file || "workspace"}:{insight.line || 1}
                                </span>
                                <span className="text-[#2563EB] font-semibold">
                                  AI Analyzed
                                </span>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Right Inspector Box (7 cols) */}
                    {activeInsight && (
                      <div className="lg:col-span-7 rounded-2xl bg-slate-50 border border-slate-200 p-4 space-y-3 flex flex-col justify-between shadow-sm">
                        <div className="space-y-2.5">
                          <div className="flex items-center justify-between border-b border-slate-200 pb-2">
                            <div className="flex items-center gap-2">
                              {(() => {
                                const vStr = (activeInsight.verdict || activeInsight.extras?.verdict || "VIOLATION").toUpperCase();
                                const isV = vStr.includes("VIOLATION");
                                const isI = vStr.includes("INSUFFICIENT") || vStr.includes("PARTIAL");
                                const bCls = isV
                                  ? "bg-red-50 text-red-700 border-red-200"
                                  : isI
                                  ? "bg-amber-50 text-amber-700 border-amber-200"
                                  : "bg-emerald-50 text-emerald-700 border-emerald-200";
                                return (
                                  <span className={`px-2 py-0.5 rounded font-mono font-bold text-xs uppercase border ${bCls}`}>
                                    {vStr}
                                  </span>
                                );
                              })()}
                              <span className="text-xs font-mono text-[#2563EB] font-bold">
                                {activeInsight.policy_id || activeInsight.extras?.policy_id || "AI-BUS-RULE"}
                              </span>
                            </div>
                          </div>

                          <div>
                            <h4 className="text-sm font-semibold text-slate-900">
                              {activeInsight.title || activeInsight.category || "Business Policy Mismatch"}
                            </h4>
                            <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                              {activeInsight.reason || activeInsight.explanation || "AI business agent identified a potential business rule gap."}
                            </p>
                          </div>

                          <div className="p-3 rounded-lg bg-white border border-slate-200 space-y-2 text-xs shadow-sm">
                            <div className="flex items-center justify-between text-slate-600">
                              <span className="flex items-center gap-1.5 text-slate-900 font-semibold">
                                <FileCode className="w-3.5 h-3.5 text-[#2563EB]" /> Affected Component:
                              </span>
                              <span className="font-mono">
                                {activeInsight.file || "N/A"}:{activeInsight.line || 1} {activeInsight.function ? `(${activeInsight.function})` : ""}
                              </span>
                            </div>
                            {activeInsight.extras?.missing_control && (
                              <div className="text-amber-800 leading-relaxed">
                                <span className="font-semibold text-amber-900 uppercase text-xs block">Missing Control:</span>
                                {activeInsight.extras.missing_control}
                              </div>
                            )}
                            {activeInsight.recommendation && (
                              <div className="text-emerald-800 leading-relaxed">
                                <span className="font-semibold text-emerald-900 uppercase text-xs block">AI Recommendation:</span>
                                {activeInsight.recommendation}
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="text-[8.5px] font-mono text-slate-500 flex items-center justify-between pt-2 border-t border-[#174A85]">
                          <span>Engine: {activeInsight.engine || "llm_business_reasoning"}{activeInsight.provider ? ` (${activeInsight.provider})` : ""}</span>
                          <span>Source: {activeInsight.source || "AI_VALIDATED"}</span>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              ) : grokStatus === "PROVIDER_DAILY_QUOTA" ? (
                <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-amber-900">
                    DAILY QUOTA EXHAUSTED
                  </div>
                  <p className="text-[10px] font-mono text-amber-800">
                    {businessAgentReason || "AI reasoning could not run because the LLM provider's daily token quota (200k TPD) was reached. Deterministic findings are fully preserved."}
                  </p>
                </div>
              ) : grokStatus === "SKIPPED_BUDGET" ? (
                <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-amber-900">
                    SKIPPED (Token Budget Limit)
                  </div>
                  <p className="text-[10px] font-mono text-amber-800">
                    {businessAgentReason || "AI Business Analysis was skipped to preserve scan token budget for other priorities. Deterministic policy evaluations are unaffected."}
                  </p>
                </div>
              ) : grokStatus === "RATE_LIMITED" ? (
                <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-amber-900">
                    RATE LIMITED (Per-Minute Limit)
                  </div>
                  <p className="text-[10px] font-mono text-amber-800">
                    {businessAgentReason || "AI Business Analysis is temporarily rate-limited by the LLM provider. Deterministic policy evaluations are fully preserved."}
                  </p>
                </div>
              ) : (grokStatus === "FAILED" || grokStatus === "UNAVAILABLE" || grokStatus === "PROVIDER_UNAVAILABLE") ? (
                <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-amber-900">
                    SERVICE UNAVAILABLE
                  </div>
                  <p className="text-[10px] font-mono text-amber-800">
                    {businessAgentReason || "The AI Business Agent reasoning service encountered an error or is currently unavailable."}
                  </p>
                </div>
              ) : grokStatus === "SKIPPED" || (aiBusinessInsights.length === 0 && businessAgentReason?.includes("conclusive baseline")) ? (
                <div className="p-4 rounded-xl bg-slate-50 border border-[#174A85] text-center space-y-1">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-slate-900">
                    AI Business Intent Analysis was not required for this scan.
                  </div>
                  <p className="text-[10px] font-mono text-slate-500">
                    {businessAgentReason || "The deterministic business intent evaluation produced a sufficiently conclusive baseline, so additional AI reasoning was not invoked."}
                  </p>
                </div>
              ) : (
                <div className="p-4 rounded-xl bg-slate-50 border border-[#174A85] text-center space-y-1">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-slate-900">
                    No additional AI business intent gaps were identified.
                  </div>
                  <p className="text-[10px] font-mono text-slate-500">
                    {businessAgentReason || "The Business Agent evaluated codebase candidate profiles against policy rules and found no unhandled business logic gaps."}
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
