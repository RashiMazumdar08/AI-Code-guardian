"use client";

import React, { useState } from "react";
import {
  Sparkles,
  Play,
  Loader2,
  ShieldAlert,
  MessageSquare,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  ChevronRight,
  Info,
} from "lucide-react";
import type { FindingItem, WorkflowStatus } from "../agentic-scan/types";

export interface AISecurityAnalysisSectionProps {
  aiSecurityInsights: FindingItem[];
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  agenticScanId?: string | null;
  sourceScanId?: string | null;
  grokStatus?: string | null;
  securityAgentReason?: string | null;
  onRunAgentic: () => void;
  onDiscussInChat?: (finding: any) => void;
  onViewTrace?: (findingId: string) => void;
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: "bg-red-50 text-red-700 border border-red-200",
  HIGH: "bg-orange-50 text-orange-700 border border-orange-200",
  MEDIUM: "bg-amber-50 text-amber-700 border border-amber-200",
  LOW: "bg-blue-50 text-blue-700 border border-blue-200",
};

export default function AISecurityAnalysisSection({
  aiSecurityInsights,
  workflowStatus,
  hasRunForThisScan,
  agenticScanId,
  sourceScanId,
  grokStatus,
  securityAgentReason,
  onRunAgentic,
  onDiscussInChat,
  onViewTrace,
}: AISecurityAnalysisSectionProps) {
  const [open, setOpen] = useState(true);
  const [selectedInsightId, setSelectedInsightId] = useState<string | null>(null);

  const isRunningForThisTarget =
    workflowStatus === "starting" || workflowStatus === "running";

  const activeInsight = React.useMemo(() => {
    if (!aiSecurityInsights || aiSecurityInsights.length === 0) return null;
    if (selectedInsightId) {
      const found = aiSecurityInsights.find(
        (item) => (item.finding_id || item.id) === selectedInsightId
      );
      if (found) return found;
    }
    return aiSecurityInsights[0];
  }, [aiSecurityInsights, selectedInsightId]);

  return (
    <div className="rounded-2xl bg-white border border-[#244A86] overflow-hidden shadow-sm space-y-0">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-5 py-4 bg-[#EEF4FF] hover:bg-[#E8F0FF] transition-colors text-left border-b border-[#C9D7EA]"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-white border border-[#C9D7EA] flex items-center justify-center shadow-xs shrink-0">
            <Sparkles className="w-5 h-5 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[12px] font-sans font-semibold uppercase tracking-[0.04em] px-2.5 py-0.5 rounded-full bg-[#EEF4FF] text-[#2563EB] border border-[#C9D7EA]">
                SECURITY AGENT
              </span>
              <h2 className="text-[16px] font-bold text-[#14213D] leading-[1.4] tracking-tight">
                AI Security Analysis
              </h2>
            </div>
            <p className="text-[14px] font-sans font-normal text-[#536987] mt-1 leading-[1.5]">
              AI semantic reasoning, AST evidence validation &amp; framework-specific security gap detection
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[14px] font-sans font-semibold text-[#2563EB] px-3 py-1.5 rounded-lg bg-white border border-[#244A86] hover:bg-[#EEF4FF] transition shadow-xs">
            {open ? "▾ Hide Panel" : "▸ Expand Panel"}
          </span>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-[#BFDBFE] space-y-4 pt-3 bg-white">
          {/* Explainer Callout */}
          <div className="p-3 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] flex items-start gap-2.5 text-[14px] font-sans font-normal text-[#1E40AF] leading-[1.5]">
            <Lightbulb className="w-4 h-4 text-amber-600 shrink-0 mt-0.5" />
            <div>
              While deterministic static rules establish baseline AST evidence, the LangGraph Security Agent uses AI reasoning over candidate evidence to identify complex semantic vulnerabilities and framework coverage gaps.
            </div>
          </div>

          {/* Un-run Banner State */}
          {!hasRunForThisScan && !isRunningForThisTarget && (
            <div className="my-2 p-5 rounded-xl bg-[#EFF6FF] border border-[#BFDBFE] text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-white border border-[#BFDBFE] flex items-center justify-center mx-auto text-[#2563EB] shadow-sm">
                <Sparkles className="w-5 h-5 animate-pulse" />
              </div>
              <div className="max-w-md mx-auto">
                <h4 className="text-[15px] font-sans font-semibold text-slate-900 uppercase tracking-wide">
                  Enrich Codebase with Security Agent Reasoning
                </h4>
                <p className="text-[14px] font-sans font-normal text-slate-600 mt-1 leading-[1.5]">
                  Run an AI Agentic Scan to perform AI semantic security analysis over code evidence and detect hidden framework vulnerabilities.
                </p>
              </div>
              <button
                onClick={onRunAgentic}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[14px] font-sans font-semibold uppercase tracking-wide bg-[#2563EB] text-white hover:bg-[#1D4ED8] transition-colors shadow-sm"
              >
                <Play className="w-3.5 h-3.5 fill-current" /> Run AI Agentic Scan
              </button>
            </div>
          )}

          {/* Running State */}
          {isRunningForThisTarget && (
            <div className="pt-4 flex items-center gap-2 text-xs font-medium text-[#2563EB] py-6 justify-center">
              <Loader2 className="w-4 h-4 animate-spin text-[#2563EB]" />
              Security Agent analyzing evidence via AI reasoning…
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
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
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
                {(grokStatus === "FAILED" || grokStatus === "UNAVAILABLE" || grokStatus === "PROVIDER_UNAVAILABLE") && (
                  <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                    SERVICE UNAVAILABLE
                  </span>
                )}
              </div>

              {grokStatus === "PROVIDER_DAILY_QUOTA" ? (
                <div className="p-4 rounded-lg bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-xs font-semibold text-amber-800">
                    DAILY QUOTA EXHAUSTED
                  </div>
                  <p className="text-xs text-slate-600">
                    {securityAgentReason || "AI reasoning could not run because the LLM provider's daily token quota (200k TPD) was reached. Deterministic findings are fully preserved."}
                  </p>
                </div>
              ) : grokStatus === "SKIPPED_BUDGET" ? (
                <div className="p-4 rounded-lg bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-xs font-semibold text-amber-800">
                    SKIPPED (Token Budget Limit)
                  </div>
                  <p className="text-xs text-slate-600">
                    {securityAgentReason || "AI Security Analysis was skipped to preserve scan token budget for other priorities. Deterministic baseline findings are unaffected."}
                  </p>
                </div>
              ) : grokStatus === "RATE_LIMITED" ? (
                <div className="p-4 rounded-lg bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-xs font-semibold text-amber-800">
                    RATE LIMITED (Per-Minute Limit)
                  </div>
                  <p className="text-xs text-slate-600">
                    {securityAgentReason || "AI Security Analysis is temporarily rate-limited by the LLM provider. Deterministic findings are fully preserved."}
                  </p>
                </div>
              ) : (grokStatus === "FAILED" || grokStatus === "UNAVAILABLE" || grokStatus === "PROVIDER_UNAVAILABLE") ? (
                <div className="p-4 rounded-lg bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-xs font-semibold text-amber-800">
                    SERVICE UNAVAILABLE
                  </div>
                  <p className="text-xs text-slate-600">
                    {securityAgentReason || "The AI Security Agent reasoning service encountered an error or is currently unavailable."}
                  </p>
                </div>
              ) : grokStatus === "SKIPPED" || (aiSecurityInsights.length === 0 && securityAgentReason?.includes("conclusive baseline")) ? (
                <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center space-y-1">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 mx-auto" />
                  <div className="text-xs font-semibold text-slate-900">
                    AI Security Analysis was not required for this scan.
                  </div>
                  <p className="text-xs text-slate-600">
                    {securityAgentReason || "The deterministic security analysis produced a sufficiently conclusive baseline, so additional AI reasoning was not invoked."}
                  </p>
                </div>
              ) : aiSecurityInsights.length === 0 ? (
                <div className="p-4 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] text-center space-y-1">
                  <CheckCircle2 className="w-5 h-5 text-emerald-600 mx-auto" />
                  <div className="text-xs font-semibold text-slate-900">
                    No additional AI security findings were identified.
                  </div>
                  <p className="text-xs text-slate-600">
                    {securityAgentReason || "The Security Agent evaluated codebase profiles against the baseline scanner results and found no extra semantic vulnerabilities."}
                  </p>
                </div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                  {/* Left List of AI Security Insights (5 cols) */}
                  <div className="lg:col-span-5 rounded-lg bg-white border border-[#E2E8F0] flex flex-col overflow-hidden shadow-sm">
                    <div className="px-3 py-2 bg-[#F8FAFC] border-b border-[#E2E8F0] flex items-center justify-between">
                      <span className="text-xs font-semibold uppercase tracking-wider text-slate-600">
                        AI Findings ({aiSecurityInsights.length})
                      </span>
                      <span className="text-xs font-semibold text-[#2563EB]">
                        AI Validated
                      </span>
                    </div>

                    <div className="divide-y divide-[#E2E8F0] max-h-[320px] overflow-y-auto p-1.5 space-y-1">
                      {aiSecurityInsights.map((insight) => {
                        const id = insight.finding_id || insight.id || insight.rule_id;
                        const isSelected = activeInsight && (activeInsight.finding_id || activeInsight.id) === id;
                        const sev = (insight.severity || "MEDIUM").toUpperCase();
                        const sevStyle = SEVERITY_STYLES[sev] || SEVERITY_STYLES.MEDIUM;

                        return (
                          <div
                            key={id}
                            onClick={() => setSelectedInsightId(id)}
                            className={`p-2.5 rounded cursor-pointer transition relative ${
                              isSelected
                                ? "bg-[#EFF6FF] border border-[#BFDBFE]"
                                : "bg-white border border-transparent hover:bg-[#F8FAFC]"
                            }`}
                          >
                            <div className="flex items-start justify-between gap-1.5">
                              <div className="space-y-1 min-w-0">
                                <div className="flex items-center gap-1.5">
                                  <span className={`px-1.5 py-0.5 rounded font-mono font-bold text-[10px] uppercase border ${sevStyle}`}>
                                    {sev}
                                  </span>
                                  <span className="text-xs font-mono text-[#2563EB] font-bold truncate">
                                    {insight.rule_id || "AI-SEC-FINDING"}
                                  </span>
                                </div>
                                <h5 className="text-xs font-semibold text-slate-900 truncate">
                                  {insight.title || insight.category || "AI Security Insight"}
                                </h5>
                              </div>
                              <ChevronRight className={`w-3.5 h-3.5 flex-shrink-0 transition ${isSelected ? "text-[#2563EB]" : "text-[#94A3B8]"}`} />
                            </div>

                            <div className="mt-1.5 flex items-center justify-between text-xs text-slate-500">
                              <span className="truncate max-w-[170px] font-mono text-slate-600">
                                {insight.file || insight.file_path || "app.py"}:{insight.line || insight.line_number || 1}
                              </span>
                              <span className="text-[#2563EB] font-semibold">
                                {typeof insight.confidence === "number"
                                  ? `${Math.round(insight.confidence * 100)}% Conf`
                                  : "AI Verified"}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Right Inspector Box (7 cols) */}
                  {activeInsight && (
                    <div className="lg:col-span-7 rounded-lg bg-white border border-[#E2E8F0] p-4 space-y-3 flex flex-col justify-between shadow-sm">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between border-b border-[#E2E8F0] pb-2">
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-0.5 rounded font-mono font-bold text-xs uppercase border ${SEVERITY_STYLES[(activeInsight.severity || "MEDIUM").toUpperCase()] || SEVERITY_STYLES.MEDIUM}`}>
                              {(activeInsight.severity || "MEDIUM").toUpperCase()}
                            </span>
                            <span className="text-xs font-mono text-[#2563EB] font-bold">
                              {activeInsight.rule_id || "AI-SEC"}
                            </span>
                          </div>

                          <div className="flex items-center gap-2">
                            {onDiscussInChat && (
                              <button
                                onClick={() => onDiscussInChat(activeInsight)}
                                className="px-2.5 py-1 rounded-lg bg-[#EFF6FF] hover:bg-[#DBEAFE] text-[#2563EB] text-xs font-semibold border border-[#BFDBFE] flex items-center gap-1 transition"
                              >
                                <MessageSquare className="w-3.5 h-3.5" /> Discuss AI
                              </button>
                            )}
                            {onViewTrace && (activeInsight.finding_id || activeInsight.id) && (
                              <button
                                onClick={() => onViewTrace(activeInsight.finding_id || activeInsight.id || "")}
                                className="px-2.5 py-1 rounded-lg bg-[#F8FAFC] hover:bg-[#E2E8F0] text-slate-700 text-xs font-semibold border border-[#E2E8F0] transition"
                              >
                                View Trace
                              </button>
                            )}
                          </div>
                        </div>

                        <div>
                          <h4 className="text-sm font-semibold text-slate-900">
                            {activeInsight.title || activeInsight.category || "AI Security Vulnerability"}
                          </h4>
                          <p className="text-xs text-slate-600 mt-1 leading-relaxed">
                            {activeInsight.description || activeInsight.snippet || "AI semantic security reasoning identified a potential coverage gap or framework vulnerability."}
                          </p>
                        </div>

                        <div className="p-3 rounded-lg bg-[#F8FAFC] border border-[#E2E8F0] space-y-1 text-xs">
                          <div className="flex items-center justify-between text-slate-600">
                            <span className="flex items-center gap-1 text-slate-900 font-semibold">
                              <FileCode className="w-3.5 h-3.5 text-[#2563EB]" /> Affected File:
                            </span>
                            <span className="font-mono">
                              {activeInsight.file || activeInsight.file_path || "app.py"}:{activeInsight.line || activeInsight.line_number || 1}
                            </span>
                          </div>
                          {activeInsight.recommendation && (
                            <div className="pt-1.5 text-emerald-800 leading-relaxed">
                              <span className="font-semibold text-emerald-700 uppercase text-xs block">AI Recommendation:</span>
                              {activeInsight.recommendation}
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="text-xs font-mono text-slate-500 flex items-center justify-between pt-2 border-t border-[#E2E8F0]">
                        <span>Engine: {activeInsight.engine === "grok_security_reasoning" ? "ai_security_reasoning" : (activeInsight.engine || "ai_security_reasoning")}</span>
                        <span>Source: {activeInsight.source || "AI_VALIDATED"}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
