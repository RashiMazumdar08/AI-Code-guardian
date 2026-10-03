"use client";

import React, { useState, useEffect } from "react";
import { ArrowRight, Play, Loader2, Eye, EyeOff, ShieldAlert, Globe, Zap, Target, Info, Sparkles, HelpCircle, Lightbulb, ChevronLeft, ChevronRight } from "lucide-react";
import type { AttackPathItem, PatchItem, ValidationResultItem, WorkflowStatus } from "../agentic-scan/types";
import PatchDiffViewer from "./PatchDiffViewer";

export interface AIThreatAnalysisSectionProps {
  findings: any[];
  attackPaths: AttackPathItem[];
  patches: PatchItem[];
  validationResults: ValidationResultItem[];
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  agenticScanId?: string | null;
  sourceScanId?: string | null;
  onRunAgentic: () => void;
  onViewTrace?: (findingId: string) => void;
}

export function AIThreatAnalysisSection({
  findings, attackPaths, patches, validationResults, workflowStatus,
  hasRunForThisScan, agenticScanId, sourceScanId, onRunAgentic, onViewTrace,
}: AIThreatAnalysisSectionProps) {
  const [open, setOpen] = useState(true);
  const [showAllSeverities, setShowAllSeverities] = useState(false);
  const [currentPage, setCurrentPage] = useState(1);

  const PAGE_SIZE = 4;

  useEffect(() => {
    setCurrentPage(1);
  }, [findings, showAllSeverities, agenticScanId, sourceScanId]);

  const criticalHigh = (findings || []).filter((f) =>
    ["critical", "high"].includes(String(f.severity || "").toLowerCase())
  );
  const relevantFindings = showAllSeverities ? (findings || []) : criticalHigh;

  const totalPages = Math.max(1, Math.ceil(relevantFindings.length / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const startIndex = (safePage - 1) * PAGE_SIZE;
  const endIndex = Math.min(startIndex + PAGE_SIZE, relevantFindings.length);
  const displayedFindings = relevantFindings.slice(startIndex, endIndex);

  const pathByFinding = new Map((attackPaths || []).map((p) => [p.finding_id, p]));
  const patchByFinding = new Map((patches || []).map((p) => [p.finding_id, p]));
  const validationByPatch = new Map((validationResults || []).map((v) => [v.patch_id, v]));

  const isRunningForThisTarget = (workflowStatus === "starting" || workflowStatus === "running");

  return (
    <div className="rounded-2xl bg-white border border-slate-200 shadow-sm overflow-hidden">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-5 py-4 bg-[#EEF4FF] hover:bg-[#E8F0FF] transition-colors text-left border-b border-slate-200"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center shadow-xs shrink-0">
            <Zap className="w-5 h-5 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[12px] font-sans font-semibold uppercase tracking-[0.04em] px-2.5 py-0.5 rounded-full bg-[#EEF4FF] text-[#2563EB] border border-blue-200">
                AI SIMULATOR
              </span>
              <h2 className="text-[16px] font-bold text-slate-900 leading-[1.4] tracking-tight">
                AI Threat Analysis &amp; Attack Simulation
              </h2>
            </div>
            <p className="text-[14px] font-sans font-normal text-slate-600 mt-1 leading-[1.5]">
              Simulates the exact steps a hacker would take to break into your app and provides an instant code fix.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {open && hasRunForThisScan && (
            <button
              onClick={(e) => { e.stopPropagation(); setShowAllSeverities((v) => !v); }}
              className="inline-flex items-center gap-1.5 text-[14px] font-sans font-semibold px-2.5 py-1 rounded-lg bg-white text-slate-700 hover:text-slate-900 hover:bg-slate-100 transition-colors border border-slate-200 shadow-sm"
            >
              {showAllSeverities ? <EyeOff className="w-3.5 h-3.5 text-blue-600" /> : <Eye className="w-3.5 h-3.5 text-blue-600" />}
              {showAllSeverities ? "Show High Risk Only" : "Show All Risks"}
            </button>
          )}
          <span className="text-[14px] font-sans font-semibold text-[#2563EB] px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-[#EEF4FF] transition shadow-xs">
            {open ? "▾ Hide Panel" : "▸ Expand Panel"}
          </span>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-slate-200 space-y-4 pt-3 bg-white">
          {/* Explainer Callout */}
          <div className="p-3 rounded-lg bg-blue-50/60 border border-blue-100 flex items-start gap-2.5 text-[14px] font-sans font-normal text-slate-700 leading-[1.5]">
            <Lightbulb className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
            <div>
              Standard scanners just list code mistakes. This AI agent acts like a friendly hacker—testing if an external visitor can actually reach the broken code, showing you the exact attack path, and drafting a safe code fix.
            </div>
          </div>

          {/* Un-run Banner State */}
          {!hasRunForThisScan && !isRunningForThisTarget && (
            <div className="my-2 p-5 rounded-xl bg-blue-50/50 border border-blue-200 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-blue-100 border border-blue-200 flex items-center justify-center mx-auto text-blue-600">
                <Sparkles className="w-5 h-5 animate-pulse" />
              </div>
              <div className="max-w-md mx-auto">
                <h4 className="text-[15px] font-sans font-semibold text-slate-900 uppercase tracking-wide">
                  Test If Your Code Can Be Hacked
                </h4>
                <p className="text-[14px] font-sans font-normal text-slate-600 mt-1 leading-[1.5]">
                  Click below to simulate a hacker attack, measure how easy it is to exploit, and generate a safe 1-click code repair.
                </p>
              </div>
              <button
                onClick={onRunAgentic}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-[14px] font-sans font-semibold uppercase tracking-wide bg-blue-600 hover:bg-blue-700 text-white shadow-sm transition-all hover:scale-105"
              >
                <Play className="w-3.5 h-3.5 fill-current" /> Run Hacker Attack Simulation
              </button>
            </div>
          )}

          {/* Running State */}
          {isRunningForThisTarget && (
            <div className="my-4 p-6 rounded-xl bg-slate-50 border border-slate-200 flex flex-col items-center justify-center text-center space-y-2">
              <Loader2 className="w-6 h-6 text-blue-600 animate-spin" />
              <span className="text-xs font-mono font-bold text-blue-700">
                AI Agent Testing Hacker Attack Routes &amp; Drafting Code Repair…
              </span>
              <p className="text-[10.5px] font-sans text-slate-500">
                Checking public web entry points, data flows, and verifying safety.
              </p>
            </div>
          )}

          {/* Results State */}
          {hasRunForThisScan && !isRunningForThisTarget && (
            <div className="space-y-4">
              {relevantFindings.length === 0 && (
                <div className="text-[11px] font-sans text-slate-500 text-center py-6 bg-slate-50 rounded-lg border border-slate-200">
                  {showAllSeverities
                    ? "No code flaws detected for attack simulation."
                    : "No high-danger code flaws detected. Use the toggle above to inspect lower severity items."}
                </div>
              )}

              {displayedFindings.map((f) => {
                const fid = f.finding_id || f.id;
                const path = pathByFinding.get(fid);
                const patch = patchByFinding.get(fid);
                const validation = patch ? validationByPatch.get(patch.patch_id) : undefined;
                const exploitScore = typeof path?.exploitability === "number"
                  ? Math.round(path.exploitability * 100)
                  : typeof path?.exploitability === "string"
                  ? parseFloat(path.exploitability) * 100
                  : null;

                return (
                  <div key={fid} className="rounded-xl bg-slate-50 border border-slate-200 hover:border-blue-300 transition-all p-4 space-y-3 shadow-sm">
                    {/* Finding Header */}
                    <div className="flex items-center justify-between gap-3 flex-wrap border-b border-slate-200 pb-2.5">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-amber-600 shrink-0" />
                        <div>
                          <span className="text-xs font-mono font-bold text-slate-900">
                            Code Issue: {f.title || f.rule_id || fid}
                          </span>
                          <span className="ml-2 text-[10px] font-mono text-slate-600 bg-white px-2 py-0.5 rounded border border-slate-200">
                            File: {f.file} (Line {f.line || f.line_number})
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                          String(f.severity).toLowerCase() === "critical"
                            ? "bg-red-50 text-red-700 border-red-200"
                            : "bg-orange-50 text-orange-700 border-orange-200"
                        }`}>
                          {f.severity} DANGER
                        </span>
                        {onViewTrace && (
                          <button
                            onClick={() => onViewTrace(fid)}
                            className="text-[9.5px] font-mono font-bold text-blue-600 hover:text-blue-700 underline decoration-dotted underline-offset-2"
                            title="Inspect full AI trace logs"
                          >
                            Full AI Trace →
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Hacker Attack Story (Layman Stepper) */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-[10.5px] font-sans text-slate-600 font-bold">
                        <span className="flex items-center gap-1.5 text-slate-900">
                          ⚡ Hacker Attack Path (Step-by-Step):
                        </span>
                        {exploitScore !== null && !isNaN(exploitScore) && (
                          <span className="flex items-center gap-1.5">
                            Hacker Success Chance:
                            <b className={`font-mono text-xs ${exploitScore > 60 ? "text-red-600" : "text-amber-600"}`}>
                              {exploitScore}% ({exploitScore > 60 ? "Easy to Attack" : "Moderate Effort"})
                            </b>
                          </span>
                        )}
                      </div>

                      {path ? (
                        <div className="p-3.5 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
                          {/* 3 Layman Steps Grid */}
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px] font-sans">
                            {/* Step 1: Entry Point */}
                            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                              <div className="flex items-center gap-1.5 text-sky-700 text-[10px] font-mono font-bold uppercase">
                                <Globe className="w-3.5 h-3.5 shrink-0 text-sky-600" />
                                <span>Step 1: Where Hacker Enters</span>
                              </div>
                              <div className="text-slate-900 font-semibold text-[11px] truncate" title={path.entry_point}>
                                {path.entry_point}
                              </div>
                              <p className="text-[9.5px] text-slate-500">Public web page or API link accessible on the internet.</p>
                            </div>

                            {/* Step 2: Attack Vector */}
                            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                              <div className="flex items-center gap-1.5 text-amber-700 text-[10px] font-mono font-bold uppercase">
                                <Zap className="w-3.5 h-3.5 shrink-0 text-amber-600" />
                                <span>Step 2: How They Trick Code</span>
                              </div>
                              <div className="text-amber-800 font-semibold text-[11px] truncate" title={path.attack_vector}>
                                {path.attack_vector}
                              </div>
                              <p className="text-[9.5px] text-slate-500">Sends malformed or malicious data to fool the app.</p>
                            </div>

                            {/* Step 3: Target File */}
                            <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1">
                              <div className="flex items-center gap-1.5 text-blue-700 text-[10px] font-mono font-bold uppercase">
                                <Target className="w-3.5 h-3.5 shrink-0 text-blue-600" />
                                <span>Step 3: What Breaks</span>
                              </div>
                              <div className="text-blue-800 font-semibold text-[11px] truncate" title={path.target_file}>
                                {path.target_file}
                              </div>
                              <p className="text-[9.5px] text-slate-500">The exact file line where the app succumbs to the attack.</p>
                            </div>
                          </div>

                          {/* Progress Meter */}
                          {exploitScore !== null && !isNaN(exploitScore) && (
                            <div className="space-y-1 pt-1">
                              <div className="flex justify-between text-[9.5px] font-mono text-slate-500">
                                <span>Hacker Risk Gauge</span>
                                <span>{exploitScore}% Risk</span>
                              </div>
                              <div className="w-full h-2 rounded-full bg-slate-100 overflow-hidden border border-slate-200">
                                <div
                                  className="h-full bg-gradient-to-r from-amber-500 to-red-500 rounded-full transition-all"
                                  style={{ width: `${Math.min(100, Math.max(10, exploitScore))}%` }}
                                />
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="p-3 rounded-lg bg-white border border-slate-200 flex items-center gap-2.5 text-[11px] font-sans text-slate-600">
                          <Info className="w-4 h-4 text-sky-600 shrink-0" />
                          <span>
                            <b>Good news!</b> No direct path for external internet hackers was found for this code line. (It is isolated inside your private code).
                          </span>
                        </div>
                      )}
                    </div>

                    {/* Layman Trace */}
                    {(() => {
                      const evidenceId = (f.evidence_ids && f.evidence_ids[0]) || path?.evidence_id;
                      const hops = [
                        { label: `1. Code Flaw Flagged (${f.rule_id || fid})`, icon: "🔍" },
                        evidenceId ? { label: `2. Code Evidence Saved (${evidenceId})`, icon: "🧾" } : null,
                        path ? { label: "3. Hacker Route Tested", icon: "🤖" } : null,
                        patch ? { label: "4. Automated Fix Created", icon: "🛠️" } : null,
                      ].filter(Boolean) as { label: string; icon: string }[];

                      if (hops.length < 2) return null;
                      return (
                        <div className="flex items-center gap-1.5 text-[9.5px] font-sans text-slate-500 flex-wrap pt-1 border-t border-slate-200">
                          <span className="text-slate-900 font-bold uppercase mr-1">Verification History:</span>
                          {hops.map((hop, idx) => (
                            <React.Fragment key={idx}>
                              {idx > 0 && <ArrowRight className="w-3 h-3 text-slate-400" />}
                              <span className="px-2 py-0.5 rounded bg-white text-slate-700 border border-slate-200 flex items-center gap-1 font-mono text-[9px] shadow-sm">
                                <span>{hop.icon}</span>
                                <span>{hop.label}</span>
                              </span>
                            </React.Fragment>
                          ))}
                        </div>
                      );
                    })()}

                    {/* AI Proposed Fix Diff */}
                    <div className="pt-2 border-t border-slate-200">
                      {patch ? (
                        <PatchDiffViewer patch={patch} validation={validation} />
                      ) : (
                        <div className="text-[10.5px] font-sans text-slate-500 italic">
                          No automatic code fix generated yet for this item.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}

              {/* Pagination Bar */}
              {relevantFindings.length > PAGE_SIZE && (
                <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 pb-1 px-3 bg-slate-50 rounded-xl border border-slate-200 text-xs font-mono">
                  <div className="text-slate-500">
                    Showing <span className="text-slate-900 font-bold">{startIndex + 1}–{endIndex}</span> of{" "}
                    <span className="text-slate-900 font-bold">{relevantFindings.length}</span> threats
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
                      {Array.from({ length: totalPages }, (_, i) => i + 1).map((pageNum) => (
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
                      ))}
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
          )}
        </div>
      )}
    </div>
  );
}

export default AIThreatAnalysisSection;
