"use client";

import React, { useState } from "react";
import { ArrowRight, Play, Loader2, Eye, EyeOff, ShieldAlert, Globe, Zap, Target, Info, Sparkles, HelpCircle, Lightbulb } from "lucide-react";
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

  const criticalHigh = (findings || []).filter((f) =>
    ["critical", "high"].includes(String(f.severity || "").toLowerCase())
  );
  const relevantFindings = showAllSeverities ? (findings || []) : criticalHigh;

  const pathByFinding = new Map((attackPaths || []).map((p) => [p.finding_id, p]));
  const patchByFinding = new Map((patches || []).map((p) => [p.finding_id, p]));
  const validationByPatch = new Map((validationResults || []).map((v) => [v.patch_id, v]));

  const isRunningForThisTarget = (workflowStatus === "starting" || workflowStatus === "running");

  return (
    <div className="rounded-xl bg-[#12131a] border border-violet-500/30 overflow-hidden shadow-lg shadow-violet-950/20">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3.5 bg-gradient-to-r from-violet-950/30 via-transparent to-transparent hover:bg-white/4 transition-colors text-left"
      >
        <div className="flex items-center gap-2.5">
          <span className="text-[9px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/40 shadow-[0_0_10px_rgba(139,92,246,0.2)]">
            AI SIMULATOR
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-[#f4f4f8]">
                AI Threat Analysis — How a Hacker Can Attack
              </span>
            </div>
            <p className="text-[10.5px] font-sans text-[#8e8e9a] mt-0.5">
              Simulates the exact steps a hacker would take to break into your app and provides an instant code fix.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {open && hasRunForThisScan && (
            <button
              onClick={(e) => { e.stopPropagation(); setShowAllSeverities((v) => !v); }}
              className="inline-flex items-center gap-1.5 text-[9px] font-mono font-bold uppercase px-2 py-1 rounded bg-white/6 text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/10 transition-colors border border-white/5"
            >
              {showAllSeverities ? <EyeOff className="w-3 h-3 text-violet-400" /> : <Eye className="w-3 h-3 text-violet-400" />}
              {showAllSeverities ? "Show High Risk Only" : "Show All Risks"}
            </button>
          )}
          <span className="text-xs font-mono text-violet-400 font-bold px-2 py-0.5 rounded bg-violet-500/10 border border-violet-500/20">
            {open ? "▾ Hide" : "▸ Show"}
          </span>
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-violet-500/15 space-y-4 pt-3">
          {/* Explainer Callout */}
          <div className="p-3 rounded-lg bg-violet-500/10 border border-violet-500/25 flex items-start gap-2.5 text-[11px] font-sans text-violet-200">
            <Lightbulb className="w-4 h-4 text-amber-300 shrink-0 mt-0.5" />
            <div>
              Standard scanners just list code mistakes. This AI agent acts like a friendly hacker—testing if an external visitor can actually reach the broken code, showing you the exact attack path, and drafting a safe code fix.
            </div>
          </div>

          {/* Un-run Banner State */}
          {!hasRunForThisScan && !isRunningForThisTarget && (
            <div className="my-2 p-5 rounded-xl bg-gradient-to-br from-violet-950/40 via-[#0c0d11] to-[#0c0d11] border border-violet-500/30 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-violet-500/15 border border-violet-500/30 flex items-center justify-center mx-auto text-violet-300">
                <Sparkles className="w-5 h-5 animate-pulse" />
              </div>
              <div className="max-w-md mx-auto">
                <h4 className="text-xs font-mono font-bold text-[#f4f4f8] uppercase tracking-wide">
                  Test If Your Code Can Be Hacked
                </h4>
                <p className="text-[11px] font-sans text-[#8e8e9a] mt-1 leading-relaxed">
                  Click below to simulate a hacker attack, measure how easy it is to exploit, and generate a safe 1-click code repair.
                </p>
              </div>
              <button
                onClick={onRunAgentic}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-[11px] font-mono font-bold uppercase tracking-wider bg-violet-600 hover:bg-violet-500 text-white shadow-lg shadow-violet-600/30 transition-all hover:scale-105"
              >
                <Play className="w-3.5 h-3.5 fill-current" /> Run Hacker Attack Simulation
              </button>
            </div>
          )}

          {/* Running State */}
          {isRunningForThisTarget && (
            <div className="my-4 p-6 rounded-xl bg-[#0c0d11] border border-violet-500/30 flex flex-col items-center justify-center text-center space-y-2">
              <Loader2 className="w-6 h-6 text-violet-400 animate-spin" />
              <span className="text-xs font-mono font-bold text-violet-300">
                AI Agent Testing Hacker Attack Routes &amp; Drafting Code Repair…
              </span>
              <p className="text-[10.5px] font-sans text-[#8e8e9a]">
                Checking public web entry points, data flows, and verifying safety.
              </p>
            </div>
          )}

          {/* Results State */}
          {hasRunForThisScan && !isRunningForThisTarget && (
            <div className="space-y-4">
              {relevantFindings.length === 0 && (
                <div className="text-[11px] font-sans text-[#8e8e9a] text-center py-6 bg-[#0c0d11] rounded-lg border border-white/5">
                  {showAllSeverities
                    ? "No code flaws detected for attack simulation."
                    : "No high-danger code flaws detected. Use the toggle above to inspect lower severity items."}
                </div>
              )}

              {relevantFindings.map((f) => {
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
                  <div key={fid} className="rounded-xl bg-[#0c0d11] border border-white/10 hover:border-violet-500/30 transition-all p-4 space-y-3 shadow-md">
                    {/* Finding Header */}
                    <div className="flex items-center justify-between gap-3 flex-wrap border-b border-white/5 pb-2.5">
                      <div className="flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0" />
                        <div>
                          <span className="text-xs font-mono font-bold text-[#f4f4f8]">
                            Code Issue: {f.title || f.rule_id || fid}
                          </span>
                          <span className="ml-2 text-[10px] font-mono text-[#8e8e9a] bg-white/5 px-2 py-0.5 rounded">
                            File: {f.file} (Line {f.line || f.line_number})
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded border ${
                          String(f.severity).toLowerCase() === "critical"
                            ? "bg-red-500/15 text-red-400 border-red-500/30"
                            : "bg-orange-500/15 text-orange-400 border-orange-500/30"
                        }`}>
                          {f.severity} DANGER
                        </span>
                        {onViewTrace && (
                          <button
                            onClick={() => onViewTrace(fid)}
                            className="text-[9.5px] font-mono font-bold text-violet-300 hover:text-violet-200 underline decoration-dotted underline-offset-2"
                            title="Inspect full AI trace logs"
                          >
                            Full AI Trace →
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Hacker Attack Story (Layman Stepper) */}
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-[10.5px] font-sans text-[#8e8e9a] font-bold">
                        <span className="flex items-center gap-1.5 text-[#f4f4f8]">
                          ⚡ Hacker Attack Path (Step-by-Step):
                        </span>
                        {exploitScore !== null && !isNaN(exploitScore) && (
                          <span className="flex items-center gap-1.5">
                            Hacker Success Chance:
                            <b className={`font-mono text-xs ${exploitScore > 60 ? "text-red-400" : "text-amber-300"}`}>
                              {exploitScore}% ({exploitScore > 60 ? "Easy to Attack" : "Moderate Effort"})
                            </b>
                          </span>
                        )}
                      </div>

                      {path ? (
                        <div className="p-3.5 rounded-xl bg-[#12131a] border border-violet-500/20 space-y-3">
                          {/* 3 Layman Steps Grid */}
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 text-[11px] font-sans">
                            {/* Step 1: Entry Point */}
                            <div className="p-2.5 rounded-lg bg-white/4 border border-white/5 space-y-1">
                              <div className="flex items-center gap-1.5 text-sky-400 text-[10px] font-mono font-bold uppercase">
                                <Globe className="w-3.5 h-3.5 shrink-0" />
                                <span>Step 1: Where Hacker Enters</span>
                              </div>
                              <div className="text-[#f4f4f8] font-semibold text-[11px] truncate" title={path.entry_point}>
                                {path.entry_point}
                              </div>
                              <p className="text-[9.5px] text-[#8e8e9a]">Public web page or API link accessible on the internet.</p>
                            </div>

                            {/* Step 2: Attack Vector */}
                            <div className="p-2.5 rounded-lg bg-white/4 border border-white/5 space-y-1">
                              <div className="flex items-center gap-1.5 text-amber-400 text-[10px] font-mono font-bold uppercase">
                                <Zap className="w-3.5 h-3.5 shrink-0" />
                                <span>Step 2: How They Trick Code</span>
                              </div>
                              <div className="text-amber-300 font-semibold text-[11px] truncate" title={path.attack_vector}>
                                {path.attack_vector}
                              </div>
                              <p className="text-[9.5px] text-[#8e8e9a]">Sends malformed or malicious data to fool the app.</p>
                            </div>

                            {/* Step 3: Target File */}
                            <div className="p-2.5 rounded-lg bg-white/4 border border-white/5 space-y-1">
                              <div className="flex items-center gap-1.5 text-violet-300 text-[10px] font-mono font-bold uppercase">
                                <Target className="w-3.5 h-3.5 shrink-0" />
                                <span>Step 3: What Breaks</span>
                              </div>
                              <div className="text-violet-300 font-semibold text-[11px] truncate" title={path.target_file}>
                                {path.target_file}
                              </div>
                              <p className="text-[9.5px] text-[#8e8e9a]">The exact file line where the app succumbs to the attack.</p>
                            </div>
                          </div>

                          {/* Progress Meter */}
                          {exploitScore !== null && !isNaN(exploitScore) && (
                            <div className="space-y-1 pt-1">
                              <div className="flex justify-between text-[9.5px] font-mono text-[#8e8e9a]">
                                <span>Hacker Risk Gauge</span>
                                <span>{exploitScore}% Risk</span>
                              </div>
                              <div className="w-full h-2 rounded-full bg-white/5 overflow-hidden">
                                <div
                                  className="h-full bg-gradient-to-r from-amber-500 to-red-500 rounded-full transition-all"
                                  style={{ width: `${Math.min(100, Math.max(10, exploitScore))}%` }}
                                />
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div className="p-3 rounded-lg bg-[#12131a] border border-white/5 flex items-center gap-2.5 text-[11px] font-sans text-[#8e8e9a]">
                          <Info className="w-4 h-4 text-sky-400 shrink-0" />
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
                        <div className="flex items-center gap-1.5 text-[9.5px] font-sans text-[#8e8e9a] flex-wrap pt-1 border-t border-white/5">
                          <span className="text-[#f4f4f8] font-bold uppercase mr-1">Verification History:</span>
                          {hops.map((hop, idx) => (
                            <React.Fragment key={idx}>
                              {idx > 0 && <ArrowRight className="w-3 h-3 text-[#5c5c68]" />}
                              <span className="px-2 py-0.5 rounded bg-white/5 text-[#f4f4f8] border border-white/5 flex items-center gap-1 font-mono text-[9px]">
                                <span>{hop.icon}</span>
                                <span>{hop.label}</span>
                              </span>
                            </React.Fragment>
                          ))}
                        </div>
                      );
                    })()}

                    {/* AI Proposed Fix Diff */}
                    <div className="pt-2 border-t border-white/5">
                      {patch ? (
                        <PatchDiffViewer patch={patch} validation={validation} />
                      ) : (
                        <div className="text-[10.5px] font-sans text-[#8e8e9a] italic">
                          No automatic code fix generated yet for this item.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AIThreatAnalysisSection;
