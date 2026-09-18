"use client";

import React, { useState } from "react";
import { Play, Loader2, AlertOctagon } from "lucide-react";
import type { BusinessIntentFinding, CorrelatedChainItem, WorkflowStatus } from "../agentic-scan/types";

export interface AIBusinessImpactSectionProps {
  violations: BusinessIntentFinding[];
  /** Chains from correlated_findings whose business_criticality is
   * HIGH/CRITICAL -- "correlated risks that touch business rules", using
   * the real classification the Business Agent set, not an invented one. */
  businessCriticalChains: CorrelatedChainItem[];
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  agenticScanId?: string | null;
  sourceScanId?: string | null;
  onRunAgentic: () => void;
  /** Deep link: jumps to Security with this chain's underlying finding_id
   * selected -- a correlated risk always traces back to one real
   * deterministic finding (guardian/evidence/correlation.py). Optional --
   * rows render as plain text if not provided. */
  onViewFinding?: (findingId: string) => void;
}

const STATUS_LABEL: Record<string, { label: string; cls: string }> = {
  VIOLATION: { label: "Violated", cls: "text-red-400 bg-red-500/15" },
  POTENTIAL_VIOLATION: { label: "Violated", cls: "text-red-400 bg-red-500/15" },
};

/**
 * Inline enrichment section for the Business Intent tab. `violations` is
 * exactly state.business_violations (guardian/agents/business/agent.py) --
 * the SAME agent-produced list the Agentic Scan tab's Business Impact tab
 * and Intelligence Dashboard "Business Violations" count read from, not a
 * re-derived copy. The business intent data model has no per-violation
 * finding_id or severity field (it evaluates code AST behavior, not SAST
 * findings), so this deliberately shows the real fields that DO exist --
 * match confidence (`score`) and the file/function `evidence` string --
 * rather than fabricating a finding link or a severity number.
 */
export function AIBusinessImpactSection({
  violations, businessCriticalChains, workflowStatus, hasRunForThisScan,
  agenticScanId, sourceScanId, onRunAgentic, onViewFinding,
}: AIBusinessImpactSectionProps) {
  // Section 4: collapsed by default so deterministic rule results stay primary.
  const [open, setOpen] = useState(false);
  const isRunningForThisTarget = (workflowStatus === "starting" || workflowStatus === "running");

  return (
    <div className="rounded-xl bg-[#12131a] border border-violet-500/25 overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3 px-4 py-3 hover:bg-white/4 transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/25">AI</span>
          <span className="text-[11px] font-mono font-bold text-[#f4f4f8]">AI Business Impact Analysis</span>
          <span className="text-[9px] font-mono text-[#8e8e9a]">(powered by LangGraph Business Agent)</span>
        </div>
        <span className="text-[10px] font-mono text-[#5c5c68]">{open ? "▾" : "▸"}</span>
      </button>

      {open && (
        <div className="px-4 pb-4 border-t border-violet-500/15">
          {!hasRunForThisScan && !isRunningForThisTarget && (
            <div className="pt-4 text-center py-6">
              <p className="text-[10px] font-mono text-[#8e8e9a] mb-3">
                Run Agentic Analysis to see AI-generated business impact analysis for this codebase.
              </p>
              <button
                onClick={onRunAgentic}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-mono font-bold uppercase tracking-wide bg-violet-500/15 text-violet-300 border border-violet-500/30 hover:bg-violet-500/25 transition-colors"
              >
                <Play className="w-3 h-3" /> Run Agentic Analysis
              </button>
            </div>
          )}

          {isRunningForThisTarget && (
            <div className="pt-4 flex items-center gap-2 text-[10px] font-mono text-violet-300 py-6 justify-center">
              <Loader2 className="w-3.5 h-3.5 animate-spin" /> Business Agent analyzing…
            </div>
          )}

          {hasRunForThisScan && !isRunningForThisTarget && (
            <div className="pt-4 space-y-4">
              <div className="text-[8.5px] font-mono text-[#5c5c68]">
                agentic run: {agenticScanId || "—"} · grounded in deterministic scan: {sourceScanId || "—"}
              </div>

              <div>
                <div className="flex items-center gap-2 mb-2">
                  <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] font-bold">
                    Business Violations ({violations.length})
                  </span>
                </div>
                {violations.length === 0 ? (
                  <div className="text-[10px] font-mono text-[#5c5c68] text-center py-4 rounded-lg bg-[#0c0d11] border border-white/8">
                    No business-impact violations flagged by the Business Agent.
                  </div>
                ) : (
                  <div className="rounded-lg bg-[#0c0d11] border border-white/8 overflow-hidden overflow-x-auto">
                    <table className="w-full text-[10px] font-mono">
                      <thead>
                        <tr className="text-[#8e8e9a] border-b border-white/8">
                          <th className="text-left px-3 py-1.5">Requirement</th>
                          <th className="text-left px-3 py-1.5">Status</th>
                          <th className="text-left px-3 py-1.5">Match Confidence</th>
                          <th className="text-left px-3 py-1.5">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {violations.map((v, i) => {
                          const s = STATUS_LABEL[v.status] || { label: v.status, cls: "text-[#8e8e9a] bg-white/8" };
                          return (
                            <tr key={`${v.rule_id}-${i}`} className="border-b border-white/5 last:border-0 align-top">
                              <td className="px-3 py-1.5 text-[#f4f4f8]">
                                <div className="font-semibold whitespace-nowrap">{v.rule_id}</div>
                                <div className="text-[#8e8e9a] max-w-[280px]">{v.why || v.what || v.rule}</div>
                              </td>
                              <td className="px-3 py-1.5">
                                <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${s.cls}`}>{s.label}</span>
                              </td>
                              <td className="px-3 py-1.5 text-[#8e8e9a]">
                                {typeof v.score === "number" ? `${Math.round(v.score * 100)}%` : "—"}
                              </td>
                              <td className="px-3 py-1.5 text-[#8e8e9a] max-w-[220px] truncate">{v.evidence || "—"}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              <div>
                <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] font-bold mb-2">
                  Correlated Risks Touching Business-Critical Assets ({businessCriticalChains.length})
                </div>
                {businessCriticalChains.length === 0 ? (
                  <div className="text-[10px] font-mono text-[#5c5c68] text-center py-4 rounded-lg bg-[#0c0d11] border border-white/8">
                    No correlated risks flagged against business-critical assets.
                  </div>
                ) : (
                  <div className="space-y-1.5">
                    {businessCriticalChains.slice(0, 5).map((c) => (
                      <div key={c.chain_id} className="flex items-center justify-between gap-2 text-[10px] font-mono px-3 py-2 rounded-lg bg-[#0c0d11] border border-white/8">
                        <span className="text-[#f4f4f8]">
                          {onViewFinding ? (
                            <button
                              onClick={() => onViewFinding(c.finding_id)}
                              className="hover:text-[#ff5400] underline decoration-dotted underline-offset-2 transition-colors"
                              title="View this chain's underlying finding in Security"
                            >
                              {c.title || c.finding_id}
                            </button>
                          ) : (
                            c.title || c.finding_id
                          )} <span className="text-[#8e8e9a]">→ {c.target_asset}</span>
                        </span>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-red-500/15 text-red-400">{c.business_criticality}</span>
                          {(c.policy_violations || []).length > 0 && (
                            <span className="text-[8.5px] text-[#8e8e9a]">{(c.policy_violations || []).length} policy violation(s)</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default AIBusinessImpactSection;
