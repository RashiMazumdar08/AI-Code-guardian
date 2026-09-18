"use client";

import React from "react";
import { AlertOctagon, Building2 } from "lucide-react";
import type { CuratedState } from "../types";

const STATUS_LABEL: Record<string, { label: string; cls: string }> = {
  COMPLIANT: { label: "Satisfied", cls: "text-emerald-400 bg-emerald-500/15" },
  VIOLATION: { label: "Violated", cls: "text-red-400 bg-red-500/15" },
  POTENTIAL_VIOLATION: { label: "Violated", cls: "text-red-400 bg-red-500/15" },
  PARTIAL: { label: "Partial", cls: "text-amber-400 bg-amber-500/15" },
  INSUFFICIENT_EVIDENCE: { label: "Unknown", cls: "text-[#8e8e9a] bg-white/8" },
};

/**
 * "Business Impact" (the Business Agent's own output) -- deliberately
 * distinct from the left-nav's deterministic "Business Intent" tab. That
 * tab runs the rule-vs-code compliance check on demand for the whole
 * repository; this panel shows what the LangGraph Business Agent itself
 * produced for THIS agentic run: `state.business_violations` (guardian/
 * agents/business/agent.py's `new_state["business_violations"]`), the same
 * list the Intelligence Dashboard's "Business Violations" count reads from
 * -- never the full pass/fail compliance matrix.
 */
export function BusinessIntentPanel({ state }: { state: CuratedState }) {
  const bi = state.business_intent_results;
  const ctx = state.business_context || {};
  const violations = state.business_violations || [];

  if (!bi || !bi.status) {
    return <div className="text-[11px] font-mono text-[#5c5c68] text-center py-10">Business Agent hasn't reported results yet.</div>;
  }

  if (bi.status !== "SUCCESS") {
    return (
      <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-4">
        <div className="text-[11px] font-mono font-bold text-amber-400">{bi.status}</div>
        <div className="text-[10px] font-mono text-[#8e8e9a] mt-1">{bi.agent_reason || "No business requirements were available to evaluate."}</div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-3 gap-3">
        <div className={`rounded-lg bg-[#0c0d11] border p-3 ${violations.length > 0 ? "border-red-500/25" : "border-white/8"}`}>
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Business Violations</div>
          <div className={`text-sm font-mono font-bold ${violations.length > 0 ? "text-red-400" : "text-emerald-400"}`}>{violations.length}</div>
        </div>
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Business Criticality</div>
          <div className="text-sm font-mono font-bold text-[#f4f4f8]">{ctx.criticality || "—"}</div>
          <div className="text-[9px] font-mono text-[#8e8e9a]">{ctx.data_classification || ""}</div>
        </div>
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Agent Confidence</div>
          <div className="text-sm font-mono font-bold text-[#f4f4f8]">{ctx.confidence ?? "—"}</div>
        </div>
      </div>
      <div className="text-[9px] font-mono text-[#8e8e9a]">
        {bi.total_rules} rule(s) evaluated against {(bi.documents || []).join(", ") || "0 documents"} — {violations.length} flagged as violations.
      </div>

      <div className="rounded-lg bg-[#0c0d11] border border-white/8 overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 border-b border-white/8">
          {violations.length > 0 ? (
            <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
          ) : (
            <Building2 className="w-3.5 h-3.5 text-emerald-400" />
          )}
          <span className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a]">
            Business Agent Violations
          </span>
        </div>
        <table className="w-full text-[10px] font-mono">
          <thead>
            <tr className="text-[#8e8e9a] border-b border-white/8">
              <th className="text-left px-3 py-1.5">Requirement ID</th>
              <th className="text-left px-3 py-1.5">Status</th>
              <th className="text-left px-3 py-1.5">Why</th>
              <th className="text-left px-3 py-1.5">Supporting Evidence</th>
            </tr>
          </thead>
          <tbody>
            {violations.map((v, i) => {
              const s = STATUS_LABEL[v.status] || { label: v.status, cls: "text-[#8e8e9a] bg-white/8" };
              return (
                <tr key={`${v.rule_id}-${i}`} className="border-b border-white/5 last:border-0 align-top">
                  <td className="px-3 py-1.5 text-[#f4f4f8] font-semibold whitespace-nowrap">{v.rule_id}</td>
                  <td className="px-3 py-1.5">
                    <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${s.cls}`}>{s.label}</span>
                  </td>
                  <td className="px-3 py-1.5 text-[#8e8e9a] max-w-[260px]">{v.why || v.what || v.rule}</td>
                  <td className="px-3 py-1.5 text-[#8e8e9a] max-w-[220px] truncate">{v.evidence || "—"}</td>
                </tr>
              );
            })}
            {violations.length === 0 && (
              <tr><td colSpan={4} className="px-3 py-4 text-center text-[#5c5c68]">No business-impact violations flagged by the Business Agent for this run.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default BusinessIntentPanel;
