"use client";

import React from "react";
import { ArrowRight } from "lucide-react";
import type { CuratedState } from "../types";

const REACHABILITY_COLOR: Record<string, string> = {
  DIRECT: "text-red-400 bg-red-500/15",
  INDIRECT: "text-amber-400 bg-amber-500/15",
};

/**
 * Attack chains rendered exactly from ThreatSimulationAgent's real output
 * (guardian/agents/threat_simulation/agent.py) -- entry_point,
 * attack_vector, target_file are the actual fields it produces; this
 * panel never invents intermediate hops that aren't in the data.
 */
export function ThreatPanel({ state }: { state: CuratedState }) {
  const paths = state.attack_paths || [];
  const threatCtx = state.threat_context || {};
  const findingsById = new Map((state.findings || []).map((f) => [f.finding_id, f]));

  if (paths.length === 0) {
    return (
      <div className="text-[11px] font-mono text-[#5c5c68] text-center py-10">
        No attack paths modeled yet (no findings to simulate against, or ThreatSimulationAgent hasn't run).
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {(threatCtx.privilege_escalation_risk || threatCtx.data_exposure_risk) && (
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3 flex flex-wrap gap-4 text-[10px] font-mono">
          <span className="text-[#8e8e9a]">Privilege escalation risk: <b className="text-[#f4f4f8]">{threatCtx.privilege_escalation_risk}</b></span>
          <span className="text-[#8e8e9a]">Data exposure risk: <b className="text-[#f4f4f8]">{threatCtx.data_exposure_risk}</b></span>
          <span className="text-[#8e8e9a]">Business impact: <b className="text-[#f4f4f8]">{threatCtx.business_impact}</b></span>
        </div>
      )}
      {paths.map((p, i) => {
        const finding = findingsById.get(p.finding_id);
        return (
          <div key={`${p.finding_id}-${i}`} className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
            <div className="flex items-center justify-between gap-2 mb-2">
              <span className="text-[11px] font-mono font-semibold text-[#f4f4f8]">{p.title || `Attack Chain ${i + 1}`}</span>
              <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${REACHABILITY_COLOR[p.reachability] || "text-[#8e8e9a] bg-white/8"}`}>
                {p.reachability}
              </span>
            </div>
            <div className="flex items-center gap-2 text-[10px] font-mono text-[#f4f4f8] flex-wrap">
              <span className="px-2 py-1 rounded bg-white/6">{p.entry_point}</span>
              <ArrowRight className="w-3 h-3 text-[#5c5c68]" />
              <span className="px-2 py-1 rounded bg-white/6 text-[#8e8e9a]">{p.attack_vector}</span>
              <ArrowRight className="w-3 h-3 text-[#5c5c68]" />
              <span className="px-2 py-1 rounded bg-[#ff5400]/10 text-[#ff5400]">{p.target_file}</span>
            </div>
            <div className="flex items-center gap-4 mt-2 text-[9px] font-mono text-[#8e8e9a]">
              <span>exploitability: <b className="text-[#f4f4f8]">{typeof p.exploitability === "number" ? p.exploitability.toFixed(2) : p.exploitability}</b></span>
              <span>finding: <b className="text-[#f4f4f8]">{p.finding_id}</b>{finding ? ` (${finding.rule_id})` : ""}</span>
              <span>evidence: <b className="text-[#f4f4f8]">{p.evidence_id || "—"}</b></span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default ThreatPanel;
