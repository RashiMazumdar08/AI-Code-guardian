"use client";

import React from "react";
import { Bot, Database, BookText, Crosshair, GitMerge, Wrench, ShieldCheck } from "lucide-react";
import type { AgenticScanGraph, CuratedState, NodeRuntime } from "../types";

/**
 * Replaces the deterministic triage funnel on the Agentic Scan tab only
 * (that funnel -- Total Scan Alerts / Reachable & Exploitable / High
 * Priority / Immediate Risk -- is a deterministic-scan concept and stays
 * in IDE Workspace, unchanged). Every number here is real
 * AgentWorkflowState / SSE-derived state, never a placeholder -- it just
 * reads as 0 until a run produces something.
 */
function Card({ icon: Icon, label, value, colorClass }: {
  icon: React.ComponentType<any>; label: string; value: React.ReactNode; colorClass?: string;
}) {
  return (
    <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3 flex-1 min-w-[130px]">
      <div className="flex items-center gap-1.5 mb-1">
        <Icon className="w-3 h-3 text-[#8e8e9a]" />
        <span className="text-[8.5px] font-mono uppercase tracking-wider text-[#8e8e9a]">{label}</span>
      </div>
      <div className={`text-lg font-mono font-bold ${colorClass || "text-[#f4f4f8]"}`}>{value}</div>
    </div>
  );
}

export function IntelligenceDashboard({
  state, nodeRuntime, graph, hasRun,
}: {
  state: CuratedState;
  nodeRuntime: Record<string, NodeRuntime>;
  graph: AgenticScanGraph;
  hasRun: boolean;
}) {
  const totalAgents = graph.nodes.length;
  const completedAgents = Object.values(nodeRuntime).filter((r) => r.status === "COMPLETED").length;
  const evidenceCount = (state.evidence || []).length;
  const businessViolations = (state.business_violations || []).length;
  const attackPaths = (state.attack_paths || []).length;
  const correlatedRisks = state.correlated_findings?.total_correlated ?? 0;
  const patchesGenerated = (state.patches || []).length;
  const patchesValidated = state.validation_report?.passed_count ?? 0;

  return (
    <div className="rounded-xl bg-[#12131a] border border-white/8 p-4">
      <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-3">Intelligence Dashboard</div>
      {!hasRun ? (
        <div className="text-[10px] font-mono text-[#5c5c68] text-center py-3">Awaiting analysis — run an agentic analysis above to populate.</div>
      ) : (
        <div className="flex flex-wrap gap-2.5">
          <Card icon={Bot} label="Agents Executed" value={`${completedAgents} / ${totalAgents}`} colorClass="text-[#ff5400]" />
          <Card icon={Database} label="Evidence Objects" value={evidenceCount} />
          <Card icon={BookText} label="Business Violations" value={businessViolations} colorClass={businessViolations > 0 ? "text-amber-400" : undefined} />
          <Card icon={Crosshair} label="Attack Paths" value={attackPaths} colorClass={attackPaths > 0 ? "text-red-400" : undefined} />
          <Card icon={GitMerge} label="Correlated Risks" value={correlatedRisks} />
          <Card icon={Wrench} label="Patches Generated" value={patchesGenerated} />
          <Card icon={ShieldCheck} label="Patches Validated" value={patchesValidated} colorClass="text-emerald-400" />
        </div>
      )}
    </div>
  );
}

export default IntelligenceDashboard;
