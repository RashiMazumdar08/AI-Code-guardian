"use client";

import React, { useState } from "react";
import { GRAPH_LABELS } from "../types";
import type { AgenticAnalysisResult, AgenticScanGraph, NodeRuntime } from "../types";

const STATUS_COLOR: Record<string, string> = {
  WAITING: "text-[#8e8e9a] bg-white/8",
  RUNNING: "text-[#ff5400] bg-[#ff5400]/12",
  COMPLETED: "text-emerald-400 bg-emerald-500/12",
  FAILED: "text-red-400 bg-red-500/12",
  SKIPPED: "text-[#5c5c68] bg-white/5",
};

export function ExecutionPanel({
  result, nodeRuntime, graph,
}: {
  /** AgenticAnalysisResult.execution -- see types.ts. Null until the first
   * state.snapshot event arrives (before any agent has started). */
  result: AgenticAnalysisResult | null;
  nodeRuntime: Record<string, NodeRuntime>;
  graph?: AgenticScanGraph;
}) {
  const execution = result?.execution;
  const trace = execution?.agent_trace || [];
  const traceByAgent = new Map(trace.map((t) => [t.agent_name, t]));
  const completed = execution?.completed_agents || [];
  const pending = execution?.pending_agents || [];
  const plan = execution?.execution_plan;
  const [tableOpen, setTableOpen] = useState(true);

  // Every node in the real graph topology, not just the ones that have
  // finished -- so WAITING agents show up too (per the Agent Execution
  // Summary table), matching what the live graph above is showing.
  const nodeOrder = graph?.nodes || Object.keys(nodeRuntime);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Current Agent</div>
          <div className="text-sm font-mono font-bold text-[#ff5400]">{execution?.active_agent || "—"}</div>
          <div className="text-[9px] font-mono text-[#8e8e9a] mt-0.5 truncate">{execution?.current_task || ""}</div>
        </div>
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Completed</div>
          <div className="text-sm font-mono font-bold text-emerald-400">{completed.length} agent(s)</div>
          <div className="text-[9px] font-mono text-[#8e8e9a] mt-0.5 truncate">{completed.join(", ") || "—"}</div>
        </div>
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Pending</div>
          <div className="text-sm font-mono font-bold text-[#8e8e9a]">{pending.length} agent(s)</div>
          <div className="text-[9px] font-mono text-[#8e8e9a] mt-0.5 truncate">{pending.join(", ") || "—"}</div>
        </div>
      </div>

      {plan && (
        <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Execution Plan (PlannerAgent)</div>
          <div className="text-[10px] font-mono text-[#f4f4f8]">
            priority=<span className="text-[#ff5400]">{plan.priority}</span> · confidence=
            <span className="text-[#ff5400]">{plan.confidence}</span> · order=
            <span className="text-[#8e8e9a]">{plan.agent_order.join(" → ")}</span>
          </div>
          <div className="text-[10px] font-mono text-[#8e8e9a] mt-1">{plan.reason}</div>
        </div>
      )}

      <div className="rounded-lg bg-[#0c0d11] border border-white/8 overflow-hidden">
        <button
          onClick={() => setTableOpen((v) => !v)}
          className="w-full flex items-center justify-between px-3 py-2 border-b border-white/8 text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] hover:text-[#f4f4f8]"
        >
          <span>{tableOpen ? "▾" : "▸"} Agent Execution Summary</span>
          <span className="text-[#5c5c68] normal-case">{nodeOrder.length} node(s) in this run's graph</span>
        </button>
        {tableOpen && (
          <div className="overflow-x-auto">
            <table className="w-full text-[10px] font-mono">
              <thead>
                <tr className="text-[#8e8e9a] border-b border-white/8">
                  <th className="text-left px-3 py-1.5">Agent</th>
                  <th className="text-left px-3 py-1.5">Status</th>
                  <th className="text-left px-3 py-1.5">Time</th>
                  <th className="text-left px-3 py-1.5">Tools Used</th>
                  <th className="text-left px-3 py-1.5">Evidence IDs</th>
                  <th className="text-left px-3 py-1.5">Result</th>
                </tr>
              </thead>
              <tbody>
                {nodeOrder.map((agent) => {
                  const t = traceByAgent.get(agent);
                  const runtime = nodeRuntime[agent];
                  const status = runtime?.status || "WAITING";
                  return (
                    <tr key={agent} className="border-b border-white/5 last:border-0">
                      <td className="px-3 py-1.5 text-[#f4f4f8] font-semibold">{GRAPH_LABELS[agent] || agent}</td>
                      <td className="px-3 py-1.5">
                        <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${STATUS_COLOR[status] || STATUS_COLOR.WAITING}`}>
                          {status}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-[#8e8e9a]">{t ? `${(t.execution_time * 1000).toFixed(1)}ms` : (runtime?.duration ? `${(runtime.duration * 1000).toFixed(1)}ms` : "—")}</td>
                      <td className="px-3 py-1.5 text-[#8e8e9a] max-w-[160px] truncate">{t ? (t.tools_used || []).join(", ") || "—" : "—"}</td>
                      <td className="px-3 py-1.5 text-[#8e8e9a] max-w-[160px] truncate">{t ? (t.evidence_ids || []).join(", ") || "—" : "—"}</td>
                      <td className="px-3 py-1.5">
                        {status === "SKIPPED" ? (
                          <span className="text-[#5c5c68]">{runtime?.reason || "skipped"}</span>
                        ) : t?.result?.status === "error" ? (
                          <span className="text-red-400">error: {t.errors?.[0] || t.result?.error}</span>
                        ) : t ? (
                          <span className="text-emerald-400">success</span>
                        ) : (
                          <span className="text-[#5c5c68]">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default ExecutionPanel;
