"use client";

import React, { useState } from "react";
import { GRAPH_LABELS } from "../types";
import type { AgenticAnalysisResult, AgenticScanGraph, NodeRuntime } from "../types";

const STATUS_COLOR: Record<string, string> = {
  WAITING: "text-slate-600 bg-slate-100 border border-slate-200",
  RUNNING: "text-blue-700 bg-blue-50 border border-blue-200",
  COMPLETED: "text-emerald-700 bg-emerald-50 border border-emerald-200",
  FAILED: "text-rose-700 bg-rose-50 border border-rose-200",
  SKIPPED: "text-slate-500 bg-slate-100",
};

export function ExecutionPanel({
  result, nodeRuntime, graph,
}: {
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

  const nodeOrder = graph?.nodes || Object.keys(nodeRuntime);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">Current Agent</div>
          <div className="text-sm font-mono font-bold text-blue-600">{execution?.active_agent || "—"}</div>
          <div className="text-[9px] font-mono text-slate-500 mt-0.5 truncate">{execution?.current_task || ""}</div>
        </div>
        <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">Completed</div>
          <div className="text-sm font-mono font-bold text-emerald-600">{completed.length} agent(s)</div>
          <div className="text-[9px] font-mono text-slate-500 mt-0.5 truncate">{completed.join(", ") || "—"}</div>
        </div>
        <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">Pending</div>
          <div className="text-sm font-mono font-bold text-slate-600">{pending.length} agent(s)</div>
          <div className="text-[9px] font-mono text-slate-500 mt-0.5 truncate">{pending.join(", ") || "—"}</div>
        </div>
      </div>

      {plan && (
        <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-slate-500 mb-1">Execution Plan (PlannerAgent)</div>
          <div className="text-[10px] font-mono text-[#111827]">
            priority=<span className="text-blue-600 font-bold">{plan.priority}</span> · confidence=
            <span className="text-blue-600 font-bold">{plan.confidence}</span> · order=
            <span className="text-slate-600">{plan.agent_order.join(" → ")}</span>
          </div>
          <div className="text-[10px] font-mono text-slate-500 mt-1">{plan.reason}</div>
        </div>
      )}

      <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm overflow-hidden">
        <button
          onClick={() => setTableOpen((v) => !v)}
          className="w-full flex items-center justify-between px-3 py-2 border-b border-[#DCE5F0] bg-slate-50 text-[9px] font-mono uppercase tracking-wider text-slate-600 hover:text-[#111827]"
        >
          <span>{tableOpen ? "▾" : "▸"} Agent Execution Summary</span>
          <span className="text-slate-500 normal-case">{nodeOrder.length} node(s) in this run's graph</span>
        </button>
        {tableOpen && (
          <div className="overflow-x-auto">
            <table className="w-full text-[10px] font-mono">
              <thead>
                <tr className="text-slate-500 border-b border-[#DCE5F0] bg-slate-50">
                  <th className="text-left px-3 py-1.5 font-semibold">Agent</th>
                  <th className="text-left px-3 py-1.5 font-semibold">Status</th>
                  <th className="text-left px-3 py-1.5 font-semibold">Time</th>
                  <th className="text-left px-3 py-1.5 font-semibold">Tools Used</th>
                  <th className="text-left px-3 py-1.5 font-semibold">Evidence IDs</th>
                  <th className="text-left px-3 py-1.5 font-semibold">Result</th>
                </tr>
              </thead>
              <tbody>
                {nodeOrder.map((agent) => {
                  const t = traceByAgent.get(agent);
                  const runtime = nodeRuntime[agent];
                  const status = runtime?.status || "WAITING";
                  return (
                    <tr key={agent} className="border-b border-slate-100 last:border-0 hover:bg-slate-50/50">
                      <td className="px-3 py-1.5 text-[#111827] font-semibold">{GRAPH_LABELS[agent] || agent}</td>
                      <td className="px-3 py-1.5">
                        <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${STATUS_COLOR[status] || STATUS_COLOR.WAITING}`}>
                          {status}
                        </span>
                      </td>
                      <td className="px-3 py-1.5 text-slate-600">{t ? `${(t.execution_time * 1000).toFixed(1)}ms` : (runtime?.duration ? `${(runtime.duration * 1000).toFixed(1)}ms` : "—")}</td>
                      <td className="px-3 py-1.5 text-slate-600 max-w-[160px] truncate">{t ? (t.tools_used || []).join(", ") || "—" : "—"}</td>
                      <td className="px-3 py-1.5 text-slate-600 max-w-[160px] truncate">{t ? (t.evidence_ids || []).join(", ") || "—" : "—"}</td>
                      <td className="px-3 py-1.5">
                        {status === "SKIPPED" ? (
                          <span className="text-slate-400">{runtime?.reason || "skipped"}</span>
                        ) : t?.result?.status === "error" ? (
                          <span className="text-rose-600 font-semibold">error: {t.errors?.[0] || t.result?.error}</span>
                        ) : t ? (
                          <span className="text-emerald-600 font-semibold">success</span>
                        ) : (
                          <span className="text-slate-400">—</span>
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
