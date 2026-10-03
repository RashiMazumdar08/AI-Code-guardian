"use client";

import React from "react";
import { GRAPH_LABELS } from "../types";
import type { ScanEvent } from "../types";

const TYPE_COLOR: Record<string, string> = {
  "workflow.started": "text-blue-600",
  "workflow.completed": "text-emerald-600",
  "workflow.failed": "text-rose-600",
  "agent.started": "text-blue-600",
  "agent.completed": "text-emerald-600",
  "agent.skipped": "text-slate-400",
  "planner.completed": "text-purple-600",
};

function describeEvent(evt: ScanEvent): string {
  const label = evt.agent ? GRAPH_LABELS[evt.agent] || evt.agent : "";
  switch (evt.type) {
    case "workflow.cloning": return `Cloning ${evt.repo_url}…`;
    case "workflow.cloned": return `Repository ready at ${evt.path}`;
    case "workflow.profiled": return `Profiled: ${evt.primary_language}, ${evt.total_files} files, frameworks: ${(evt.frameworks || []).join(", ") || "none"}`;
    case "workflow.started": return `LangGraph workflow started (mode=${evt.scan_mode})`;
    case "planner.completed": return "PlannerAgent produced the execution plan";
    case "agent.started": return `${label}.started`;
    case "agent.completed": return `${label}.completed (${((evt.duration || 0) * 1000).toFixed(0)}ms, ${evt.status})`;
    case "agent.skipped": return `${label}.skipped — ${evt.reason || ""}`;
    case "workflow.completed": return `Workflow completed — ${evt.total_findings} finding(s), ${evt.total_patches} patch(es)`;
    case "workflow.failed": return `Workflow failed — ${evt.error}`;
    case "stream.end": return "Stream closed";
    default: return evt.type;
  }
}

export function TimelinePanel({ events }: { events: ScanEvent[] }) {
  const visible = events.filter((e) => e.type !== "state.snapshot");
  if (visible.length === 0) {
    return <div className="text-[11px] font-mono text-slate-500 text-center py-10">No events yet.</div>;
  }
  return (
    <div className="rounded-lg bg-white border border-[#DCE5F0] shadow-sm p-3 max-h-[420px] overflow-y-auto">
      <div className="space-y-1.5">
        {visible.map((e, i) => (
          <div key={i} className="flex items-start gap-2 text-[10px] font-mono border-b border-slate-100 pb-1 last:border-0">
            <span className="text-slate-400 shrink-0 w-16">{new Date(e.ts * 1000).toLocaleTimeString()}</span>
            <span className={`font-semibold shrink-0 ${TYPE_COLOR[e.type] || "text-slate-600"}`}>{e.type}</span>
            <span className="text-slate-600 truncate">{describeEvent(e)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default TimelinePanel;
