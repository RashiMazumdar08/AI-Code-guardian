"use client";

import React from "react";
import { GRAPH_LABELS } from "../types";
import type { ScanEvent } from "../types";

const TYPE_COLOR: Record<string, string> = {
  "workflow.started": "text-sky-400",
  "workflow.completed": "text-emerald-400",
  "workflow.failed": "text-red-400",
  "agent.started": "text-[#ff5400]",
  "agent.completed": "text-emerald-400",
  "agent.skipped": "text-[#5c5c68]",
  "planner.completed": "text-purple-400",
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
    return <div className="text-[11px] font-mono text-[#5c5c68] text-center py-10">No events yet.</div>;
  }
  return (
    <div className="rounded-lg bg-[#0c0d11] border border-white/8 p-3 max-h-[420px] overflow-y-auto">
      <div className="space-y-1.5">
        {visible.map((e, i) => (
          <div key={i} className="flex items-start gap-2 text-[10px] font-mono">
            <span className="text-[#5c5c68] shrink-0 w-16">{new Date(e.ts * 1000).toLocaleTimeString()}</span>
            <span className={`font-semibold shrink-0 ${TYPE_COLOR[e.type] || "text-[#8e8e9a]"}`}>{e.type}</span>
            <span className="text-[#8e8e9a] truncate">{describeEvent(e)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default TimelinePanel;
