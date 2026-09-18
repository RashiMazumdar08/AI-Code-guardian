"use client";

import React from "react";
import type { CuratedState } from "../types";

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "text-red-400 bg-red-500/15",
  HIGH: "text-orange-400 bg-orange-500/15",
  MEDIUM: "text-amber-400 bg-amber-500/15",
  LOW: "text-sky-400 bg-sky-500/15",
};

export function FindingsPanel({ state }: { state: CuratedState }) {
  const findings = state.findings || [];
  if (findings.length === 0) {
    return <div className="text-[11px] font-mono text-[#5c5c68] text-center py-10">No findings yet — SecurityAgent / DependencyAgent haven't reported results (or none exist).</div>;
  }
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <div key={f.finding_id} className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${SEV_COLOR[f.severity] || "text-[#8e8e9a] bg-white/8"}`}>
                {f.severity}
              </span>
              <span className="text-[11px] font-mono font-semibold text-[#f4f4f8] truncate">{f.category}</span>
            </div>
            <span className="text-[9px] font-mono text-[#8e8e9a] shrink-0">{f.rule_id}</span>
          </div>
          <div className="text-[10px] font-mono text-[#8e8e9a] mt-1">
            {f.file_path}:{f.line_number} {f.language ? `· ${f.language}` : ""}
          </div>
          {f.recommendation && (
            <div className="text-[10px] font-mono text-[#8e8e9a] mt-1 truncate">↳ {f.recommendation}</div>
          )}
        </div>
      ))}
    </div>
  );
}

export default FindingsPanel;
