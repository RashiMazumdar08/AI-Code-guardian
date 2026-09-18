"use client";

import React from "react";
import { CheckCircle2, XCircle, Clock3 } from "lucide-react";
import type { CuratedState } from "../types";

function StageBadge({ ok, label, pending }: { ok: boolean; label: string; pending?: boolean }) {
  if (pending) {
    return (
      <span className="inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-white/8 text-[#8e8e9a]">
        <Clock3 className="w-2.5 h-2.5" /> {label}: pending
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${ok ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"}`}>
      {ok ? <CheckCircle2 className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />} {label}: {ok ? "yes" : "no"}
    </span>
  );
}

export function RemediationPanel({ state }: { state: CuratedState }) {
  const patches = state.patches || [];
  const validationByPatch = new Map((state.validation_results || []).map((v) => [v.patch_id, v]));

  if (patches.length === 0) {
    return <div className="text-[11px] font-mono text-[#5c5c68] text-center py-10">No patches generated (no findings, or PatchGenerationAgent hasn't run yet).</div>;
  }

  return (
    <div className="space-y-3">
      {state.validation_report && (
        <div className="text-[9px] font-mono text-[#8e8e9a]">
          {state.validation_report.total_validated} patch(es) validated · {state.validation_report.passed_count} passed · {state.validation_report.rejected_count} rejected
        </div>
      )}
      {patches.map((p) => {
        const v = validationByPatch.get(p.patch_id);
        const pending = p.validation_status === "PENDING" && !v;
        const validated = p.validation_status === "PASSED";
        return (
          <div key={p.patch_id} className="rounded-lg bg-[#0c0d11] border border-white/8 p-3">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <div className="text-[11px] font-mono font-semibold text-[#f4f4f8]">{p.affected_file}:{p.affected_lines}</div>
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-white/8 text-[#8e8e9a]">generated</span>
                <StageBadge ok={!!v?.grounding_passed} label="grounded" pending={pending} />
                {/* Never labeled "validated" unless validation_status is literally PASSED. */}
                <StageBadge ok={validated} label="validated" pending={pending} />
              </div>
            </div>
            <div className="mt-2 grid grid-cols-2 gap-2">
              <div>
                <div className="text-[8.5px] font-mono uppercase text-[#5c5c68] mb-0.5">Original</div>
                <pre className="text-[9.5px] font-mono text-red-300/80 bg-red-500/5 rounded p-2 overflow-x-auto whitespace-pre-wrap">{p.original_snippet}</pre>
              </div>
              <div>
                <div className="text-[8.5px] font-mono uppercase text-[#5c5c68] mb-0.5">Suggested Replacement</div>
                <pre className="text-[9.5px] font-mono text-emerald-300/80 bg-emerald-500/5 rounded p-2 overflow-x-auto whitespace-pre-wrap">{p.suggested_replacement}</pre>
              </div>
            </div>
            <div className="mt-2 text-[10px] font-mono text-[#8e8e9a]">{p.explanation}</div>
            {v && v.issues && v.issues.length > 0 && (
              <div className="mt-2 text-[10px] font-mono text-amber-400">issues: {v.issues.join("; ")}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default RemediationPanel;
