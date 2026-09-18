"use client";

import React from "react";
import { X } from "lucide-react";
import { GRAPH_LABELS } from "../types";
import type { AgenticScanGraph, CuratedState, NodeRuntime } from "../types";

/**
 * What each specialist agent actually reads from / writes to
 * AgentWorkflowState, taken directly from each agent's _process() method
 * (guardian/agents/<name>/agent.py) -- not invented. "repository" has no
 * agent implementation (BaseAgent-less structural node in the graph, see
 * guardian/orchestrator/langgraph_flow.py), so it's described accordingly.
 */
const AGENT_IO: Record<string, { reads: string[]; writes: string[] }> = {
  planner: { reads: ["repository_profile", "scan_mode"], writes: ["execution_plan"] },
  repository: { reads: ["repository_profile"], writes: ["repository_context"] },
  security: { reads: ["repository_profile", "findings (pre-seeded from the deterministic scan)", "evidence"], writes: ["findings", "evidence", "security_context"] },
  business: { reads: ["business_context", "findings"], writes: ["business_context", "business_intent_results", "business_violations"] },
  architecture: { reads: ["repository_profile", "repository_context"], writes: ["architecture_context"] },
  dependency: { reads: ["repository_profile", "findings"], writes: ["findings (dependency findings appended)", "dependency_context"] },
  threat_simulation: { reads: ["findings", "evidence", "repository_context", "architecture_context", "business_context"], writes: ["threat_context", "attack_paths", "exploitability"] },
  policy: { reads: ["findings", "policy_context"], writes: ["policy_results", "policy_context"] },
  risk_fusion: { reads: ["findings", "evidence", "business_context", "threat_context", "policy_results", "architecture_context", "agent_trace"], writes: ["risk_scores", "correlated_findings"] },
  patch: { reads: ["findings", "evidence", "threat_context", "business_context", "policy_results"], writes: ["patches", "git_diff", "developer_explanation", "remediation_summary"] },
  validation: { reads: ["patches", "findings", "evidence", "repository_profile"], writes: ["patches (validation_status set)", "validation_results", "validation_report", "grounding_report", "validation_confidence"] },
};

function findingsAffected(agentKey: string, state: CuratedState): { label: string; value: React.ReactNode } | null {
  switch (agentKey) {
    case "security":
      return { label: "Findings in shared evidence store", value: (state.findings || []).length };
    case "business":
      return { label: "Business-intent violations", value: (state.business_violations || []).length };
    case "dependency":
      return { label: "Vulnerable dependencies", value: state.dependency_context?.vulnerable_dependencies_count ?? "—" };
    case "threat_simulation":
      return { label: "Attack paths modeled", value: (state.attack_paths || []).length };
    case "policy":
      return { label: "Policy violations", value: state.policy_results?.total_violations ?? "—" };
    case "risk_fusion":
      return { label: "Correlated risks", value: state.correlated_findings?.total_correlated ?? "—" };
    case "patch":
      return { label: "Patches proposed", value: (state.patches || []).length };
    case "validation":
      return { label: "Patches validated (passed)", value: state.validation_report?.passed_count ?? "—" };
    default:
      return null;
  }
}

export function DetailPanel({
  agentKey, state, runtime, graph, onClose,
}: {
  agentKey: string;
  state: CuratedState;
  runtime?: NodeRuntime;
  graph?: AgenticScanGraph;
  onClose: () => void;
}) {
  const trace = (state.agent_trace || []).find((t) => t.agent_name === agentKey);
  const label = GRAPH_LABELS[agentKey] || agentKey;
  const io = AGENT_IO[agentKey];
  const affected = findingsAffected(agentKey, state);
  const downstream = (graph?.edges || []).filter(([source]) => source === agentKey).map(([, target]) => target);

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-end bg-black/40 backdrop-blur-sm" onClick={onClose}>
      <div
        className="h-full w-full max-w-md bg-[#0c0d11] border-l border-white/10 p-5 overflow-y-auto animate-in slide-in-from-right duration-200"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a]">Agent Detail</div>
            <div className="text-lg font-mono font-bold text-[#f4f4f8]">{label}</div>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white/8 text-[#8e8e9a]">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="rounded-lg bg-[#12131a] border border-white/8 p-3 mb-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Status</div>
          <div className="text-sm font-mono font-bold text-[#ff5400]">{runtime?.status || "WAITING"}</div>
          {runtime?.reason && <div className="text-[10px] font-mono text-[#8e8e9a] mt-1">{runtime.reason}</div>}
          {runtime?.error && <div className="text-[10px] font-mono text-red-400 mt-1">error: {runtime.error}</div>}
        </div>

        {io && (
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
              <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Input State Read</div>
              <ul className="text-[10px] font-mono text-[#f4f4f8] space-y-0.5">
                {io.reads.map((r) => <li key={r}>· {r}</li>)}
              </ul>
            </div>
            <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
              <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Output State Written</div>
              <ul className="text-[10px] font-mono text-[#f4f4f8] space-y-0.5">
                {io.writes.map((w) => <li key={w}>· {w}</li>)}
              </ul>
            </div>
          </div>
        )}

        {affected && (
          <div className="rounded-lg bg-[#12131a] border border-white/8 p-3 mb-3">
            <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">{affected.label}</div>
            <div className="text-[13px] font-mono font-bold text-[#f4f4f8]">{affected.value}</div>
          </div>
        )}

        <div className="rounded-lg bg-[#12131a] border border-white/8 p-3 mb-3">
          <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Downstream Consumers</div>
          <div className="text-[11px] font-mono text-[#f4f4f8]">
            {downstream.length > 0 ? downstream.map((d) => GRAPH_LABELS[d] || d).join(", ") : "— (terminal node in this run's execution order)"}
          </div>
        </div>

        {trace ? (
          <div className="space-y-3">
            <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
              <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Task</div>
              <div className="text-[11px] font-mono text-[#f4f4f8]">{trace.current_task}</div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
                <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Execution Time</div>
                <div className="text-[11px] font-mono text-[#f4f4f8]">{(trace.execution_time * 1000).toFixed(1)}ms</div>
              </div>
              <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
                <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Confidence</div>
                <div className="text-[11px] font-mono text-[#f4f4f8]">{trace.confidence}</div>
              </div>
            </div>
            <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
              <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Tools Used</div>
              <div className="text-[11px] font-mono text-[#f4f4f8]">{(trace.tools_used || []).join(", ") || "—"}</div>
            </div>
            <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
              <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Evidence IDs Generated</div>
              <div className="text-[11px] font-mono text-[#f4f4f8]">{(trace.evidence_ids || []).join(", ") || "—"}</div>
            </div>
            <div className="rounded-lg bg-[#12131a] border border-white/8 p-3">
              <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a] mb-1">Result</div>
              {trace.result?.status === "error" ? (
                <div className="text-[11px] font-mono text-red-400">
                  error — {trace.errors?.join("; ") || trace.result?.error}
                </div>
              ) : (
                <div className="text-[11px] font-mono text-emerald-400">success</div>
              )}
            </div>
          </div>
        ) : (
          <div className="text-[11px] font-mono text-[#5c5c68] text-center py-8">
            {runtime?.status === "SKIPPED"
              ? "This agent was not executed for this scan (see reason above)."
              : "This agent hasn't produced a trace record yet."}
          </div>
        )}
      </div>
    </div>
  );
}

export default DetailPanel;
