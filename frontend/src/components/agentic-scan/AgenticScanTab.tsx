"use client";

import React, { useEffect, useMemo, useState } from "react";
import { ReactFlow, Background, BackgroundVariant, Controls, Node, Edge } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  GitBranch, Play, Loader2, AlertTriangle, CheckCircle2, ListTree,
  Radar, Gauge, Clock, LayoutDashboard,
  RefreshCw, Info, ShieldOff, ArrowRight,
} from "lucide-react";

import { getLayoutedElements } from "../mindmap/layout";
import { agenticNodeTypes } from "./nodes";
import { GRAPH_LABELS } from "./types";
import type {
  AgentStatus, AgenticAnalysisResult, AgenticScanGraph, AgenticSummary, CuratedState,
  DeterministicBaseline, DeterministicScanSummary, NodeRuntime, ScanEvent, WorkflowStatus,
} from "./types";
import type { StartAgenticScanParams } from "./useAgenticScan";

import IntelligenceDashboard from "./panels/IntelligenceDashboard";
import OverviewPanel from "./panels/OverviewPanel";
import ExecutionPanel from "./panels/ExecutionPanel";
import DetailPanel from "./panels/DetailPanel";
import EvidencePanel from "./panels/EvidencePanel";
import RiskPanel from "./panels/RiskPanel";
import TimelinePanel from "./panels/TimelinePanel";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const SUB_TABS = [
  { id: "overview", label: "Overview", icon: LayoutDashboard },
  { id: "execution", label: "Execution", icon: ListTree },
  { id: "risk", label: "Risk Fusion", icon: Gauge },
  { id: "evidence", label: "Evidence", icon: Radar },
  { id: "timeline", label: "Timeline", icon: Clock },
] as const;

type SubTab = typeof SUB_TABS[number]["id"];

const STATUS_LEGEND: { status: AgentStatus; color: string }[] = [
  { status: "WAITING", color: "bg-slate-400" },
  { status: "RUNNING", color: "bg-blue-600" },
  { status: "COMPLETED", color: "bg-emerald-600" },
  { status: "FAILED", color: "bg-rose-600" },
  { status: "SKIPPED", color: "bg-slate-300" },
];

function edgeColor(sourceStatus?: AgentStatus, targetStatus?: AgentStatus): string {
  if (targetStatus === "FAILED") return "rgba(244,63,94,0.95)"; // bright rose
  if (sourceStatus === "COMPLETED" && targetStatus === "COMPLETED") return "rgba(52,211,153,0.95)"; // bright emerald
  if (sourceStatus === "COMPLETED" && targetStatus === "SKIPPED") return "rgba(148,163,184,0.6)";
  return "rgba(96,165,250,0.85)"; // vibrant sky blue for visible flow
}

function formatTimestamp(unixSeconds?: number): string {
  if (!unixSeconds) return "unknown time";
  try {
    return new Date(unixSeconds * 1000).toLocaleString();
  } catch {
    return "unknown time";
  }
}

export interface AgenticScanTabProps {
  /** Navigates the app to IDE Workspace so the person can run a deterministic
   * scan first. The Agentic Scan tab is purely an enrichment layer -- it
   * never scans independently -- so when no deterministic scan exists this
   * is the only way forward. */
  onGoToWorkspace?: () => void;
  /**
   * The live agentic run, lifted up to app/page.tsx's own useAgenticScan()
   * call (rather than owned here) so the Security and Business Intent tabs
   * can read the SAME running/completed state -- this component used to
   * hold the only copy, which meant navigating away (unmounting this tab)
   * dropped the SSE connection and all live progress. This tab is now a
   * purely presentational execution control panel over that shared state.
   */
  scanId: string | null;
  sourceScanId: string | null;
  graph: AgenticScanGraph;
  nodeRuntime: Record<string, NodeRuntime>;
  events: ScanEvent[];
  state: CuratedState;
  /** AgenticAnalysisResult -- the canonical, bucketed read model (see
   * backend/app/api/v1/agentic_scan.py::_build_agentic_analysis_result and
   * types.ts). Execution/Risk Fusion/Evidence panels read from this;
   * `state` is kept for the raw execution log / anything not yet
   * migrated. Null until the first state.snapshot event arrives. */
  result: AgenticAnalysisResult | null;
  deterministicBaseline: DeterministicBaseline | null;
  agenticSummary: AgenticSummary | null;
  workflowStatus: WorkflowStatus;
  error: string | null;
  start: (params: StartAgenticScanParams) => void;
  /** Requests real cooperative cancellation of the in-flight run -- see
   * useAgenticScan.ts::cancel. Optional only for prop-typing safety; page.tsx
   * always passes it. */
  cancel?: () => void;
  /** Deep-link support (see app/page.tsx's viewFindingTrace /
   * viewFindingInSecurity): initialSubTab opens straight to a specific
   * sub-tab (e.g. "evidence") when arriving via a link from Security or
   * Business Intent; focusFindingId scrolls/highlights that finding in
   * the Evidence panel; onViewFinding lets the Evidence panel send the
   * user back to Security with that finding's drawer open. */
  initialSubTab?: string;
  focusFindingId?: string | null;
  onViewFinding?: (findingId: string) => void;
}

export default function AgenticScanTab({
  onGoToWorkspace, scanId, graph, nodeRuntime, events, state, result,
  deterministicBaseline, agenticSummary, workflowStatus, error, start, cancel,
  initialSubTab, focusFindingId, onViewFinding,
}: AgenticScanTabProps) {
  const [existingScans, setExistingScans] = useState<DeterministicScanSummary[]>([]);
  const [scansLoading, setScansLoading] = useState(false);
  const [scansChecked, setScansChecked] = useState(false);
  const [autoDetected, setAutoDetected] = useState(false);
  // The single deterministic scan_id agentic analysis will run against.
  // Always a real scan_id from GET /api/v1/scans -- there is no
  // independent-scan option any more.
  const [selectedOption, setSelectedOption] = useState<string>("");
  const [scanMode, setScanMode] = useState<"full_scan" | "security_only">("full_scan");
  const [activeSubTab, setActiveSubTab] = useState<SubTab>(
    (initialSubTab as SubTab) && SUB_TABS.some((t) => t.id === initialSubTab)
      ? (initialSubTab as SubTab)
      : "overview"
  );

  // Re-focus if a NEW deep link arrives while this tab is already mounted
  // (e.g. clicking "View full trace" again for a different finding).
  useEffect(() => {
    if (focusFindingId && initialSubTab && SUB_TABS.some((t) => t.id === initialSubTab)) {
      setActiveSubTab(initialSubTab as SubTab);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusFindingId]);
  const [selectedAgent, setSelectedAgent] = useState<string | null>(null);
  const [infoOpen, setInfoOpen] = useState(false);

  const isRunning = workflowStatus === "starting" || workflowStatus === "running";
  const hasDeterministicScans = existingScans.length > 0;
  const selectedScan = existingScans.find((s) => s.scan_id === selectedOption);

  const loadExistingScans = React.useCallback(async () => {
    setScansLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/v1/scans`);
      if (res.ok) {
        const data: DeterministicScanSummary[] = await res.json();
        setExistingScans(data);
        // Auto-detect on first load only: pre-select the most recent
        // deterministic scan if one exists. Never overrides a choice the
        // person makes afterwards.
        if (!autoDetected) {
          setAutoDetected(true);
          if (data.length > 0) setSelectedOption(data[data.length - 1].scan_id);
        }
      }
    } catch {
      // No scans yet is a normal state here, not an error.
    } finally {
      setScansLoading(false);
      setScansChecked(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoDetected]);

  useEffect(() => {
    loadExistingScans();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleStart = () => {
    if (isRunning || !selectedOption) return;
    start({ scanId: selectedOption, scanMode });
  };

  // Real, coded LangGraph topology from the backend (guardian/orchestrator/
  // planner.py::FULL_AGENT_ORDER) laid out left-to-right with dagre — the
  // same auto-layout helper the Code Mind Map view already uses. Live status
  // per node is merged in on every render from nodeRuntime, which is itself
  // built purely from real SSE events (see useAgenticScan.ts).
  const { nodes, edges } = useMemo(() => {
    if (graph.nodes.length === 0) return { nodes: [] as Node[], edges: [] as Edge[] };

    const baseNodes: Node[] = graph.nodes.map((key) => ({
      id: key,
      type: "agent",
      position: { x: 0, y: 0 },
      data: { agentKey: key, label: GRAPH_LABELS[key] || key, status: "WAITING" as AgentStatus },
    }));
    const baseEdges: Edge[] = graph.edges.map(([source, target]) => {
      const sourceStatus = nodeRuntime[source]?.status;
      const targetStatus = nodeRuntime[target]?.status;
      const running = sourceStatus === "RUNNING" || (sourceStatus === "COMPLETED" && targetStatus === "RUNNING");
      const pendingHandoff = sourceStatus === "COMPLETED" && (!targetStatus || targetStatus === "WAITING");
      return {
        id: `${source}->${target}`,
        source,
        target,
        animated: running || pendingHandoff,
        style: { stroke: edgeColor(sourceStatus, targetStatus), strokeWidth: targetStatus === "FAILED" ? 2.5 : 1.5 },
      };
    });

    const layouted = getLayoutedElements(baseNodes, baseEdges, "LR");

    const liveNodes = layouted.nodes.map((n) => {
      const runtime: NodeRuntime = nodeRuntime[n.id] || { status: "WAITING" };
      return {
        ...n,
        data: {
          ...n.data,
          status: runtime.status,
          duration: runtime.duration,
          onSelect: (agentKey: string) => setSelectedAgent(agentKey),
        },
      };
    });

    return { nodes: liveNodes, edges: layouted.edges };
  }, [graph, nodeRuntime]);

  return (
    <div className="space-y-4">
      {/* Header / smart control */}
      <div className="rounded-xl bg-white border border-[#DCE5F0] p-5 shadow-sm">
        <div className="flex items-center gap-2 mb-2">
          <GitBranch className="w-4 h-4 text-blue-600" />
          <h2 className="text-sm font-mono font-bold text-[#111827] tracking-wide">Agentic Analysis</h2>
          <div className="relative" onMouseEnter={() => setInfoOpen(true)} onMouseLeave={() => setInfoOpen(false)}>
            <Info className="w-3.5 h-3.5 text-slate-400 hover:text-slate-600 cursor-help" />
            {infoOpen && (
              <div className="absolute left-0 top-5 z-20 w-80 rounded-lg bg-white border border-[#DCE5F0] p-3 text-[9.5px] font-mono text-slate-600 leading-relaxed shadow-xl">
                The deterministic scanner (IDE Workspace) is the source of technical truth. The agentic layer
                (LangGraph multi-agent workflow) reasons over those findings to produce business violations,
                attack paths, risk scores, and validated patches. It never re-clones, re-scans, or
                independently detects vulnerabilities -- it is purely an enrichment layer, grounded in real
                evidence rather than hallucinating.
              </div>
            )}
          </div>
        </div>
        <p className="text-[10px] font-mono text-slate-500 mb-4">
          Agentic analysis runs on top of deterministic scan results. It does not re-detect vulnerabilities.
          It enriches findings with business impact, threat modeling, and automated remediation.
        </p>

        {/* Deterministic-first gate */}
        {!scansChecked ? (
          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500 py-4">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Checking for a deterministic scan…
          </div>
        ) : !hasDeterministicScans ? (
          <div className="rounded-lg border border-rose-200 bg-rose-50/50 p-4">
            <div className="flex items-center gap-2 mb-1.5">
              <ShieldOff className="w-4 h-4 text-rose-600" />
              <span className="text-[11px] font-mono font-bold text-rose-700 uppercase tracking-wide">
                No Deterministic Scan Available
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-600 mb-3 leading-relaxed">
              The agentic analysis layer requires a deterministic scan as its source of truth. Run a
              deterministic scan in IDE Workspace first, then return here for agentic analysis.
            </p>
            <button
              onClick={() => onGoToWorkspace?.()}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-[11px] font-mono font-bold uppercase tracking-wide bg-blue-600 text-white hover:bg-blue-700 transition-all shadow-xs"
            >
              Go to IDE Workspace and Run Scan <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        ) : (
          <div className="rounded-lg border border-blue-200 bg-blue-50/40 p-4">
            <div className="flex items-center gap-2 mb-1.5">
              <CheckCircle2 className="w-4 h-4 text-blue-600" />
              <span className="text-[11px] font-mono font-bold text-blue-700 uppercase tracking-wide">
                Deterministic Scan Found
              </span>
            </div>
            <p className="text-[10px] font-mono text-slate-600 mb-3">
              {selectedScan
                ? `Scan from ${formatTimestamp(selectedScan.created_at)} — ${selectedScan.scan?.total_findings ?? "?"} findings`
                : "Select a deterministic scan below."}
              {" "}Agentic analysis will reason over these findings.
            </p>

            <div className="flex items-center gap-2 flex-wrap">
              <select
                value={selectedOption}
                onChange={(e) => setSelectedOption(e.target.value)}
                disabled={isRunning || scansLoading}
                className="flex-1 min-w-[280px] bg-white border border-[#DCE5F0] rounded-lg px-3 py-2 text-[11px] font-mono text-[#111827] focus:outline-none focus:border-blue-500 shadow-xs"
              >
                {existingScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    Scan from {formatTimestamp(s.created_at)} — {s.target || "?"} — {s.scan?.total_findings ?? "?"} findings
                  </option>
                ))}
              </select>
              <button
                onClick={loadExistingScans}
                disabled={scansLoading}
                title="Refresh scan list"
                className="p-2 rounded-lg border border-[#DCE5F0] text-slate-600 hover:text-[#111827] hover:bg-slate-100 disabled:opacity-40"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${scansLoading ? "animate-spin" : ""}`} />
              </button>
              <select
                value={scanMode}
                onChange={(e) => setScanMode(e.target.value as "full_scan" | "security_only")}
                disabled={isRunning}
                className="bg-white border border-[#DCE5F0] rounded-lg px-2.5 py-2 text-[10px] font-mono text-slate-600 focus:outline-none focus:border-blue-500 shadow-xs"
              >
                <option value="full_scan">full_scan (all agents)</option>
                <option value="security_only">security_only (core chain)</option>
              </select>
              <button
                onClick={handleStart}
                disabled={isRunning || !selectedOption}
                className="flex items-center gap-2 px-4 py-2 rounded-lg text-[11px] font-mono font-bold uppercase tracking-wide bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed transition-all shadow-sm"
              >
                {isRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                {isRunning ? "Running…" : "RUN AGENTIC ANALYSIS"}
              </button>
              {isRunning && cancel && (
                <button
                  onClick={cancel}
                  title="Cancel this run -- stops at the next agent boundary, already-completed agents' results are kept"
                  className="flex items-center gap-2 px-3 py-2 rounded-lg text-[11px] font-mono font-bold uppercase tracking-wide bg-white text-slate-600 border border-[#DCE5F0] hover:bg-rose-50 hover:text-rose-700 hover:border-rose-200 transition-all shadow-xs"
                >
                  <ShieldOff className="w-3.5 h-3.5" /> Cancel
                </button>
              )}
            </div>
          </div>
        )}

        {error && (
          <div className="mt-3 flex items-center gap-2 text-[10px] font-mono text-rose-600">
            <AlertTriangle className="w-3.5 h-3.5" /> {error}
          </div>
        )}
        {workflowStatus === "completed" && (
          <div className="mt-3 flex items-center gap-2 text-[10px] font-mono text-emerald-600">
            <CheckCircle2 className="w-3.5 h-3.5" /> Agentic analysis completed — scan_id: {scanId}
          </div>
        )}
        {workflowStatus === "cancelled" && (
          <div className="mt-3 flex items-center gap-2 text-[10px] font-mono text-amber-600">
            <ShieldOff className="w-3.5 h-3.5" /> Agentic analysis cancelled — results from agents that completed before cancellation are kept below.
          </div>
        )}
      </div>

      {/* Intelligence Dashboard */}
      <IntelligenceDashboard
        state={state}
        nodeRuntime={nodeRuntime}
        graph={graph}
        hasRun={graph.nodes.length > 0}
      />

      {/* Live graph */}
      {graph.nodes.length > 0 && (
        <div className="rounded-xl bg-[#062B5C] border border-[#174A85] shadow-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2.5 bg-[#041F42] border-b border-[#174A85]">
            <span className="text-[10px] font-mono uppercase font-bold tracking-wider text-white">Live LangGraph Execution Graph</span>
            <div className="flex items-center gap-3">
              {STATUS_LEGEND.map((s) => (
                <span key={s.status} className="flex items-center gap-1 text-[8.5px] font-mono font-bold text-[#D9E8F8]">
                  <span className={`w-1.5 h-1.5 rounded-full ${s.color}`} /> {s.status}
                </span>
              ))}
            </div>
          </div>
          <div style={{ height: 320, minHeight: 300, width: "100%", backgroundColor: "#041F42" }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              nodeTypes={agenticNodeTypes}
              nodesDraggable={false}
              nodesConnectable={false}
              elementsSelectable={true}
              fitView
              fitViewOptions={{ padding: 0.15 }}
              onInit={(instance) => { requestAnimationFrame(() => instance.fitView({ padding: 0.15 })); }}
              proOptions={{ hideAttribution: true }}
              colorMode="dark"
              className="!bg-[#041F42]"
            >
              <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="rgba(255, 255, 255, 0.22)" />
              <Controls
                showInteractive={false}
                className="!bg-[#062B5C] !border !border-[#174A85] !rounded-lg !shadow-md [&>button]:!bg-[#0A3A78] [&>button]:!border-[#174A85] [&>button]:!text-white [&>button:hover]:!bg-[#0070F2]"
              />
            </ReactFlow>
          </div>
        </div>
      )}

      {/* Sub-tab panels */}
      {graph.nodes.length > 0 && (
        <div className="rounded-xl bg-white border border-[#DCE5F0] shadow-sm p-4">
          <div className="flex items-center gap-1 mb-4 border-b border-[#DCE5F0] pb-2 overflow-x-auto">
            {SUB_TABS.map((t) => {
              const Icon = t.icon;
              const active = activeSubTab === t.id;
              return (
                <button
                  key={t.id}
                  onClick={() => setActiveSubTab(t.id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[10px] font-mono font-semibold whitespace-nowrap transition-all ${
                    active ? "bg-blue-50 text-blue-600 border border-blue-200" : "text-slate-600 hover:text-[#111827] hover:bg-slate-100"
                  }`}
                >
                  <Icon className="w-3 h-3" /> {t.label}
                </button>
              );
            })}
          </div>

          {isRunning && workflowStatus === "running" && activeSubTab !== "execution" && (
            <div className="mb-3 text-[9px] font-mono text-slate-500 flex items-center gap-1.5">
              <Loader2 className="w-3 h-3 animate-spin" /> Analysis still running — this panel fills in as agents complete.
            </div>
          )}

          {activeSubTab === "overview" && (
            <OverviewPanel baseline={deterministicBaseline} summary={agenticSummary} running={isRunning} />
          )}
          {activeSubTab === "execution" && <ExecutionPanel result={result} nodeRuntime={nodeRuntime} graph={graph} />}
          {activeSubTab === "risk" && <RiskPanel result={result} />}
          {activeSubTab === "evidence" && <EvidencePanel result={result} focusFindingId={focusFindingId} onViewFinding={onViewFinding} />}
          {activeSubTab === "timeline" && <TimelinePanel events={events} />}
        </div>
      )}

      {graph.nodes.length === 0 && workflowStatus === "idle" && hasDeterministicScans && (
        <div className="rounded-xl bg-white border border-[#DCE5F0] shadow-sm p-10 text-center">
          <div className="text-[11px] font-mono text-slate-500">
            Pick an existing deterministic scan above and run agentic analysis to see the live multi-agent workflow.
          </div>
        </div>
      )}

      {selectedAgent && (
        <DetailPanel
          agentKey={selectedAgent}
          state={state}
          runtime={nodeRuntime[selectedAgent]}
          graph={graph}
          onClose={() => setSelectedAgent(null)}
        />
      )}
    </div>
  );
}
