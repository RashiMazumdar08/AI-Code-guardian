"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type {
  AgenticAnalysisResult,
  AgenticScanGraph,
  AgentStatus,
  AgenticSummary,
  CuratedState,
  DeterministicBaseline,
  NodeRuntime,
  ScanEvent,
  WorkflowStatus,
} from "./types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const INITIAL_GRAPH: AgenticScanGraph = { nodes: [], edges: [] };

export interface StartAgenticScanParams {
  /**
   * Existing deterministic scan_id (from GET /api/v1/scans). Always
   * required -- the agentic layer is purely an enrichment layer over a
   * real deterministic scan's findings/evidence, it never scans
   * independently. See backend/app/api/v1/agentic_scan.py.
   */
  scanId: string;
  scanMode: "full_scan" | "security_only";
}

/**
 * Owns the live connection to a single agentic scan run. Every piece of
 * state here is derived directly from real backend events/snapshots
 * received over the SSE stream at GET /api/v1/agentic-scan/{scan_id}/stream
 * -- there is no client-side timer, fake percentage, or simulated
 * progression anywhere in this hook. If the backend hasn't said an agent
 * ran, this hook has no opinion about it (it stays WAITING).
 *
 * Two result domains are tracked separately, per the "deterministic
 * scanner is the source of technical truth" architecture:
 *   - deterministicBaseline: real counts from the ORIGINAL ScanPipeline
 *     scan (never recomputed by an agent).
 *   - agenticSummary: real counts from the AGENT GRAPH's runtime state
 *     once it finishes (correlated risks, business violations, attack
 *     paths, policy violations, remediation proposals, validated patches).
 * Both come verbatim from backend events -- see workflow.adopted /
 * workflow.completed in backend/app/api/v1/agentic_scan.py.
 */
export function useAgenticScan() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [sourceScanId, setSourceScanId] = useState<string | null>(null);
  const [graph, setGraph] = useState<AgenticScanGraph>(INITIAL_GRAPH);
  const [nodeRuntime, setNodeRuntime] = useState<Record<string, NodeRuntime>>({});
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [state, setState] = useState<CuratedState>({});
  // AgenticAnalysisResult -- the canonical, bucketed read model (see
  // backend/app/api/v1/agentic_scan.py::_build_agentic_analysis_result).
  // Populated from the same state.snapshot / workflow.completed events as
  // `state` above; prefer this in new/updated consumers.
  const [result, setResult] = useState<AgenticAnalysisResult | null>(null);
  const [deterministicBaseline, setDeterministicBaseline] = useState<DeterministicBaseline | null>(null);
  const [agenticSummary, setAgenticSummary] = useState<AgenticSummary | null>(null);
  const [workflowStatus, setWorkflowStatus] = useState<WorkflowStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Restore persisted agentic report on mount if it matches the current active scan
  useEffect(() => {
    try {
      const activeScanId = sessionStorage.getItem("guardian_active_scan_id");
      const raw = sessionStorage.getItem("guardian_agentic_report");
      if (raw) {
        const cached = JSON.parse(raw);
        if (cached && cached.sourceScanId && (!activeScanId || cached.sourceScanId === activeScanId)) {
          setScanId(cached.scanId || null);
          setSourceScanId(cached.sourceScanId);
          if (cached.state) setState(cached.state);
          if (cached.result) setResult(cached.result);
          if (cached.deterministicBaseline) setDeterministicBaseline(cached.deterministicBaseline);
          if (cached.agenticSummary) setAgenticSummary(cached.agenticSummary);
          setWorkflowStatus("completed");
        }
      }
    } catch {
      // ignore storage errors
    }
  }, []);

  const reset = useCallback(() => {
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
    setScanId(null);
    setSourceScanId(null);
    setGraph(INITIAL_GRAPH);
    setNodeRuntime({});
    setEvents([]);
    setState({});
    setResult(null);
    setDeterministicBaseline(null);
    setAgenticSummary(null);
    setWorkflowStatus("idle");
    setError(null);
  }, []);

  const applyEvent = useCallback((evt: ScanEvent) => {
    setEvents((prev) => [...prev, evt]);

    switch (evt.type) {
      case "workflow.started":
        setWorkflowStatus("running");
        break;
      case "workflow.adopted":
        if (evt.baseline) setDeterministicBaseline(evt.baseline);
        break;
      case "agent.started":
        if (evt.agent) {
          setNodeRuntime((prev) => ({
            ...prev,
            [evt.agent as string]: { status: "RUNNING" as AgentStatus, task: evt.task, startedAt: evt.ts },
          }));
        }
        break;
      case "agent.completed":
        if (evt.agent) {
          setNodeRuntime((prev) => ({
            ...prev,
            [evt.agent as string]: {
              ...(prev[evt.agent as string] || {}),
              status: (evt.status === "error" ? "FAILED" : "COMPLETED") as AgentStatus,
              duration: evt.duration,
              error: evt.error,
              completedAt: evt.ts,
            },
          }));
        }
        break;
      case "agent.skipped":
        if (evt.agent) {
          setNodeRuntime((prev) => ({
            ...prev,
            [evt.agent as string]: { status: "SKIPPED" as AgentStatus, reason: evt.reason },
          }));
        }
        break;
      case "state.snapshot":
        if (evt.state) setState(evt.state as CuratedState);
        if (evt.result) setResult(evt.result);
        break;
      case "workflow.completed":
        setWorkflowStatus("completed");
        if (evt.deterministic_baseline) setDeterministicBaseline(evt.deterministic_baseline);
        if (evt.agentic_summary) setAgenticSummary(evt.agentic_summary);
        if (evt.result) setResult(evt.result);
        break;
      case "workflow.failed":
        setWorkflowStatus("error");
        setError(evt.error || "Agentic scan failed.");
        break;
      case "workflow.cancelled":
        setWorkflowStatus("cancelled");
        break;
      default:
        break;
    }
  }, []);

  const connectStream = useCallback((id: string) => {
    eventSourceRef.current?.close();
    const es = new EventSource(`${API_BASE}/api/v1/agentic-scan/${id}/stream`);
    eventSourceRef.current = es;
    es.onmessage = (msg) => {
      try {
        const evt: ScanEvent = JSON.parse(msg.data);
        applyEvent(evt);
        if (evt.type === "stream.end") {
          es.close();
        }
      } catch {
        // ignore malformed/keepalive frames
      }
    };
    // EventSource auto-retries on transient network errors by itself; once
    // the backend sends "stream.end" we close it explicitly above, so a
    // later onerror after that point is an expected closed-connection event,
    // not a failure to surface.
  }, [applyEvent]);

  const start = useCallback(async (params: StartAgenticScanParams) => {
    reset();
    setWorkflowStatus("starting");
    setSourceScanId(params.scanId || null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/agentic-scan/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scan_id: params.scanId,
          scan_mode: params.scanMode,
        }),
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(`Failed to start agentic analysis (${res.status}): ${detail}`);
      }
      const data = await res.json();
      setScanId(data.scan_id);
      setGraph(data.graph || INITIAL_GRAPH);
      setWorkflowStatus("running");
      connectStream(data.scan_id);
    } catch (e: any) {
      setWorkflowStatus("error");
      setError(e?.message || "Failed to start agentic analysis.");
    }
  }, [connectStream, reset]);

  // Requests real, cooperative cancellation of the in-flight run (see
  // backend/app/api/v1/agentic_scan.py::cancel_agentic_scan) -- this does
  // NOT set workflowStatus to "cancelled" itself; that only happens once
  // the backend actually stops and sends the real "workflow.cancelled" SSE
  // event (handled in applyEvent above), same as every other status
  // transition in this hook.
  const cancel = useCallback(async () => {
    if (!scanId) return;
    try {
      await fetch(`${API_BASE}/api/v1/agentic-scan/${scanId}/cancel`, { method: "POST" });
    } catch (e: any) {
      setError(e?.message || "Failed to request cancellation.");
    }
  }, [scanId]);

  // Persist the last completed run to sessionStorage (mirrors the
  // existing `guardian_report` pattern used for the deterministic scan
  // in app/page.tsx) so the Reports tab -- a completely separate part of
  // the tree -- can build Agentic/Unified downloads without prop-drilling
  // agentic state through the whole app. Only real, completed run data is
  // ever written here.
  useEffect(() => {
    if (workflowStatus !== "completed" || !scanId) return;
    try {
      sessionStorage.setItem(
        "guardian_agentic_report",
        JSON.stringify({
          scanId, sourceScanId, state, result, deterministicBaseline, agenticSummary,
          completedAt: Date.now(),
        })
      );
    } catch {
      // sessionStorage can throw in some contexts (private browsing, etc.)
      // -- the Reports tab just won't find a cached agentic run, which it
      // already handles as "no agentic run yet".
    }
  }, [workflowStatus, scanId, sourceScanId, state, result, deterministicBaseline, agenticSummary]);

  return {
    scanId, sourceScanId, graph, nodeRuntime, events, state, result,
    deterministicBaseline, agenticSummary, workflowStatus, error, start, cancel, reset,
  };
}
