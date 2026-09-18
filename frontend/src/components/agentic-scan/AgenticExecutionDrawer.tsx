"use client";

import React, { useEffect, useRef, useState } from "react";
import { X, Sparkles, CheckCircle2 } from "lucide-react";
import AgenticScanTab, { AgenticScanTabProps } from "./AgenticScanTab";

export interface AgenticExecutionDrawerProps extends AgenticScanTabProps {
  open: boolean;
  onClose: () => void;
}

/**
 * Right-side slide-out drawer that hosts the Agentic Scan control panel.
 * This does NOT reimplement the Intelligence Dashboard / Live Graph /
 * Execution Log / Risk / Evidence / Timeline panels -- it reuses
 * <AgenticScanTab> wholesale (it already renders all of that from real
 * AgentWorkflowState / SSE data). This component only adds the modal/
 * drawer shell: backdrop, header, close affordance, and the "analysis
 * complete" banner + auto-dismiss behavior described in the spec.
 *
 * Mounting is fully conditional (`open && ...`) rather than CSS-hidden,
 * so the ReactFlow graph inside AgenticScanTab always mounts fresh into a
 * visible, correctly-sized container -- a display:none-hidden ReactFlow
 * instance is the single most common cause of a "blank graph" bug, since
 * it measures a zero-size viewport at mount and never re-measures on its
 * own.
 */
export default function AgenticExecutionDrawer({
  open, onClose, ...tabProps
}: AgenticExecutionDrawerProps) {
  const { deterministicBaseline, sourceScanId, workflowStatus } = tabProps;

  const [dismissing, setDismissing] = useState(false);
  const autoCloseRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevStatusRef = useRef(workflowStatus);

  // Auto-dismiss 3s after the run completes (spec: "Auto-dismiss the modal
  // after 3 seconds OR let user close manually"). Edge-triggered off the
  // transition INTO "completed" so it only fires once per run, and is
  // cancelled if the drawer is closed manually or unmounts first.
  useEffect(() => {
    if (prevStatusRef.current !== "completed" && workflowStatus === "completed" && open) {
      setDismissing(true);
      autoCloseRef.current = setTimeout(() => {
        setDismissing(false);
        onClose();
      }, 3000);
    }
    prevStatusRef.current = workflowStatus;
    return () => {
      if (autoCloseRef.current) clearTimeout(autoCloseRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workflowStatus, open]);

  // Manual close cancels any pending auto-dismiss.
  const handleClose = () => {
    if (autoCloseRef.current) clearTimeout(autoCloseRef.current);
    setDismissing(false);
    onClose();
  };

  if (!open) return null;

  const findingsCount = deterministicBaseline?.total_findings;

  return (
    <div className="fixed inset-0 z-[90]">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-[2px] animate-in fade-in-0 duration-200"
        onClick={handleClose}
      />

      {/* Panel -- 70% viewport width (within the spec's 60-80% range), full height */}
      <div className="absolute top-0 right-0 h-full w-full sm:w-[70%] min-w-[360px] bg-[#0B0F19] border-l border-white/10 shadow-[-8px_0_40px_rgba(0,0,0,0.5)] flex flex-col animate-in slide-in-from-right duration-250 ease-out">
        {/* Header */}
        <div className="shrink-0 px-6 py-4 border-b border-white/10 flex items-center justify-between gap-4 bg-[#0c0d11]">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#ff5400] shrink-0" />
              <h2 className="text-sm font-mono font-bold text-[#f4f4f8] tracking-wide truncate">
                Agentic Analysis — Multi-Agent Workflow
              </h2>
            </div>
            <p className="text-[10px] font-mono text-[#8e8e9a] mt-1 truncate">
              {typeof findingsCount === "number"
                ? `Reasoning over ${findingsCount} finding${findingsCount === 1 ? "" : "s"} from scan `
                : "Reasoning over findings from scan "}
              <code className="text-[#f4f4f8]">{sourceScanId || "—"}</code>
            </p>
          </div>
          <button
            onClick={handleClose}
            title="Close (returns to IDE Workspace)"
            className="shrink-0 flex items-center justify-center w-8 h-8 rounded-lg text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/8 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Completion banner */}
        {dismissing && (
          <div className="shrink-0 px-6 py-3 bg-emerald-500/10 border-b border-emerald-500/20 flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <p className="text-[10.5px] font-mono text-emerald-300 leading-snug">
              Agentic analysis complete. View AI threat analysis in the Security tab and business impact in
              Business Intent. Closing automatically…
            </p>
          </div>
        )}

        {/* Body -- the existing, fully-built Agentic Scan control panel */}
        <div className="flex-1 overflow-y-auto p-5">
          <AgenticScanTab {...tabProps} />
        </div>
      </div>
    </div>
  );
}
