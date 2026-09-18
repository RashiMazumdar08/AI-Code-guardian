"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import {
  Brain, FolderTree, Building2, ShieldHalf, Network as NetworkIcon,
  Package, Crosshair, Gavel, GitMerge, Wrench, CheckCircle2,
  Loader2, XCircle, MinusCircle, Clock,
} from "lucide-react";
import type { AgentStatus } from "../types";

const NODE_ICONS: Record<string, React.ComponentType<any>> = {
  planner: Brain,
  repository: FolderTree,
  business: Building2,
  security: ShieldHalf,
  architecture: NetworkIcon,
  dependency: Package,
  threat_simulation: Crosshair,
  policy: Gavel,
  risk_fusion: GitMerge,
  patch: Wrench,
  validation: CheckCircle2,
};

const STATUS_STYLE: Record<AgentStatus, { border: string; glow: string; badge: string; dot: string }> = {
  WAITING: { border: "border-white/12", glow: "", badge: "bg-white/8 text-[#8e8e9a]", dot: "bg-[#8e8e9a]" },
  RUNNING: {
    border: "border-[#ff5400]/70 animate-pulse",
    glow: "shadow-[0_0_18px_rgba(255,84,0,0.35)]",
    badge: "bg-[#ff5400]/15 text-[#ff5400]",
    dot: "bg-[#ff5400] animate-pulse",
  },
  COMPLETED: {
    border: "border-emerald-500/50",
    glow: "shadow-[0_0_12px_rgba(16,185,129,0.2)]",
    badge: "bg-emerald-500/15 text-emerald-400",
    dot: "bg-emerald-400",
  },
  FAILED: {
    border: "border-red-500/60",
    glow: "shadow-[0_0_14px_rgba(239,68,68,0.3)]",
    badge: "bg-red-500/15 text-red-400",
    dot: "bg-red-400",
  },
  SKIPPED: { border: "border-dashed border-slate-500/50", glow: "opacity-50", badge: "bg-white/5 text-[#5c5c68]", dot: "bg-[#5c5c68]" },
};

const STATUS_ICON: Record<AgentStatus, React.ComponentType<any>> = {
  WAITING: Clock,
  RUNNING: Loader2,
  COMPLETED: CheckCircle2,
  FAILED: XCircle,
  SKIPPED: MinusCircle,
};

export interface AgentNodeData {
  agentKey: string;
  label: string;
  status: AgentStatus;
  duration?: number;
  onSelect?: (agentKey: string) => void;
  [key: string]: unknown;
}

export const AgentNode = ({ data }: { data: AgentNodeData }) => {
  const Icon = NODE_ICONS[data.agentKey] || Brain;
  const style = STATUS_STYLE[data.status] || STATUS_STYLE.WAITING;
  const StatusIcon = STATUS_ICON[data.status] || Clock;

  return (
    <div
      onClick={() => data.onSelect?.(data.agentKey)}
      className={`cursor-pointer select-none rounded-xl bg-[#12131a] border ${style.border} ${style.glow} px-3.5 py-3 min-w-[168px] transition-all duration-300 hover:scale-[1.03]`}
    >
      <Handle type="target" position={Position.Left} className="!bg-white/30 !w-1.5 !h-1.5 !border-0" />

      <div className="flex items-center gap-2">
        <span className={`w-1.5 h-1.5 rounded-full ${style.dot} shrink-0`} />
        <Icon className="w-3.5 h-3.5 text-[#f4f4f8] shrink-0" />
        <span className="text-[11px] font-mono font-semibold text-[#f4f4f8] truncate">{data.label}</span>
      </div>

      <div className="mt-2 flex items-center justify-between gap-2">
        <span className={`inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${style.badge}`}>
          <StatusIcon className={`w-2.5 h-2.5 ${data.status === "RUNNING" ? "animate-spin" : ""}`} />
          {data.status}
        </span>
        {typeof data.duration === "number" && data.status === "COMPLETED" && (
          <span className="text-[8.5px] font-mono text-[#8e8e9a]">{(data.duration * 1000).toFixed(0)}ms</span>
        )}
      </div>

      <Handle type="source" position={Position.Right} className="!bg-white/30 !w-1.5 !h-1.5 !border-0" />
    </div>
  );
};

export default AgentNode;
