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
  WAITING: {
    border: "border-white animate-node-blink-white",
    glow: "shadow-[0_0_14px_rgba(255,255,255,0.85)]",
    badge: "bg-[#EAF3FF] text-[#0064D8] border border-[#BFDBFE] font-bold",
    dot: "bg-slate-400",
  },
  RUNNING: {
    border: "border-white animate-node-blink-white",
    glow: "shadow-[0_0_22px_rgba(255,255,255,1)]",
    badge: "bg-[#0064D8] text-white font-bold border border-white",
    dot: "bg-[#0070F2] animate-ping",
  },
  COMPLETED: {
    border: "border-emerald-400 animate-node-blink-white",
    glow: "shadow-[0_0_16px_rgba(255,255,255,0.9)]",
    badge: "bg-emerald-600 text-white font-bold",
    dot: "bg-emerald-500",
  },
  FAILED: {
    border: "border-rose-400 animate-node-blink-white",
    glow: "shadow-[0_0_16px_rgba(255,255,255,0.9)]",
    badge: "bg-rose-600 text-white font-bold",
    dot: "bg-rose-500",
  },
  SKIPPED: {
    border: "border-dashed border-white/80 animate-node-blink-white",
    glow: "opacity-80 shadow-[0_0_10px_rgba(255,255,255,0.7)]",
    badge: "bg-slate-200 text-slate-700 font-bold",
    dot: "bg-slate-400",
  },
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
      className={`cursor-pointer select-none rounded-xl bg-white border-2 ${style.border} ${style.glow} px-3.5 py-3 min-w-[168px] transition-all duration-300 hover:scale-[1.05] shadow-lg`}
    >
      <Handle type="target" position={Position.Left} className="!bg-white !w-2 !h-2 !border !border-[#0070F2] shadow-[0_0_8px_rgba(255,255,255,1)]" />

      <div className="flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full ${style.dot} shrink-0`} />
        <Icon className="w-4 h-4 text-[#0064D8] shrink-0" />
        <span className="text-[11px] font-mono font-bold text-[#062B5C] truncate">{data.label}</span>
      </div>

      <div className="mt-2 flex items-center justify-between gap-2">
        <span className={`inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase tracking-wider px-1.5 py-0.5 rounded ${style.badge}`}>
          <StatusIcon className={`w-2.5 h-2.5 ${data.status === "RUNNING" ? "animate-spin" : ""}`} />
          {data.status}
        </span>
        {typeof data.duration === "number" && data.status === "COMPLETED" && (
          <span className="text-[8.5px] font-mono text-[#4F6480] font-semibold">{(data.duration * 1000).toFixed(0)}ms</span>
        )}
      </div>

      <Handle type="source" position={Position.Right} className="!bg-white !w-2 !h-2 !border !border-[#0070F2] shadow-[0_0_8px_rgba(255,255,255,1)]" />
    </div>
  );
};

export default AgentNode;
