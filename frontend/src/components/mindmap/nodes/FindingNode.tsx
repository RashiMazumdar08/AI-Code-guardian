"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { ShieldAlert, AlertTriangle } from "lucide-react";
import { MindMapNodeData } from "../types";

export const FindingNode = ({ data }: { data: MindMapNodeData }) => {
  const severity = (data.severity || "high").toLowerCase();
  
  const getSeverityStyle = () => {
    switch (severity) {
      case "critical":
        return "border-red-500/80 bg-red-950/40 text-red-300 shadow-[0_0_20px_rgba(239,68,68,0.5)]";
      case "high":
        return "border-orange-500/80 bg-orange-950/40 text-orange-300 shadow-[0_0_18px_rgba(249,115,22,0.4)]";
      case "medium":
        return "border-amber-500/80 bg-amber-950/40 text-amber-300 shadow-[0_0_15px_rgba(245,158,11,0.3)]";
      default:
        return "border-blue-500/80 bg-blue-950/40 text-blue-300 shadow-[0_0_15px_rgba(59,130,246,0.3)]";
    }
  };

  return (
    <div className={`p-3 rounded-xl border backdrop-blur-md min-w-[180px] transition-all duration-300 animate-pulse ${getSeverityStyle()}`}>
      <Handle type="target" position={Position.Top} className="!bg-red-400 !w-2.5 !h-2.5" />

      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-red-400 shrink-0" />
          <div>
            <div className="text-xs font-bold truncate max-w-[120px]">{data.label}</div>
            {data.path && <div className="text-[9px] font-mono text-slate-300 truncate max-w-[120px]">{data.path}</div>}
          </div>
        </div>

        <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-black/40 border border-white/10 shrink-0">
          {severity}
        </span>
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-red-400 !w-2.5 !h-2.5" />
    </div>
  );
};

export default FindingNode;
