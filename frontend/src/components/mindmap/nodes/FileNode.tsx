"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { FileCode, ShieldAlert } from "lucide-react";
import { MindMapNodeData } from "../types";

export const FileNode = ({ data }: { data: MindMapNodeData }) => {
  const hasRisk = (data.riskScore || 0) > 0 || (data.findings && data.findings.length > 0);

  return (
    <div className={`glass-card p-3 rounded-xl border min-w-[170px] transition-all hover:scale-105 ${
      hasRisk ? "border-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.2)]" : "border-white/10"
    }`}>
      <Handle type="target" position={Position.Top} className="!bg-blue-400 !w-2 !h-2" />

      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-blue-400 shrink-0" />
          <span className="text-xs font-semibold text-slate-100 truncate max-w-[110px]">{data.label}</span>
        </div>

        {data.language && (
          <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">
            {data.language}
          </span>
        )}
      </div>

      {hasRisk && (
        <div className="mt-2 flex items-center justify-between text-[10px]">
          <span className="text-amber-400 font-medium flex items-center gap-1">
            <ShieldAlert className="w-3 h-3" /> Risk: {data.riskScore || 50}/100
          </span>
          {data.findings && (
            <span className="text-red-400 font-mono font-bold">{data.findings.length} issue(s)</span>
          )}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-blue-400 !w-2 !h-2" />
    </div>
  );
};

export default FileNode;
