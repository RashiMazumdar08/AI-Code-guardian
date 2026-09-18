"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Package } from "lucide-react";
import { MindMapNodeData } from "../types";

export const ModuleNode = ({ data }: { data: MindMapNodeData }) => {
  return (
    <div className="glass-panel p-2.5 rounded-lg border border-cyan-500/30 min-w-[150px] shadow-sm hover:border-cyan-400/60 transition">
      <Handle type="target" position={Position.Top} className="!bg-cyan-400 !w-2 !h-2" />

      <div className="flex items-center gap-2">
        <Package className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
        <span className="text-xs font-semibold text-slate-200 truncate">{data.label}</span>
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-cyan-400 !w-2 !h-2" />
    </div>
  );
};

export default ModuleNode;
