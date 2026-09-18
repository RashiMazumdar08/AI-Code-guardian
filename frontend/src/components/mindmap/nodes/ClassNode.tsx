"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Box } from "lucide-react";
import { MindMapNodeData } from "../types";

export const ClassNode = ({ data }: { data: MindMapNodeData }) => {
  return (
    <div className="glass-card p-2.5 rounded-lg border border-emerald-500/30 min-w-[150px] shadow-sm hover:border-emerald-400/60 transition">
      <Handle type="target" position={Position.Top} className="!bg-emerald-400 !w-2 !h-2" />

      <div className="flex items-center gap-2">
        <Box className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
        <span className="text-xs font-semibold text-slate-200 truncate">{data.label}</span>
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-emerald-400 !w-2 !h-2" />
    </div>
  );
};

export default ClassNode;
