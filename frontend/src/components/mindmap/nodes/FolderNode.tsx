"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Folder, FolderOpen, ChevronRight, ChevronDown } from "lucide-react";
import { MindMapNodeData } from "../types";

export const FolderNode = ({ id, data }: { id: string; data: MindMapNodeData }) => {
  const isCollapsed = data.isCollapsed ?? false;

  return (
    <div className="glass-panel p-3 rounded-xl border border-indigo-500/30 min-w-[180px] shadow-lg hover:border-indigo-400/60 transition group cursor-pointer">
      <Handle type="target" position={Position.Top} className="!bg-indigo-400 !w-2.5 !h-2.5" />
      
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {isCollapsed ? (
            <Folder className="w-4 h-4 text-indigo-400 shrink-0" />
          ) : (
            <FolderOpen className="w-4 h-4 text-indigo-300 shrink-0" />
          )}
          <span className="text-xs font-bold text-slate-100 truncate max-w-[120px]">{data.label}</span>
        </div>

        {data.onToggleCollapse && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              data.onToggleCollapse?.(id);
            }}
            className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white transition"
          >
            {isCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {data.path && (
        <div className="text-[10px] text-slate-400 font-mono mt-1.5 truncate">
          {data.path}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-indigo-400 !w-2.5 !h-2.5" />
    </div>
  );
};

export default FolderNode;
