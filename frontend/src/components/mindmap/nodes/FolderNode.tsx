"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Folder, FolderOpen, ChevronRight, ChevronDown } from "lucide-react";
import { MindMapNodeData, getNodeSeverityStyle } from "../types";

export const FolderNode = ({ id, data, selected }: { id: string; data: MindMapNodeData; selected?: boolean }) => {
  const isCollapsed = data.isCollapsed ?? false;
  const style = getNodeSeverityStyle(data, "folder", selected);

  return (
    <div className={`p-3 rounded-xl min-w-[180px] transition-all group cursor-pointer ${style.containerClass}`}>
      <Handle type="target" position={Position.Top} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />
      
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {isCollapsed ? (
            <Folder className="w-4 h-4 text-[#0064D8] shrink-0" />
          ) : (
            <FolderOpen className="w-4 h-4 text-[#0070F2] shrink-0" />
          )}
          <span className="text-xs font-bold text-[#0B1F33] truncate max-w-[120px]">{data.label}</span>
        </div>

        {style.isAffected && style.severity && (
          <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${style.badgeClass}`}>
            {style.severity}
          </span>
        )}

        {data.onToggleCollapse && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              data.onToggleCollapse?.(id);
            }}
            className="p-1 rounded hover:bg-black/5 text-[#4F6480] hover:text-[#0B1F33] transition"
          >
            {isCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
      </div>

      {data.path && (
        <div className="text-[10px] text-[#4F6480] font-mono mt-1 truncate">
          {data.path}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />
    </div>
  );
};

export default FolderNode;
