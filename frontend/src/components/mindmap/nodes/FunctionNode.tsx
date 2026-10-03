"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { Code2 } from "lucide-react";
import { MindMapNodeData, getNodeSeverityStyle } from "../types";

export const FunctionNode = ({ data, selected }: { data: MindMapNodeData; selected?: boolean }) => {
  const style = getNodeSeverityStyle(data, "function", selected);

  return (
    <div className={`p-2.5 rounded-xl min-w-[150px] transition-all cursor-pointer ${style.containerClass}`}>
      <Handle type="target" position={Position.Top} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />

      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Code2 className="w-3.5 h-3.5 text-[#0064D8] shrink-0" />
          <span className="text-xs font-mono font-bold text-[#0B1F33] truncate">{data.label}()</span>
        </div>
        {style.isAffected && style.severity && (
          <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${style.badgeClass}`}>
            {style.severity}
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />
    </div>
  );
};

export default FunctionNode;
