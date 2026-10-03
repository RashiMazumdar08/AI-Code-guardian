"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { ShieldAlert, AlertTriangle } from "lucide-react";
import { MindMapNodeData, getNodeSeverityStyle } from "../types";

export const FindingNode = ({ data, selected }: { data: MindMapNodeData; selected?: boolean }) => {
  const severity = (data.severity || "high").toLowerCase();
  const style = getNodeSeverityStyle(data, "finding", selected);

  return (
    <div className={`p-3 rounded-xl min-w-[180px] transition-all cursor-pointer ${style.containerClass}`}>
      <Handle type="target" position={Position.Top} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />

      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0" style={{ color: style.indicatorColor }} />
          <div>
            <div className="text-xs font-bold truncate max-w-[120px] text-[#0B1F33]">{data.label}</div>
            {data.path && <div className="text-[9px] font-mono text-[#4F6480] truncate max-w-[120px]">{data.path}</div>}
          </div>
        </div>

        <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded shrink-0 ${style.badgeClass}`}>
          {severity}
        </span>
      </div>

      <Handle type="source" position={Position.Bottom} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />
    </div>
  );
};

export default FindingNode;
