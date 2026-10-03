"use client";

import React from "react";
import { Handle, Position } from "@xyflow/react";
import { FileCode, ShieldAlert } from "lucide-react";
import { MindMapNodeData, getNodeSeverityStyle } from "../types";

export const FileNode = ({ data, selected }: { data: MindMapNodeData; selected?: boolean }) => {
  const style = getNodeSeverityStyle(data, "file", selected);

  return (
    <div className={`p-3 rounded-xl min-w-[170px] transition-all cursor-pointer ${style.containerClass}`}>
      <Handle type="target" position={Position.Top} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />

      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-[#0064D8] shrink-0" />
          <span className="text-xs font-bold text-[#0B1F33] truncate max-w-[110px]">{data.label}</span>
        </div>

        {style.isAffected && style.severity ? (
          <span className={`text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${style.badgeClass}`}>
            {style.severity}
          </span>
        ) : data.language ? (
          <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-[#F1F5F9] text-[#4F6480] font-semibold border border-[#CBD5E1]">
            {data.language}
          </span>
        ) : null}
      </div>

      {style.isAffected && (
        <div className="mt-2 flex items-center justify-between text-[10px]">
          <span className="font-semibold flex items-center gap-1 font-mono" style={{ color: style.indicatorColor }}>
            <ShieldAlert className="w-3 h-3" /> Risk: {data.riskScore || 50}/100
          </span>
          {style.count > 0 && (
            <span className="font-mono font-bold" style={{ color: style.indicatorColor }}>
              {style.count} issue(s)
            </span>
          )}
        </div>
      )}

      <Handle type="source" position={Position.Bottom} className="!bg-[#0070F2] !w-2 !h-2 !border-0" />
    </div>
  );
};

export default FileNode;
