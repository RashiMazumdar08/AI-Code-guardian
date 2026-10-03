"use client";

import React, { useState } from "react";
import { ChevronRight, ChevronDown, File, Folder, ShieldAlert, ShieldX, ShieldCheck, Shield } from "lucide-react";

export interface FileNode {
  name: string;
  path: string;
  type: "file" | "directory";
  children?: FileNode[];
  has_vulnerabilities?: boolean;
  vulnerability_count?: number;
  max_severity?: string | null;
}

interface FileTreeSidebarProps {
  tree: FileNode | null;
  onSelectFile: (path: string) => void;
  selectedPath?: string | null;
}

const getSeverityIcon = (severity: string | null | undefined, count: number = 0) => {
  if (!severity || count === 0) return null;
  switch (severity.toUpperCase()) {
    case "CRITICAL": return <ShieldAlert className="w-3 h-3 text-red-600 shrink-0" />;
    case "HIGH":     return <ShieldX     className="w-3 h-3 text-orange-600 shrink-0" />;
    case "MEDIUM":   return <Shield      className="w-3 h-3 text-amber-600 shrink-0" />;
    case "LOW":      return <ShieldCheck className="w-3 h-3 text-blue-600 shrink-0" />;
    default:         return <Shield      className="w-3 h-3 text-slate-500 shrink-0" />;
  }
};

const TreeNode = ({
  node,
  level = 0,
  onSelectFile,
  selectedPath,
}: {
  node: FileNode;
  level?: number;
  onSelectFile: (path: string) => void;
  selectedPath?: string | null;
}) => {
  const [isOpen, setIsOpen] = useState(true);
  const isSelected = selectedPath === node.path && node.type === "file";

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (node.type === "directory") {
      setIsOpen(!isOpen);
    } else {
      onSelectFile(node.path);
    }
  };

  return (
    <div>
      <div
        className={`flex items-center py-1.5 px-2 cursor-pointer rounded-sm group transition-colors ${
          isSelected
            ? "bg-[#EFF6FF] text-[#2563EB] font-semibold border-l-2 border-l-[#2563EB]"
            : "text-[#475569] hover:bg-[#F8FAFC] hover:text-[#111827]"
        }`}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={handleToggle}
      >
        <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
          {node.type === "directory" && (
            isOpen
              ? <ChevronDown  className="w-3 h-3 text-[#64748B]" />
              : <ChevronRight className="w-3 h-3 text-[#64748B]" />
          )}
        </span>

        <span className="mr-2 shrink-0">
          {node.type === "directory" ? (
            <Folder className={`w-3.5 h-3.5 ${node.has_vulnerabilities ? "text-orange-600" : "text-[#64748B]"}`} />
          ) : (
            <File className={`w-3.5 h-3.5 ${node.has_vulnerabilities ? "text-orange-600" : "text-[#64748B]"}`} />
          )}
        </span>

        <span className="truncate text-[14px] font-sans font-normal leading-[1.5] mr-2 flex-1 group-hover:text-[#111827] transition-colors">
          {node.name}
        </span>

        {node.has_vulnerabilities && node.vulnerability_count! > 0 && (
          <div className="flex items-center gap-1 shrink-0 bg-white px-1.5 py-0.5 rounded border border-[#E2E8F0]">
            {getSeverityIcon(node.max_severity, node.vulnerability_count)}
            <span className="text-[12px] font-sans font-semibold leading-[1.3] text-[#64748B]">{node.vulnerability_count}</span>
          </div>
        )}
      </div>

      {node.type === "directory" && isOpen && node.children && (
        <div>
          {node.children.map((child, i) => (
            <TreeNode
              key={`${child.path}-${i}`}
              node={child}
              level={level + 1}
              onSelectFile={onSelectFile}
              selectedPath={selectedPath}
            />
          ))}
        </div>
      )}
    </div>
  );
};

export default function FileTreeSidebar({ tree, onSelectFile, selectedPath }: FileTreeSidebarProps) {
  if (!tree) {
    return (
      <div className="h-full flex items-center justify-center bg-white border-r border-slate-200 p-4 text-center">
        <p className="text-[15px] font-sans font-normal leading-[1.5] text-slate-500">Run a scan to view the repository file tree.</p>
      </div>
    );
  }

  return (
    <div className="h-full bg-white border-r border-slate-200 flex flex-col overflow-hidden">
      <div className="p-3 border-b border-slate-200 bg-[#F8FAFC]">
        <h3 className="text-[13px] font-sans font-semibold text-slate-500 uppercase tracking-[0.04em] leading-[1.4]">
          EXPLORER
        </h3>
      </div>
      <div className="flex-1 overflow-y-auto py-2">
        <TreeNode node={tree} onSelectFile={onSelectFile} selectedPath={selectedPath} />
      </div>
    </div>
  );
}
