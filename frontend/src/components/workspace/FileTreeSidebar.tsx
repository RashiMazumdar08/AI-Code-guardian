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
    case "CRITICAL": return <ShieldAlert className="w-3 h-3 text-red-400 shrink-0" />;
    case "HIGH":     return <ShieldX     className="w-3 h-3 text-[#ff5400] shrink-0" />;
    case "MEDIUM":   return <Shield      className="w-3 h-3 text-yellow-400 shrink-0" />;
    case "LOW":      return <ShieldCheck className="w-3 h-3 text-emerald-400 shrink-0" />;
    default:         return <Shield      className="w-3 h-3 text-[#8e8e9a] shrink-0" />;
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
            ? "bg-[#ff5400]/10 text-[#ff5400] border-l-2 border-l-[#ff5400]"
            : "text-[#8e8e9a] hover:bg-white/5 hover:text-[#f4f4f8]"
        }`}
        style={{ paddingLeft: `${level * 12 + 8}px` }}
        onClick={handleToggle}
      >
        <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
          {node.type === "directory" && (
            isOpen
              ? <ChevronDown  className="w-3 h-3 text-[#8e8e9a]" />
              : <ChevronRight className="w-3 h-3 text-[#8e8e9a]" />
          )}
        </span>

        <span className="mr-2 shrink-0">
          {node.type === "directory" ? (
            <Folder className={`w-3.5 h-3.5 ${node.has_vulnerabilities ? "text-[#ff5400]" : "text-[#8e8e9a]"}`} />
          ) : (
            <File className={`w-3.5 h-3.5 ${node.has_vulnerabilities ? "text-[#ff5400]" : "text-[#8e8e9a]"}`} />
          )}
        </span>

        <span className="truncate text-xs mr-2 flex-1 font-mono group-hover:text-[#f4f4f8] transition-colors">
          {node.name}
        </span>

        {node.has_vulnerabilities && node.vulnerability_count! > 0 && (
          <div className="flex items-center gap-1 shrink-0 bg-[#0c0d11] px-1.5 py-0.5 rounded border border-white/8">
            {getSeverityIcon(node.max_severity, node.vulnerability_count)}
            <span className="text-[9px] font-mono text-[#8e8e9a]">{node.vulnerability_count}</span>
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
      <div className="h-full flex items-center justify-center bg-[#0c0d11] border-r border-white/8 p-4 text-center">
        <p className="text-xs font-mono text-[#8e8e9a]">Run a scan to view the repository file tree.</p>
      </div>
    );
  }

  return (
    <div className="h-full bg-[#0c0d11] border-r border-white/8 flex flex-col overflow-hidden">
      <div className="p-3 border-b border-white/8 bg-[#12131a]">
        <h3 className="text-[10px] font-mono font-semibold text-[#8e8e9a] uppercase tracking-[0.2em]">
          EXPLORER
        </h3>
      </div>
      <div className="flex-1 overflow-y-auto py-2">
        <TreeNode node={tree} onSelectFile={onSelectFile} selectedPath={selectedPath} />
      </div>
    </div>
  );
}
