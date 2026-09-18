"use client";

import React from "react";
import { X, ShieldAlert, FileCode, Code2, Folder, Box, Package, TerminalSquare, Copy, Check } from "lucide-react";
import { Node } from "@xyflow/react";
import { MindMapNodeData } from "./types";

interface MindMapDetailPanelProps {
  node: Node<MindMapNodeData> | null;
  onClose: () => void;
}

export const MindMapDetailPanel: React.FC<MindMapDetailPanelProps> = ({ node, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  if (!node) return null;

  const { data, type } = node;
  const findings = data.findings || [];

  const getNodeIcon = () => {
    switch (type) {
      case "folder": return <Folder className="w-5 h-5 text-indigo-400" />;
      case "file": return <FileCode className="w-5 h-5 text-blue-400" />;
      case "function": return <Code2 className="w-5 h-5 text-purple-400" />;
      case "class": return <Box className="w-5 h-5 text-emerald-400" />;
      case "module": return <Package className="w-5 h-5 text-cyan-400" />;
      case "finding": return <ShieldAlert className="w-5 h-5 text-red-400" />;
      default: return <FileCode className="w-5 h-5 text-slate-400" />;
    }
  };

  const handleCopyCode = () => {
    if (data.codePreview) {
      navigator.clipboard.writeText(data.codePreview);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="absolute right-4 top-4 bottom-4 w-96 glass-panel border border-white/10 rounded-2xl p-5 z-20 shadow-2xl flex flex-col overflow-hidden animate-in slide-in-from-right duration-200">
      {/* Header */}
      <div className="flex items-center justify-between pb-4 border-b border-white/10 shrink-0">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-xl glass-card">
            {getNodeIcon()}
          </div>
          <div>
            <h3 className="text-sm font-bold text-slate-100 truncate max-w-[200px]">{data.label}</h3>
            <span className="text-[10px] font-mono text-indigo-400 uppercase font-semibold">{type} Node</span>
          </div>
        </div>

        <button
          onClick={onClose}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white glass-card transition"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Body Details */}
      <div className="flex-1 overflow-y-auto space-y-5 py-4">
        {data.path && (
          <div>
            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">File Path</span>
            <div className="glass-input p-2 rounded-lg font-mono text-xs text-slate-200 break-all">
              {data.path}
            </div>
          </div>
        )}

        {data.riskScore !== undefined && (
          <div>
            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">Risk Score</span>
            <div className="flex items-center justify-between glass-card p-3 rounded-xl">
              <span className="text-xs text-slate-300">Systemic Risk Assessment</span>
              <span className={`text-sm font-bold ${
                data.riskScore > 60 ? "text-red-400" : data.riskScore > 30 ? "text-amber-400" : "text-emerald-400"
              }`}>
                {data.riskScore} / 100
              </span>
            </div>
          </div>
        )}

        {data.codePreview && (
          <div className="space-y-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Code Snippet</span>
              <button
                onClick={handleCopyCode}
                className="text-[10px] text-indigo-400 hover:text-indigo-300 flex items-center gap-1 font-semibold"
              >
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            <pre className="glass-input p-3 rounded-xl font-mono text-xs text-slate-200 overflow-x-auto max-h-48 leading-relaxed">
              <code>{data.codePreview}</code>
            </pre>
          </div>
        )}

        {findings.length > 0 && (
          <div className="space-y-3">
            <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block">
              Associated Security Findings ({findings.length})
            </span>
            <div className="space-y-2.5">
              {findings.map((f: any, idx: number) => (
                <div key={idx} className="glass-card p-3 rounded-xl border border-red-500/30 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-bold text-red-300">{f.category || f.title}</span>
                    <span className="text-[9px] font-mono font-bold uppercase px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                      {f.severity || "High"}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 leading-normal">{f.reason || f.description}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default MindMapDetailPanel;
