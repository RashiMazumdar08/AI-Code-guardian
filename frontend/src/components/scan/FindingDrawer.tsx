"use client";

import React, { useState } from "react";
import { X, Copy, MessageSquare, Check, ShieldAlert, AlertTriangle, Code, ChevronRight } from "lucide-react";

export interface FindingDetail {
  finding_id: string;
  category: string;
  severity: string;
  rule_id?: string;
  cwe?: string;
  owasp?: string;
  file: string;
  line: number;
  snippet: string;
  recommendation: string;
  reason?: string;
  is_exploitable?: boolean;
  exploitability_score?: number;
  exploit_scenario?: string;
  business_impact?: string;
  remediation_patch?: string;
}

interface FindingDrawerProps {
  finding: FindingDetail | null;
  isOpen: boolean;
  onClose: () => void;
  onDiscussInChat?: (finding: FindingDetail) => void;
}

export const FindingDrawer: React.FC<FindingDrawerProps> = ({
  finding,
  isOpen,
  onClose,
  onDiscussInChat,
}) => {
  const [copied, setCopied] = useState(false);

  if (!isOpen || !finding) return null;

  const handleCopyAgentInstructions = () => {
    const prompt = `Fix security vulnerability in ${finding.file} at line ${finding.line}:\n` +
      `- Category: ${finding.category} (${finding.cwe || "Security"})\n` +
      `- Severity: ${finding.severity}\n` +
      `- Reason: ${finding.reason || "Vulnerable code pattern detected"}\n` +
      `- Recommendation: ${finding.recommendation}\n` +
      (finding.remediation_patch ? `- Suggested Patch:\n${finding.remediation_patch}\n` : "");

    navigator.clipboard.writeText(prompt);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    const s = severity.toLowerCase();
    if (s === "critical") return "bg-rose-50 text-rose-700 border-rose-200";
    if (s === "high") return "bg-amber-50 text-amber-700 border-amber-200";
    if (s === "medium") return "bg-yellow-50 text-yellow-700 border-yellow-200";
    return "bg-blue-50 text-blue-700 border-blue-200";
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-900/60 backdrop-blur-xs flex justify-end">
      <div className="w-full max-w-2xl bg-[#EEF4FB] border-l border-[#DCE5F0] text-[#111827] h-full overflow-y-auto flex flex-col shadow-2xl animate-in slide-in-from-right duration-300">

        {/* Header */}
        <div className="p-6 border-b border-[#DCE5F0] bg-white flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded border ${getSeverityBadge(finding.severity)}`}>
                {finding.severity.toUpperCase()}
              </span>
              {finding.cwe && (
                <span className="px-2 py-0.5 text-xs font-mono bg-slate-100 border border-[#DCE5F0] text-slate-600 rounded">
                  {finding.cwe}
                </span>
              )}
              {finding.owasp && (
                <span className="px-2 py-0.5 text-xs font-mono bg-slate-100 border border-[#DCE5F0] text-slate-600 rounded">
                  OWASP {finding.owasp}
                </span>
              )}
              {finding.is_exploitable && (
                <span className="px-2 py-0.5 text-xs font-mono bg-rose-50 border border-rose-200 text-rose-700 rounded flex items-center gap-1 font-bold">
                  <ShieldAlert className="w-3 h-3" /> REACHABLE
                </span>
              )}
            </div>
            <h2 className="text-lg font-bold text-[#111827] font-mono">{finding.category}</h2>
            <p className="text-xs text-slate-500 font-mono mt-1">
              {finding.file}:{finding.line}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-[#111827] hover:bg-slate-100 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 flex-1 overflow-y-auto bg-slate-50/50">

          {/* Exploitability Meter */}
          {finding.exploitability_score !== undefined && (
            <div className="bg-white border border-[#DCE5F0] p-4 rounded-xl shadow-sm">
              <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500">
                  Exploitability Feasibility Score
                </span>
                <span className="text-sm font-bold font-mono text-blue-600">
                  {Math.round((finding.exploitability_score || 0) * 100)}%
                </span>
              </div>
              <div className="w-full bg-slate-100 h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-blue-600 h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.round((finding.exploitability_score || 0) * 100)}%` }}
                />
              </div>
            </div>
          )}

          {/* Exploit Scenario */}
          {finding.exploit_scenario && (
            <div className="bg-white border border-rose-200 p-4 rounded-xl space-y-2 shadow-sm">
              <h3 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-rose-700 flex items-center gap-1.5 font-bold">
                <AlertTriangle className="w-3.5 h-3.5" /> EXPLOIT SCENARIO
              </h3>
              <p className="text-sm text-slate-700 leading-relaxed">{finding.exploit_scenario}</p>
            </div>
          )}

          {/* Code Snippet */}
          <div className="space-y-2">
            <h3 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-slate-500 flex items-center gap-1.5">
              <Code className="w-3.5 h-3.5 text-blue-600" /> VULNERABLE SNIPPET
            </h3>
            <pre className="p-4 rounded-xl bg-[#0F172A] border border-slate-800 text-xs font-mono text-slate-200 overflow-x-auto shadow-inner">
              <code>{finding.snippet}</code>
            </pre>
          </div>

          {/* Recommendation */}
          <div className="bg-emerald-50 border border-emerald-200 p-4 rounded-xl space-y-2 shadow-sm">
            <h3 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-emerald-800 font-bold">
              REMEDIATION GUIDANCE
            </h3>
            <p className="text-sm text-emerald-900 leading-relaxed">{finding.recommendation}</p>
          </div>

        </div>

        {/* Action Buttons Footer */}
        <div className="p-6 border-t border-[#DCE5F0] bg-white flex flex-wrap items-center justify-between gap-3">
          <button
            onClick={handleCopyAgentInstructions}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-[#111827] font-mono text-xs border border-[#DCE5F0] transition font-semibold"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-600" /> : <Copy className="w-4 h-4" />}
            {copied ? "COPIED!" : "COPY AGENT INSTRUCTIONS"}
          </button>

          {onDiscussInChat && (
            <button
              onClick={() => onDiscussInChat(finding)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-mono text-xs transition font-semibold shadow-xs"
            >
              <MessageSquare className="w-4 h-4" />
              DISCUSS IN CHAT
            </button>
          )}
        </div>

      </div>
    </div>
  );
};

export default FindingDrawer;
