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
    if (s === "critical") return "bg-red-500/10 text-red-400 border-red-500/30";
    if (s === "high") return "bg-[#ff5400]/10 text-[#ff5400] border-[#ff5400]/30";
    if (s === "medium") return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
    return "bg-white/5 text-[#8e8e9a] border-white/10";
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-md flex justify-end">
      <div className="w-full max-w-2xl bg-[#0c0d11] border-l border-white/8 text-[#f4f4f8] h-full overflow-y-auto flex flex-col shadow-[-20px_0_60px_rgba(0,0,0,0.6)] animate-in slide-in-from-right duration-300">

        {/* Header */}
        <div className="p-6 border-b border-white/8 bg-[#12131a] flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2 flex-wrap">
              <span className={`px-2.5 py-0.5 text-xs font-mono font-bold rounded border ${getSeverityBadge(finding.severity)}`}>
                {finding.severity.toUpperCase()}
              </span>
              {finding.cwe && (
                <span className="px-2 py-0.5 text-xs font-mono bg-[#0c0d11] border border-white/10 text-[#8e8e9a] rounded">
                  {finding.cwe}
                </span>
              )}
              {finding.owasp && (
                <span className="px-2 py-0.5 text-xs font-mono bg-[#0c0d11] border border-white/10 text-[#8e8e9a] rounded">
                  OWASP {finding.owasp}
                </span>
              )}
              {finding.is_exploitable && (
                <span className="px-2 py-0.5 text-xs font-mono bg-red-500/10 border border-red-500/30 text-red-400 rounded flex items-center gap-1">
                  <ShieldAlert className="w-3 h-3" /> REACHABLE
                </span>
              )}
            </div>
            <h2 className="text-lg font-bold text-[#f4f4f8] font-mono">{finding.category}</h2>
            <p className="text-xs text-[#8e8e9a] font-mono mt-1">
              {finding.file}:{finding.line}
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/8 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 space-y-5 flex-1 overflow-y-auto bg-[#0B0F19]">

          {/* Exploitability Meter */}
          {finding.exploitability_score !== undefined && (
            <div className="bg-[#12131a] border border-white/8 p-4 rounded-xl">
              <div className="flex justify-between items-center mb-2">
                <span className="text-[10px] font-mono font-semibold uppercase tracking-wider text-[#8e8e9a]">
                  Exploitability Feasibility Score
                </span>
                <span className="text-sm font-bold font-mono text-[#ff5400]">
                  {Math.round((finding.exploitability_score || 0) * 100)}%
                </span>
              </div>
              <div className="w-full bg-[#0c0d11] h-1.5 rounded-full overflow-hidden">
                <div
                  className="bg-[#ff5400] h-full rounded-full transition-all duration-500"
                  style={{ width: `${Math.round((finding.exploitability_score || 0) * 100)}%` }}
                />
              </div>
            </div>
          )}

          {/* Exploit Scenario */}
          {finding.exploit_scenario && (
            <div className="bg-[#12131a] border border-red-500/15 p-4 rounded-xl space-y-2">
              <h3 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-red-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> EXPLOIT SCENARIO
              </h3>
              <p className="text-sm text-[#f4f4f8] leading-relaxed">{finding.exploit_scenario}</p>
            </div>
          )}

          {/* Code Snippet */}
          <div className="space-y-2">
            <h3 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-[#8e8e9a] flex items-center gap-1.5">
              <Code className="w-3.5 h-3.5" /> VULNERABLE SNIPPET
            </h3>
            <pre className="p-4 rounded-xl bg-[#090a0d] border border-white/8 text-xs font-mono text-[#f4f4f8] overflow-x-auto">
              <code>{finding.snippet}</code>
            </pre>
          </div>

          {/* Recommendation */}
          <div className="bg-[#12131a] border border-emerald-500/15 p-4 rounded-xl space-y-2">
            <h3 className="text-[10px] font-mono font-semibold uppercase tracking-wider text-emerald-400">
              REMEDIATION GUIDANCE
            </h3>
            <p className="text-sm text-[#f4f4f8] leading-relaxed">{finding.recommendation}</p>
          </div>

        </div>

        {/* Action Buttons Footer */}
        <div className="p-6 border-t border-white/8 bg-[#12131a] flex flex-wrap items-center justify-between gap-3">
          <button
            onClick={handleCopyAgentInstructions}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#0c0d11] hover:bg-[#1a1b24] text-[#f4f4f8] font-mono text-xs border border-white/10 hover:border-[#ff5400]/30 transition"
          >
            {copied ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            {copied ? "COPIED!" : "COPY AGENT INSTRUCTIONS"}
          </button>

          {onDiscussInChat && (
            <button
              onClick={() => onDiscussInChat(finding)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-lg glass-button font-mono text-xs transition"
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
