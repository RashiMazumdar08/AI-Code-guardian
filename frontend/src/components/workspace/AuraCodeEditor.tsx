"use client";

import React, { useState, useEffect, useRef } from "react";
import {
  Check,
  FileCode2,
  PanelRightClose,
  PanelRightOpen,
  ShieldAlert,
} from "lucide-react";

interface AuraCodeEditorProps {
  filePath: string;
  content: string;
  findings: any[];
  onApplyFix?: (finding: any) => void;
  onToggleRightPane?: () => void;
  isRightPaneOpen?: boolean;
  onContentChange?: (newContent: string) => void;
}

export default function AuraCodeEditor({
  filePath,
  content,
  findings,
  onApplyFix,
  onToggleRightPane,
  isRightPaneOpen = true,
  onContentChange,
}: AuraCodeEditorProps) {
  const [acceptedFixes, setAcceptedFixes] = useState<Record<number, boolean>>({});
  const vulnLineRef = useRef<HTMLDivElement | null>(null);
  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  /* Default sample code */
  const defaultCode = `import requests
from flask import jsonify
import logging

logger = logging.getLogger(__name__)

# Fetch remote security findings from scanning node
def fetch_findings(endpoint):
    logger.info(f"Connecting to security endpoint: {endpoint}")
    
    # ⚠️ VULNERABLE LINE: Disables TLS certificate verification
    resp = requests.get(endpoint, verify=False, timeout=30)
    
    if resp.status_code != 200:
        return jsonify({"error": "Fetch failed", "status": resp.status_code})
        
    return resp.json()

def post_autofix(url, payload):
    # ⚠️ VULNERABLE LINE: No cert verification
    return requests.post(url, json=payload, verify=False)
`;

  const displayCode = content || defaultCode;
  const lines = displayCode.split("\n");

  /* Identify vulnerable line index */
  const vulnLineIndex = findings.length > 0
    ? (findings[0].line || findings[0].line_number || 12) - 1
    : 11; // default line 12

  const primaryFinding = findings[0] || {
    category: "Improper Certificate Validation",
    cwe: "CWE-295",
    severity: "CRITICAL",
    line: 12,
  };

  /* Auto-scroll to vulnerable line when file opens */
  useEffect(() => {
    if (vulnLineRef.current) {
      setTimeout(() => {
        vulnLineRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "center",
        });
      }, 100);
    }
  }, [filePath, findings]);

  const handleAcceptFix = (lineIdx: number) => {
    setAcceptedFixes((prev) => ({ ...prev, [lineIdx]: true }));

    if (onApplyFix) {
      onApplyFix(primaryFinding);
    } else if (onContentChange) {
      const updatedLines = [...lines];
      const orig = updatedLines[lineIdx];
      const indent = orig.match(/^(\s*)/)?.[1] || "";
      if (orig.includes("verify=False")) {
        updatedLines[lineIdx] = orig.replace("verify=False", "verify=certifi.where(), timeout=10");
      } else {
        updatedLines[lineIdx] = `${indent}resp = requests.get(endpoint, verify=certifi.where(), timeout=10)`;
      }
      onContentChange(updatedLines.join("\n"));
    }
  };

  return (
    <div className="h-full flex flex-col bg-[#090D16] border-r border-slate-800 text-slate-200 font-sans">
      
      {/* Editor Header / Tab Bar */}
      <div className="px-4 py-2 bg-[#111726] border-b border-slate-800 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2 overflow-hidden">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#090D16] border border-slate-800 text-xs font-mono text-white">
            <FileCode2 className="w-3.5 h-3.5 text-[#FF5E1E]" />
            <span className="font-semibold truncate">
              {filePath || "backend/app/api/v1/findings.py"}
            </span>
            {findings.length > 0 && !acceptedFixes[vulnLineIndex] && (
              <span className="flex items-center gap-1 text-[10px] font-mono text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20 ml-1">
                <ShieldAlert className="w-3 h-3" />
                Line {vulnLineIndex + 1}
              </span>
            )}
          </div>
        </div>

        {/* Toggle Right Pane Button */}
        <button
          onClick={onToggleRightPane}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-mono font-semibold text-slate-400 hover:text-white hover:bg-white/5 border border-slate-800 transition-colors"
          title={isRightPaneOpen ? "Hide Vulnerability Insight Pane" : "Show Vulnerability Insight Pane"}
        >
          {isRightPaneOpen ? (
            <>
              <PanelRightClose className="w-4 h-4 text-slate-300" />
              <span className="hidden sm:inline">Hide Info</span>
            </>
          ) : (
            <>
              <PanelRightOpen className="w-4 h-4 text-[#FF5E1E]" />
              <span className="hidden sm:inline">AI Insight</span>
            </>
          )}
        </button>
      </div>

      {/* Code Editor Viewport with Auto-Scroll */}
      <div
        ref={scrollContainerRef}
        className="flex-1 overflow-auto p-4 font-mono text-xs leading-relaxed"
        style={{ scrollbarWidth: "thin", scrollbarColor: "rgba(148,163,184,0.15) transparent" }}
      >
        <div className="bg-[#111726] rounded-xl border border-slate-800 overflow-hidden shadow-2xl">
          {lines.map((lineText, idx) => {
            const lineNum = idx + 1;
            const isVuln = idx === vulnLineIndex && !acceptedFixes[idx];

            return (
              <React.Fragment key={idx}>
                {/* Standard Code Line OR Red Highlighted Vulnerable Line */}
                <div
                  ref={idx === vulnLineIndex ? vulnLineRef : null}
                  className={`flex items-stretch transition-colors duration-150 ${
                    isVuln
                      ? "bg-red-500/20 border-l-4 border-red-500 text-red-200 font-semibold"
                      : "hover:bg-white/2 text-slate-300 border-l-4 border-transparent"
                  }`}
                >
                  {/* Line Number */}
                  <span
                    className={`w-12 text-right pr-3 select-none shrink-0 py-1 font-mono text-[11px] border-r border-slate-800/80 ${
                      isVuln
                        ? "bg-red-950/60 text-red-300 font-bold"
                        : "text-slate-600"
                    }`}
                  >
                    {lineNum}
                  </span>

                  {/* Diff Marker (- for red, space for normal) */}
                  <span
                    className={`w-5 text-center shrink-0 py-1 select-none font-extrabold ${
                      isVuln ? "text-red-400" : "text-transparent"
                    }`}
                  >
                    {isVuln ? "-" : " "}
                  </span>

                  {/* Code Line */}
                  <div className="py-1 px-2 whitespace-pre flex-1 font-mono">
                    <span className={isVuln ? "text-red-200 font-semibold" : "text-slate-300"}>
                      {lineText}
                    </span>
                  </div>
                </div>

                {/* GREEN REPLACEMENT LINE WITH JUST A TICK MARK BUTTON TO REPLACE IT */}
                {isVuln && (
                  <div className="flex items-stretch bg-emerald-950/60 border-l-4 border-[#22C55E] text-emerald-200 my-0.5 font-semibold">
                    {/* Line Number area */}
                    <span className="w-12 text-right pr-3 select-none shrink-0 py-1 font-mono text-[11px] bg-emerald-950 text-emerald-400 font-bold border-r border-slate-800/80">
                      +
                    </span>

                    {/* Diff marker */}
                    <span className="w-5 text-center shrink-0 py-1 select-none font-extrabold text-[#22C55E]">
                      +
                    </span>

                    {/* Replacement Code Text */}
                    <div className="py-1 px-2 whitespace-pre flex-1 font-mono flex items-center justify-between">
                      <span className="text-emerald-300">
                        resp = requests.get(endpoint, verify=certifi.where(), timeout=10)
                      </span>

                      {/* SIMPLE TICK MARK BUTTON TO REPLACE IT */}
                      <button
                        onClick={() => handleAcceptFix(idx)}
                        className="ml-4 w-7 h-7 rounded-lg flex items-center justify-center text-black font-bold transition-all hover:scale-110 active:scale-95 shadow-md cursor-pointer shrink-0"
                        style={{ background: "#22C55E" }}
                        title="Click ✓ to replace code"
                      >
                        <Check className="w-4 h-4 stroke-[3]" />
                      </button>
                    </div>
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
}
