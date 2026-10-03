"use client";

import React from "react";
import { Search, FolderGit2, Loader2, Play, CheckCircle2, Sparkles, Shield } from "lucide-react";
import { useScanState } from "../../context/ScanStateContext";

interface RepoInputProps {
  onScan: (target: string, isUrl: boolean, aiEnabled: boolean) => void;
  isScanning?: boolean;
}

export default function RepoInput({ onScan }: RepoInputProps) {
  const [target, setTarget] = React.useState("");
  const { scanPhase } = useScanState();

  const isScanning = ["FETCHING", "WALKING", "PARSING", "SCANNING"].includes(scanPhase);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || isScanning) return;
    const isUrl = target.includes("github.com") || target.startsWith("http://") || target.startsWith("https://");
    onScan(target.trim(), isUrl, false);
  };

  const renderBadge = () => {
    switch (scanPhase) {
      case "COMPLETE":
        return (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-[12px] font-sans font-semibold leading-[1.3] select-none">
            <CheckCircle2 className="h-3 w-3 text-emerald-600" />
            RESULTS READY
          </div>
        );
      case "AGENTIC_RUNNING":
        return (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#EFF6FF] border border-[#BFDBFE] text-[#2563EB] text-[12px] font-sans font-semibold leading-[1.3] select-none animate-pulse">
            <Sparkles className="h-3 w-3 text-[#2563EB]" />
            AI ANALYSIS ACTIVE
          </div>
        );
      case "AGENTIC_COMPLETE":
        return (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-50 border border-amber-200 text-amber-800 text-[12px] font-sans font-semibold leading-[1.3] select-none">
            <Sparkles className="h-3 w-3 text-amber-600" />
            AI ENRICHMENT READY
          </div>
        );
      case "FETCHING":
      case "WALKING":
      case "PARSING":
      case "SCANNING":
      case "IDLE":
      default:
        return (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#F8FAFC] border border-slate-200 text-slate-600 text-[12px] font-sans font-semibold leading-[1.3] select-none">
            <Shield className="h-3 w-3 text-slate-500" />
            DETERMINISTIC SCAN
          </div>
        );
    }
  };

  return (
    <div className="w-full bg-white border border-slate-200 text-slate-900 rounded-2xl overflow-hidden shadow-sm">
      <div className="p-6">
        <form onSubmit={handleSubmit} className="flex flex-wrap md:flex-nowrap items-end gap-4">

          {/* URL Input */}
          <div className="flex-1 space-y-2">
            <label htmlFor="targetInput" className="text-[13px] font-sans font-semibold tracking-[0.04em] leading-[1.4] text-[#64748B] uppercase flex items-center gap-2">
              <FolderGit2 className="h-3.5 w-3.5 text-[#2563EB]" />
              GITHUB REPOSITORY URL
            </label>
            <div className="relative flex items-center">
              <Search className="absolute left-3 h-3.5 w-3.5 text-[#94A3B8]" />
              <input
                id="targetInput"
                type="text"
                placeholder="https://github.com/user/repository"
                className="w-full h-10 pl-10 pr-3 rounded-lg glass-input text-[16px] font-sans font-normal leading-[1.5] text-slate-900 placeholder:text-[#94A3B8] focus:outline-none disabled:opacity-50"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
              />
            </div>
          </div>

          {/* Dynamic Status Badges */}
          <div className="flex items-center gap-2.5 pb-1 shrink-0">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-700 text-[12px] font-sans font-semibold leading-[1.3] select-none">
              <CheckCircle2 className="h-3 w-3 text-emerald-600" />
              GITHUB URL
            </div>

            {renderBadge()}
          </div>

          {/* Run Scan Button */}
          <button
            type="submit"
            disabled={!target.trim() || isScanning}
            className="h-10 px-5 py-2 rounded-lg flex items-center justify-center w-full md:w-36 glass-button font-sans text-[14px] font-semibold leading-[1.4] tracking-normal transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none"
          >
            {isScanning ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                {scanPhase === "FETCHING" ? "FETCHING" : scanPhase === "PARSING" ? "PARSING" : "SCANNING"}
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4" />
                RUN SCAN
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
