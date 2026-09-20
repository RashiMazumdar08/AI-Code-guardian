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
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-mono font-semibold select-none">
            <CheckCircle2 className="h-3 w-3 text-emerald-400" />
            RESULTS READY
          </div>
        );
      case "AGENTIC_RUNNING":
        return (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#ff5400]/15 border border-[#ff5400]/40 text-[#ff5400] text-[10px] font-mono font-semibold select-none animate-pulse">
            <Sparkles className="h-3 w-3 text-[#ff5400]" />
            AI ANALYSIS ACTIVE
          </div>
        );
      case "AGENTIC_COMPLETE":
        return (
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-500/15 border border-amber-500/40 text-amber-300 text-[10px] font-mono font-semibold select-none">
            <Sparkles className="h-3 w-3 text-amber-300" />
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
          <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white/8 border border-white/20 text-[#f4f4f8] text-[10px] font-mono font-semibold select-none">
            <Shield className="h-3 w-3 text-[#8e8e9a]" />
            DETERMINISTIC SCAN
          </div>
        );
    }
  };

  return (
    <div className="w-full bg-[#12131a] border border-white/8 text-[#f4f4f8] rounded-xl overflow-hidden shadow-lg">
      <div className="p-4">
        <form onSubmit={handleSubmit} className="flex flex-wrap md:flex-nowrap items-end gap-4">

          {/* URL Input */}
          <div className="flex-1 space-y-2">
            <label htmlFor="targetInput" className="text-[11px] font-mono font-semibold tracking-wider text-[#8e8e9a] uppercase flex items-center gap-2">
              <FolderGit2 className="h-3.5 w-3.5 text-[#ff5400]" />
              GITHUB REPOSITORY URL
            </label>
            <div className="relative flex items-center">
              <Search className="absolute left-3 h-3.5 w-3.5 text-[#8e8e9a]" />
              <input
                id="targetInput"
                type="text"
                placeholder="https://github.com/user/repository"
                className="w-full h-10 pl-10 pr-3 rounded-lg glass-input text-sm font-mono placeholder:text-[#8e8e9a]/50 focus:outline-none disabled:opacity-50"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={isScanning}
              />
            </div>
          </div>

          {/* Dynamic Status Badges */}
          <div className="flex items-center gap-2.5 pb-1 shrink-0">
            <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500/8 border border-emerald-500/20 text-emerald-400 text-[10px] font-mono font-semibold select-none">
              <CheckCircle2 className="h-3 w-3" />
              GITHUB URL
            </div>

            {renderBadge()}
          </div>

          {/* Run Scan Button */}
          <button
            type="submit"
            disabled={!target.trim() || isScanning}
            className="h-10 px-5 py-2 rounded-lg flex items-center justify-center w-full md:w-36 glass-button font-mono text-xs font-bold tracking-wider transition-all disabled:opacity-40 disabled:cursor-not-allowed disabled:transform-none"
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
