"use client";

import React, { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Circle, Shield, Code2, Search, FileCode, Cpu, Layers } from "lucide-react";

interface ScanProgressPanelProps {
  scanId: string | null;
  apiBase: string;
  isScanning: boolean;
}

interface StatusData {
  scan_id?: string;
  stage?: string;
  status?: string;
  files_done?: number;
  files_total?: number;
  stage_timings?: Record<string, number>;
}

export default function ScanProgressPanel({ scanId, apiBase, isScanning }: ScanProgressPanelProps) {
  const [status, setStatus] = useState<StatusData | null>(null);

  useEffect(() => {
    if (!isScanning || !scanId) return;

    let isMounted = true;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${apiBase}/api/v1/scans/${scanId}/status`);
        if (res.ok && isMounted) {
          const data = await res.json();
          setStatus(data);
        }
      } catch (err) {
        console.warn("Scan status polling error:", err);
      }
    }, 250);

    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [scanId, isScanning, apiBase]);

  const currentStage = status?.stage || "github_fetch";
  const timings = status?.stage_timings || {};
  const filesDone = status?.files_done || 0;
  const filesTotal = status?.files_total || 0;

  const STAGES = [
    {
      id: "github_fetch",
      label: "Repository Fetch",
      icon: Search,
      getDescription: (isDone: boolean, isRunning: boolean) => {
        if (isDone) return `Repository fetched (${timings.github_fetch?.toFixed(1) || "0.1"}s)`;
        if (isRunning) return "Fetching repository source...";
        return "Repository fetch pending";
      },
    },
    {
      id: "file_walk",
      label: "File Discovery",
      icon: Code2,
      getDescription: (isDone: boolean, isRunning: boolean) => {
        if (isDone) {
          const count = status?.files_total || filesTotal || 0;
          return `${count > 0 ? count : "Files"} discovered (${timings.file_walk?.toFixed(1) || "0.1"}s)`;
        }
        if (isRunning) return "Discovering repository files...";
        return "File discovery pending";
      },
    },
    {
      id: "ust_parse",
      label: "UST Parsing",
      icon: FileCode,
      getDescription: (isDone: boolean, isRunning: boolean) => {
        if (isDone) return `Parsed UST (${timings.ust_parse?.toFixed(1) || "1.9"}s)`;
        if (isRunning) return `Parsing UST... ${filesDone}/${filesTotal || "..."}`;
        return "UST parsing pending";
      },
    },
    {
      id: "sast_rules",
      label: "Security Rules",
      icon: Shield,
      getDescription: (isDone: boolean, isRunning: boolean) => {
        if (isDone) return `Security rules scanned (${timings.sast_rules?.toFixed(1) || "0.4"}s)`;
        if (isRunning) return "Evaluating SAST security rules...";
        return "Security rules pending";
      },
    },
    {
      id: "dependency_scan",
      label: "Dependency Scan",
      icon: Layers,
      getDescription: (isDone: boolean, isRunning: boolean) => {
        if (isDone) return `Dependency scan complete (${timings.dependency_scan?.toFixed(1) || "85.0"}s)`;
        if (isRunning) return "Analyzing dependencies & manifests...";
        return "Dependency scan pending";
      },
    },
    {
      id: "risk_business",
      label: "Risk & Business Intent",
      icon: Cpu,
      getDescription: (isDone: boolean, isRunning: boolean) => {
        if (isDone) return `Risk & intent evaluated (${timings.risk_business?.toFixed(1) || "5.7"}s)`;
        if (isRunning) return "Calculating unified risk score...";
        return "Risk evaluation pending";
      },
    },
  ];

  const getStageState = (stageId: string) => {
    const stageOrder = ["github_fetch", "file_walk", "ust_parse", "sast_rules", "dependency_scan", "risk_business", "complete"];
    const currentIdx = stageOrder.indexOf(currentStage);
    const targetIdx = stageOrder.indexOf(stageId);

    if (currentStage === "complete" || currentIdx > targetIdx) {
      return "done";
    }
    if (currentStage === stageId) {
      return "running";
    }
    return "pending";
  };

  const isError = status?.status === "error";

  return (
    <div className="h-full bg-[#0c0d11] border-r border-white/8 flex flex-col p-4 overflow-y-auto">
      <div className="flex items-center gap-2 pb-4 border-b border-white/8 mb-4">
        {isError ? (
          <Circle className="w-4 h-4 text-red-500 shrink-0" />
        ) : (
          <Loader2 className="w-4 h-4 text-[#ff5400] animate-spin shrink-0" />
        )}
        <span className={`text-xs font-mono font-bold tracking-wider ${isError ? "text-red-400" : "text-[#f4f4f8]"}`}>
          {isError ? "SCAN FAILED" : "SCAN IN PROGRESS"}
        </span>
      </div>

      <div className="space-y-3 flex-1">
        {STAGES.map((s) => {
          const state = getStageState(s.id);
          const isDone = state === "done";
          const isRunning = state === "running";

          return (
            <div
              key={s.id}
              className={`flex items-start gap-3 p-2.5 rounded-lg border transition-all ${
                isRunning
                  ? "bg-[#ff5400]/10 border-[#ff5400]/30 text-[#f4f4f8]"
                  : isDone
                  ? "bg-emerald-500/5 border-emerald-500/20 text-[#f4f4f8]"
                  : "bg-white/[0.02] border-white/5 text-[#8e8e9a]/50"
              }`}
            >
              <div className="mt-0.5 shrink-0">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                ) : isRunning ? (
                  <Loader2 className="w-4 h-4 text-[#ff5400] animate-spin" />
                ) : (
                  <Circle className="w-4 h-4 text-[#8e8e9a]/30" />
                )}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={`text-xs font-mono font-semibold truncate ${
                      isRunning
                        ? "text-[#ff5400]"
                        : isDone
                        ? "text-emerald-400"
                        : "text-[#8e8e9a]/60"
                    }`}
                  >
                    {s.label}
                  </span>
                </div>
                <p className="text-[11px] font-mono text-[#8e8e9a] mt-0.5 truncate">
                  {s.getDescription(isDone, isRunning)}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
