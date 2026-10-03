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
    <div className="h-full bg-white border-r border-slate-200 flex flex-col p-4 overflow-y-auto">
      <div className="flex items-center gap-2 pb-4 border-b border-slate-200 mb-4">
        {isError ? (
          <Circle className="w-4 h-4 text-red-600 shrink-0" />
        ) : (
          <Loader2 className="w-4 h-4 text-[#2563EB] animate-spin shrink-0" />
        )}
        <span className={`text-[13px] font-sans font-semibold tracking-[0.04em] leading-[1.4] ${isError ? "text-red-600" : "text-slate-900"}`}>
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
                  ? "bg-[#EFF6FF] border-[#BFDBFE] text-slate-900"
                  : isDone
                  ? "bg-emerald-50 border-emerald-200 text-slate-900"
                  : "bg-[#F8FAFC] border-slate-200 text-slate-400"
              }`}
            >
              <div className="mt-0.5 shrink-0">
                {isDone ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                ) : isRunning ? (
                  <Loader2 className="w-4 h-4 text-[#2563EB] animate-spin" />
                ) : (
                  <Circle className="w-4 h-4 text-slate-300" />
                )}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span
                    className={`text-[14px] font-sans font-semibold leading-[1.4] truncate ${
                      isRunning
                        ? "text-[#2563EB]"
                        : isDone
                        ? "text-emerald-700"
                        : "text-[#64748B]"
                    }`}
                  >
                    {s.label}
                  </span>
                </div>
                <p className="text-[13px] font-sans font-normal leading-[1.4] text-[#64748B] mt-0.5 truncate">
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
