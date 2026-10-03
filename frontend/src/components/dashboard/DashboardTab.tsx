"use client";

import React, { useEffect, useState } from "react";
import {
  Shield, Code2, BookText, Network, Play, ArrowRight,
  Sparkles, CheckCircle2, Loader2, ScanLine, Layers, ShieldCheck,
  Activity, ArrowUpRight
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface DeterministicScanListItem {
  scan_id: string;
  target?: string;
  created_at?: number;
  scan?: { total_findings?: number; by_severity?: Record<string, number> };
}

interface AgenticScanListItem {
  scan_id: string;
  status: string;
  source_scan_id?: string | null;
  started_at?: number;
  agentic_summary?: {
    correlated_risks?: number;
    business_violations?: number;
    attack_paths?: number;
    remediation_proposals?: number;
    validated_patches?: number;
  } | null;
}

function formatTimestamp(unixSeconds?: number): string {
  if (!unixSeconds) return "unknown time";
  try {
    return new Date(unixSeconds * 1000).toLocaleString();
  } catch {
    return "unknown time";
  }
}

function QuickAction({ icon: Icon, label, onClick }: { icon: React.ComponentType<any>; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-3 px-4 py-3.5 rounded-xl bg-white border border-[#174A85] hover:border-[#BFDBFE] hover:bg-[#EFF6FF] hover:shadow-sm transition-all group flex-1 min-w-[180px]"
    >
      <div className="w-8 h-8 rounded-lg bg-[#F8FAFC] group-hover:bg-[#EFF6FF] flex items-center justify-center transition-colors shrink-0">
        <Icon className="w-5 h-5 text-[#64748B] group-hover:text-[#2563EB] transition-colors" />
      </div>
      <span className="text-sm md:text-base font-semibold text-[#111827] group-hover:text-[#2563EB] transition-colors">{label}</span>
      <ArrowRight className="w-4 h-4 text-[#94A3B8] ml-auto group-hover:text-[#2563EB] group-hover:translate-x-0.5 transition-all shrink-0" />
    </button>
  );
}

export interface DashboardTabProps {
  report: any;
  currentScanId: string | null;
  agenticWorkflowStatus: "idle" | "starting" | "running" | "completed" | "error" | "cancelled";
  agenticMatchesCurrentScan: boolean;
  agenticSummary: AgenticScanListItem["agentic_summary"];
  navigateTo: (tabId: string) => void;
  onRunAgentic: () => void;
}

export default function DashboardTab({
  report, currentScanId, agenticWorkflowStatus, agenticMatchesCurrentScan,
  agenticSummary, navigateTo, onRunAgentic,
}: DashboardTabProps) {
  const [scans, setScans] = useState<DeterministicScanListItem[]>([]);
  const [agenticRuns, setAgenticRuns] = useState<AgenticScanListItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch(`${API_BASE}/api/v1/scans`).then((r) => (r.ok ? r.json() : [])).catch(() => []),
      fetch(`${API_BASE}/api/v1/agentic-scan`).then((r) => (r.ok ? r.json() : [])).catch(() => []),
    ])
      .then(([scanList, agenticList]) => {
        if (cancelled) return;
        setScans(Array.isArray(scanList) ? scanList : []);
        setAgenticRuns(Array.isArray(agenticList) ? agenticList : []);
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [agenticWorkflowStatus]);

  const latestScan = scans.length > 0 ? scans[scans.length - 1] : null;
  const bySeverity = latestScan?.scan?.by_severity || {};
  const recentAgenticRuns = [...agenticRuns]
    .sort((a, b) => (b.started_at || 0) - (a.started_at || 0))
    .slice(0, 5);

  const totalValidatedPatches = agenticRuns.reduce(
    (sum, r) => sum + (r.agentic_summary?.validated_patches || 0), 0
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="rounded-2xl bg-white border border-slate-200 p-6 flex items-center justify-between flex-wrap gap-4 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-[#2563EB] shadow-xs shrink-0">
            <Shield className="w-6 h-6 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-[28px] font-bold text-slate-900 tracking-tight leading-tight">AI CODE GUARDIAN</h1>
              <span className="text-xs font-mono font-semibold px-2.5 py-0.5 rounded-full bg-blue-50 text-[#2563EB] border border-blue-200">v2.1.0</span>
            </div>
            <p className="text-sm text-slate-600 mt-1 leading-relaxed">Multi-language, evidence-grounded code analysis platform</p>
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div className="space-y-3">
        <div className="text-xs font-medium text-slate-500 uppercase tracking-wider flex items-center gap-2">
          <Activity className="w-4 h-4 text-[#2563EB]" />
          <span className="text-base font-semibold text-slate-900">Quick Actions</span>
        </div>
        <div className="flex flex-wrap gap-3">
          <QuickAction icon={Code2} label="Start New Scan" onClick={() => navigateTo("workspace")} />
          <QuickAction icon={BookText} label="Upload Business Rules" onClick={() => navigateTo("business_intent")} />
          <QuickAction icon={Network} label="Open Mind Map" onClick={() => navigateTo("mindmap")} />
        </div>
      </div>

      {/* Latest deterministic scan */}
      <div className="rounded-2xl bg-white border border-slate-200 p-6 space-y-4 shadow-sm">
        <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider flex items-center justify-between">
          <span className="flex items-center gap-2 text-base font-semibold text-slate-900 normal-case">
            <ScanLine className="w-5 h-5 text-[#2563EB]" />
            <span>Latest Deterministic Scan</span>
          </span>
          {latestScan && (
            <span className="text-xs font-mono text-slate-500 bg-slate-100 px-2.5 py-1 rounded border border-slate-200">
              ID: {latestScan.scan_id}
            </span>
          )}
        </div>
        {!latestScan ? (
          <p className="text-sm md:text-base font-normal text-slate-600">No scans yet — start one from IDE Workspace.</p>
        ) : (
          <>
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 text-sm text-slate-900">
                <ScanLine className="w-4 h-4 text-[#2563EB]" />
                <span className="font-semibold text-base text-slate-900">{latestScan.target || latestScan.scan_id}</span>
                <span className="text-xs font-medium text-slate-700 bg-slate-100 px-2.5 py-1 rounded border border-slate-200">
                  {latestScan.scan?.total_findings ?? 0} findings
                </span>
              </div>
              <button
                onClick={() => navigateTo("workspace")}
                className="text-sm font-semibold text-[#2563EB] hover:text-[#1D4ED8] flex items-center gap-1 transition"
              >
                View in IDE Workspace <ArrowRight className="w-4 h-4" />
              </button>
            </div>

            {/* Severity Breakdown Badges */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
              {[
                { sev: "Critical", count: bySeverity["Critical"] ?? bySeverity["CRITICAL"] ?? 0, color: "text-red-700 bg-red-50 border-red-200" },
                { sev: "High", count: bySeverity["High"] ?? bySeverity["HIGH"] ?? 0, color: "text-orange-700 bg-orange-50 border-orange-200" },
                { sev: "Medium", count: bySeverity["Medium"] ?? bySeverity["MEDIUM"] ?? 0, color: "text-amber-700 bg-amber-50 border-amber-200" },
                { sev: "Low", count: bySeverity["Low"] ?? bySeverity["LOW"] ?? 0, color: "text-blue-700 bg-blue-50 border-blue-200" },
              ].map(({ sev, count, color }) => (
                <div key={sev} className={`px-3.5 py-2.5 rounded-lg border flex items-center justify-between text-xs font-medium ${color}`}>
                  <span className="font-semibold uppercase tracking-wider">{sev}</span>
                  <b className="text-sm font-bold">{count}</b>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-slate-200">
              {agenticWorkflowStatus === "running" || agenticWorkflowStatus === "starting" ? (
                <div className="flex items-center gap-2 text-sm text-blue-700 bg-blue-50 p-3 rounded-lg border border-blue-200 font-medium">
                  <Loader2 className="w-4 h-4 animate-spin" /> Agentic analysis running…
                </div>
              ) : agenticMatchesCurrentScan && agenticWorkflowStatus === "completed" ? (
                <div className="flex items-center justify-between flex-wrap gap-2 bg-emerald-50 p-3 rounded-lg border border-emerald-200">
                  <div className="flex items-center gap-2 text-sm text-emerald-700 font-medium">
                    <CheckCircle2 className="w-4 h-4" />
                    <span className="font-semibold">Agentic Status: Complete</span>
                    {typeof agenticSummary?.correlated_risks === "number" && (
                      <span className="text-slate-600">· {agenticSummary.correlated_risks} correlated risks</span>
                    )}
                  </div>
                  <button
                    onClick={() => navigateTo("security_compliance")}
                    className="text-sm font-semibold text-[#2563EB] hover:text-[#1D4ED8] flex items-center gap-1 transition"
                  >
                    View AI Results in Security Tab <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              ) : (
                <button
                  onClick={onRunAgentic}
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-semibold uppercase tracking-wide bg-[#EFF6FF] text-[#2563EB] border border-[#BFDBFE] hover:bg-[#DBEAFE] transition-all shadow-sm"
                >
                  <Play className="w-4 h-4 fill-current" /> Run Agentic Analysis
                </button>
              )}
            </div>
          </>
        )}
      </div>

      {/* Agentic run history */}
      <div className="rounded-2xl bg-white border border-slate-200 p-6 space-y-4 shadow-sm">
        <div className="text-base font-semibold text-slate-900 flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-[#2563EB]" />
          <span>Agentic Run History</span>
        </div>
        {loading ? (
          <p className="text-sm text-slate-400">Loading…</p>
        ) : recentAgenticRuns.length === 0 ? (
          <p className="text-sm md:text-base font-normal text-slate-600">No agentic runs yet.</p>
        ) : (
          <div className="space-y-2.5">
            {recentAgenticRuns.map((r) => (
              <div key={r.scan_id} className="flex items-center justify-between gap-3 text-sm px-4 py-3 rounded-xl bg-[#F8FAFC] border border-slate-200 hover:border-blue-200 transition flex-wrap">
                <span className="text-slate-700 font-medium">{formatTimestamp(r.started_at)}</span>
                <span className={`font-semibold uppercase px-2.5 py-0.5 rounded text-xs ${
                  r.status === "completed" ? "bg-emerald-50 text-emerald-700 border border-emerald-200" :
                  r.status === "error" ? "bg-red-50 text-red-700 border border-red-200" :
                  r.status === "cancelled" ? "bg-amber-50 text-amber-700 border border-amber-200" :
                  "bg-slate-100 text-slate-700 border border-slate-200"
                }`}>{r.status}</span>
                <span className="text-slate-600">{r.agentic_summary?.validated_patches ?? 0} validated patch{(r.agentic_summary?.validated_patches ?? 0) === 1 ? "" : "es"}</span>
                <span className="text-slate-600">{r.agentic_summary?.correlated_risks ?? 0} correlated</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Platform stats */}
      <div className="rounded-2xl bg-white border border-slate-200 p-6 shadow-sm space-y-4">
        <div className="text-base font-semibold text-slate-900 flex items-center gap-2">
          <Layers className="w-5 h-5 text-[#2563EB]" />
          <span>Platform Stats</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { icon: Layers, label: "Total Scans", value: scans.length, color: "text-[#2563EB]" },
            { icon: Sparkles, label: "Agentic Runs", value: agenticRuns.length, color: "text-[#2563EB]" },
            { icon: ShieldCheck, label: "Validated Patches", value: totalValidatedPatches, color: "text-emerald-600" },
          ].map((s) => (
            <div key={s.label} className="p-4 rounded-xl bg-[#F8FAFC] border border-slate-200 hover:border-blue-200 transition flex items-center gap-4">
              <div className="w-11 h-11 rounded-xl bg-white flex items-center justify-center shrink-0 border border-slate-200 shadow-xs">
                <s.icon className={`w-5 h-5 ${s.color}`} />
              </div>
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">{s.label}</div>
                <div className="text-3xl font-bold text-slate-900 mt-0.5">{s.value}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
