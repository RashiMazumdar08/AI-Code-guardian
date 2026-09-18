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
      className="flex items-center gap-3 px-4 py-3 rounded-xl bg-[#0c0d11] border border-white/8 hover:border-[#ff5400]/40 hover:bg-[#ff5400]/5 hover:shadow-[0_0_15px_rgba(255,84,0,0.1)] transition-all group flex-1 min-w-[180px]"
    >
      <div className="w-7 h-7 rounded-lg bg-white/4 group-hover:bg-[#ff5400]/15 flex items-center justify-center transition-colors">
        <Icon className="w-4 h-4 text-[#8e8e9a] group-hover:text-[#ff5400] transition-colors shrink-0" />
      </div>
      <span className="text-[11px] font-mono font-bold text-[#f4f4f8] group-hover:text-[#ff5400] transition-colors">{label}</span>
      <ArrowRight className="w-3.5 h-3.5 text-[#5c5c68] ml-auto group-hover:text-[#ff5400] group-hover:translate-x-0.5 transition-all" />
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
    <div className="space-y-5">
      {/* Header */}
      <div className="rounded-xl bg-[#12131a] border border-white/10 p-5 flex items-center justify-between flex-wrap gap-3 shadow-lg shadow-black/40">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#ff5400] to-orange-700 border border-[#ff5400]/40 flex items-center justify-center text-white shadow-[0_0_15px_rgba(255,84,0,0.25)]">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-mono font-bold text-[#f4f4f8] tracking-wide uppercase">AI CODE GUARDIAN</h2>
              <span className="text-[9px] font-mono font-bold px-2 py-0.5 rounded bg-white/6 text-[#ff5400] border border-[#ff5400]/30">v2.1.0</span>
            </div>
            <p className="text-[10px] font-mono text-[#8e8e9a] mt-0.5">Multi-language, evidence-grounded code analysis platform</p>
          </div>
        </div>
      </div>

      {/* Quick actions */}
      <div className="space-y-2">
        <div className="text-[9px] font-mono font-semibold text-[#8e8e9a]/80 uppercase tracking-[0.2em] flex items-center gap-1.5">
          <Activity className="w-3 h-3 text-[#ff5400]" />
          <span>Quick Actions</span>
        </div>
        <div className="flex flex-wrap gap-3">
          <QuickAction icon={Code2} label="Start New Scan" onClick={() => navigateTo("workspace")} />
          <QuickAction icon={BookText} label="Upload Business Rules" onClick={() => navigateTo("business_intent")} />
          <QuickAction icon={Network} label="Open Mind Map" onClick={() => navigateTo("mindmap")} />
        </div>
      </div>

      {/* Latest deterministic scan */}
      <div className="rounded-xl bg-[#12131a] border border-white/10 p-5 space-y-4 shadow-md">
        <div className="text-[9px] font-mono font-semibold text-[#8e8e9a]/80 uppercase tracking-[0.2em] flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <ScanLine className="w-3 h-3 text-[#ff5400]" />
            <span>Latest Deterministic Scan</span>
          </span>
          {latestScan && (
            <span className="text-[9px] font-mono text-[#8e8e9a]">
              ID: {latestScan.scan_id}
            </span>
          )}
        </div>
        {!latestScan ? (
          <p className="text-[10.5px] font-mono text-[#5c5c68]">No scans yet — start one from IDE Workspace.</p>
        ) : (
          <>
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2 text-xs font-mono text-[#f4f4f8]">
                <ScanLine className="w-3.5 h-3.5 text-[#ff5400]" />
                <span className="font-bold text-sm text-[#f4f4f8]">{latestScan.target || latestScan.scan_id}</span>
                <span className="text-[#8e8e9a] bg-white/5 px-2 py-0.5 rounded text-[10px]">
                  {latestScan.scan?.total_findings ?? 0} findings
                </span>
              </div>
              <button
                onClick={() => navigateTo("workspace")}
                className="text-[10px] font-mono font-bold text-[#ff5400] hover:text-[#ff7430] flex items-center gap-1 transition"
              >
                View in IDE Workspace <ArrowRight className="w-3 h-3" />
              </button>
            </div>

            {/* Severity Breakdown Badges */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
              {[
                { sev: "Critical", count: bySeverity["Critical"] ?? bySeverity["CRITICAL"] ?? 0, color: "text-red-400 bg-red-500/10 border-red-500/25" },
                { sev: "High", count: bySeverity["High"] ?? bySeverity["HIGH"] ?? 0, color: "text-[#ff5400] bg-[#ff5400]/10 border-[#ff5400]/25" },
                { sev: "Medium", count: bySeverity["Medium"] ?? bySeverity["MEDIUM"] ?? 0, color: "text-amber-400 bg-amber-500/10 border-amber-500/25" },
                { sev: "Low", count: bySeverity["Low"] ?? bySeverity["LOW"] ?? 0, color: "text-sky-400 bg-sky-500/10 border-sky-500/25" },
              ].map(({ sev, count, color }) => (
                <div key={sev} className={`px-3 py-2 rounded-lg border flex items-center justify-between font-mono text-[10.5px] ${color}`}>
                  <span className="font-semibold uppercase tracking-wider">{sev}</span>
                  <b className="text-xs">{count}</b>
                </div>
              ))}
            </div>

            <div className="pt-3 border-t border-white/8">
              {agenticWorkflowStatus === "running" || agenticWorkflowStatus === "starting" ? (
                <div className="flex items-center gap-2 text-[10.5px] font-mono text-violet-300 bg-violet-500/10 p-2.5 rounded-lg border border-violet-500/20">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Agentic analysis running…
                </div>
              ) : agenticMatchesCurrentScan && agenticWorkflowStatus === "completed" ? (
                <div className="flex items-center justify-between flex-wrap gap-2 bg-emerald-500/8 p-2.5 rounded-lg border border-emerald-500/20">
                  <div className="flex items-center gap-2 text-[10.5px] font-mono text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span className="font-bold">Agentic Status: Complete</span>
                    {typeof agenticSummary?.correlated_risks === "number" && (
                      <span className="text-[#8e8e9a]">· {agenticSummary.correlated_risks} correlated risks</span>
                    )}
                  </div>
                  <button
                    onClick={() => navigateTo("security_compliance")}
                    className="text-[10px] font-mono font-bold text-violet-300 hover:text-violet-200 flex items-center gap-1 transition"
                  >
                    View AI Results in Security Tab <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              ) : (
                <button
                  onClick={onRunAgentic}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[10.5px] font-mono font-bold uppercase tracking-wide bg-violet-500/15 text-violet-300 border border-violet-500/30 hover:bg-violet-500/25 transition-all shadow-[0_0_10px_rgba(139,92,246,0.15)]"
                >
                  <Play className="w-3.5 h-3.5 fill-current" /> Run Agentic Analysis
                </button>
              )}
            </div>
          </>
        )}
      </div>

      {/* Agentic run history */}
      <div className="rounded-xl bg-[#12131a] border border-white/10 p-5 space-y-3 shadow-md">
        <div className="text-[9px] font-mono font-semibold text-[#8e8e9a]/80 uppercase tracking-[0.2em] flex items-center gap-1.5">
          <Sparkles className="w-3 h-3 text-violet-400" />
          <span>Agentic Run History</span>
        </div>
        {loading ? (
          <p className="text-[10.5px] font-mono text-[#5c5c68]">Loading…</p>
        ) : recentAgenticRuns.length === 0 ? (
          <p className="text-[10.5px] font-mono text-[#5c5c68]">No agentic runs yet.</p>
        ) : (
          <div className="space-y-2">
            {recentAgenticRuns.map((r) => (
              <div key={r.scan_id} className="flex items-center justify-between gap-3 text-[10.5px] font-mono px-3.5 py-2.5 rounded-lg bg-[#0c0d11] border border-white/8 hover:border-white/15 transition flex-wrap">
                <span className="text-[#8e8e9a] font-semibold">{formatTimestamp(r.started_at)}</span>
                <span className={`font-bold uppercase px-2 py-0.5 rounded text-[9px] ${
                  r.status === "completed" ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/30" :
                  r.status === "error" ? "bg-red-500/15 text-red-400 border border-red-500/30" :
                  r.status === "cancelled" ? "bg-amber-500/15 text-amber-400 border border-amber-500/30" :
                  "bg-white/5 text-[#8e8e9a]"
                }`}>{r.status}</span>
                <span className="text-[#8e8e9a]">{r.agentic_summary?.validated_patches ?? 0} validated patch{(r.agentic_summary?.validated_patches ?? 0) === 1 ? "" : "es"}</span>
                <span className="text-[#8e8e9a]">{r.agentic_summary?.correlated_risks ?? 0} correlated</span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Platform stats */}
      <div className="rounded-xl bg-[#12131a] border border-white/10 p-5 shadow-md">
        <div className="text-[9px] font-mono font-semibold text-[#8e8e9a]/80 uppercase tracking-[0.2em] mb-3 flex items-center gap-1.5">
          <Layers className="w-3 h-3 text-sky-400" />
          <span>Platform Stats</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { icon: Layers, label: "Total Scans", value: scans.length, color: "text-sky-400" },
            { icon: Sparkles, label: "Agentic Runs", value: agenticRuns.length, color: "text-violet-400" },
            { icon: ShieldCheck, label: "Validated Patches", value: totalValidatedPatches, color: "text-emerald-400" },
          ].map((s) => (
            <div key={s.label} className="p-3.5 rounded-lg bg-[#0c0d11] border border-white/8 hover:border-white/15 transition flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-white/4 flex items-center justify-center shrink-0">
                <s.icon className={`w-4 h-4 ${s.color}`} />
              </div>
              <div>
                <div className="text-[9px] font-mono uppercase tracking-wider text-[#8e8e9a]">{s.label}</div>
                <div className="text-base font-mono font-bold text-[#f4f4f8]">{s.value}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

