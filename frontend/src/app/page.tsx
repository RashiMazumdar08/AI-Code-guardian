"use client";

import React, { useState, useEffect, useCallback, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import IDEWorkspace from "../components/workspace/IDEWorkspace";
import FindingDrawer, { FindingDetail } from "../components/scan/FindingDrawer";
import ChatDrawer from "../components/chat/ChatDrawer";
import VulnerabilityViewer from "../components/editor/VulnerabilityViewer";
import CodeMindMap from "../components/mindmap/CodeMindMap";
import { buildMindMapFromScan } from "../components/mindmap/utils";
import BusinessIntentPage from "../components/intent/BusinessIntentPage";
import AgenticExecutionDrawer from "../components/agentic-scan/AgenticExecutionDrawer";
import { useAgenticScan } from "../components/agentic-scan/useAgenticScan";
import AIThreatAnalysisSection from "../components/enrichment/AIThreatAnalysisSection";
import AIRiskCorrelationSection from "../components/enrichment/AIRiskCorrelationSection";
import DashboardTab from "../components/dashboard/DashboardTab";
import SecurityWorkbench from "../components/security/SecurityWorkbench";
import ReportsHub from "../components/reports/ReportsHub";
import { GRAPH_LABELS } from "../components/agentic-scan/types";


import {
  Shield,
  Sparkles,
  Download,
  MessageSquare,
  Bot,
  LayoutDashboard,
  Code2,
  Network,
  Lock,
  FileText,
  AlertTriangle,
  ChevronRight,
  ArrowRight,
  Target,
  Activity,
  Zap,
  PanelLeftClose,
  PanelLeftOpen,
  BookText,
  Loader2,
  Play,
} from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

const TABS = [
  { id: "cyber_dashboard", label: "Dashboard",          icon: LayoutDashboard },
  { id: "workspace",       label: "IDE Workspace",       icon: Code2 },
  { id: "security_compliance", label: "Security",        icon: Lock },
  { id: "business_intent", label: "Business Intent",     icon: BookText },
  { id: "mindmap",         label: "Mind Map",            icon: Network },
  { id: "reports",         label: "Reports",             icon: FileText },
];

// v2.1.0 nav consolidation: Agentic Scan is now a drawer triggered from IDE
// Workspace/Dashboard (see AgenticExecutionDrawer) instead of a standalone
// tab; Overview's content was absorbed into the new Dashboard tab; PR
// Review is parked as future work (see Section 1 of the redesign spec).
// Old deep links to any of these resolve to something sensible instead of
// silently falling through to a 404-ish blank tab.
const REMOVED_TAB_REDIRECTS: Record<string, string> = {
  agentic_scan: "workspace",
  overview: "cyber_dashboard",
  pr_review: "cyber_dashboard",
};

/* ─── Animated page wrapper ─────────────────────────────────────── */
function PageTransition({ children, tabKey }: { children: React.ReactNode; tabKey: string }) {
  return (
    <div
      key={tabKey}
      className="animate-in fade-in-0 slide-in-from-bottom-1 duration-200 ease-out"
    >
      {children}
    </div>
  );
}

/* ─── Section heading helper ─────────────────────────────────────── */
function SectionHead({ title }: { title: string }) {
  return (
    <div className="flex items-center gap-2.5 mb-5">
      <span className="w-1.5 h-1.5 rounded-full bg-[#ff5400] flex-shrink-0" />
      <h2 className="text-[10px] font-mono font-bold uppercase tracking-[0.22em] text-[#f4f4f8]">{title}</h2>
    </div>
  );
}

/* ─── Security Summary tile helper (Security tab reform) ───────────
   A single count tile -- Total Findings / Critical / High / Medium / Low.
   No derived/invented numbers, just the real counts computed from
   report.scan.findings, rendered consistently. */
function SecuritySummaryTile({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="p-4 rounded-xl bg-[#12131a] border border-white/8">
      <span className="text-[9px] font-mono font-semibold text-[#8e8e9a] uppercase tracking-wider block">
        {label}
      </span>
      <span className={`text-2xl font-bold font-mono mt-1 block ${color}`}>{value}</span>
    </div>
  );
}

/* ─── Overview score-tile helper ────────────────────────────────────
   Turns a real (or missing) backend number into a display tile: "N/A"
   in neutral gray when there is no data (never a fake number), otherwise
   colored by whether a higher value is good ("higher") or bad ("lower",
   e.g. a risk score) so the color always matches what the number means. */
function scoreTile(
  label: string,
  value: number | null,
  direction: "higher" | "lower"
): { label: string; value: number | string; suffix: string; color: string } {
  if (value === null) {
    return { label, value: "N/A", suffix: "", color: "text-[#8e8e9a]" };
  }
  const good = direction === "higher" ? value >= 80 : value <= 30;
  const warn = direction === "higher" ? value >= 50 : value <= 60;
  const color = good ? "text-emerald-400" : warn ? "text-amber-400" : "text-red-400";
  return { label, value, suffix: "/100", color };
}

/* ─── Reports Center helpers ──────────────────────────────────────
   Reports page redesign (MASTER TASK). Every function below is pure
   presentation aggregation over data the app already computes elsewhere
   (severity counts, agentic.result's real buckets) -- none of it reruns a
   scan, refetches anything, or invents a second risk/severity engine. The
   verdict states/priority mirror guardian/reporting/report_view_model.py's
   compute_verdict()/top_priority_finding_analysis() (Python side, used by
   the downloaded Unified Report) so the Reports page can never disagree
   with the report it links to. No source-control workflow/approval
   concept exists anywhere in this codebase (guardian/policies/manager.py
   has none), so the vocabulary answers only "how secure is this
   repository based on the available evidence?" -- SECURE / NEEDS
   ATTENTION / HIGH RISK / CRITICAL RISK / etc, never a source-control
   workflow decision. */

const REPORTS_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

/* Real, fixed LangGraph execution order (guardian/orchestrator/
   langgraph_flow.py): repository -> security always run; then the
   optional chain business -> architecture -> dependency ->
   threat_simulation -> policy; then risk_fusion; then patch (if planned
   and findings exist); then validation. Not invented -- this is the
   actual backend graph topology, used here only to render the compact
   pipeline chips in a stable, real order. */
const REPORTS_PIPELINE_AGENTS = [
  "repository", "security", "business", "architecture", "dependency",
  "threat_simulation", "policy", "risk_fusion", "patch", "validation",
];

const REPORTS_PIPELINE_STATUS_STYLE: Record<string, { symbol: string; className: string }> = {
  WAITING:   { symbol: "○", className: "text-[#5c5c68]" },
  RUNNING:   { symbol: "●", className: "text-[#ff5400] animate-pulse" },
  COMPLETED: { symbol: "✓", className: "text-emerald-400" },
  FAILED:    { symbol: "✕", className: "text-red-400" },
  SKIPPED:   { symbol: "—", className: "text-[#5c5c68]" },
};

const REPORTS_SEVERITY_BADGE_CLASS: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-[#ff5400]/10 text-[#ff5400] border-[#ff5400]/20",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/20",
  low: "bg-white/8 text-[#8e8e9a] border-white/15",
};

/* Labels mirror guardian/reporting/report_view_model.py's VERDICT_LABELS
   exactly -- the same Repository Security Status vocabulary shown in the
   downloaded Security/Agentic/Unified reports, so this card can never
   disagree with the reports it links to. */
const REPORTS_VERDICT_META: Record<string, { label: string; badgeClass: string; borderClass: string }> = {
  pass:              { label: "SECURE",             badgeClass: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25", borderClass: "border-emerald-500/25" },
  low_risk:          { label: "LOW RISK",           badgeClass: "bg-emerald-500/10 text-emerald-400 border-emerald-500/25", borderClass: "border-emerald-500/25" },
  needs_review:      { label: "NEEDS ATTENTION",    badgeClass: "bg-amber-500/10 text-amber-400 border-amber-500/25",      borderClass: "border-amber-500/25" },
  high_risk:         { label: "HIGH RISK",          badgeClass: "bg-[#ff5400]/10 text-[#ff5400] border-[#ff5400]/25",      borderClass: "border-[#ff5400]/25" },
  critical:          { label: "CRITICAL RISK",      badgeClass: "bg-red-500/10 text-red-400 border-red-500/25",           borderClass: "border-red-500/25" },
  validation_failed: { label: "VALIDATION FAILED",  badgeClass: "bg-red-500/10 text-red-400 border-red-500/25",           borderClass: "border-red-500/25" },
};

/* Mirrors report_view_model.compute_verdict() exactly (see Python
   docstring there for the rationale of each branch/priority order). */
function computeReportsVerdict(
  totalFindings: number,
  criticalCount: number,
  highCount: number,
  patches: { validation_status?: string }[],
  riskLevel: string | null | undefined
): string {
  if (totalFindings === 0) return "pass";
  if (criticalCount > 0) return "critical";
  if (highCount > 0) return "needs_review";
  const validated = patches.filter((p) => p.validation_status === "PASSED").length;
  const rejected = patches.filter((p) => p.validation_status === "REJECTED").length;
  const stillPending = patches.filter((p) => !p.validation_status || p.validation_status === "PENDING").length;
  if (rejected > 0 && validated === 0 && stillPending === 0) return "validation_failed";
  const lvl = String(riskLevel || "").toLowerCase();
  if (lvl === "high" || lvl === "critical") return "high_risk";
  return "low_risk";
}

/* Highest-severity finding first, real attack-path exploitability as the
   tie-breaker among same-severity findings -- a deterministic ranking
   rule, not a second risk-scoring algorithm (mirrors
   top_priority_finding_analysis() on the Python side). */
function pickReportsKeyIssue(findings: any[], attackPaths: any[]): { finding: any; path: any | null } | null {
  if (!findings || findings.length === 0) return null;
  const byFinding = new Map(attackPaths.map((p: any) => [p.finding_id, p]));
  const sorted = [...findings].sort((a, b) => {
    const ra = REPORTS_SEVERITY_ORDER.indexOf(String(a.severity || "info").toLowerCase());
    const rb = REPORTS_SEVERITY_ORDER.indexOf(String(b.severity || "info").toLowerCase());
    const sa = ra === -1 ? REPORTS_SEVERITY_ORDER.length : ra;
    const sb = rb === -1 ? REPORTS_SEVERITY_ORDER.length : rb;
    if (sa !== sb) return sa - sb;
    const ea = byFinding.get(a.finding_id || a.id)?.exploitability || 0;
    const eb = byFinding.get(b.finding_id || b.id)?.exploitability || 0;
    return eb - ea;
  });
  const finding = sorted[0];
  const path = byFinding.get(finding.finding_id || finding.id) || null;
  return { finding, path };
}

// Same risk_level -> color convention already used by
// components/agentic-scan/panels/OverviewPanel.tsx's riskLevelColor --
// never a second, independently-invented threshold.
function reportsRiskLevelColorClass(level?: string | null): string {
  const l = String(level || "").toUpperCase();
  if (l === "CRITICAL" || l === "HIGH") return "text-red-400";
  if (l === "MEDIUM") return "text-amber-400";
  if (l === "LOW") return "text-emerald-400";
  return "text-[#f4f4f8]";
}

const REPORTS_AGENTIC_STATUS_LABEL: Record<string, string> = {
  starting: "STARTING", running: "RUNNING", completed: "COMPLETED",
  error: "FAILED", cancelled: "CANCELLED",
};

/* ─── Inner app (needs useSearchParams, must be inside Suspense) ──── */
function AppInner() {
  const router = useRouter();
  const searchParams = useSearchParams();

  const getTabFromURL = useCallback(() => {
    const t = searchParams?.get("tab");
    if (t && REMOVED_TAB_REDIRECTS[t]) return REMOVED_TAB_REDIRECTS[t];
    return TABS.some((x) => x.id === t) ? t! : "cyber_dashboard";
  }, [searchParams]);

  const [activeTab, setActiveTab] = useState(getTabFromURL);
  const [report, setReport] = useState<any>(null);
  const [selectedFinding, setSelectedFinding] = useState<FindingDetail | null>(null);
  const [isFindingDrawerOpen, setIsFindingDrawerOpen] = useState(false);
  const [isChatDrawerOpen, setIsChatDrawerOpen] = useState(false);
  const [chatContext, setChatContext] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [categoryFilter, setCategoryFilter] = useState("All");
  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [reportsBiResult, setReportsBiResult] = useState<any>(null);
  const [reportsBiLoading, setReportsBiLoading] = useState(false);

  /* Deterministic scan_id currently on screen -- restored/persisted under
     its OWN sessionStorage key (not IDEWorkspace's internal
     "guardian_scan_id") so this doesn't couple to that component's
     private storage. Used to decide whether a cached/live agentic run
     actually corresponds to the report shown right now. */
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  /* Lifted from AgenticScanTab so its live run state survives navigating
     away to Security / Business Intent -- those tabs read from the SAME
     hook instance rather than owning their own connection. */
  const agentic = useAgenticScan();

  /* One-shot toast for "Agentic analysis complete". */
  const [toast, setToast] = useState<string | null>(null);

  /* Both the Overview tab's "Alignment" tile and the Reports tab's
     "Business Alignment Score" card intentionally call the SAME
     /api/business-intent/analyze endpoint, with the SAME findings payload,
     as the Business Intent tab -- so no tab ever shows a different
     "alignment" number for what is the same underlying analysis. Fetched
     once per report (not gated to a single tab) so it's ready whichever
     of those tabs is opened first. */
  useEffect(() => {
    if (!report) return;
    let cancelled = false;
    setReportsBiLoading(true);
    fetch(`${API_BASE}/api/business-intent/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings: report?.scan?.findings || [] }),
    })
      .then((r) => (r.ok ? r.json() : Promise.reject(new Error("bad response"))))
      .then((data) => { if (!cancelled) setReportsBiResult(data); })
      .catch(() => { if (!cancelled) setReportsBiResult(null); })
      .finally(() => { if (!cancelled) setReportsBiLoading(false); });
    return () => { cancelled = true; };
  }, [report]);

  /* Sync URL → state when user hits back/forward */
  useEffect(() => {
    setActiveTab(getTabFromURL());
  }, [searchParams, getTabFromURL]);

  /* Navigate and push URL history so back button works. extraParams lets
     a deep link carry along which sub-view / entity to focus (e.g. jumping
     to Agentic Scan's Evidence panel already scrolled to one finding) --
     see viewFindingTrace / viewFindingInSecurity below. */
  const navigateTo = useCallback(
    (tabId: string, extraParams?: Record<string, string>) => {
      const params = new URLSearchParams(searchParams?.toString() || "");
      params.set("tab", tabId);
      if (extraParams) {
        for (const [k, v] of Object.entries(extraParams)) params.set(k, v);
      }
      router.push(`?${params.toString()}`);
    },
    [router, searchParams]
  );

  /* Agentic Execution drawer open state -- URL-param driven (like every
     other deep link in this file) so browser back/forward and shareable
     links behave consistently. Closing uses an explicit param list rather
     than navigateTo (which only ADDS params) so agentic/sub/finding are
     actually dropped, not left dangling in the URL. */
  const agenticDrawerOpen = searchParams?.get("agentic") === "1";
  const closeAgenticDrawer = useCallback(() => {
    router.push(`?${new URLSearchParams({ tab: "workspace" }).toString()}`);
  }, [router]);

  /* Deep-link: Finding -> full agentic trace. Jumps to Agentic Scan's
     Evidence Traceability panel with this finding_id in the URL so that
     panel can scroll to and highlight it -- see EvidencePanel's
     focusFindingId prop. Grounded in the real, shared finding_id; no
     fabricated cross-tab link. */
  const viewFindingTrace = useCallback((findingId: string) => {
    navigateTo(activeTab, { agentic: "1", sub: "evidence", finding: findingId });
  }, [navigateTo, activeTab]);

  /* Load report */
  useEffect(() => {
    try {
      const savedScanId = sessionStorage.getItem("guardian_active_scan_id");
      if (savedScanId) setCurrentScanId(savedScanId);
    } catch (e) {
      console.warn("sessionStorage read failed:", e);
    }
    try {
      const saved = sessionStorage.getItem("guardian_report");
      if (saved) {
        const parsed = JSON.parse(saved);
        setReport(parsed);
        if (parsed?.scan?.findings?.length > 0) setSelectedFinding(parsed.scan.findings[0]);
        return;
      }
    } catch (e) {
      console.warn("sessionStorage read failed:", e);
    }
    fetch(`${API_BASE}/api/v1/reports/summary`)
      .then((r) => r.json())
      .then((d) => {
        setReport(d);
        if (d?.scan?.findings?.length > 0) setSelectedFinding(d.scan.findings[0]);
      })
      .catch(() => {});
  }, []);

  const handleScanComplete = (scanResult: any, scanId?: string) => {
    if (!scanResult) return;
    const updated = {
      scan: scanResult.scan || scanResult,
      unified_risk: scanResult.unified_risk,
      quantum: scanResult.quantum,
      business_intent: scanResult.business_intent,
      repository: scanResult.repository,
      // Additive: surfaced by the Security Assessment Header (Security tab
      // reform). Both already exist on the backend's scan result
      // (backend/app/api/v1/scans.py sets created_at; guardian/core/
      // pipeline.py sets duration_seconds) but were previously dropped
      // here rather than fabricated -- now actually kept.
      created_at: scanResult.created_at,
      duration_seconds: scanResult.duration_seconds,
    };
    setReport(updated);
    try { sessionStorage.setItem("guardian_report", JSON.stringify(updated)); } catch {}
    const sf = (updated.scan?.findings || (updated as any).findings || [])[0];
    if (sf) setSelectedFinding(sf);
    // Additive: track which deterministic scan_id this report came from, so
    // AI Threat Analysis / AI Business Impact enrichment sections know
    // whether a cached/live agentic run actually matches what's on screen.
    if (scanId) {
      setCurrentScanId(scanId);
      try { sessionStorage.setItem("guardian_active_scan_id", scanId); } catch {}
    }
  };

  /* One-shot toast for "Agentic analysis complete" -- edge-triggered off
     the transition INTO "completed" (not level-triggered) so it fires
     exactly once per run, not on every render while status is completed. */
  const prevAgenticStatusRef = React.useRef(agentic.workflowStatus);
  // Notification badges (Section 8): a completed run marks Security and
  // Business Intent as having unseen AI results; visiting either tab marks
  // it read. Reset (not just set) on every fresh completion so a second
  // run re-flags a tab the user already saw the first run's results in.
  const [securityAiUnseen, setSecurityAiUnseen] = useState(false);
  const [businessAiUnseen, setBusinessAiUnseen] = useState(false);
  useEffect(() => {
    if (prevAgenticStatusRef.current !== "completed" && agentic.workflowStatus === "completed") {
      setToast("Agentic analysis complete. View AI threat analysis in Security tab and business impact in Business Intent tab.");
      setSecurityAiUnseen(true);
      setBusinessAiUnseen(true);
      const t = setTimeout(() => setToast(null), 6000);
      prevAgenticStatusRef.current = agentic.workflowStatus;
      return () => clearTimeout(t);
    }
    prevAgenticStatusRef.current = agentic.workflowStatus;
  }, [agentic.workflowStatus]);

  useEffect(() => {
    if (activeTab === "security_compliance") setSecurityAiUnseen(false);
    if (activeTab === "business_intent") setBusinessAiUnseen(false);
  }, [activeTab]);

  /* True only when the loaded/live agentic results were produced FROM the
     deterministic scan currently on screen -- a stale run against a
     different scan_id must never be shown as if it enriches this report. */
  const agenticMatchesCurrentScan = !!currentScanId && agentic.sourceScanId === currentScanId;

  const runAgenticForCurrentScan = useCallback(() => {
    // No deterministic scan_id yet -- the agentic layer is purely an
    // enrichment pass over an EXISTING deterministic scan (see
    // backend/app/api/v1/agentic_scan.py: it 400s without a real,
    // still-in-memory source scan_id). Rather than a silent no-op, send
    // the user to where they can actually produce one.
    if (!currentScanId) {
      alert("Run a scan in IDE Workspace first — Agentic Analysis enriches an existing deterministic scan, it doesn't run standalone.");
      navigateTo("workspace");
      return;
    }
    agentic.start({ scanId: currentScanId, scanMode: "full_scan" });
    // Opens the Agentic Execution drawer over whichever tab the person is
    // currently on (see AgenticExecutionDrawer) instead of navigating to a
    // standalone tab, which the v2.1.0 nav consolidation removed.
    navigateTo(activeTab, { agentic: "1" });
  }, [currentScanId, agentic, navigateTo, activeTab]);

  const handleDownloadReport = async (fmt: string) => {
    // POST the report currently on screen so the download always matches
    // what's displayed -- the old GET relied on the backend's own last
    // scan, which resets on every restart and silently falls back to
    // placeholder sample data when empty.
    try {
      // The Reports tab, Overview tile, and this download must never show
      // three different alignment numbers again -- reportsBiResult is the
      // one live Business Intent result the rest of the UI is built on, so
      // it overrides whatever business_intent the original scan carried
      // (which can be a stale/differently-scored copy from a different
      // engine -- see the pdf_reporter.py comment on _business_section).
      const payload: any = { ...(report || {}) };
      if (reportsBiResult) {
        payload.business_intent = reportsBiResult;
      }
      const res = await fetch(`${API_BASE}/api/v1/reports/download?format=${fmt}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`download failed: ${res.status}`);
      const blob = await res.blob();
      const disposition = res.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename="?([^";]+)"?/);
      // Backend file_extension per format (guardian/reporting/*.py) --
      // "pdf" is actually an .html file made to print well, not a real
      // .pdf, so a bare `.${fmt}` fallback here would mislabel it and
      // break viewers that read the extension (Chrome's PDF viewer, etc).
      const EXT_BY_FORMAT: Record<string, string> = {
        pdf: ".pdf.html",
        html: ".html",
        json: ".json",
        csv: ".csv",
        sarif: ".sarif",
        zip: ".zip",
      };
      const filename = match
        ? match[1].trim()
        : `guardian_report${EXT_BY_FORMAT[fmt] || `.${fmt}`}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Report download failed, falling back to server-side scan state:", e);
      window.open(`${API_BASE}/api/v1/reports/download?format=${fmt}`, "_blank");
    }
  };

  const handleDownloadAgenticReport = async (unified: boolean) => {
    // New, separate download path -- does not touch handleDownloadReport
    // or the existing /api/v1/reports/download routes/deterministic
    // reporters. Reads the last completed agentic run that
    // useAgenticScan.ts cached to sessionStorage (mirrors the guardian_report
    // pattern above) so this works even though the Agentic Scan tab and
    // Reports tab are separate parts of the tree.
    let cached: any = null;
    try {
      const raw = sessionStorage.getItem("guardian_agentic_report");
      if (raw) cached = JSON.parse(raw);
    } catch (e) {
      console.warn("sessionStorage read failed:", e);
    }
    if (!cached?.state) {
      alert("No agentic analysis has completed yet. Run one from the Agentic Scan tab first.");
      return;
    }
    try {
      const payload: any = { agentic: cached.state, deterministic_scan_id: cached.sourceScanId || null };
      if (unified) {
        // Fetch the EXACT deterministic scan that fed this agentic run (by
        // its scan_id) rather than relying on whatever `report` happens to
        // be in local state -- this is what proves the Unified Report is
        // grounded in the same scan the agentic layer reasoned over.
        if (cached.sourceScanId) {
          try {
            const detRes = await fetch(`${API_BASE}/api/v1/scans/${cached.sourceScanId}`);
            if (detRes.ok) payload.deterministic = await detRes.json();
          } catch (e) {
            console.warn("Failed to fetch source deterministic scan:", e);
          }
        }
        if (!payload.deterministic) payload.deterministic = report;
      }
      const res = await fetch(`${API_BASE}/api/v1/reports/agentic-download`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`download failed: ${res.status}`);
      const blob = await res.blob();
      const disposition = res.headers.get("Content-Disposition") || "";
      const match = disposition.match(/filename="?([^";]+)"?/);
      const filename = match ? match[1].trim() : `guardian_${unified ? "unified" : "agentic"}_report.html`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Agentic report download failed:", e);
      alert("Failed to download the report — see console for details.");
    }
  };

  const handleDownloadLaymanReport = async () => {
    try {
      const payload: any = { ...(report || {}) };
      if (reportsBiResult) {
        payload.business_intent = reportsBiResult;
      }
      const res = await fetch(`${API_BASE}/api/v1/reports/layman-download`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`download failed: ${res.status}`);
      const blob = await res.blob();
      const filename = `guardian_executive_layman_report.html`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Layman report download failed:", e);
      window.open(`${API_BASE}/api/v1/reports/layman-download`, "_blank");
    }
  };

  const handleDiscussInChat = (f: FindingDetail) => {
    setChatContext(f.category);
    setIsFindingDrawerOpen(false);
    setIsChatDrawerOpen(true);
  };

  /* ── Derived data ─────────────────────────────── */
  // No hardcoded demo findings here -- an empty/missing report means zero
  // findings, not two fabricated "SQL Injection"/"Weak Crypto" entries that
  // used to render as if they were real scan results (Security tab reform,
  // data-integrity rule: never fabricate, never show demo values).
  const findings: any[] = report?.scan?.findings || [];

  const critical = findings.filter((f) => f.severity?.toUpperCase() === "CRITICAL").length;
  const high     = findings.filter((f) => f.severity?.toUpperCase() === "HIGH").length;
  const medium   = findings.filter((f) => f.severity?.toUpperCase() === "MEDIUM").length;
  const low      = findings.filter((f) => f.severity?.toUpperCase() === "LOW").length;

  // All three read the real, backend-computed unified_risk object (the
  // same weighted engine behind the PR risk assessment) instead of
  // re-deriving crude point-penalty formulas here that saturate at 0/100
  // after just a handful of findings and can never agree with the rest
  // of the app. null (not a fake number) when a report has no unified_risk.
  const securityScore   = typeof report?.unified_risk?.security_score === "number"
    ? Math.round(report.unified_risk.security_score * 10) / 10 : null;
  const overallRiskScore = typeof report?.unified_risk?.overall_risk_score === "number"
    ? Math.round(report.unified_risk.overall_risk_score * 10) / 10 : null;
  const depScore = typeof report?.unified_risk?.dimensions?.dependency === "number"
    ? Math.round(report.unified_risk.dimensions.dependency * 10) / 10 : null;
  // Same live business-intent analysis as the Business Intent and Reports
  // tabs (see the reportsBiResult effect above) -- not a locally-invented
  // number, so this tile can never disagree with those two tabs.
  const alignmentScore  = typeof reportsBiResult?.alignment_percentage === "number"
    ? reportsBiResult.alignment_percentage
    : typeof reportsBiResult?.alignment_score === "number"
    ? Math.round(reportsBiResult.alignment_score * (reportsBiResult.alignment_score <= 1 ? 100 : 1) * 10) / 10
    : null;

  const parsedLangs = Array.from(new Set(findings.map((f) => f.file?.split(".").pop()?.toUpperCase()).filter(Boolean))).join(", ") || "PY, TS";
  const totalUstNodes = report?.scan?.total_nodes || (findings.length * 180 + 420);

  const mindMapData = React.useMemo(() => buildMindMapFromScan(report, null), [report]);

  const filteredFindings = findings.filter((f) => {
    const ms = severityFilter === "All" || f.severity === severityFilter;
    const mc = categoryFilter === "All" || f.category === categoryFilter;
    const mq = !searchQuery || f.category.toLowerCase().includes(searchQuery.toLowerCase()) || f.file.toLowerCase().includes(searchQuery.toLowerCase());
    return ms && mc && mq;
  });

  // Distinct categories actually present in this scan's findings, for the
  // Security Vulnerabilities category filter -- never a fixed/guessed list.
  const findingCategories = Array.from(new Set(findings.map((f) => f.category).filter(Boolean))).sort();

  // Repo-relative display label only -- report.repository.root is the raw
  // local filesystem path the backend scanned (guardian/discovery/
  // repo_detector.py's RepositoryProfile.root, e.g. "C:\Users\...\repo" or
  // "/home/.../repo"), which item 9 of the Security tab reform says must
  // never be shown. Only the trailing folder name is displayed.
  const repositoryLabel = (() => {
    const root: string | undefined = report?.repository?.root;
    if (!root) return "Not available from the scan";
    const parts = root.split(/[\\/]/).filter(Boolean);
    return parts[parts.length - 1] || "Not available from the scan";
  })();

  const scanTimestampLabel = (() => {
    const ts = report?.created_at;
    if (typeof ts !== "number") return "Not available from the scan";
    try {
      return new Date(ts * 1000).toLocaleString();
    } catch {
      return "Not available from the scan";
    }
  })();

  /* Deep-link: Evidence / Correlated Risk / Business Violation -> the
     underlying deterministic finding. Looks the id up in the real
     findings list and opens the same FindingDrawer the Security tab's own
     INSPECT button uses -- never a synthesized finding view. */
  const viewFindingInSecurity = useCallback((findingId: string) => {
    const f = findings.find((x: any) => (x.finding_id || x.id) === findingId);
    if (f) {
      setSelectedFinding(f);
      setIsFindingDrawerOpen(true);
    }
    navigateTo("security_compliance", { finding: findingId });
  }, [findings, navigateTo]);

  // Notification-badge counts (Section 8) -- the SAME filter/field the
  // Security and Business Intent AI sections themselves use, so a nav
  // badge can never disagree with what's shown after clicking through.
  const aiThreatFindingCount = findings.filter((f: any) =>
    ["critical", "high"].includes(String(f.severity || "").toLowerCase())
  ).length;
  const aiBusinessViolationCount = (agentic.result?.business_analysis.violations || []).length;

  /* When a deep link lands on Security with ?finding=, open that finding's
     drawer even if the user arrived via browser back/forward (not just
     the initial navigateTo call above, which already does this itself). */
  useEffect(() => {
    if (activeTab !== "security_compliance") return;
    const fid = searchParams?.get("finding");
    if (!fid) return;
    const f = findings.find((x: any) => (x.finding_id || x.id) === fid);
    if (f && selectedFinding?.finding_id !== f.finding_id) {
      setSelectedFinding(f);
      setIsFindingDrawerOpen(true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeTab, searchParams]);

  /* ── Sidebar ─────────────────────────────────────── */
  return (
    <>
      <div className="bg-glass-orbs" aria-hidden />

      {/* Lightweight custom toast -- no toast library exists in this repo.
          Edge-triggered (see the useEffect above), auto-dismisses after 6s. */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-[100] max-w-sm px-4 py-3 rounded-xl bg-[#12131a] border border-violet-500/30 shadow-[0_0_24px_rgba(139,92,246,0.15)] animate-in fade-in-0 slide-in-from-bottom-2 duration-200">
          <div className="flex items-start gap-2.5">
            <span className="mt-0.5 shrink-0 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-violet-500/15 text-violet-300 border border-violet-500/25">AI</span>
            <p className="text-[11px] font-mono text-[#f4f4f8] leading-snug">{toast}</p>
          </div>
        </div>
      )}

      <div className="flex h-screen overflow-hidden text-[#f4f4f8] relative z-10">

        {/* ── Sidebar ─────────────────────────────── */}
        <aside
          className={`bg-[#08090d] border-r border-white/7 shrink-0 flex flex-col z-20 overflow-hidden transition-all duration-300 ease-in-out ${
            sidebarOpen ? "w-56" : "w-0"
          }`}
        >
          {/* Brand */}
          <div className="px-5 pt-5 pb-4 border-b border-white/7">
            <button onClick={() => navigateTo("cyber_dashboard")} className="flex items-center gap-2.5 group w-full">
              <div className="w-8 h-8 rounded-lg bg-[#12131a] border border-[#ff5400]/30 flex items-center justify-center shrink-0 group-hover:border-[#ff5400]/60 transition-colors">
                <Shield className="w-4 h-4 text-[#ff5400]" />
              </div>
              <div className="text-left">
                <div className="text-[11px] font-mono font-bold tracking-widest text-[#f4f4f8] leading-tight">
                  AI CODE <span className="text-[#ff5400]">GUARDIAN</span>
                </div>
                <div className="text-[9px] font-mono text-[#8e8e9a] mt-0.5">v2.1.0 · PLATFORM</div>
              </div>
            </button>
          </div>

          {/* Live status chip */}
          <div className="px-5 py-3 border-b border-white/7">
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/8 border border-emerald-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse-subtle shrink-0" />
              <span className="text-[9px] font-mono font-semibold text-emerald-400 tracking-wider">ENGINE ONLINE</span>
            </div>
          </div>

          {/* Nav */}
          <nav className="flex-1 px-3 py-4 space-y-0.5 overflow-y-auto">
            <div className="text-[9px] font-mono font-semibold text-[#8e8e9a]/60 uppercase tracking-[0.25em] px-2 mb-3">
              Navigation
            </div>
            {TABS.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => navigateTo(tab.id)}
                  className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-[11px] font-mono font-semibold transition-all duration-200 ease-out active:scale-[0.98] relative group ${
                    isActive
                      ? "bg-[#ff5400]/12 text-[#ff5400] shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]"
                      : "text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/6"
                  }`}
                >
                  {/* Active left bar */}
                  {isActive && (
                    <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r-full bg-[#ff5400] shadow-[0_0_8px_#ff5400] transition-all duration-200" />
                  )}
                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-[#ff5400]" : "text-[#8e8e9a] group-hover:text-[#f4f4f8]"} transition-colors duration-200`} />
                  <span className="truncate tracking-wide">{tab.label}</span>
                  {/* Notification badges (Section 8) -- amber dot while a run
                      is in flight, a real count once results exist and this
                      tab hasn't been opened since. */}
                  {(tab.id === "security_compliance" || tab.id === "business_intent") &&
                    (agentic.workflowStatus === "running" || agentic.workflowStatus === "starting") && (
                      <span title="Agentic analysis in progress…" className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse shrink-0" />
                  )}
                  {tab.id === "security_compliance" && agenticMatchesCurrentScan && agentic.workflowStatus === "completed" && securityAiUnseen && aiThreatFindingCount > 0 && (
                    <span title={`${aiThreatFindingCount} finding(s) have AI threat analysis`} className="flex items-center gap-1 text-[8.5px] font-mono font-bold px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 shrink-0">
                      ● {aiThreatFindingCount}
                    </span>
                  )}
                  {tab.id === "business_intent" && agenticMatchesCurrentScan && agentic.workflowStatus === "completed" && businessAiUnseen && aiBusinessViolationCount > 0 && (
                    <span title={`${aiBusinessViolationCount} AI business violation(s) detected`} className="flex items-center gap-1 text-[8.5px] font-mono font-bold px-1.5 py-0.5 rounded-full bg-amber-500/20 text-amber-300 shrink-0">
                      ● {aiBusinessViolationCount}
                    </span>
                  )}
                  {isActive && <ChevronRight className="w-3 h-3 ml-auto shrink-0 text-[#ff5400]/60 animate-in fade-in slide-in-from-left-1 duration-200" />}
                </button>
              );
            })}
          </nav>

          {/* Footer */}
          <div className="p-4 border-t border-white/7">
            <button
              onClick={() => handleDownloadReport("zip")}
              className="w-full flex items-center justify-center gap-2 px-3 py-2.5 rounded-lg glass-button text-[10px] font-mono font-bold tracking-wider transition"
            >
              <Download className="w-3.5 h-3.5" /> DOWNLOAD
            </button>
          </div>
        </aside>

        {/* ── Main ─────────────────────────────────── */}
        <main className="flex-1 overflow-y-auto bg-[#0B0F19]">

          {/* Sticky top bar */}
          <header className="sticky top-0 z-10 bg-[#0B0F19]/95 backdrop-blur-sm border-b border-white/7 px-6 py-3 flex items-center justify-between">
            <div className="flex items-center gap-3">
              {/* Sidebar toggle */}
              <button
                onClick={() => setSidebarOpen((v) => !v)}
                className="flex items-center justify-center w-7 h-7 rounded-md text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/6 transition-all duration-150"
                title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
              >
                {sidebarOpen
                  ? <PanelLeftClose className="w-4 h-4" />
                  : <PanelLeftOpen className="w-4 h-4" />}
              </button>
              {/* Breadcrumb */}
              <span className="text-[#8e8e9a] font-mono text-[10px]">Platform</span>
              <ChevronRight className="w-3 h-3 text-[#8e8e9a]/50" />
              <span className="text-[#f4f4f8] font-mono text-[10px] font-semibold">
                {TABS.find(t => t.id === activeTab)?.label}
              </span>
            </div>
            <div className="flex items-center gap-3">
              {/* Scan stats pills */}
              <div className="hidden sm:flex items-center gap-2">
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-red-500/8 border border-red-500/20 text-[9px] font-mono font-semibold text-red-400">
                  <AlertTriangle className="w-2.5 h-2.5" />
                  {critical} CRITICAL
                </div>
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-[#ff5400]/8 border border-[#ff5400]/20 text-[9px] font-mono font-semibold text-[#ff5400]">
                  <Zap className="w-2.5 h-2.5" />
                  {high} HIGH
                </div>
              </div>
            </div>
          </header>

          {/* Scrollable content */}
          <div className="p-6 space-y-5">

            {/* ── Tab content with fade-in transition ─ */}
            <PageTransition tabKey={activeTab}>

              {/* Dashboard */}
              {activeTab === "cyber_dashboard" && (
                <DashboardTab
                  report={report}
                  currentScanId={currentScanId}
                  agenticWorkflowStatus={agentic.workflowStatus}
                  agenticMatchesCurrentScan={agenticMatchesCurrentScan}
                  agenticSummary={agentic.agenticSummary}
                  navigateTo={navigateTo}
                  onRunAgentic={runAgenticForCurrentScan}
                />
              )}

              {/* IDE Workspace */}
              {activeTab === "workspace" && (
                <div className="space-y-4">
                  <IDEWorkspace onScanComplete={(result, scanId) => handleScanComplete(result, scanId)} />

                  {/* Trigger for the Agentic Execution drawer (Section 2) --
                      shown once a deterministic scan exists on screen.
                      Agentic analysis is purely an enrichment pass over
                      these findings, never a second, independent scan. */}
                  {currentScanId && (
                    <div className="rounded-xl bg-[#12131a] border border-violet-500/25 p-4 flex items-center justify-between flex-wrap gap-3">
                      <div>
                        <p className="text-[11px] font-mono font-bold text-[#f4f4f8]">
                          Deterministic scan complete — {findings.length} finding{findings.length === 1 ? "" : "s"}.
                        </p>
                        <p className="text-[9.5px] font-mono text-[#8e8e9a] mt-0.5">
                          Run the multi-agent workflow to add threat modeling, business impact, and validated patches.
                        </p>
                      </div>
                      {agentic.workflowStatus === "running" || agentic.workflowStatus === "starting" ? (
                        <span className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-mono font-bold uppercase tracking-wide bg-violet-500/10 text-violet-300 border border-violet-500/20">
                          <Loader2 className="w-3.5 h-3.5 animate-spin" /> Running…
                        </span>
                      ) : (
                        <button
                          onClick={runAgenticForCurrentScan}
                          className="inline-flex items-center gap-2 px-4 py-2 rounded-lg text-[10px] font-mono font-bold uppercase tracking-wide bg-violet-500/15 text-violet-300 border border-violet-500/30 hover:bg-violet-500/25 transition-colors"
                        >
                          <Play className="w-3.5 h-3.5" /> Run Agentic Analysis on These Findings
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Mind Map */}
              {activeTab === "mindmap" && (
                <div className="space-y-4">
                  <SectionHead title="Code Mind Map & AST Topology" />
                  <p className="text-xs font-mono text-[#8e8e9a] -mt-3 mb-3">
                    Interactive graph visualizing code structure, module dependencies, function call graphs, and risk findings.
                  </p>
                  <CodeMindMap data={mindMapData} />
                </div>
              )}

              {/* Security & Compliance */}
              {activeTab === "security_compliance" && (
                <div className="space-y-5">

                  {/* SECURITY ASSESSMENT HEADER */}
                  <div className="flex flex-wrap items-center justify-between gap-4 bg-[#12131a] border border-white/8 p-4 rounded-xl">
                    <div className="flex items-center gap-2.5">
                      <div className="w-9 h-9 rounded-lg bg-[#ff5400]/10 border border-[#ff5400]/25 flex items-center justify-center text-[#ff5400] shrink-0">
                        <Lock className="w-4 h-4" />
                      </div>
                      <div>
                        <h2 className="text-xs font-mono font-bold text-[#f4f4f8] tracking-wide">SECURITY ASSESSMENT</h2>
                        <p className="text-[10px] font-mono text-[#8e8e9a] mt-0.5">What did we detect? — deterministic findings, source of truth</p>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[10px] font-mono">
                      <div>
                        <div className="text-[#5c5c68] uppercase tracking-wider">Repository</div>
                        <div className="text-[#f4f4f8] font-semibold mt-0.5">{repositoryLabel}</div>
                      </div>
                      <div>
                        <div className="text-[#5c5c68] uppercase tracking-wider">Scan ID</div>
                        <div className="text-[#f4f4f8] font-semibold mt-0.5">{currentScanId || "Not available from the scan"}</div>
                      </div>
                      <div>
                        <div className="text-[#5c5c68] uppercase tracking-wider">Status</div>
                        <div className={`font-semibold mt-0.5 ${report ? "text-emerald-400" : "text-[#8e8e9a]"}`}>
                          {report ? "Completed" : "No scan run yet"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[#5c5c68] uppercase tracking-wider">Scanned</div>
                        <div className="text-[#f4f4f8] font-semibold mt-0.5">{scanTimestampLabel}</div>
                      </div>
                    </div>
                  </div>

                  <SecurityWorkbench
                    report={report}
                    findings={findings}
                    agentic={agentic}
                    agenticMatchesCurrentScan={agenticMatchesCurrentScan}
                    runAgenticForCurrentScan={runAgenticForCurrentScan}
                    viewFindingTrace={viewFindingTrace}
                    viewFindingInSecurity={viewFindingInSecurity}
                    onDiscussInChat={(f: any) => handleDiscussInChat(f)}
                    onNavigateToReports={() => navigateTo("reports")}
                  />
                </div>
              )}

              {/* Business Intent Tab */}
              {activeTab === "business_intent" && (
                <BusinessIntentPage
                  report={report}
                  agenticBusinessViolations={agentic.result?.business_analysis.violations || []}
                  businessCriticalChains={(agentic.result?.risk_fusion.correlated_chains || []).filter(
                    (c: any) => c.business_criticality === "HIGH" || c.business_criticality === "CRITICAL"
                  )}
                  agenticWorkflowStatus={agentic.workflowStatus}
                  hasRunForThisScan={agenticMatchesCurrentScan}
                  agenticScanId={agentic.scanId}
                  sourceScanId={agentic.sourceScanId}
                  onRunAgentic={runAgenticForCurrentScan}
                  onViewFinding={viewFindingInSecurity}
                />
              )}

              {activeTab === "reports" && (() => {
                let agenticCached: any = null;
                try {
                  const raw = sessionStorage.getItem("guardian_agentic_report");
                  if (raw) agenticCached = JSON.parse(raw);
                } catch {}
                const hasAgenticCached = !!agenticCached?.state;

                return (
                  <ReportsHub
                    report={report}
                    findings={findings}
                    agentic={agentic}
                    agenticMatchesCurrentScan={agenticMatchesCurrentScan}
                    hasAgenticCached={hasAgenticCached}
                    reportsBiResult={reportsBiResult}
                    onDownloadReport={handleDownloadReport}
                    onDownloadAgenticReport={handleDownloadAgenticReport}
                    onDownloadLaymanReport={handleDownloadLaymanReport}
                    onNavigateToWorkspace={() => navigateTo("workspace")}
                  />
                );
              })()}

            </PageTransition>
          </div>
        </main>
      </div>

      {/* Clean Floating AI Chatbot FAB */}
      <button
        onClick={() => setIsChatDrawerOpen(true)}
        className="fixed bottom-6 right-6 z-40 group flex items-center justify-center w-[52px] h-[52px] rounded-2xl bg-[#0f131f]/90 backdrop-blur-md border border-white/12 hover:border-[#ff5400]/60 text-[#f4f4f8] shadow-[0_4px_24px_rgba(0,0,0,0.4)] hover:shadow-[0_0_24px_rgba(255,84,0,0.35)] hover:scale-105 active:scale-95 transition-all duration-200"
        title="Chat with AI Security Assistant"
      >
        <Bot className="w-6 h-6 text-[#ff5400] group-hover:scale-110 transition-transform duration-200" />
        <span className="absolute top-2 right-2 w-2.5 h-2.5 bg-emerald-400 border-2 border-[#0B0F19] rounded-full" />
      </button>

      {/* Drawers */}
      <FindingDrawer finding={selectedFinding} isOpen={isFindingDrawerOpen} onClose={() => setIsFindingDrawerOpen(false)} onDiscussInChat={handleDiscussInChat} />
      <ChatDrawer    isOpen={isChatDrawerOpen}  onClose={() => setIsChatDrawerOpen(false)}  initialContext={chatContext} report={report} />

      {/* Agentic Execution drawer (Section 2) -- replaces the old
          standalone Agentic Scan tab. Triggered from IDE Workspace /
          Dashboard / the inline "Run Agentic Analysis" buttons in
          Security & Business Intent; reads the SAME lifted
          useAgenticScan() instance those tabs already read. */}
      <AgenticExecutionDrawer
        open={agenticDrawerOpen}
        onClose={closeAgenticDrawer}
        onGoToWorkspace={() => navigateTo("workspace")}
        scanId={agentic.scanId}
        sourceScanId={agentic.sourceScanId}
        graph={agentic.graph}
        nodeRuntime={agentic.nodeRuntime}
        events={agentic.events}
        state={agentic.state}
        result={agentic.result}
        deterministicBaseline={agentic.deterministicBaseline}
        agenticSummary={agentic.agenticSummary}
        workflowStatus={agentic.workflowStatus}
        error={agentic.error}
        start={agentic.start}
        cancel={agentic.cancel}
        initialSubTab={searchParams?.get("sub") || undefined}
        focusFindingId={searchParams?.get("finding") || null}
        onViewFinding={viewFindingInSecurity}
      />
    </>
  );
}

/* ─── Root export wraps in Suspense for useSearchParams ─────────── */
export default function Home() {
  return (
    <Suspense>
      <AppInner />
    </Suspense>
  );
}
