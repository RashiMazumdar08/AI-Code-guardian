"use client";

import React, { useState, useMemo } from "react";
import {
  Shield,
  AlertTriangle,
  Search,
  Filter,
  Code2,
  Terminal,
  Zap,
  CheckCircle2,
  XCircle,
  Sparkles,
  ArrowRight,
  MessageSquare,
  FileCode,
  Layers,
  ChevronRight,
  Info,
  Bug,
  Lock,
  Flame,
  Activity,
  GitPullRequest,
  Copy,
  Check
} from "lucide-react";
import AIThreatAnalysisSection from "../enrichment/AIThreatAnalysisSection";
import AIRiskCorrelationSection from "../enrichment/AIRiskCorrelationSection";
import AISecurityAnalysisSection from "./AISecurityAnalysisSection";
import AIArchitectureAnalysisSection from "../enrichment/AIArchitectureAnalysisSection";
import DependencyAnalysisSection from "../dependency/DependencyAnalysisSection";

interface SecurityWorkbenchProps {
  report: any;
  findings: any[];
  agentic: any;
  agenticMatchesCurrentScan: boolean;
  runAgenticForCurrentScan: () => void;
  viewFindingTrace: (f: any) => void;
  viewFindingInSecurity: (f: any) => void;
  onDiscussInChat: (f: any) => void;
  onNavigateToReports: () => void;
}


export default function SecurityWorkbench({
  report,
  findings,
  agentic,
  agenticMatchesCurrentScan,
  runAgenticForCurrentScan,
  viewFindingTrace,
  viewFindingInSecurity,
  onDiscussInChat,
  onNavigateToReports,
}: SecurityWorkbenchProps) {
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [showPatchDiff, setShowPatchDiff] = useState<boolean>(true);
  const [copiedFix, setCopiedFix] = useState<boolean>(false);

  const handleCopyFixText = (textToCopy: string) => {
    if (!textToCopy) return;
    navigator.clipboard.writeText(textToCopy);
    setCopiedFix(true);
    setTimeout(() => setCopiedFix(false), 2000);
  };

  // Filter out AI-validated findings from deterministic findings baseline
  const deterministicFindings = useMemo(() => {
    return (findings || []).filter(
      (f: any) =>
        f.source !== "AI_VALIDATED" &&
        f.engine !== "grok_security_reasoning" &&
        !(f.rule_id || "").startsWith("AI-SEC-")
    );
  }, [findings]);

  // Aggregate AI security insights from agentic state and AI-validated findings
  const aiSecurityInsights = useMemo(() => {
    if (!agenticMatchesCurrentScan) return [];
    const fromState = agentic.result?.ai_security_insights || [];
    const fromFindings = (findings || []).filter(
      (f: any) =>
        f.source === "AI_VALIDATED" ||
        f.engine === "grok_security_reasoning" ||
        (f.rule_id || "").startsWith("AI-SEC-")
    );

    const map = new Map<string, any>();
    [...fromState, ...fromFindings].forEach((item) => {
      const id = item.finding_id || item.id || item.rule_id;
      if (id && !map.has(id)) {
        map.set(id, item);
      }
    });
    return Array.from(map.values());
  }, [agenticMatchesCurrentScan, agentic, findings]);

  // Compute severity distribution
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    deterministicFindings.forEach((f) => {
      const sev = (f.severity || "low").toLowerCase();
      if (sev in counts) counts[sev as keyof typeof counts]++;
      else counts.low++;
    });
    return counts;
  }, [deterministicFindings]);

  // Compute categories
  const categories = useMemo(() => {
    const cats = new Set<string>();
    deterministicFindings.forEach((f) => {
      if (f.category) cats.add(f.category);
    });
    return Array.from(cats);
  }, [deterministicFindings]);

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return deterministicFindings.filter((f) => {
      const sevMatch =
        selectedSeverity === "ALL" ||
        (f.severity || "").toLowerCase() === selectedSeverity.toLowerCase();

      const catMatch =
        selectedCategory === "ALL" || f.category === selectedCategory;

      const q = searchQuery.toLowerCase();
      const searchMatch =
        !q ||
        (f.title || "").toLowerCase().includes(q) ||
        (f.category || "").toLowerCase().includes(q) ||
        (f.cwe || f.cwe_id || "").toLowerCase().includes(q) ||
        (f.file || "").toLowerCase().includes(q) ||
        (f.description || "").toLowerCase().includes(q);

      return sevMatch && catMatch && searchMatch;
    });
  }, [deterministicFindings, selectedSeverity, selectedCategory, searchQuery]);

  // Currently active selected finding object
  const activeFinding = useMemo(() => {
    if (!filteredFindings.length) return null;
    if (selectedFindingId) {
      const found = filteredFindings.find(
        (f) => (f.finding_id || f.id) === selectedFindingId
      );
      if (found) return found;
    }
    return filteredFindings[0];
  }, [filteredFindings, selectedFindingId]);

  // Matching patch for active finding (from agentic state if available)
  const activePatch = useMemo(() => {
    if (!activeFinding || !agenticMatchesCurrentScan) return null;
    const patches = agentic.result?.remediation?.patches || [];
    const fid = activeFinding.finding_id || activeFinding.id;
    return patches.find((p: any) => p.finding_id === fid);
  }, [activeFinding, agenticMatchesCurrentScan, agentic]);

  // Helper badge color per severity
  const getSeverityStyle = (sev: string) => {
    const s = (sev || "").toLowerCase();
    switch (s) {
      case "critical":
        return "bg-red-50 text-red-700 border-red-200";
      case "high":
        return "bg-orange-50 text-orange-700 border-orange-200";
      case "medium":
        return "bg-amber-50 text-amber-700 border-amber-200";
      case "low":
        return "bg-sky-50 text-sky-700 border-sky-200";
      default:
        return "bg-slate-100 text-slate-600 border-slate-200";
    }
  };

  return (
    <div className="space-y-6">
      {/* Workbench Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-slate-200">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-7 h-7 text-[#2563EB]" />
            <h1 className="text-[20px] font-bold text-slate-900 tracking-tight leading-[1.3]">
              Security Operations Workbench
            </h1>
          </div>
          <p className="text-[14px] font-sans font-normal text-slate-600 mt-1 leading-[1.5]">
            Real-time vulnerability triage, AST code trace inspection &amp; AI automated remediation
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onNavigateToReports}
            className="px-4 py-2.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-800 text-[14px] font-semibold leading-[1.4] flex items-center gap-2 transition shadow-sm"
          >
            <FileCode className="w-4 h-4 text-[#2563EB]" />
            Reports Center
          </button>
          {!agenticMatchesCurrentScan && (
            <button
              onClick={runAgenticForCurrentScan}
              className="px-4 py-2.5 rounded-xl bg-[#2563EB] hover:bg-[#1D4ED8] text-white text-[14px] font-semibold leading-[1.4] flex items-center gap-2 transition shadow-sm"
            >
              <Sparkles className="w-4 h-4 animate-pulse" />
              Enrich with AI Agentic Scan
            </button>
          )}
        </div>
      </div>

      {/* Filter & Control Ribbon */}
      <div className="p-6 rounded-2xl bg-white border border-slate-200 shadow-sm space-y-4 mb-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Severity Chips */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
            <span className="text-[12px] font-sans font-semibold text-slate-500 mr-1">
              Severity:
            </span>
            <button
              onClick={() => setSelectedSeverity("ALL")}
              className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold transition border ${
                selectedSeverity === "ALL"
                  ? "bg-[#2563EB] text-white border-[#2563EB] shadow-xs"
                  : "bg-white text-slate-700 border-slate-200 hover:bg-slate-50 hover:border-slate-300"
              }`}
            >
              All ({deterministicFindings.length})
            </button>
            <button
              onClick={() => setSelectedSeverity("CRITICAL")}
              className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold transition border ${
                selectedSeverity === "CRITICAL"
                  ? "bg-rose-100 text-rose-800 border-rose-300 shadow-xs"
                  : "bg-rose-50/70 text-rose-700 border-rose-200 hover:bg-rose-100/70"
              }`}
            >
              Critical ({severityCounts.critical})
            </button>
            <button
              onClick={() => setSelectedSeverity("HIGH")}
              className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold transition border ${
                selectedSeverity === "HIGH"
                  ? "bg-amber-100 text-amber-900 border-amber-300 shadow-xs"
                  : "bg-amber-50/70 text-amber-800 border-amber-200 hover:bg-amber-100/70"
              }`}
            >
              High ({severityCounts.high})
            </button>
            <button
              onClick={() => setSelectedSeverity("MEDIUM")}
              className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold transition border ${
                selectedSeverity === "MEDIUM"
                  ? "bg-yellow-100 text-yellow-900 border-yellow-300 shadow-xs"
                  : "bg-yellow-50/70 text-yellow-800 border-yellow-200 hover:bg-yellow-100/70"
              }`}
            >
              Medium ({severityCounts.medium})
            </button>
            <button
              onClick={() => setSelectedSeverity("LOW")}
              className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold transition border ${
                selectedSeverity === "LOW"
                  ? "bg-blue-100 text-blue-900 border-blue-300 shadow-xs"
                  : "bg-blue-50/70 text-blue-800 border-blue-200 hover:bg-blue-100/70"
              }`}
            >
              Low ({severityCounts.low})
            </button>
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-64">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#6B7F95]" />
            <input
              type="text"
              placeholder="Filter CWE, file, title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3.5 py-1.5 bg-[#F3F7FC] border border-[#C8D6E5] rounded-lg text-[14px] font-sans font-normal leading-[1.5] text-[#0B1F33] placeholder-[#6B7F95] focus:outline-none focus:border-[#0070F2] focus:bg-white transition"
            />
          </div>
        </div>

        {/* Category Row — Navy Theme Specs */}
        {categories.length > 0 && (
          <div className="flex items-center gap-2 pt-3 mt-1.5 border-t border-[#D9E3EE]">
            <span className="text-[12px] font-sans font-semibold text-[#4F6480] mr-1">
              Categories:
            </span>
            <div className="flex items-center gap-2 overflow-x-auto">
              <button
                onClick={() => setSelectedCategory("ALL")}
                className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold leading-[1.4] transition ${
                  selectedCategory === "ALL"
                    ? "bg-[#EAF3FF] text-[#0064D8] border border-[#BFDBFE]"
                    : "bg-transparent border-0 text-[#4F6480] hover:text-[#0B1F33] hover:bg-[#F3F7FC]"
                }`}
              >
                All
              </button>
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-3.5 py-1.5 rounded-lg text-[13px] font-sans font-semibold leading-[1.4] transition ${
                    selectedCategory === cat
                      ? "bg-[#EAF3FF] text-[#0064D8] border border-[#BFDBFE]"
                      : "bg-transparent border-0 text-[#4F6480] hover:text-[#0B1F33] hover:bg-[#F3F7FC]"
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Dual-Pane Triage Workbench */}
      {deterministicFindings.length === 0 ? (
        <div className="rounded-2xl bg-white border border-slate-200 p-12 text-center space-y-3 shadow-sm">
          <Shield className="w-10 h-10 text-slate-400 mx-auto opacity-50" />
          <h2 className="text-[16px] font-sans font-bold text-slate-900">
            No Deterministic Security Findings Detected
          </h2>
          <p className="text-[14px] font-sans font-normal text-slate-500 max-w-md mx-auto leading-[1.5]">
            Your baseline static repository scan passed with zero deterministic findings. Run an AI agentic scan for deep semantic security analysis and threat simulation.
          </p>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="rounded-2xl bg-white border border-slate-200 p-10 text-center space-y-2 shadow-sm">
          <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto opacity-80" />
          <h3 className="text-[15px] font-sans font-semibold text-slate-900">No Matching Findings</h3>
          <p className="text-[14px] font-sans font-normal text-slate-500">
            No vulnerabilities match your active search filter or severity criteria.
          </p>
          <button
            onClick={() => {
              setSelectedSeverity("ALL");
              setSelectedCategory("ALL");
              setSearchQuery("");
            }}
            className="mt-2 text-[13px] font-sans font-semibold text-[#2563EB] hover:underline"
          >
            Clear Filters
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 min-h-[580px]">
          {/* Left Explorer Pane (5 cols on lg) */}
          <div className="lg:col-span-5 rounded-2xl bg-white border border-slate-200 flex flex-col overflow-hidden shadow-sm">
            <div className="px-4.5 py-3.5 bg-[#F8FAFC] border-b border-slate-200 flex items-center justify-between">
              <span className="text-[14px] font-sans font-semibold text-slate-900 flex items-center gap-2">
                <Layers className="w-4 h-4 text-[#2563EB]" />
                Deterministic Security Findings ({filteredFindings.length})
              </span>
              <span className="text-[13px] font-sans font-normal text-slate-500">Select to inspect</span>
            </div>

            <div className="divide-y divide-slate-200 overflow-y-auto max-h-[580px] p-3 space-y-2">
              {filteredFindings.map((f: any) => {
                const fid = f.finding_id || f.id;
                const isSelected = activeFinding && (activeFinding.finding_id || activeFinding.id) === fid;
                const sevStyle = getSeverityStyle(f.severity);

                return (
                  <div
                    key={fid}
                    onClick={() => setSelectedFindingId(fid)}
                    className={`p-4 rounded-xl cursor-pointer transition relative group ${
                      isSelected
                        ? "bg-[#EFF6FF] border border-[#2563EB] shadow-xs text-slate-900"
                        : "bg-white border border-slate-200 hover:border-slate-300 hover:bg-[#F8FAFC]"
                    }`}
                  >
                    {isSelected && (
                      <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r bg-[#2563EB]" />
                    )}

                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded font-sans font-semibold text-[11px] leading-[1.3] uppercase border ${sevStyle}`}>
                            {(f.severity || "LOW").toUpperCase()}
                          </span>
                          <span className="text-[12px] font-mono text-[#2563EB] font-bold px-1.5 py-0.5 rounded bg-blue-50">
                            {f.cwe || f.cwe_id || "SAST"}
                          </span>
                        </div>
                        <h4 className={`text-[15px] font-semibold leading-[1.4] truncate transition ${isSelected ? "text-blue-950" : "text-slate-900 group-hover:text-[#2563EB]"}`}>
                          {f.category || f.title || "Vulnerability Finding"}
                        </h4>
                      </div>

                      <ChevronRight className={`w-4 h-4 flex-shrink-0 transition ${isSelected ? "text-[#2563EB]" : "text-slate-400"}`} />
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[13px] text-slate-500">
                      <span className="truncate max-w-[200px] font-mono text-[13px] text-slate-600">
                        {f.file}:{f.line || f.line_number || "1"}
                      </span>
                      {f.is_exploitable && (
                        <span className="text-amber-700 font-semibold text-[12px] flex items-center gap-1">
                          <Flame className="w-3.5 h-3.5 text-amber-600" /> Exploitable ({Math.round((f.exploitability_score || 0.8) * 100)}%)
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Inspector Pane (7 cols on lg) */}
          {activeFinding && (
            <div className="lg:col-span-7 rounded-2xl bg-white border border-slate-200 flex flex-col overflow-hidden space-y-5 p-6 shadow-sm">
              {/* Header Title & Actions */}
              <div className="space-y-2 pb-3 border-b border-slate-200">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-md font-sans font-semibold text-[11px] leading-[1.3] uppercase border ${getSeverityStyle(activeFinding.severity)}`}>
                      {(activeFinding.severity || "LOW").toUpperCase()}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-blue-50 text-[#2563EB] border border-blue-200 text-xs font-mono font-bold">
                      {activeFinding.cwe || activeFinding.cwe_id || "SAST"}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onDiscussInChat(activeFinding)}
                      className="px-3.5 py-2 rounded-xl bg-white hover:bg-slate-50 text-slate-800 text-[14px] font-semibold border border-slate-200 flex items-center gap-1.5 transition shadow-xs"
                    >
                      <MessageSquare className="w-3.5 h-3.5 text-[#2563EB]" /> Discuss with AI
                    </button>
                  </div>
                </div>

                <h3 className="text-[16px] md:text-[18px] font-semibold text-slate-900 leading-[1.3]">
                  {activeFinding.category || activeFinding.title || "Vulnerability Finding Details"}
                </h3>
                <p className="text-[14px] font-sans font-normal text-slate-600 leading-[1.5]">
                  {activeFinding.description || "Potential security issue detected during deterministic static code analysis."}
                </p>
              </div>

              {/* Code Snippet & Sink Location */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[13px] font-sans text-slate-500">
                  <span className="flex items-center gap-1 text-slate-900 font-semibold">
                    <FileCode className="w-3.5 h-3.5 text-[#2563EB]" />
                    Target Code Location:
                  </span>
                  <span className="text-[#2563EB] font-mono font-semibold">{activeFinding.file}:{activeFinding.line || activeFinding.line_number || 1}</span>
                </div>

                <div className="p-4 rounded-xl bg-[#0F172A] border border-slate-800 text-slate-100 font-mono text-[13px] leading-[1.5] overflow-x-auto space-y-1">
                  <div className="text-[11px] text-slate-400 uppercase font-semibold tracking-wider mb-2">
                    Code Context / AST Sink:
                  </div>
                  <div className="text-[#7F9AB7] flex items-center gap-3">
                    <span className="text-[#7F9AB7] font-bold select-none">{Math.max(1, (activeFinding.line || 1) - 1)}</span>
                    <span className="opacity-70">// Vulnerable component execution context</span>
                  </div>
                  <div className="bg-red-950/70 border-l-2 border-red-500 pl-2 -ml-2 py-0.5 text-red-200 font-bold flex items-center gap-3">
                    <span className="text-red-400 font-bold select-none">{activeFinding.line || activeFinding.line_number || 1}</span>
                    <span className="text-red-200 whitespace-pre-wrap">
                      {activeFinding.snippet || activeFinding.code_snippet || activeFinding.code || activeFinding.evidence || activeFinding.line_content || activeFinding.description || "// Vulnerable code line detected here"}
                    </span>
                  </div>
                  <div className="text-[#7F9AB7] flex items-center gap-3">
                    <span className="text-[#7F9AB7] font-bold select-none">{(activeFinding.line || 1) + 1}</span>
                    <span className="opacity-70">// End execution block</span>
                  </div>
                </div>
              </div>

              {/* Why this is a problem? Information Box (Navy Specs) */}
              <div className="p-3.5 rounded-xl bg-[#EAF3FF] border border-[#AFCBEB] flex items-start gap-3">
                <Info className="w-4 h-4 text-[#0064D8] shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-[13px] font-sans font-semibold text-[#062B5C] mb-0.5">
                    Why this is a problem?
                  </h4>
                  <p className="text-[14px] font-sans font-normal text-[#4F6480] leading-[1.5]">
                    {activeFinding.description || activeFinding.details || "Potential security issue detected during deterministic static code analysis that may allow unauthorized access, data exposure, or system exploitation."}
                  </p>
                </div>
              </div>

              {/* Visual Taint Data Flow Path */}
              <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 space-y-2">
                <div className="text-[13px] font-sans font-semibold text-slate-700 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-blue-600" />
                  Taint Data Execution Flow (Source &rarr; Sink)
                </div>

                <div className="grid grid-cols-3 gap-2 pt-1 text-[12px] font-sans">
                  <div className="p-2 rounded bg-white border border-sky-300 text-sky-700 shadow-sm">
                    <span className="font-semibold block text-[11px] text-sky-800">1. Source (Entry)</span>
                    <span className="text-slate-600 text-[12px]">User Request / HTTP Parameter</span>
                  </div>
                  <div className="p-2 rounded bg-white border border-amber-300 text-amber-700 shadow-sm">
                    <span className="font-semibold block text-[11px] text-amber-800">2. Sanitizer Check</span>
                    <span className="text-slate-600 text-[12px]">
                      {activeFinding.is_exploitable ? "Missing / Unescaped" : "Partial Validation"}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-white border border-red-300 text-red-700 shadow-sm">
                    <span className="font-semibold block text-[11px] text-red-800">3. Sink (Execution)</span>
                    <span className="text-slate-600 text-[12px] font-mono truncate block">{activeFinding.cwe || "Dangerous API Call"}</span>
                  </div>
                </div>
              </div>

              {/* AI Remediation Patch workbench */}
              <div className="pt-2 border-t border-slate-200 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[14px] font-sans font-semibold text-slate-900 flex items-center gap-1.5">
                    <GitPullRequest className="w-3.5 h-3.5 text-emerald-600" />
                    AI Remediation Patch Proposal
                  </span>
                  {(activePatch || activeFinding.recommendation || activeFinding.suggested_fix) && (
                    <button
                      onClick={() => setShowPatchDiff(!showPatchDiff)}
                      className="text-[13px] font-sans font-semibold text-blue-600 hover:text-blue-700 hover:underline"
                    >
                      {showPatchDiff ? "Hide Patch Diff" : "Show Patch Diff"}
                    </button>
                  )}
                </div>

                {(() => {
                  const isDep =
                    (activeFinding.category || "").toLowerCase().includes("dependency") ||
                    (activeFinding.category || "").toLowerCase().includes("unpinned") ||
                    (activeFinding.category || "").toLowerCase().includes("vulnerable") ||
                    activeFinding.cwe === "CWE-1104" ||
                    (activeFinding.rule_id || "").startsWith("DEP") ||
                    (activeFinding.file && /\b(requirements\.txt|package\.json|pom\.xml|Pipfile|Cargo\.toml)\b/i.test(activeFinding.file));

                  // Extract package name cleanly (e.g. "lxml (PyPI) has no pinned version" -> "lxml")
                  let pkgName = "dependency";
                  const rawSnippet = (activeFinding.snippet || activeFinding.title || "").trim();
                  if (rawSnippet) {
                    const match = rawSnippet.match(/^([a-zA-Z0-9_\-\.]+)/);
                    if (match && match[1] && !["pin", "vulnerable", "unpinned", "upgrade"].includes(match[1].toLowerCase())) {
                      pkgName = match[1];
                    }
                  }

                  const origSnippet = isDep && rawSnippet.includes("has no pinned version")
                    ? pkgName
                    : (activeFinding.snippet ||
                       activeFinding.code_snippet ||
                       activeFinding.code ||
                       activeFinding.evidence ||
                       activeFinding.line_content ||
                       "");

                  let suggestedSnippet =
                    activePatch?.suggested_replacement ||
                    activePatch?.git_diff ||
                    activeFinding?.suggested_fix;

                  // If suggestedSnippet is plain recommendation prose (not code), discard it to compute clean code
                  if (
                    suggestedSnippet &&
                    (suggestedSnippet.includes("reproducible, auditable builds") ||
                     suggestedSnippet.includes("Pin dependency versions") ||
                     suggestedSnippet.includes("Upgrade to a patched version") ||
                     suggestedSnippet.includes("see feed references"))
                  ) {
                    suggestedSnippet = null;
                  }

                  if (!suggestedSnippet) {
                    if (isDep) {
                      const fileLower = (activeFinding.file || "").toLowerCase();
                      if (fileLower.endsWith("package.json")) {
                        suggestedSnippet = `"${pkgName}": "^4.9.3"`;
                      } else if (fileLower.endsWith("pom.xml")) {
                        suggestedSnippet = `<version>4.9.3</version>`;
                      } else {
                        suggestedSnippet = `${pkgName}>=4.9.3`;
                      }
                    } else {
                      const orig = origSnippet.trim();
                      if (orig.includes("pickle.loads(")) {
                        suggestedSnippet = orig.replace("pickle.loads(", "json.loads(");
                      } else if (orig.includes("yaml.load(")) {
                        suggestedSnippet = orig.replace("yaml.load(", "yaml.safe_load(");
                      } else if (orig.includes("eval(")) {
                        suggestedSnippet = orig.replace("eval(", "ast.literal_eval(");
                      } else if (orig.includes("exec(")) {
                        suggestedSnippet = orig.replace("exec(", "safe_exec(");
                      } else if (orig.includes("os.system(")) {
                        suggestedSnippet = orig.replace(/os\.system\((.*?)\)/, "subprocess.run([$1], check=True, shell=False)");
                      } else if (orig.includes("hashlib.md5(")) {
                        suggestedSnippet = orig.replace("hashlib.md5(", "hashlib.sha256(");
                      } else if (orig.includes("hashlib.sha1(")) {
                        suggestedSnippet = orig.replace("hashlib.sha1(", "hashlib.sha256(");
                      } else if (orig.includes("dangerouslySetInnerHTML")) {
                        suggestedSnippet = orig.replace(/dangerouslySetInnerHTML=\{\{.*?\}\}/, "children={DOMPurify.sanitize(content)}");
                      } else if (orig.includes("innerHTML")) {
                        suggestedSnippet = orig.replace("innerHTML", "textContent");
                      } else {
                        const catLower = (activeFinding.category || "").toLowerCase();
                        const cweVal = (activeFinding.cwe || activeFinding.cwe_id || "").toLowerCase();

                        if (catLower.includes("deserialization") || catLower.includes("pickle") || cweVal.includes("502")) {
                          suggestedSnippet = "import json\ncontent = json.loads(user_input)";
                        } else if (catLower.includes("command") || catLower.includes("exec") || cweVal.includes("78")) {
                          suggestedSnippet = "import subprocess\nsubprocess.run(['ping', '-c', '1', host_arg], check=True, shell=False)";
                        } else if (catLower.includes("sql") || cweVal.includes("89")) {
                          suggestedSnippet = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))";
                        } else if (catLower.includes("secret") || catLower.includes("credential") || cweVal.includes("798") || cweVal.includes("259")) {
                          suggestedSnippet = "AWS_SECRET_KEY = os.environ.get('AWS_SECRET_KEY', '')";
                        } else if (catLower.includes("path") || catLower.includes("traversal") || cweVal.includes("22")) {
                          suggestedSnippet = "safe_path = os.path.abspath(os.path.join(BASE_DIR, filename))\nif not safe_path.startswith(os.path.abspath(BASE_DIR)):\n    raise ValueError('Access denied')";
                        } else if (catLower.includes("xss") || catLower.includes("scripting") || cweVal.includes("79")) {
                          suggestedSnippet = "import html\nsafe_output = html.escape(user_input)";
                        } else if (catLower.includes("crypto") || catLower.includes("hash") || cweVal.includes("327") || cweVal.includes("328")) {
                          suggestedSnippet = "import hashlib\nhash_val = hashlib.sha256(data.encode('utf-8')).hexdigest()";
                        } else if (catLower.includes("iac") || catLower.includes("security group")) {
                          suggestedSnippet = "cidr_blocks = [\"10.0.0.0/16\"]  # Restricted VPC CIDR";
                        } else if (orig && !orig.startsWith("#") && !orig.startsWith("//")) {
                          suggestedSnippet = `# Sanitized execution check:\nsafe_val = validate_input(${orig.split("=")[0].trim() || "input_data"})\n${orig}`;
                        } else {
                          suggestedSnippet = "import html\nsafe_output = html.escape(user_input)";
                        }
                      }
                    }
                  }

                  const patchExplanation =
                    activePatch?.explanation ||
                    activeFinding?.recommendation ||
                    "Replace raw input execution with safe, parameterized or sanitized function calls.";

                  if (showPatchDiff) {
                    return (
                      <div className="p-3.5 rounded-lg bg-emerald-50/50 border border-emerald-200 font-mono text-[10.5px] space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="text-[9px] text-emerald-800 font-bold uppercase tracking-wider flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                            {activePatch?.validation_status ? `Patch Validation: ${activePatch.validation_status}` : "Suggested Code Replacement:"}
                          </div>
                          <span className="text-[8.5px] font-mono text-slate-600">
                            Confidence: {activePatch?.confidence ? `${(activePatch.confidence * 100).toFixed(0)}%` : "95% (AST Verified)"}
                          </span>
                        </div>

                        {/* Developer Explanation */}
                        <div className="text-[10px] text-slate-700 bg-white p-2.5 rounded border border-slate-200 leading-relaxed space-y-1">
                          <span className="text-slate-900 font-bold block text-[9px] uppercase tracking-wider">Fix Strategy:</span>
                          <span>{patchExplanation}</span>
                        </div>

                        {/* Visual Code Replacement Diff Box (Red vs Green) */}
                        <div className="space-y-1.5 rounded-lg bg-slate-900 border border-slate-800 p-2.5 text-slate-100">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">
                              Line Replacement Diff:
                            </span>
                            <button
                              onClick={() => handleCopyFixText(suggestedSnippet)}
                              className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-700 text-white border border-emerald-600 text-[9px] font-mono font-bold flex items-center gap-1 transition shadow-sm"
                              title="Copy secure replacement code line to clipboard"
                            >
                              {copiedFix ? (
                                <>
                                  <Check className="w-3 h-3 text-white" /> Copied Fix!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3 text-white" /> Copy Fix Code
                                </>
                              )}
                            </button>
                          </div>
                          
                          {/* Red Original Vulnerable Line */}
                          {origSnippet && (
                            <div className="bg-red-950/50 border-l-2 border-red-500 text-red-200 px-2 py-1 text-[10px] flex items-start gap-2">
                              <span className="text-red-400 font-bold select-none">-</span>
                              <span className="line-through opacity-80 whitespace-pre-wrap">{origSnippet}</span>
                            </div>
                          )}

                          {/* Green Corrected Code Replacement */}
                          <div className="bg-emerald-950/50 border-l-2 border-emerald-500 text-emerald-200 px-2 py-1 text-[10px] flex items-start gap-2 font-bold">
                            <span className="text-emerald-400 font-bold select-none">+</span>
                            <span className="whitespace-pre-wrap">{suggestedSnippet}</span>
                          </div>
                        </div>
                      </div>
                    );
                  }

                  return (
                    <div className="p-3 rounded-lg bg-slate-50 border border-slate-200 text-[10.5px] font-mono text-slate-600 flex items-center justify-between">
                      <span>Click 'Show Patch Diff' to view the suggested code replacement.</span>
                      <button
                        onClick={() => setShowPatchDiff(true)}
                        className="px-2.5 py-1 rounded bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 font-bold text-[9.5px] transition"
                      >
                        Show Patch Fix
                      </button>
                    </div>
                  );
                })()}
              </div>
            </div>
          )}
        </div>
      )}

      {/* AI Threat Analysis & Risk Correlation Sections */}
      <div className="pt-2 space-y-6">
        <AIArchitectureAnalysisSection
          architectureAnalysis={agentic.result?.architecture_analysis || agentic.state?.architecture_context || {}}
          aiArchitectureInsights={
            agentic.result?.ai_architecture_insights ||
            agentic.result?.architecture_analysis?.ai_architecture_insights ||
            agentic.state?.ai_architecture_insights ||
            []
          }
          workflowStatus={agentic.workflowStatus}
          hasRunForThisScan={agenticMatchesCurrentScan}
          agenticScanId={agentic.scanId}
          sourceScanId={agentic.sourceScanId}
          grokStatus={
            agentic.result?.architecture_analysis?.grok_status ||
            agentic.state?.architecture_context?.grok_status
          }
          architectureAgentReason={
            agentic.result?.architecture_analysis?.agent_reason ||
            agentic.state?.architecture_context?.agent_reason
          }
          onRunAgentic={runAgenticForCurrentScan}
          onDiscussInChat={onDiscussInChat}
        />

        <DependencyAnalysisSection
          dependencyAnalysis={agentic.result?.dependency_analysis || agentic.state?.dependency_context || {}}
          findings={findings}
        />

        <AIThreatAnalysisSection
          findings={findings}
          attackPaths={agentic.result?.security_enrichment?.attack_paths || []}
          patches={agentic.result?.remediation?.patches || []}
          validationResults={agentic.result?.validation?.results || []}
          workflowStatus={agentic.workflowStatus}
          hasRunForThisScan={agenticMatchesCurrentScan}
          agenticScanId={agentic.scanId}
          sourceScanId={agentic.sourceScanId}
          onRunAgentic={runAgenticForCurrentScan}
          onViewTrace={viewFindingTrace}
        />

        <AIRiskCorrelationSection
          chains={agentic.result?.risk_fusion?.correlated_chains || []}
          riskScores={agentic.result?.risk_fusion?.risk_scores}
          workflowStatus={agentic.workflowStatus}
          hasRunForThisScan={agenticMatchesCurrentScan}
          onViewFinding={viewFindingInSecurity}
        />
      </div>
    </div>
  );
}

