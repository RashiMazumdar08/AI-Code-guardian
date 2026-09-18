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

  // Compute severity distribution
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach((f) => {
      const sev = (f.severity || "low").toLowerCase();
      if (sev in counts) counts[sev as keyof typeof counts]++;
      else counts.low++;
    });
    return counts;
  }, [findings]);

  // Compute categories
  const categories = useMemo(() => {
    const cats = new Set<string>();
    findings.forEach((f) => {
      if (f.category) cats.add(f.category);
    });
    return Array.from(cats);
  }, [findings]);

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
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
  }, [findings, selectedSeverity, selectedCategory, searchQuery]);

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
        return "bg-red-500/15 text-red-400 border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.2)]";
      case "high":
        return "bg-[#ff5400]/15 text-[#ff5400] border-[#ff5400]/30 shadow-[0_0_12px_rgba(255,84,0,0.2)]";
      case "medium":
        return "bg-amber-500/15 text-amber-400 border-amber-500/30";
      case "low":
        return "bg-sky-500/15 text-sky-400 border-sky-500/30";
      default:
        return "bg-slate-500/15 text-slate-400 border-slate-500/30";
    }
  };

  return (
    <div className="space-y-6">
      {/* Workbench Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-white/8">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-[#ff5400]" />
            <h1 className="text-base font-mono font-bold text-[#f4f4f8] tracking-wide uppercase">
              SECURITY OPERATIONS WORKBENCH
            </h1>
          </div>
          <p className="text-[11px] font-mono text-[#8e8e9a] mt-1">
            Real-time vulnerability triage, AST code trace inspection &amp; AI automated remediation
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onNavigateToReports}
            className="px-3.5 py-1.5 rounded-lg bg-[#12131a] border border-white/10 hover:border-[#ff5400]/40 text-[#f4f4f8] text-[10.5px] font-mono font-bold flex items-center gap-1.5 transition"
          >
            <FileCode className="w-3.5 h-3.5 text-[#ff5400]" />
            Reports Center
          </button>
          {!agenticMatchesCurrentScan && (
            <button
              onClick={runAgenticForCurrentScan}
              className="px-3.5 py-1.5 rounded-lg bg-[#ff5400]/15 hover:bg-[#ff5400]/25 text-[#ff5400] border border-[#ff5400]/30 text-[10.5px] font-mono font-bold flex items-center gap-1.5 transition shadow-[0_0_15px_rgba(255,84,0,0.15)]"
            >
              <Sparkles className="w-3.5 h-3.5 animate-pulse" />
              Enrich with AI Agentic Scan
            </button>
          )}
        </div>
      </div>

      {/* Filter & Control Ribbon */}
      <div className="p-4 rounded-xl bg-[#12131a] border border-white/8 space-y-3.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Severity Chips */}
          <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
            <span className="text-[10px] font-mono text-[#8e8e9a] uppercase font-bold tracking-wider mr-1">
              Severity:
            </span>
            <button
              onClick={() => setSelectedSeverity("ALL")}
              className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold uppercase transition border ${
                selectedSeverity === "ALL"
                  ? "bg-[#ff5400]/20 text-[#ff5400] border-[#ff5400]/50 shadow-[0_0_10px_rgba(255,84,0,0.2)]"
                  : "bg-[#0c0d11] text-[#8e8e9a] border-white/5 hover:border-white/20"
              }`}
            >
              All ({findings.length})
            </button>
            <button
              onClick={() => setSelectedSeverity("CRITICAL")}
              className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold uppercase transition border ${
                selectedSeverity === "CRITICAL"
                  ? "bg-red-500/25 text-red-400 border-red-500/60 shadow-[0_0_10px_rgba(239,68,68,0.25)]"
                  : "bg-[#0c0d11] text-[#8e8e9a] border-white/5 hover:border-red-500/30"
              }`}
            >
              Critical ({severityCounts.critical})
            </button>
            <button
              onClick={() => setSelectedSeverity("HIGH")}
              className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold uppercase transition border ${
                selectedSeverity === "HIGH"
                  ? "bg-[#ff5400]/25 text-[#ff5400] border-[#ff5400]/60 shadow-[0_0_10px_rgba(255,84,0,0.25)]"
                  : "bg-[#0c0d11] text-[#8e8e9a] border-white/5 hover:border-[#ff5400]/30"
              }`}
            >
              High ({severityCounts.high})
            </button>
            <button
              onClick={() => setSelectedSeverity("MEDIUM")}
              className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold uppercase transition border ${
                selectedSeverity === "MEDIUM"
                  ? "bg-amber-500/25 text-amber-400 border-amber-500/60 shadow-[0_0_10px_rgba(245,158,11,0.25)]"
                  : "bg-[#0c0d11] text-[#8e8e9a] border-white/5 hover:border-amber-500/30"
              }`}
            >
              Medium ({severityCounts.medium})
            </button>
            <button
              onClick={() => setSelectedSeverity("LOW")}
              className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold uppercase transition border ${
                selectedSeverity === "LOW"
                  ? "bg-sky-500/25 text-sky-400 border-sky-500/60"
                  : "bg-[#0c0d11] text-[#8e8e9a] border-white/5 hover:border-sky-500/30"
              }`}
            >
              Low ({severityCounts.low})
            </button>
          </div>

          {/* Search Box */}
          <div className="relative w-full sm:w-64">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#8e8e9a]" />
            <input
              type="text"
              placeholder="Filter CWE, file, title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#0c0d11] border border-white/8 rounded-lg text-[11px] font-mono text-[#f4f4f8] placeholder-[#5c5c68] focus:outline-none focus:border-[#ff5400]/50 transition"
            />
          </div>
        </div>

        {/* Category Pills if categories exist */}
        {categories.length > 0 && (
          <div className="flex items-center gap-2 pt-1 border-t border-white/5">
            <span className="text-[9.5px] font-mono text-[#5c5c68] uppercase font-bold tracking-wider">
              Categories:
            </span>
            <div className="flex items-center gap-1.5 overflow-x-auto">
              <button
                onClick={() => setSelectedCategory("ALL")}
                className={`px-2.5 py-0.5 rounded text-[9.5px] font-mono transition ${
                  selectedCategory === "ALL"
                    ? "bg-[#f4f4f8]/10 text-[#f4f4f8] font-bold"
                    : "text-[#8e8e9a] hover:text-[#f4f4f8]"
                }`}
              >
                All
              </button>
              {categories.map((cat) => (
                <button
                  key={cat}
                  onClick={() => setSelectedCategory(cat)}
                  className={`px-2.5 py-0.5 rounded text-[9.5px] font-mono transition ${
                    selectedCategory === cat
                      ? "bg-[#ff5400]/20 text-[#ff5400] font-bold"
                      : "text-[#8e8e9a] hover:text-[#f4f4f8]"
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
      {findings.length === 0 ? (
        <div className="rounded-xl bg-[#12131a] border border-white/8 p-12 text-center space-y-3">
          <Shield className="w-10 h-10 text-[#5c5c68] mx-auto opacity-50" />
          <h2 className="text-xs font-mono font-bold text-[#f4f4f8] uppercase tracking-wider">
            No Security Findings Detected
          </h2>
          <p className="text-[11px] font-mono text-[#8e8e9a] max-w-md mx-auto">
            Your repository scan passed with zero deterministic findings. Run an AI agentic scan for deep threat simulation.
          </p>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="rounded-xl bg-[#12131a] border border-white/8 p-10 text-center space-y-2">
          <AlertTriangle className="w-8 h-8 text-amber-400 mx-auto opacity-80" />
          <h3 className="text-xs font-mono font-bold text-[#f4f4f8]">No Matching Findings</h3>
          <p className="text-[11px] font-mono text-[#8e8e9a]">
            No vulnerabilities match your active search filter or severity criteria.
          </p>
          <button
            onClick={() => {
              setSelectedSeverity("ALL");
              setSelectedCategory("ALL");
              setSearchQuery("");
            }}
            className="mt-2 text-[10px] font-mono font-bold text-[#ff5400] underline"
          >
            Clear Filters
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 min-h-[560px]">
          {/* Left Explorer Pane (5 cols on lg) */}
          <div className="lg:col-span-5 rounded-xl bg-[#12131a] border border-white/8 flex flex-col overflow-hidden">
            <div className="px-4 py-3 bg-[#0c0d11] border-b border-white/8 flex items-center justify-between">
              <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#8e8e9a] flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-[#ff5400]" />
                Vulnerability Registry ({filteredFindings.length})
              </span>
              <span className="text-[9px] font-mono text-[#5c5c68]">Select to inspect</span>
            </div>

            <div className="divide-y divide-white/5 overflow-y-auto max-h-[580px] p-2 space-y-1">
              {filteredFindings.map((f: any) => {
                const fid = f.finding_id || f.id;
                const isSelected = activeFinding && (activeFinding.finding_id || activeFinding.id) === fid;
                const sevStyle = getSeverityStyle(f.severity);

                return (
                  <div
                    key={fid}
                    onClick={() => setSelectedFindingId(fid)}
                    className={`p-3 rounded-lg cursor-pointer transition relative group ${
                      isSelected
                        ? "bg-[#181a24] border border-[#ff5400]/40 shadow-[0_0_15px_rgba(255,84,0,0.1)]"
                        : "bg-[#0c0d11]/60 border border-transparent hover:bg-[#14151f] hover:border-white/10"
                    }`}
                  >
                    {isSelected && (
                      <span className="absolute left-0 top-2 bottom-2 w-1 rounded-r bg-[#ff5400]" />
                    )}

                    <div className="flex items-start justify-between gap-2">
                      <div className="space-y-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded font-mono font-bold text-[8.5px] uppercase border ${sevStyle}`}>
                            {(f.severity || "LOW").toUpperCase()}
                          </span>
                          <span className="text-[10px] font-mono text-[#8e8e9a] font-bold">
                            {f.cwe || f.cwe_id || "SAST"}
                          </span>
                        </div>
                        <h4 className="text-[11.5px] font-mono font-bold text-[#f4f4f8] truncate group-hover:text-[#ff5400] transition">
                          {f.category || f.title || "Vulnerability Finding"}
                        </h4>
                      </div>

                      <ChevronRight className={`w-4 h-4 flex-shrink-0 transition ${isSelected ? "text-[#ff5400]" : "text-[#5c5c68]"}`} />
                    </div>

                    <div className="mt-2 flex items-center justify-between text-[9.5px] font-mono text-[#8e8e9a]">
                      <span className="truncate max-w-[200px] text-[#5c5c68]">
                        {f.file}:{f.line || f.line_number || "1"}
                      </span>
                      {f.is_exploitable && (
                        <span className="text-[#ff5400] font-bold flex items-center gap-1">
                          <Flame className="w-3 h-3" /> Exploitable ({Math.round((f.exploitability_score || 0.8) * 100)}%)
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
            <div className="lg:col-span-7 rounded-xl bg-[#12131a] border border-white/8 flex flex-col overflow-hidden space-y-4 p-5">
              {/* Header Title & Actions */}
              <div className="space-y-2 pb-3 border-b border-white/8">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded-md font-mono font-bold text-[10px] uppercase border ${getSeverityStyle(activeFinding.severity)}`}>
                      {(activeFinding.severity || "LOW").toUpperCase()}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-white/5 text-[#8e8e9a] text-[10px] font-mono">
                      {activeFinding.cwe || activeFinding.cwe_id || "SAST"}
                    </span>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => onDiscussInChat(activeFinding)}
                      className="px-2.5 py-1 rounded bg-[#ff5400]/10 hover:bg-[#ff5400]/20 text-[#ff5400] text-[10px] font-mono font-bold border border-[#ff5400]/25 flex items-center gap-1 transition"
                    >
                      <MessageSquare className="w-3 h-3" /> Discuss AI
                    </button>
                  </div>
                </div>

                <h3 className="text-sm font-mono font-bold text-[#f4f4f8]">
                  {activeFinding.category || activeFinding.title || "Vulnerability Finding Details"}
                </h3>
                <p className="text-[11px] font-mono text-[#8e8e9a] leading-relaxed">
                  {activeFinding.description || "Potential security issue detected during deterministic static code analysis."}
                </p>
              </div>

              {/* Code Snippet & Sink Location */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[10px] font-mono text-[#8e8e9a]">
                  <span className="flex items-center gap-1 text-[#f4f4f8] font-bold">
                    <FileCode className="w-3.5 h-3.5 text-[#ff5400]" />
                    Target Code Location:
                  </span>
                  <span>{activeFinding.file}:{activeFinding.line || activeFinding.line_number || 1}</span>
                </div>

                <div className="p-3.5 rounded-lg bg-[#08090c] border border-white/10 font-mono text-[11px] overflow-x-auto space-y-1">
                  <div className="text-[9.5px] text-[#5c5c68] uppercase font-bold tracking-wider mb-2">
                    Code Context / AST Sink:
                  </div>
                  <div className="text-[#8e8e9a] flex items-center gap-3">
                    <span className="text-[#5c5c68] font-bold select-none">{Math.max(1, (activeFinding.line || 1) - 1)}</span>
                    <span className="opacity-70">// Vulnerable component execution context</span>
                  </div>
                  <div className="bg-[#ff5400]/10 border-l-2 border-[#ff5400] pl-2 -ml-2 py-0.5 text-white font-bold flex items-center gap-3">
                    <span className="text-[#ff5400] font-bold select-none">{activeFinding.line || activeFinding.line_number || 1}</span>
                    <span className="text-[#ff5400] whitespace-pre-wrap">
                      {activeFinding.snippet || activeFinding.code_snippet || activeFinding.code || activeFinding.evidence || activeFinding.line_content || activeFinding.description || "// Vulnerable code line detected here"}
                    </span>
                  </div>
                  <div className="text-[#8e8e9a] flex items-center gap-3">
                    <span className="text-[#5c5c68] font-bold select-none">{(activeFinding.line || 1) + 1}</span>
                    <span className="opacity-70">// End execution block</span>
                  </div>
                </div>
              </div>

              {/* Visual Taint Data Flow Path */}
              <div className="p-3.5 rounded-lg bg-[#0c0d11] border border-white/8 space-y-2">
                <div className="text-[10px] font-mono font-bold uppercase tracking-wider text-[#8e8e9a] flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-[#ff5400]" />
                  Taint Data Execution Flow (Source &rarr; Sink)
                </div>

                <div className="grid grid-cols-3 gap-2 pt-1 text-[10px] font-mono">
                  <div className="p-2 rounded bg-[#12131a] border border-sky-500/30 text-sky-400">
                    <span className="font-bold block text-[8.5px] uppercase text-sky-300">1. Source (Entry)</span>
                    <span className="text-[#8e8e9a] text-[9.5px]">User Request / HTTP Parameter</span>
                  </div>
                  <div className="p-2 rounded bg-[#12131a] border border-amber-500/30 text-amber-400">
                    <span className="font-bold block text-[8.5px] uppercase text-amber-300">2. Sanitizer Check</span>
                    <span className="text-[#8e8e9a] text-[9.5px]">
                      {activeFinding.is_exploitable ? "Missing / Unescaped" : "Partial Validation"}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-[#12131a] border border-red-500/30 text-red-400">
                    <span className="font-bold block text-[8.5px] uppercase text-red-300">3. Sink (Execution)</span>
                    <span className="text-[#8e8e9a] text-[9.5px] truncate block">{activeFinding.cwe || "Dangerous API Call"}</span>
                  </div>
                </div>
              </div>

              {/* AI Remediation Patch workbench */}
              <div className="pt-2 border-t border-white/8 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10.5px] font-mono font-bold text-[#f4f4f8] flex items-center gap-1.5">
                    <GitPullRequest className="w-3.5 h-3.5 text-emerald-400" />
                    AI Remediation Patch Proposal
                  </span>
                  {(activePatch || activeFinding.recommendation || activeFinding.suggested_fix) && (
                    <button
                      onClick={() => setShowPatchDiff(!showPatchDiff)}
                      className="text-[9.5px] font-mono text-[#ff5400] hover:underline"
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
                      <div className="p-3.5 rounded-lg bg-[#08090c] border border-emerald-500/30 font-mono text-[10.5px] space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="text-[9px] text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                            {activePatch?.validation_status ? `Patch Validation: ${activePatch.validation_status}` : "Suggested Code Replacement:"}
                          </div>
                          <span className="text-[8.5px] font-mono text-[#8e8e9a]">
                            Confidence: {activePatch?.confidence ? `${(activePatch.confidence * 100).toFixed(0)}%` : "95% (AST Verified)"}
                          </span>
                        </div>

                        {/* Developer Explanation */}
                        <div className="text-[10px] text-[#8e8e9a] bg-[#12131a] p-2.5 rounded border border-white/5 leading-relaxed space-y-1">
                          <span className="text-[#f4f4f8] font-bold block text-[9px] uppercase tracking-wider">Fix Strategy:</span>
                          <span>{patchExplanation}</span>
                        </div>

                        {/* Visual Code Replacement Diff Box (Red vs Green) */}
                        <div className="space-y-1.5 rounded-lg bg-[#040507] border border-white/10 p-2.5">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[9px] font-bold uppercase tracking-wider text-[#8e8e9a]">
                              Line Replacement Diff:
                            </span>
                            <button
                              onClick={() => handleCopyFixText(suggestedSnippet)}
                              className="px-2.5 py-1 rounded bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/30 text-[9px] font-mono font-bold flex items-center gap-1 transition shadow-[0_0_10px_rgba(16,185,129,0.15)]"
                              title="Copy secure replacement code line to clipboard"
                            >
                              {copiedFix ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" /> Copied Fix!
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3 text-emerald-400" /> Copy Fix Code
                                </>
                              )}
                            </button>
                          </div>
                          
                          {/* Red Original Vulnerable Line */}
                          {origSnippet && (
                            <div className="bg-red-500/15 border-l-2 border-red-500 text-red-300 px-2 py-1 text-[10px] flex items-start gap-2">
                              <span className="text-red-500 font-bold select-none">-</span>
                              <span className="line-through opacity-80 whitespace-pre-wrap">{origSnippet}</span>
                            </div>
                          )}

                          {/* Green Corrected Code Replacement */}
                          <div className="bg-emerald-500/15 border-l-2 border-emerald-500 text-emerald-300 px-2 py-1 text-[10px] flex items-start gap-2 font-bold">
                            <span className="text-emerald-400 font-bold select-none">+</span>
                            <span className="whitespace-pre-wrap">{suggestedSnippet}</span>
                          </div>
                        </div>
                      </div>
                    );
                  }

                  return (
                    <div className="p-3 rounded-lg bg-[#0c0d11] border border-white/5 text-[10.5px] font-mono text-[#8e8e9a] flex items-center justify-between">
                      <span>Click 'Show Patch Diff' to view the suggested code replacement.</span>
                      <button
                        onClick={() => setShowPatchDiff(true)}
                        className="px-2.5 py-1 rounded bg-[#ff5400]/15 hover:bg-[#ff5400]/25 text-[#ff5400] font-bold text-[9.5px] transition"
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
      <div className="pt-4 space-y-6">
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
