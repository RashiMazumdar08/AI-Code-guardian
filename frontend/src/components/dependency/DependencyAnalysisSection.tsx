"use client";

import React, { useState, useMemo, useEffect } from "react";
import {
  Package,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Info,
  ChevronDown,
  ChevronUp,
  Search,
  Sparkles,
  Terminal,
  Tag,
  Activity,
  Database,
  Flame,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

export interface DependencyAnalysisSectionProps {
  dependencyAnalysis?: {
    total_dependencies?: number;
    direct_dependencies_count?: number;
    transitive_dependencies_count?: number;
    vulnerable_dependencies_count?: number;
    manifest_files?: string[];
    detected_libraries?: { name: string; version: string; ecosystem: string; manifest: string }[];
    cve_list?: string[];
    grok_status?: string;
    agent_reason?: string;
    ai_dependency_insights?: any[];
  };
  aiDependencyInsights?: any[];
  findings?: any[];
}

function getPageNumbers(current: number, total: number): (number | string)[] {
  if (total <= 7) {
    return Array.from({ length: total }, (_, i) => i + 1);
  }
  if (current <= 3) {
    return [1, 2, 3, 4, "...", total];
  }
  if (current >= total - 2) {
    return [1, "...", total - 3, total - 2, total - 1, total];
  }
  return [1, "...", current - 1, current, current + 1, "...", total];
}

export default function DependencyAnalysisSection({
  dependencyAnalysis = {},
  aiDependencyInsights = [],
  findings = [],
}: DependencyAnalysisSectionProps) {
  const [open, setOpen] = useState(true);
  const [activeTab, setActiveTab] = useState<"vulnerable" | "outdated" | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [ecosystemFilter, setEcosystemFilter] = useState<string>("ALL");
  const [expandedPkg, setExpandedPkg] = useState<string | null>(null);
  const [currentPage, setCurrentPage] = useState(1);

  const PAGE_SIZE = 10;

  const rawLibraries = dependencyAnalysis.detected_libraries || [];
  const total = dependencyAnalysis.total_dependencies ?? rawLibraries.length;
  const direct = dependencyAnalysis.direct_dependencies_count ?? 0;
  const transitive = dependencyAnalysis.transitive_dependencies_count ?? 0;
  const cveList = useMemo(() => Array.from(new Set(dependencyAnalysis.cve_list || [])), [dependencyAnalysis.cve_list]);

  const allAiInsights = useMemo(() => {
    if (aiDependencyInsights && aiDependencyInsights.length > 0) return aiDependencyInsights;
    if (dependencyAnalysis.ai_dependency_insights && dependencyAnalysis.ai_dependency_insights.length > 0) {
      return dependencyAnalysis.ai_dependency_insights;
    }
    return [];
  }, [aiDependencyInsights, dependencyAnalysis.ai_dependency_insights]);

  // Extract dependency-specific findings from findings list
  const depFindings = useMemo(() => {
    return (findings || []).filter((f: any) => {
      const cat = (f.category || "").toLowerCase();
      const rule = (f.rule_id || f.ruleId || "").toLowerCase();
      const title = (f.title || "").toLowerCase();
      return (
        cat.includes("dependency") ||
        cat.includes("unpinned") ||
        rule.startsWith("dep-") ||
        rule.startsWith("cve-") ||
        title.includes("vulnerable dependency") ||
        title.includes("unpinned dependency") ||
        Boolean(f.cve || f.cve_id)
      );
    });
  }, [findings]);

  // Vulnerability Matches: Total number of vulnerability/finding matches across packages
  const vulnerabilityMatches = useMemo(() => {
    return Math.max(depFindings.length, dependencyAnalysis.vulnerable_dependencies_count ?? 0);
  }, [depFindings, dependencyAnalysis.vulnerable_dependencies_count]);

  // Calculate severity breakdown from dependency findings
  const severityCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    depFindings.forEach((f: any) => {
      const sev = (f.severity || "").toLowerCase();
      if (sev === "critical") counts.critical++;
      else if (sev === "high") counts.high++;
      else if (sev === "medium") counts.medium++;
      else if (sev === "low") counts.low++;
    });
    return counts;
  }, [depFindings]);

  // Unique ecosystems available
  const availableEcosystems = useMemo(() => {
    const ecoSet = new Set<string>();
    rawLibraries.forEach((lib) => {
      if (lib.ecosystem) ecoSet.add(lib.ecosystem);
    });
    return Array.from(ecoSet);
  }, [rawLibraries]);

  // Enriched libraries with matched findings, severities, and target fix versions
  const enrichedLibraries = useMemo(() => {
    return rawLibraries.map((lib) => {
      const pkgNameLower = (lib.name || "").toLowerCase();

      // Match findings for this package by package name
      const pkgFindings = depFindings.filter((f: any) => {
        const titleLower = (f.title || "").toLowerCase();
        const descLower = (f.description || "").toLowerCase();
        const snippetLower = (f.snippet || "").toLowerCase();
        const ruleLower = (f.rule_id || "").toLowerCase();

        return (
          titleLower.includes(pkgNameLower) ||
          descLower.includes(pkgNameLower) ||
          snippetLower.includes(pkgNameLower) ||
          ruleLower.includes(pkgNameLower)
        );
      });

      // Find highest severity among matched findings
      let highestSev = "NONE";
      const hasCritical = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "critical");
      const hasHigh = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "high");
      const hasMedium = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "medium");
      const hasLow = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "low");

      if (hasCritical) highestSev = "CRITICAL";
      else if (hasHigh) highestSev = "HIGH";
      else if (hasMedium) highestSev = "MEDIUM";
      else if (hasLow) highestSev = "LOW";

      const isUnpinned =
        lib.version === "unpinned" ||
        lib.version === "*" ||
        pkgFindings.some((f) => (f.rule_id || "") === "DEP-001" || (f.category || "").toLowerCase().includes("unpinned"));

      // Try to extract recommended fix version from finding text
      let targetVersion = "No fixed version reported";
      for (const f of pkgFindings) {
        const text = `${f.recommendation || ""} ${f.fix_recommendation || ""} ${f.description || ""}`;
        const match = text.match(/(?:upgrade|update|pin|to|>=|~=)\s*([vV]?\d+\.\d+(?:\.\d+)?)/i);
        if (match && match[1]) {
          targetVersion = `>= ${match[1]}`;
          break;
        }
      }

      return {
        ...lib,
        pkgFindings,
        highestSev,
        isUnpinned,
        targetVersion,
        isVulnerable: pkgFindings.length > 0 && highestSev !== "NONE",
      };
    });
  }, [rawLibraries, depFindings]);

  // Distinct Vulnerable Packages Count (deduplicated by ecosystem + package name)
  const distinctVulnerablePkgCount = useMemo(() => {
    const vulnSet = new Set<string>();
    enrichedLibraries.forEach((lib) => {
      if (lib.isVulnerable) {
        const key = `${lib.ecosystem || "other"}:${lib.name}`.toLowerCase();
        vulnSet.add(key);
      }
    });

    if (total > 0 && rawLibraries.length > 0) {
      return Math.min(vulnSet.size, total);
    }
    return vulnSet.size;
  }, [enrichedLibraries, total, rawLibraries.length]);

  // Ecosystem distribution counts
  const ecosystemCounts = useMemo(() => {
    const map: Record<string, number> = {};
    rawLibraries.forEach((lib) => {
      const eco = lib.ecosystem || "Other";
      map[eco] = (map[eco] || 0) + 1;
    });
    return map;
  }, [rawLibraries]);

  // Top Vulnerable Packages ranking (top 5)
  const topVulnerablePackages = useMemo(() => {
    return enrichedLibraries
      .filter((lib) => lib.pkgFindings.length > 0)
      .sort((a, b) => b.pkgFindings.length - a.pkgFindings.length)
      .slice(0, 5);
  }, [enrichedLibraries]);

  // Tab count metrics
  const outdatedLibCount = enrichedLibraries.filter((l) => l.isUnpinned).length;

  // Filtered libraries according to active tab, search query, severity, and ecosystem
  const filteredLibraries = useMemo(() => {
    return enrichedLibraries.filter((lib) => {
      // Tab filter
      if (activeTab === "vulnerable" && !lib.isVulnerable) return false;
      if (activeTab === "outdated" && !lib.isUnpinned) return false;

      // Search query filter
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchesName = lib.name.toLowerCase().includes(query);
        const matchesEco = (lib.ecosystem || "").toLowerCase().includes(query);
        const matchesManifest = (lib.manifest || "").toLowerCase().includes(query);
        const matchesCVE = lib.pkgFindings.some(
          (f) =>
            (f.cve || f.cve_id || "").toLowerCase().includes(query) ||
            (f.rule_id || "").toLowerCase().includes(query) ||
            (f.title || "").toLowerCase().includes(query)
        );
        if (!matchesName && !matchesEco && !matchesManifest && !matchesCVE) return false;
      }

      // Severity filter
      if (severityFilter !== "ALL") {
        if (lib.highestSev !== severityFilter) return false;
      }

      // Ecosystem filter
      if (ecosystemFilter !== "ALL") {
        if (lib.ecosystem !== ecosystemFilter) return false;
      }

      return true;
    });
  }, [enrichedLibraries, activeTab, searchQuery, severityFilter, ecosystemFilter]);

  // Reset pagination to Page 1 whenever filters, search, or raw library set change
  useEffect(() => {
    setCurrentPage(1);
  }, [activeTab, searchQuery, severityFilter, ecosystemFilter, rawLibraries]);

  // Pagination bounds & slice computed AFTER filtering
  const totalFilteredPackages = filteredLibraries.length;
  const totalPages = Math.max(1, Math.ceil(totalFilteredPackages / PAGE_SIZE));
  const safePage = Math.min(currentPage, totalPages);
  const startIndex = (safePage - 1) * PAGE_SIZE;
  const endIndex = Math.min(startIndex + PAGE_SIZE, totalFilteredPackages);
  const paginatedLibraries = filteredLibraries.slice(startIndex, endIndex);

  // Dynamic Key Insights generator
  const dynamicInsights = useMemo(() => {
    const insights: { type: "critical" | "warning" | "info" | "success"; text: string }[] = [];

    if (distinctVulnerablePkgCount > 0) {
      const pct = total > 0 ? Math.round((distinctVulnerablePkgCount / total) * 100) : 0;
      insights.push({
        type: "critical",
        text: `${distinctVulnerablePkgCount} out of ${total} distinct packages (${pct}%) contain known security vulnerabilities (${vulnerabilityMatches} total finding match(es)).`,
      });
    }

    if (severityCounts.critical > 0) {
      insights.push({
        type: "critical",
        text: `${severityCounts.critical} Critical severity supply chain vulnerability matches require immediate remediation.`,
      });
    }

    if (outdatedLibCount > 0) {
      insights.push({
        type: "warning",
        text: `${outdatedLibCount} dependency entries use unpinned or wildcard version specifications in lockfiles.`,
      });
    }

    if (distinctVulnerablePkgCount === 0 && vulnerabilityMatches === 0 && total > 0) {
      insights.push({
        type: "success",
        text: `No known open-source vulnerabilities matching OSV advisory database were detected across all ${total} packages.`,
      });
    }

    return insights;
  }, [distinctVulnerablePkgCount, vulnerabilityMatches, total, severityCounts, outdatedLibCount]);

  // Recommended Actions generator
  const recommendedActions = useMemo(() => {
    const actions: string[] = [];

    // Specific package fix recommendations
    enrichedLibraries.forEach((lib) => {
      if (lib.isVulnerable && lib.targetVersion !== "No fixed version reported") {
        actions.push(`Upgrade ${lib.name} from ${lib.version} to ${lib.targetVersion} in ${lib.manifest}`);
      }
    });

    if (outdatedLibCount > 0) {
      actions.push(`Pin explicit version numbers for ${outdatedLibCount} unpinned packages to prevent breaking supply-chain updates.`);
    }

    if (cveList.length > 0) {
      actions.push(`Review ${cveList.length} unique CVE security advisories and update root dependencies.`);
    }

    if (actions.length === 0) {
      actions.push("Maintain automated dependency scanning on all incoming pull requests.");
      actions.push("Keep repository lockfiles updated to receive security patches.");
    }

    return actions.slice(0, 5);
  }, [enrichedLibraries, outdatedLibCount, cveList]);

  const getSevBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case "CRITICAL":
        return "bg-rose-50 text-rose-700 border-rose-200";
      case "HIGH":
        return "bg-amber-50 text-amber-700 border-amber-200";
      case "MEDIUM":
        return "bg-yellow-50 text-yellow-700 border-yellow-200";
      case "LOW":
        return "bg-blue-50 text-blue-700 border-blue-200";
      default:
        return "bg-emerald-50 text-emerald-700 border-emerald-200";
    }
  };

  return (
    <div className="rounded-2xl bg-white border border-[#244A86] overflow-hidden shadow-sm space-y-0">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-4 px-6 py-4 bg-[#EEF4FF] hover:bg-[#E8F0FF] transition-colors text-left border-b border-[#C9D7EA]"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-white border border-[#C9D7EA] flex items-center justify-center shadow-xs shrink-0">
            <Package className="w-5 h-5 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[12px] font-sans font-semibold uppercase tracking-[0.04em] px-2.5 py-0.5 rounded-full bg-[#EEF4FF] text-[#2563EB] border border-[#C9D7EA]">
                DEPENDENCY AGENT
              </span>
              <h2 className="text-[16px] font-bold text-[#14213D] leading-[1.4] tracking-tight">
                Supply Chain &amp; Dependency Security Analysis
              </h2>
            </div>
            <p className="text-[14px] font-sans font-normal text-[#536987] mt-1 leading-[1.5]">
              Powered by Dependency Agent — AST lockfile parsing, OSV lookup &amp; vulnerability matching
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[14px] font-sans font-semibold text-[#2563EB] px-3 py-1.5 rounded-lg bg-white border border-[#244A86] flex items-center gap-1.5 hover:bg-[#EEF4FF] transition">
            {open ? (
              <>
                <ChevronUp className="w-4 h-4 text-[#2563EB]" /> Hide Panel
              </>
            ) : (
              <>
                <ChevronDown className="w-4 h-4 text-[#2563EB]" /> Expand Panel
              </>
            )}
          </span>
        </div>
      </button>

      {open && (
        <div className="p-6 space-y-6 bg-slate-50/50">
          {/* Explanatory Callout Box */}
          <div className="p-3.5 rounded-xl bg-white border border-[#DCE5F0] flex items-center gap-3 shadow-xs">
            <Info className="w-4 h-4 text-blue-500 shrink-0" />
            <div className="text-[14px] font-sans font-normal text-slate-600 leading-[1.5]">
              <span className="text-[#111827] font-sans font-semibold">Coverage Scope:</span> Identifies
              vulnerable dependencies, unpinned requirements, outdated versions, and supply-chain risk
              from repository lockfiles and package manifests.
            </div>
          </div>

          {/* 6 Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            {/* 1. Total Packages (Distinct Detected) */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-1">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                Total Packages
              </div>
              <div className="text-[28px] font-bold text-[#111827] leading-[1.2]">{total}</div>
              <div className="text-[13px] font-sans font-normal text-slate-500 truncate">
                {direct} direct · {transitive} transitive
              </div>
            </div>

            {/* 2. Vulnerable Packages */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-1">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                Vulnerable Packages
              </div>
              <div
                className={`text-[28px] font-bold leading-[1.2] ${
                  distinctVulnerablePkgCount > 0 ? "text-amber-600" : "text-emerald-600"
                }`}
              >
                {distinctVulnerablePkgCount}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500 truncate">
                {distinctVulnerablePkgCount} of {total} packages
              </div>
            </div>

            {/* 3. Vulnerability Matches */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-1">
              <div className="text-[12px] font-sans font-semibold text-amber-700">
                Vulnerability Matches
              </div>
              <div
                className={`text-[28px] font-bold leading-[1.2] ${
                  vulnerabilityMatches > 0 ? "text-amber-600" : "text-slate-400"
                }`}
              >
                {vulnerabilityMatches}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500 truncate">
                Total OSV &amp; policy matches
              </div>
            </div>

            {/* 4. Unique CVEs */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-1">
              <div className="text-[12px] font-sans font-semibold text-amber-700">
                Unique CVEs
              </div>
              <div className={`text-[28px] font-bold leading-[1.2] ${cveList.length > 0 ? "text-amber-600" : "text-slate-400"}`}>
                {cveList.length}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500">OSV Advisories</div>
            </div>

            {/* 5. Critical */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-1">
              <div className="text-[12px] font-sans font-semibold text-rose-700">
                Critical
              </div>
              <div className={`text-[28px] font-bold leading-[1.2] ${severityCounts.critical > 0 ? "text-rose-600" : "text-slate-400"}`}>
                {severityCounts.critical}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500">Critical advisories</div>
            </div>

            {/* 6. High */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-1">
              <div className="text-[12px] font-sans font-semibold text-amber-700">
                High
              </div>
              <div className={`text-[28px] font-bold leading-[1.2] ${severityCounts.high > 0 ? "text-amber-600" : "text-slate-400"}`}>
                {severityCounts.high}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500">High advisories</div>
            </div>
          </div>

          {/* AI Dependency Analysis Section */}
          {(allAiInsights.length > 0 || (dependencyAnalysis.grok_status && dependencyAnalysis.grok_status !== "SKIPPED")) && (
            <div className="p-5 rounded-2xl bg-white border border-[#DCE5F0] space-y-4 shadow-sm">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div className="flex items-center gap-2.5">
                  <div className="w-7 h-7 rounded-lg bg-blue-50 border border-blue-200 flex items-center justify-center">
                    <Sparkles className="w-4 h-4 text-blue-600" />
                  </div>
                  <div>
                    <h3 className="text-[15px] font-sans font-semibold text-[#111827]">
                      AI Dependency Analysis &amp; Contextual Reasoning
                    </h3>
                    <p className="text-[14px] font-sans font-normal text-slate-500">
                      Groq AI reasoning over deterministic vulnerable dependency evidence &amp; codebase usage context
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`px-2.5 py-1 rounded-md text-[11px] font-sans font-semibold uppercase border ${
                    dependencyAnalysis.grok_status === "COMPLETED"
                      ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                      : dependencyAnalysis.grok_status === "SKIPPED_BUDGET" || dependencyAnalysis.grok_status === "RATE_LIMITED"
                      ? "bg-amber-50 text-amber-700 border-amber-200"
                      : "bg-rose-50 text-rose-700 border-rose-200"
                  }`}>
                    {dependencyAnalysis.grok_status || "COMPLETED"}
                  </span>
                </div>
              </div>

              {dependencyAnalysis.agent_reason && (
                <div className="p-3 rounded-xl bg-slate-50 border border-[#DCE5F0] text-[13px] font-sans font-normal text-slate-600 flex items-center gap-2">
                  <Info className="w-3.5 h-3.5 text-blue-500 shrink-0" />
                  <span>{dependencyAnalysis.agent_reason}</span>
                </div>
              )}

              {allAiInsights.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {allAiInsights.map((insight: any, idx: number) => {
                    const relevance = insight.relevance || insight.extras?.relevance || "INSUFFICIENT_EVIDENCE";
                    const relBadge =
                      relevance === "RELEVANT"
                        ? "bg-rose-50 text-rose-700 border-rose-200"
                        : relevance === "POTENTIALLY_RELEVANT"
                        ? "bg-amber-50 text-amber-700 border-amber-200"
                        : "bg-slate-100 text-slate-600 border-slate-200";
                    const relLabel =
                      relevance === "RELEVANT"
                        ? "RELEVANT TO CODEBASE"
                        : relevance === "POTENTIALLY_RELEVANT"
                        ? "POTENTIALLY RELEVANT"
                        : "INSUFFICIENT CODE USAGE EVIDENCE";

                    const pkg = insight.package || insight.extras?.package || "Vulnerable Package";
                    const vulnId = insight.vulnerability_id || insight.extras?.vulnerability_id || insight.rule_id || "CVE";
                    const analysis = insight.analysis || insight.reason || insight.extras?.analysis || "";
                    const usageCtx = insight.usage_context || insight.extras?.usage_context || "";
                    const impact = insight.impact || insight.extras?.impact || "";
                    const remediation = insight.remediation || insight.recommendation || insight.extras?.remediation || "";

                    return (
                      <div key={insight.id || idx} className="p-4 rounded-xl bg-slate-50 border border-[#DCE5F0] space-y-3">
                        <div className="flex items-center justify-between gap-2 border-b border-[#DCE5F0] pb-2.5">
                          <div className="flex items-center gap-2 font-mono text-[13px] font-bold text-[#111827]">
                            <Package className="w-3.5 h-3.5 text-blue-600" />
                            <span>{pkg}</span>
                            <span className="text-[12px] text-amber-600 font-semibold font-mono">({vulnId})</span>
                          </div>
                          <span className={`px-2 py-0.5 rounded text-[11px] font-sans font-semibold border ${relBadge}`}>
                            {relLabel}
                          </span>
                        </div>

                        {analysis && (
                          <div className="space-y-1">
                            <div className="text-[12px] font-sans font-semibold text-slate-500">
                              Contextual Security Analysis
                            </div>
                            <p className="text-[14px] font-sans font-normal text-slate-700 leading-[1.5]">
                              {analysis}
                            </p>
                          </div>
                        )}

                        {usageCtx && (
                          <div className="space-y-1 p-2.5 rounded-lg bg-white border border-[#DCE5F0]">
                            <div className="text-[12px] font-sans font-semibold text-blue-600 flex items-center gap-1">
                              <Terminal className="w-3 h-3" /> Codebase Usage Evidence
                            </div>
                            <p className="text-[13px] font-mono text-slate-600">
                              {usageCtx}
                            </p>
                          </div>
                        )}

                        {impact && (
                          <div className="space-y-1">
                            <div className="text-[12px] font-sans font-semibold text-amber-700">
                              Application Security Impact
                            </div>
                            <p className="text-[14px] font-sans font-normal text-slate-600">
                              {impact}
                            </p>
                          </div>
                        )}

                        {remediation && (
                          <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 space-y-0.5">
                            <div className="text-[12px] font-sans font-semibold text-emerald-700">
                              Remediation Guidance
                            </div>
                            <p className="text-[14px] font-sans font-normal text-emerald-800 leading-[1.5]">
                              {remediation}
                            </p>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* Severity & Ecosystem Distributions Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Severity Distribution Breakdown Bar */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[15px] font-sans font-semibold text-slate-900 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5 text-blue-600" />
                  Severity Distribution
                </span>
                <span className="text-[13px] font-sans font-normal text-slate-500">
                  {depFindings.length} total findings
                </span>
              </div>

              {depFindings.length > 0 ? (
                <>
                  <div className="h-3 w-full rounded-full bg-slate-100 overflow-hidden flex">
                    {severityCounts.critical > 0 && (
                      <div
                        style={{ width: `${(severityCounts.critical / depFindings.length) * 100}%` }}
                        className="bg-rose-500 h-full"
                        title={`Critical: ${severityCounts.critical}`}
                      />
                    )}
                    {severityCounts.high > 0 && (
                      <div
                        style={{ width: `${(severityCounts.high / depFindings.length) * 100}%` }}
                        className="bg-amber-500 h-full"
                        title={`High: ${severityCounts.high}`}
                      />
                    )}
                    {severityCounts.medium > 0 && (
                      <div
                        style={{ width: `${(severityCounts.medium / depFindings.length) * 100}%` }}
                        className="bg-yellow-500 h-full"
                        title={`Medium: ${severityCounts.medium}`}
                      />
                    )}
                    {severityCounts.low > 0 && (
                      <div
                        style={{ width: `${(severityCounts.low / depFindings.length) * 100}%` }}
                        className="bg-blue-500 h-full"
                        title={`Low: ${severityCounts.low}`}
                      />
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-[13px] font-sans text-slate-600 pt-1">
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-rose-500" />
                      <span>Critical ({severityCounts.critical})</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-amber-500" />
                      <span>High ({severityCounts.high})</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-yellow-500" />
                      <span>Medium ({severityCounts.medium})</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-blue-500" />
                      <span>Low ({severityCounts.low})</span>
                    </div>
                  </div>
                </>
              ) : (
                <div className="p-4 text-center text-[13px] font-sans font-normal text-emerald-700 bg-emerald-50 rounded-lg border border-emerald-200">
                  <CheckCircle2 className="w-4 h-4 mx-auto mb-1 text-emerald-600" />
                  0 Vulnerabilities Found
                </div>
              )}
            </div>

            {/* Top Vulnerable Packages */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[15px] font-sans font-semibold text-slate-900 flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5 text-rose-500" />
                  Top Vulnerable Packages
                </span>
                <span className="text-[13px] font-sans font-normal text-slate-500">By match count</span>
              </div>

              {topVulnerablePackages.length > 0 ? (
                <div className="space-y-2">
                  {topVulnerablePackages.map((pkg, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded-lg bg-slate-50 border border-[#DCE5F0] flex items-center justify-between text-[13px] font-sans"
                    >
                      <div className="truncate max-w-[140px]">
                        <div className="font-semibold text-[#111827] truncate">{pkg.name}</div>
                        <div className="text-[12px] font-mono text-slate-500">{pkg.version} · {pkg.ecosystem}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-sans font-semibold border ${getSevBadge(pkg.highestSev)}`}>
                          {pkg.highestSev}
                        </span>
                        <span className="text-slate-500 text-[12px] font-sans">
                          {pkg.pkgFindings.length} match(es)
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-4 text-center text-[13px] font-sans font-normal text-emerald-700 bg-emerald-50 rounded-lg border border-emerald-200">
                  <CheckCircle2 className="w-4 h-4 mx-auto mb-1 text-emerald-600" />
                  No Vulnerable Packages
                </div>
              )}
            </div>

            {/* Ecosystem Distribution */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[15px] font-sans font-semibold text-slate-900 flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5 text-blue-600" />
                  Ecosystem Distribution
                </span>
                <span className="text-[13px] font-sans font-normal text-slate-500">
                  {Object.keys(ecosystemCounts).length} ecosystem(s)
                </span>
              </div>

              {Object.keys(ecosystemCounts).length > 0 ? (
                <div className="space-y-2">
                  {Object.entries(ecosystemCounts).map(([eco, count]) => {
                    const pct = total > 0 ? Math.round((count / total) * 100) : 0;
                    return (
                      <div key={eco} className="space-y-1">
                        <div className="flex items-center justify-between text-[10.5px] font-mono">
                          <span className="text-[#111827] font-bold">{eco}</span>
                          <span className="text-slate-500">
                            {count} package(s) ({pct}%)
                          </span>
                        </div>
                        <div className="h-1.5 w-full rounded-full bg-slate-100 overflow-hidden">
                          <div
                            style={{ width: `${pct}%` }}
                            className="bg-blue-600 h-full rounded-full"
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div className="p-4 text-center text-[10.5px] font-mono text-slate-500 bg-slate-50 rounded-lg border border-[#DCE5F0]">
                  No Package Ecosystems
                </div>
              )}
            </div>
          </div>

          {/* CVE List Quick Banner (if CVEs exist) */}
          {cveList.length > 0 && (
            <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 flex items-center gap-3">
              <ShieldAlert className="w-5 h-5 text-amber-600 shrink-0" />
              <div>
                <div className="text-xs font-mono font-bold text-[#111827]">
                  OSV Vulnerability Database Matches ({cveList.length} Unique CVEs)
                </div>
                <div className="text-[10.5px] font-mono text-slate-600 mt-1 flex flex-wrap gap-1.5">
                  {cveList.map((cve) => (
                    <span
                      key={cve}
                      className="px-2 py-0.5 rounded bg-white border border-amber-300 text-amber-800 font-bold text-[9.5px]"
                    >
                      {cve}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Package Explorer: Search & Filter Toolbar + Tabs */}
          <div className="space-y-4 pt-2">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#DCE5F0] pb-3">
              {/* Tab Selector */}
              <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl border border-[#DCE5F0]">
                <button
                  onClick={() => setActiveTab("all")}
                  className={`px-3 py-1.5 rounded-lg text-[10.5px] font-mono font-bold transition ${
                    activeTab === "all"
                      ? "bg-blue-600 text-white shadow-xs"
                      : "text-slate-600 hover:text-[#111827]"
                  }`}
                >
                  All Packages ({total})
                </button>
                <button
                  onClick={() => setActiveTab("vulnerable")}
                  className={`px-3 py-1.5 rounded-lg text-[10.5px] font-mono font-bold transition flex items-center gap-1.5 ${
                    activeTab === "vulnerable"
                      ? "bg-blue-600 text-white shadow-xs"
                      : "text-slate-600 hover:text-[#111827]"
                  }`}
                >
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Vulnerable ({distinctVulnerablePkgCount})
                </button>
                <button
                  onClick={() => setActiveTab("outdated")}
                  className={`px-3 py-1.5 rounded-lg text-[10.5px] font-mono font-bold transition flex items-center gap-1.5 ${
                    activeTab === "outdated"
                      ? "bg-blue-600 text-white shadow-xs"
                      : "text-slate-600 hover:text-[#111827]"
                  }`}
                >
                  <Tag className="w-3.5 h-3.5" />
                  Outdated / Unpinned ({outdatedLibCount})
                </button>
              </div>

              {/* Search & Select Controls */}
              <div className="flex flex-wrap items-center gap-2">
                {/* Search Input */}
                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search package, CVE, manifest..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-8 pr-3 py-1.5 rounded-xl bg-white border border-[#DCE5F0] text-[10.5px] font-mono text-[#111827] focus:border-blue-500 outline-none w-56 transition shadow-xs"
                  />
                </div>

                {/* Severity Filter */}
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-2.5 py-1.5 rounded-xl bg-white border border-[#DCE5F0] text-[10.5px] font-mono text-slate-600 focus:border-blue-500 outline-none shadow-xs"
                >
                  <option value="ALL">Severity: All</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>

                {/* Ecosystem Filter */}
                {availableEcosystems.length > 0 && (
                  <select
                    value={ecosystemFilter}
                    onChange={(e) => setEcosystemFilter(e.target.value)}
                    className="px-2.5 py-1.5 rounded-xl bg-white border border-[#DCE5F0] text-[10.5px] font-mono text-slate-600 focus:border-blue-500 outline-none shadow-xs"
                  >
                    <option value="ALL">Ecosystem: All</option>
                    {availableEcosystems.map((eco) => (
                      <option key={eco} value={eco}>
                        {eco}
                      </option>
                    ))}
                  </select>
                )}
              </div>
            </div>

            {/* Package Inventory Table */}
            {filteredLibraries.length > 0 ? (
              <div className="space-y-3">
                <div className="rounded-xl border border-[#DCE5F0] overflow-hidden bg-white shadow-sm">
                  <table className="w-full text-left border-collapse text-[11px] font-mono">
                    <thead>
                      <tr className="bg-slate-50 border-b border-[#DCE5F0] text-slate-600">
                        <th className="py-3 px-4 font-semibold">Package Name</th>
                        <th className="py-3 px-4 font-semibold">Installed Version</th>
                        <th className="py-3 px-4 font-semibold">Suggested Fix</th>
                        <th className="py-3 px-4 font-semibold">Ecosystem</th>
                        <th className="py-3 px-4 font-semibold">Source Manifest</th>
                        <th className="py-3 px-4 font-semibold">Security Status</th>
                        <th className="py-3 px-4 font-semibold text-right">Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100 bg-white">
                      {paginatedLibraries.map((lib) => {
                        const rowKey = `${lib.ecosystem || "eco"}:${lib.name}:${lib.version}`;
                        const isExpanded = expandedPkg === lib.name;
                        return (
                          <React.Fragment key={rowKey}>
                            <tr className="hover:bg-slate-50/80 transition-colors">
                              {/* Package Name */}
                              <td className="py-3 px-4 font-bold text-[#111827] flex items-center gap-2">
                                <Package className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                                <span>{lib.name}</span>
                              </td>

                              {/* Installed Version */}
                              <td className="py-3 px-4 text-slate-600">
                                <span
                                  className={`px-2 py-0.5 rounded font-mono ${
                                    lib.isUnpinned
                                      ? "bg-amber-50 text-amber-700 border border-amber-200 font-bold"
                                      : "bg-slate-100 text-[#111827]"
                                  }`}
                                >
                                  {lib.version}
                                </span>
                              </td>

                              {/* Target Fix Version */}
                              <td className="py-3 px-4">
                                {lib.targetVersion !== "No fixed version reported" ? (
                                  <span className="text-emerald-700 font-bold">{lib.targetVersion}</span>
                                ) : (
                                  <span className="text-slate-400 font-normal">No fixed version reported</span>
                                )}
                              </td>

                              {/* Ecosystem */}
                              <td className="py-3 px-4 text-slate-600">
                                <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 text-[10px]">
                                  {lib.ecosystem || "PyPI/npm"}
                                </span>
                              </td>

                              {/* Source Manifest */}
                              <td className="py-3 px-4 text-slate-600 truncate max-w-[180px]">
                                {lib.manifest || "manifest"}
                              </td>

                              {/* Security Status */}
                              <td className="py-3 px-4">
                                <span className={`px-2.5 py-1 rounded-md text-[10px] font-bold border ${getSevBadge(lib.highestSev)}`}>
                                  {lib.isVulnerable
                                    ? `${lib.highestSev} VULNERABILITY`
                                    : lib.isUnpinned
                                    ? "UNPINNED VERSION"
                                    : "CLEAN"}
                                </span>
                              </td>

                              {/* Actions */}
                              <td className="py-3 px-4 text-right">
                                {lib.pkgFindings.length > 0 ? (
                                  <button
                                    onClick={() => setExpandedPkg(isExpanded ? null : lib.name)}
                                    className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 text-[#111827] text-[10px] font-mono font-bold flex items-center gap-1 ml-auto transition"
                                  >
                                    {isExpanded ? "Hide" : `View (${lib.pkgFindings.length})`}
                                    {isExpanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                                  </button>
                                ) : (
                                  <span className="text-[10px] text-slate-400">No findings</span>
                                )}
                              </td>
                            </tr>

                            {/* Expanded Detail Panel */}
                            {isExpanded && lib.pkgFindings.length > 0 && (
                              <tr>
                                <td colSpan={7} className="p-4 bg-slate-50 border-y border-[#DCE5F0] space-y-3">
                                  <div className="text-[10px] font-mono font-bold text-blue-600 uppercase tracking-wider flex items-center gap-1.5">
                                    <ShieldAlert className="w-3.5 h-3.5" />
                                    Matched Vulnerability Findings for {lib.name}
                                  </div>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    {lib.pkgFindings.map((f, fIdx) => (
                                      <div
                                        key={fIdx}
                                        className="p-3 rounded-lg bg-white border border-[#DCE5F0] space-y-2 text-[10.5px] font-mono shadow-xs"
                                      >
                                        <div className="flex items-center justify-between gap-2">
                                          <span className={`px-2 py-0.5 rounded text-[9.5px] font-bold border ${getSevBadge(f.severity || "LOW")}`}>
                                            {f.severity || "LOW"}
                                          </span>
                                          <span className="text-amber-700 font-bold text-[9.5px]">
                                            {f.rule_id || f.cve || f.cve_id || "DEP-MATCH"}
                                          </span>
                                        </div>
                                        <div className="font-bold text-[#111827]">
                                          {f.title || f.category || "Vulnerability Finding"}
                                        </div>
                                        <p className="text-slate-600 font-sans text-[11px] leading-relaxed">
                                          {f.description || f.snippet || "No detailed description provided."}
                                        </p>
                                        {(f.recommendation || f.fix_recommendation) && (
                                          <div className="p-2 rounded bg-emerald-50 border border-emerald-200 text-emerald-800 text-[10px]">
                                            <span className="font-bold">Fix: </span>
                                            {f.recommendation || f.fix_recommendation}
                                          </div>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Pagination Controls Bar */}
                {totalFilteredPackages > PAGE_SIZE && (
                  <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-3 pb-1 px-3 bg-white rounded-xl border border-[#DCE5F0] text-xs font-mono shadow-sm">
                    <div className="text-slate-600">
                      Showing <span className="text-[#111827] font-bold">{startIndex + 1}–{endIndex}</span> of{" "}
                      <span className="text-[#111827] font-bold">{totalFilteredPackages}</span> packages
                    </div>

                    <div className="flex items-center gap-1.5 flex-wrap">
                      <button
                        onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                        disabled={safePage === 1}
                        className="px-2.5 py-1 rounded bg-slate-100 border border-[#DCE5F0] text-[#111827] hover:bg-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors text-[11px] font-semibold flex items-center gap-1"
                      >
                        <ChevronLeft className="w-3.5 h-3.5" /> Previous
                      </button>

                      <div className="flex items-center gap-1 px-1">
                        {getPageNumbers(safePage, totalPages).map((p, idx) => {
                          if (p === "...") {
                            return (
                              <span key={`ellipsis-${idx}`} className="px-1 text-slate-400 font-mono text-xs select-none">
                                ...
                              </span>
                            );
                          }
                          const pageNum = p as number;
                          return (
                            <button
                              key={pageNum}
                              onClick={() => setCurrentPage(pageNum)}
                              className={`w-7 h-7 rounded text-[11px] font-mono font-bold flex items-center justify-center transition-all ${
                                pageNum === safePage
                                  ? "bg-blue-600 text-white border border-blue-600 shadow-xs"
                                  : "bg-white text-slate-600 hover:text-[#111827] hover:bg-slate-100 border border-[#DCE5F0]"
                              }`}
                            >
                              {pageNum}
                            </button>
                          );
                        })}
                      </div>

                      <button
                        onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                        disabled={safePage === totalPages}
                        className="px-2.5 py-1 rounded bg-slate-100 border border-[#DCE5F0] text-[#111827] hover:bg-slate-200 disabled:opacity-30 disabled:cursor-not-allowed transition-colors text-[11px] font-semibold flex items-center gap-1"
                      >
                        Next <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-8 text-center text-[11px] font-mono text-slate-500 rounded-xl bg-white border border-[#DCE5F0] space-y-2 shadow-xs">
                <Package className="w-8 h-8 text-slate-400 mx-auto" />
                <div>
                  {rawLibraries.length === 0
                    ? "No package manifest files (e.g. requirements.txt, package.json, pom.xml) detected in this repository."
                    : "No packages matched the selected filter and search criteria."}
                </div>
              </div>
            )}
          </div>

          {/* Dynamic Key Insights & Recommended Actions Bottom Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 pt-2">
            {/* Dynamic Key Insights */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-3">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-blue-600" />
                <h3 className="text-xs font-mono font-bold text-[#111827] uppercase tracking-wide">
                  Dynamic Supply Chain Insights
                </h3>
              </div>
              <div className="space-y-2">
                {dynamicInsights.map((insight, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-50 border border-[#DCE5F0] flex items-start gap-2.5 text-[11px] font-sans text-slate-600"
                  >
                    {insight.type === "critical" && <AlertTriangle className="w-4 h-4 text-rose-500 shrink-0 mt-0.5" />}
                    {insight.type === "warning" && <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />}
                    {insight.type === "info" && <Info className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />}
                    {insight.type === "success" && <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />}
                    <span className="leading-relaxed">{insight.text}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Recommended Actions */}
            <div className="p-4 rounded-xl bg-white border border-[#DCE5F0] shadow-sm space-y-3">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-600" />
                <h3 className="text-xs font-mono font-bold text-[#111827] uppercase tracking-wide">
                  Recommended Supply Chain Actions
                </h3>
              </div>
              <div className="space-y-2">
                {recommendedActions.map((action, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-slate-50 border border-[#DCE5F0] flex items-start gap-2.5 text-[11px] font-mono text-[#111827]"
                  >
                    <span className="w-4 h-4 rounded-full bg-emerald-100 text-emerald-700 border border-emerald-200 font-bold text-[9.5px] flex items-center justify-center shrink-0 mt-0.5">
                      {idx + 1}
                    </span>
                    <span className="leading-relaxed text-slate-600">{action}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
