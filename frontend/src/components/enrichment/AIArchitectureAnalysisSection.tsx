"use client";

import React, { useState, useMemo } from "react";
import {
  Network,
  Sparkles,
  Play,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  Shield,
  Layers,
  Database,
  Lock,
  Globe,
  Key,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Activity,
  Terminal,
  FileCode,
  ArrowRight,
  Code2,
  Info,
  Flame,
} from "lucide-react";
import type { WorkflowStatus } from "../agentic-scan/types";

export interface AIArchitectureAnalysisSectionProps {
  architectureAnalysis?: Record<string, any>;
  aiArchitectureInsights?: any[];
  workflowStatus: WorkflowStatus;
  hasRunForThisScan: boolean;
  agenticScanId?: string | null;
  sourceScanId?: string | null;
  grokStatus?: string | null;
  architectureAgentReason?: string | null;
  onRunAgentic: () => void;
  onDiscussInChat?: (item: any) => void;
}

export default function AIArchitectureAnalysisSection({
  architectureAnalysis = {},
  aiArchitectureInsights = [],
  workflowStatus,
  hasRunForThisScan,
  agenticScanId,
  sourceScanId,
  grokStatus,
  architectureAgentReason,
  onRunAgentic,
}: AIArchitectureAnalysisSectionProps) {
  const [open, setOpen] = useState(true);
  const [showTechnicalEvidence, setShowTechnicalEvidence] = useState(false);
  const [showRepresentativeEndpoints, setShowRepresentativeEndpoints] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);

  const isRunningForThisTarget =
    workflowStatus === "starting" || workflowStatus === "running";

  // Raw topology arrays from backend API response
  const serviceBoundaries = architectureAnalysis?.service_boundaries || [];
  const authFlows = architectureAnalysis?.authentication_flows || [];
  const dbInteractions = architectureAnalysis?.database_interactions || [];
  const apiRelationships = architectureAnalysis?.api_relationships || [];
  const externalIntegrations = architectureAnalysis?.external_integrations || [];
  const trustBoundaries = architectureAnalysis?.trust_boundaries || [];
  const entryPoints = architectureAnalysis?.entry_points || [];
  const detectedEndpoints = architectureAnalysis?.detected_endpoints || [];

  // Endpoints authentication coverage metrics derived from backend API
  const totalEndpointsCount =
    architectureAnalysis?.detected_endpoints_count ??
    (detectedEndpoints.length > 0 ? detectedEndpoints.length : null);

  const authenticatedEndpointsCount = architectureAnalysis?.authenticated_endpoints_count ?? null;
  const unauthenticatedEndpointsCount = architectureAnalysis?.unauthenticated_endpoints_count ?? null;

  const authCoveragePct =
    architectureAnalysis?.auth_coverage_pct ??
    (totalEndpointsCount && authenticatedEndpointsCount !== null
      ? Math.round((authenticatedEndpointsCount / totalEndpointsCount) * 1000) / 10
      : null);

  const unauthenticatedSample: string[] = architectureAnalysis?.unauthenticated_endpoints_sample || [];

  // Derived metric values for summary cards
  const servicesMetric = serviceBoundaries.length > 0 ? serviceBoundaries.length : 1;
  const endpointsMetric = totalEndpointsCount !== null ? totalEndpointsCount : "N/A";
  const entryPointsMetric =
    architectureAnalysis?.entry_points_count ?? (entryPoints.length > 0 ? entryPoints.length : "N/A");
  const authCoverageMetric = authCoveragePct !== null ? `${authCoveragePct}%` : "N/A";
  const dbLayersMetric = dbInteractions.length;

  const combinedInsights =
    aiArchitectureInsights.length > 0
      ? aiArchitectureInsights
      : architectureAnalysis?.ai_architecture_insights || [];

  const activeInsight = useMemo(() => {
    if (!combinedInsights || combinedInsights.length === 0) return null;
    return combinedInsights[selectedIndex] || combinedInsights[0];
  }, [combinedInsights, selectedIndex]);

  const getSevBadge = (sev: string) => {
    switch ((sev || "").toUpperCase()) {
      case "CRITICAL":
        return "bg-red-50 text-red-700 border-red-200";
      case "HIGH":
        return "bg-orange-50 text-orange-700 border-orange-200";
      case "MEDIUM":
        return "bg-amber-50 text-amber-700 border-amber-200";
      case "LOW":
        return "bg-sky-50 text-sky-700 border-sky-200";
      default:
        return "bg-sky-50 text-sky-700 border-sky-200";
    }
  };

  return (
    <div className="rounded-2xl bg-white border border-slate-200 overflow-hidden shadow-sm space-y-0">
      {/* Accordion Header */}
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-4 px-6 py-4 bg-[#EEF4FF] hover:bg-[#E8F0FF] transition-colors text-left border-b border-slate-200"
      >
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-white border border-slate-200 flex items-center justify-center shadow-xs shrink-0">
            <Network className="w-5 h-5 text-[#2563EB]" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <span className="text-[12px] font-sans font-semibold uppercase tracking-[0.04em] px-2.5 py-0.5 rounded-full bg-[#EEF4FF] text-[#2563EB] border border-blue-200">
                ARCHITECTURE AGENT
              </span>
              <h2 className="text-[16px] font-bold text-slate-900 leading-[1.4] tracking-tight">
                System Architecture &amp; Security Topology
              </h2>
            </div>
            <p className="text-[14px] font-sans font-normal text-slate-600 mt-1 leading-[1.5]">
              Evaluates application structure, public entry points, authentication coverage, and architectural security risks
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-[14px] font-sans font-semibold text-[#2563EB] px-3 py-1.5 rounded-lg bg-white border border-[#244A86] flex items-center gap-1.5 transition shadow-xs hover:bg-[#EEF4FF]">
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
        <div className="p-6 space-y-6 bg-white">
          {/* Explanatory Scope Callout Box */}
          <div className="p-3.5 rounded-xl bg-[#EAF3FF] border border-[#AFCBEB] flex items-start gap-3">
            <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
            <div className="text-[14px] font-sans font-normal text-slate-600 leading-[1.5]">
              <span className="text-slate-900 font-sans font-semibold">Coverage Scope:</span> Scans
              your application architecture to map web services, API endpoints, authentication layers, and database connections. Identifies where external internet traffic enters your app and checks if endpoints are properly protected with authentication.
            </div>
          </div>

          {/* 5 Summary Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {/* 1. SERVICES */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1 min-w-0">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                Services
              </div>
              <div className="text-[28px] font-bold text-slate-900 leading-[1.2]">{servicesMetric}</div>
              <div className="text-[13px] font-sans font-normal text-slate-500 break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                {serviceBoundaries.join(", ") || "Core Service"}
              </div>
            </div>

            {/* 2. API ENDPOINTS */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1 min-w-0">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                API Endpoints
              </div>
              <div className="text-[28px] font-bold text-slate-900 leading-[1.2]">{endpointsMetric}</div>
              <div className="text-[13px] font-sans font-normal text-slate-500 break-words whitespace-normal min-w-0">
                Detected API routes
              </div>
            </div>

            {/* 3. ENTRY POINTS */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1 min-w-0">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                Entry Points
              </div>
              <div className="text-[28px] font-bold text-slate-900 leading-[1.2]">{entryPointsMetric}</div>
              <div className="text-[13px] font-sans font-normal text-slate-500 break-words whitespace-normal min-w-0">
                Public entry functions
              </div>
            </div>

            {/* 4. AUTH COVERAGE */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1 min-w-0">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                Auth Coverage
              </div>
              <div
                className={`text-[28px] font-bold leading-[1.2] ${
                  authCoveragePct !== null && authCoveragePct < 50
                    ? "text-orange-600"
                    : "text-emerald-600"
                }`}
              >
                {authCoverageMetric}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500 break-words whitespace-normal min-w-0">
                Endpoints with auth
              </div>
            </div>

            {/* 5. DATABASE LAYERS */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-1 min-w-0">
              <div className="text-[12px] font-sans font-semibold text-slate-500">
                Database Layers
              </div>
              <div className="text-[28px] font-bold text-slate-900 leading-[1.2]">{dbLayersMetric}</div>
              <div className="text-[13px] font-sans font-normal text-slate-500 break-words whitespace-normal min-w-0">
                Database ORM layers
              </div>
            </div>
          </div>

          {/* Architecture Topology Dashboard Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Trust Boundaries */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 flex flex-col justify-between min-w-0">
              <div className="space-y-2 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[15px] font-sans font-semibold text-slate-900 flex items-center gap-1.5 shrink-0">
                    <Shield className="w-4 h-4 text-blue-600" />
                    Trust Boundaries
                  </span>
                  <span className="text-[13px] font-sans font-semibold text-amber-700 shrink-0">
                    {trustBoundaries.length} crossing(s)
                  </span>
                </div>
                <p className="text-[14px] font-sans font-normal text-slate-600 leading-[1.5] break-words whitespace-normal">
                  Identifies entry points where external, untrusted internet visitors send data into your backend application logic.
                </p>

                {trustBoundaries.length > 0 ? (
                  <div className="space-y-1.5 pt-1">
                    {trustBoundaries.map((tb: string, idx: number) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-slate-200 text-[13px] font-mono text-amber-800 flex items-start gap-2 min-w-0 shadow-sm">
                        <span className="w-1.5 h-1.5 rounded-full bg-orange-500 shrink-0 mt-1.5" />
                        <span className="leading-normal break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">{tb}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-[13px] font-sans font-normal text-slate-500 p-2 rounded bg-white border border-slate-200 break-words whitespace-normal">
                    No trust boundary crossings detected
                  </div>
                )}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500 pt-2 border-t border-slate-200 break-words whitespace-normal min-w-0">
                Data Flow: Public Gateway ➔ App Controller
              </div>
            </div>

            {/* Auth & Session Flows */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 flex flex-col justify-between min-w-0">
              <div className="space-y-2 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[15px] font-sans font-semibold text-slate-900 flex items-center gap-1.5 shrink-0">
                    <Key className="w-4 h-4 text-sky-600" />
                    Auth &amp; Session Flows
                  </span>
                  <span className="text-[13px] font-sans font-semibold text-sky-700 shrink-0">
                    {authCoverageMetric}
                  </span>
                </div>
                <p className="text-[14px] font-sans font-normal text-slate-600 leading-[1.5] break-words whitespace-normal">
                  Detects login security mechanisms (JWT, Session tokens) and measures what percentage of API routes require authentication.
                </p>

                {authFlows.length > 0 ? (
                  <div className="space-y-1.5 pt-1">
                    {authFlows.map((af: string, idx: number) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-slate-200 text-[13px] font-mono text-sky-800 flex items-start gap-2 min-w-0 shadow-sm">
                        <span className="w-1.5 h-1.5 rounded-full bg-sky-500 shrink-0 mt-1.5" />
                        <span className="leading-normal break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">{af}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-[13px] font-sans font-normal text-slate-500 p-2 rounded bg-white border border-slate-200 break-words whitespace-normal">
                    Standard Auth Layer
                  </div>
                )}
              </div>
              <div className="text-[13px] font-sans font-normal text-slate-500 pt-2 border-t border-slate-200 break-words whitespace-normal min-w-0">
                {authenticatedEndpointsCount !== null
                  ? `${authenticatedEndpointsCount} of ${endpointsMetric} routes protected with authentication`
                  : "Global auth scheme active"}
              </div>
            </div>

            {/* Database Interactions */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 flex flex-col justify-between min-w-0">
              <div className="space-y-2 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 shrink-0">
                    <Database className="w-3.5 h-3.5 text-emerald-600" />
                    Database Interactions
                  </span>
                  <span className="text-[9.5px] font-mono text-emerald-700 font-bold shrink-0">
                    {dbLayersMetric} layer(s)
                  </span>
                </div>
                <p className="text-[10.5px] font-sans text-slate-600 leading-relaxed break-words whitespace-normal">
                  Tracks database drivers, ORM frameworks, and data persistence layers connected to your codebase.
                </p>

                {dbInteractions.length > 0 ? (
                  <div className="space-y-1.5 pt-1">
                    {dbInteractions.map((db: string, idx: number) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-white border border-slate-200 text-[10.5px] font-mono text-emerald-800 flex items-start gap-2 min-w-0 shadow-sm">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 shrink-0 mt-1.5" />
                        <span className="leading-normal break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">{db}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-[10.5px] font-mono text-slate-500 p-2.5 rounded bg-white border border-slate-200 flex items-center gap-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" />
                    <span className="break-words whitespace-normal">No database connection layers detected</span>
                  </div>
                )}
              </div>
              <div className="text-[9.5px] font-mono text-slate-500 pt-2 border-t border-slate-200 break-words whitespace-normal min-w-0">
                Database connection models active
              </div>
            </div>

            {/* Service & Endpoints */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2 flex flex-col justify-between min-w-0">
              <div className="space-y-2 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 shrink-0">
                    <Globe className="w-3.5 h-3.5 text-purple-600" />
                    Service &amp; Endpoints
                  </span>
                  <span className="text-[9.5px] font-mono text-purple-700 font-bold shrink-0">
                    {endpointsMetric} routes
                  </span>
                </div>
                <p className="text-[10.5px] font-sans text-slate-600 leading-relaxed break-words whitespace-normal">
                  Overview of application web services, framework technologies, and API endpoint routes.
                </p>

                <div className="space-y-1.5 pt-1 text-[10.5px] font-mono min-w-0">
                  <div className="p-2 rounded bg-white border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-1 min-w-0 shadow-sm">
                    <span className="text-slate-500 shrink-0">Service:</span>
                    <span className="text-purple-800 font-bold text-left sm:text-right break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                      {serviceBoundaries.join(", ") || "Python Service"}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-white border border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-1 min-w-0 shadow-sm">
                    <span className="text-slate-500 shrink-0">Framework:</span>
                    <span className="text-purple-800 text-left sm:text-right break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                      {externalIntegrations.join(", ") || "Framework"}
                    </span>
                  </div>
                </div>
              </div>
              <div className="text-[9.5px] font-mono text-slate-500 pt-2 border-t border-slate-200 break-words whitespace-normal min-w-0">
                {entryPointsMetric} entry functions handling web requests
              </div>
            </div>
          </div>

          {/* Un-run Banner State */}
          {!hasRunForThisScan && !isRunningForThisTarget && (
            <div className="my-2 p-5 rounded-xl bg-blue-50/50 border border-blue-200 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-blue-100 border border-blue-200 flex items-center justify-center mx-auto text-blue-600">
                <Sparkles className="w-5 h-5 animate-pulse" />
              </div>
              <div className="max-w-md mx-auto">
                <h4 className="text-xs font-mono font-bold text-slate-900 uppercase tracking-wide">
                  Run AI Architecture Security Analysis
                </h4>
                <p className="text-[11px] font-sans text-slate-600 mt-1 leading-relaxed">
                  Click below to scan your application structure, measure authentication coverage, and detect architectural security risks.
                </p>
              </div>
              <button
                onClick={onRunAgentic}
                className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-[10px] font-mono font-bold uppercase tracking-wide bg-blue-600 text-white hover:bg-blue-700 transition-colors shadow-sm"
              >
                <Play className="w-3 h-3 fill-current" /> Run AI Agentic Scan
              </button>
            </div>
          )}

          {/* Running State */}
          {isRunningForThisTarget && (
            <div className="pt-4 flex items-center gap-2 text-[10.5px] font-mono text-blue-600 py-6 justify-center">
              <Loader2 className="w-4 h-4 animate-spin text-blue-600" />
              AI Architecture Agent scanning app structure, API endpoints, and authentication coverage…
            </div>
          )}

          {/* Completed State: Findings Dashboard & Status */}
          {hasRunForThisScan && !isRunningForThisTarget && (
            <div className="space-y-4 pt-2 border-t border-slate-200">
              {/* Status Header Bar */}
              <div className="flex items-center justify-between text-[10px] font-mono text-slate-600">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-slate-900">Agent Execution Status:</span>
                  {grokStatus === "COMPLETED" && (
                    <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                      COMPLETED
                    </span>
                  )}
                  {grokStatus === "SKIPPED" && (
                    <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold bg-sky-50 text-sky-700 border border-sky-200">
                      SKIPPED (Structural Baseline Sufficient)
                    </span>
                  )}
                  {grokStatus === "SKIPPED_BUDGET" && (
                    <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                      SKIPPED (Token Budget Limit)
                    </span>
                  )}
                  {grokStatus === "PROVIDER_DAILY_QUOTA" && (
                    <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                      DAILY QUOTA EXHAUSTED
                    </span>
                  )}
                  {grokStatus === "RATE_LIMITED" && (
                    <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                      RATE LIMITED
                    </span>
                  )}
                  {(grokStatus === "FAILED" || grokStatus === "UNAVAILABLE" || grokStatus === "PROVIDER_UNAVAILABLE") && (
                    <span className="px-2.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-50 text-amber-700 border border-amber-200">
                      SERVICE UNAVAILABLE
                    </span>
                  )}
                </div>
              </div>

              {/* Status Notice Callouts if applicable */}
              {grokStatus === "PROVIDER_DAILY_QUOTA" && (
                <div className="p-4 rounded-xl bg-amber-50 border border-amber-200 text-center space-y-1">
                  <AlertTriangle className="w-5 h-5 text-amber-600 mx-auto" />
                  <div className="text-[11px] font-mono font-bold text-amber-900">
                    DAILY QUOTA EXHAUSTED
                  </div>
                  <p className="text-[10px] font-sans text-amber-800">
                    {architectureAgentReason || "AI reasoning could not run because the LLM provider's daily token quota was reached. Deterministic topology is fully preserved."}
                  </p>
                </div>
              )}

              {/* Zero-Finding State */}
              {combinedInsights.length === 0 &&
                (grokStatus === "COMPLETED" || grokStatus === "SKIPPED" || !grokStatus) && (
                  <div className="p-4 rounded-xl bg-emerald-50 border border-emerald-200 flex items-start gap-3">
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-mono font-bold text-emerald-900">
                        No Architectural Vulnerabilities Flagged
                      </div>
                      <p className="text-[11px] font-sans text-slate-600 mt-1 leading-relaxed">
                        Architecture analysis completed successfully. No structural security gaps, unprotected sensitive routes, or trust boundary risks were detected in your application.
                      </p>
                    </div>
                  </div>
                )}

              {/* AI Architectural Security Evaluation Findings Section */}
              {combinedInsights.length > 0 && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-slate-600 flex items-center gap-1.5">
                      <Flame className="w-3.5 h-3.5 text-blue-600" />
                      Architectural Security Findings ({combinedInsights.length})
                    </span>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
                    {/* Left Finding Card List */}
                    <div className="lg:col-span-5 space-y-2 max-h-[320px] overflow-y-auto pr-1">
                      {combinedInsights.map((insight: any, idx: number) => {
                        const isSelected = selectedIndex === idx;
                        const displayTitle = insight.title || insight.reason || "Architectural Security Evaluation";
                        return (
                          <div
                            key={idx}
                            onClick={() => setSelectedIndex(idx)}
                            className={`p-3.5 rounded-xl cursor-pointer border transition text-left space-y-1.5 ${
                              isSelected
                                ? "bg-blue-50/80 border-blue-300 shadow-sm"
                                : "bg-slate-50 border-slate-200 hover:bg-slate-100"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-2 min-w-0">
                              <span className={`px-2 py-0.5 rounded text-[9px] font-mono font-bold border shrink-0 ${getSevBadge(insight.severity || "HIGH")}`}>
                                {insight.severity || "HIGH"}
                              </span>
                              <span className="text-[9.5px] font-mono text-slate-500 break-all whitespace-normal min-w-0 text-right">
                                {insight.file || "workspace"}
                              </span>
                            </div>
                            <div className="text-[11px] font-mono font-bold text-slate-900 leading-snug break-words whitespace-normal min-w-0">
                              {displayTitle}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    {/* Right Detail & Recommendation Inspector Pane */}
                    {activeInsight && (
                      <div className="lg:col-span-7 p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4 min-w-0">
                        <div className="flex items-center justify-between border-b border-slate-200 pb-3 gap-2">
                          <div className="space-y-1 min-w-0">
                            <span className={`px-2.5 py-0.5 rounded text-[9.5px] font-mono font-bold uppercase border ${getSevBadge(activeInsight.severity || "HIGH")}`}>
                              {activeInsight.severity || "HIGH"}
                            </span>
                            <h4 className="text-xs font-mono font-bold text-slate-900 pt-1 break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                              {activeInsight.title || "Architectural Security Evaluation"}
                            </h4>
                          </div>
                          <span className="text-[9.5px] font-mono text-emerald-700 font-bold px-2.5 py-1 rounded bg-emerald-50 border border-emerald-200 shrink-0">
                            AI VALIDATED
                          </span>
                        </div>

                        {/* Plain Language Finding Explanation */}
                        <div className="space-y-1 min-w-0">
                          <div className="text-[10px] font-mono text-blue-600 font-bold uppercase">
                            Risk Description &amp; Impact
                          </div>
                          <p className="text-[11px] font-sans text-slate-700 leading-relaxed break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                            {activeInsight.reason || activeInsight.description || "Architectural risk detected across component boundaries."}
                          </p>
                        </div>

                        {activeInsight.file && (
                          <div className="text-[10px] font-mono text-slate-500 break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                            Affected Code Component: <span className="text-slate-900 font-bold">{activeInsight.file}:{activeInsight.line || 1}</span> {activeInsight.function ? `(${activeInsight.function})` : ""}
                          </div>
                        )}

                        {/* Styled Recommendation Box */}
                        {activeInsight.recommendation && (
                          <div className="p-3.5 rounded-lg bg-emerald-50 border border-emerald-200 space-y-1 text-[10.5px] font-mono text-emerald-900 min-w-0">
                            <span className="font-bold text-emerald-800 block uppercase tracking-wider text-[9.5px]">
                              Recommended Action:
                            </span>
                            <p className="leading-relaxed font-sans text-[11px] text-emerald-900 break-words whitespace-normal min-w-0 [overflow-wrap:anywhere]">
                              {activeInsight.recommendation}
                            </p>
                          </div>
                        )}

                        {/* Optional Representative Endpoints Toggle */}
                        {unauthenticatedSample.length > 0 && (
                          <div className="pt-2 border-t border-slate-200">
                            <button
                              onClick={() => setShowRepresentativeEndpoints((v) => !v)}
                              className="text-[10px] font-mono text-blue-600 hover:underline font-bold flex items-center gap-1"
                            >
                              {showRepresentativeEndpoints ? "Hide" : "Show"} Unauthenticated Endpoints ({unauthenticatedSample.length})
                              {showRepresentativeEndpoints ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
                            </button>

                            {showRepresentativeEndpoints && (
                              <div className="mt-2 p-3 rounded-lg bg-white border border-slate-200 text-[10px] font-mono text-slate-600 max-h-36 overflow-y-auto space-y-1">
                                {unauthenticatedSample.map((ep, idx) => (
                                  <div key={idx} className="flex items-start gap-2 text-slate-900 min-w-0">
                                    <Code2 className="w-3 h-3 text-blue-600 shrink-0 mt-0.5" />
                                    <span className="break-all whitespace-normal min-w-0">{ep}</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Technical Evidence Accordion */}
              <div className="pt-2">
                <button
                  onClick={() => setShowTechnicalEvidence((v) => !v)}
                  className="text-[10.5px] font-mono text-slate-500 hover:text-slate-900 font-bold flex items-center gap-1.5 transition"
                >
                  {showTechnicalEvidence ? <ChevronUp className="w-3.5 h-3.5 text-blue-600" /> : <ChevronDown className="w-3.5 h-3.5 text-blue-600" />}
                  <span>{showTechnicalEvidence ? "Hide Technical Evidence & Trace IDs" : "Show Technical Evidence & Trace IDs"}</span>
                </button>

                {showTechnicalEvidence && (
                  <div className="mt-3 p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-3 font-mono text-[10.5px]">
                    <div className="text-blue-600 font-bold uppercase text-[9.5px]">
                      Raw Technical Evidence Dump (E1–E6)
                    </div>
                    <div className="space-y-2 text-slate-600">
                      <div className="break-words whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-sky-700 font-bold">E1 (Service Boundaries):</span>{" "}
                        {serviceBoundaries.join(", ") || "Core"}
                      </div>
                      <div className="break-words whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-sky-700 font-bold">E2 (Global Auth Mechanism):</span>{" "}
                        {authFlows.join(", ") || "Standard Auth"}
                      </div>
                      <div className="break-words whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-sky-700 font-bold">E3 (Database Interactions):</span>{" "}
                        {dbInteractions.join(", ") || "None"}
                      </div>
                      <div className="break-words whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-sky-700 font-bold">E4 (Trust Boundaries):</span>{" "}
                        {trustBoundaries.join(", ") || "None"}
                      </div>
                      <div className="break-words whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-sky-700 font-bold">E5 (Endpoint Auth Coverage):</span>{" "}
                        {authCoverageMetric} ({authenticatedEndpointsCount ?? 0} / {endpointsMetric} endpoints)
                      </div>
                      <div className="break-words whitespace-normal [overflow-wrap:anywhere]">
                        <span className="text-sky-700 font-bold">E6 (Representative Endpoints):</span>{" "}
                        {unauthenticatedSample.slice(0, 5).join(", ") || "None"}
                      </div>
                    </div>
                    <div className="pt-2 border-t border-slate-200 text-[9px] text-slate-400">
                      agentic run: {agenticScanId || "N/A"} · source scan: {sourceScanId || "N/A"}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
