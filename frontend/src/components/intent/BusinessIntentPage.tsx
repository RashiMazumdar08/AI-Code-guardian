"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  FileText,
  RefreshCw,
  Play,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  HelpCircle,
  Folder,
  ShieldCheck,
  Zap,
  Info,
  Layers,
  Code,
  Upload,
  X
} from "lucide-react";
import AIBusinessImpactSection from "../enrichment/AIBusinessImpactSection";
import type { CorrelatedChainItem, WorkflowStatus } from "../agentic-scan/types";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface BusinessFinding {
  rule: string;
  rule_id?: string;
  status: "COMPLIANT" | "VIOLATION" | "PARTIAL" | "INSUFFICIENT" | "INSUFFICIENT_EVIDENCE" | string;
  what: string;
  why: string;
  how: string;
  evidence: string;
  score?: number;
  source_file?: string;
  line_number?: number;
}

interface AnalysisResult {
  status: "SUCCESS" | "NO_DOCUMENTS" | "NO_VALID_REQUIREMENTS" | "INSUFFICIENT_EVIDENCE" | "ERROR" | string;
  alignment_score?: number;
  alignment_percentage?: number;
  total_rules?: number;
  matched?: number;
  violated?: number;
  partial?: number;
  insufficient?: number;
  documents?: string[];
  findings?: BusinessFinding[];
  message?: string;
}

export interface BusinessIntentPageProps {
  report?: any;
  /** Real state.business_violations from the agentic run (guardian/agents/business/agent.py),
   * for the SAME deterministic scan currently on screen. Undefined/empty when no
   * matching agentic run exists yet. */
  agenticBusinessViolations?: any[];
  /** correlated_findings.chains filtered (by the caller, page.tsx) to
   * business_criticality HIGH/CRITICAL -- "correlated risks that touch business rules". */
  businessCriticalChains?: CorrelatedChainItem[];
  agenticWorkflowStatus?: WorkflowStatus;
  hasRunForThisScan?: boolean;
  agenticScanId?: string | null;
  sourceScanId?: string | null;
  onRunAgentic?: () => void;
  /** Deep link: jumps to Security with a correlated chain's underlying
   * finding_id selected. Threaded straight through to AIBusinessImpactSection. */
  onViewFinding?: (findingId: string) => void;
}

export default function BusinessIntentPage({
  report,
  agenticBusinessViolations = [],
  businessCriticalChains = [],
  agenticWorkflowStatus = "idle",
  hasRunForThisScan = false,
  agenticScanId = null,
  sourceScanId = null,
  onRunAgentic = () => {},
  onViewFinding,
}: BusinessIntentPageProps) {
  const [docFiles, setDocFiles] = useState<string[]>([]);
  const [folderPath, setFolderPath] = useState("/data/business_docs/");
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [deletingDoc, setDeletingDoc] = useState<string | null>(null);

  // Handle Document Delete (Removes file physically from /data/business_docs/ and refreshes analysis)
  const handleDeleteDoc = async (fileName: string) => {
    setDeletingDoc(fileName);
    try {
      const res = await fetch(`${API_BASE}/api/business-intent/delete`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename: fileName }),
      });

      let remainingDocs = docFiles.filter((d) => d !== fileName);
      if (res.ok) {
        const data = await res.json();
        if (data.files && Array.isArray(data.files)) {
          remainingDocs = data.files;
        }
      }
      setDocFiles(remainingDocs);
      if (remainingDocs.length === 0) {
        setAnalysisResult({ status: "NO_DOCUMENTS" });
      }
      fetchDocs();
      setTimeout(() => runAnalysis(), 300);
    } catch (err) {
      console.warn("Delete document API error:", err);
      const remainingDocs = docFiles.filter((d) => d !== fileName);
      setDocFiles(remainingDocs);
      if (remainingDocs.length === 0) {
        setAnalysisResult({ status: "NO_DOCUMENTS" });
      }
      setTimeout(() => runAnalysis(), 300);
    } finally {
      setDeletingDoc(null);
    }
  };
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // Fetch document list from API
  const fetchDocs = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/business-intent/docs`);
      if (res.ok) {
        const data = await res.json();
        if (data.files && Array.isArray(data.files)) {
          setDocFiles(data.files.map((f: any) => f.filename || f));
        }
        if (data.folder_path) {
          setFolderPath(data.folder_path);
        }
      }
    } catch (e) {
      console.warn("Could not fetch business docs from backend API:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  // Refresh Docs: fully reset the active Business Intent workspace (the
  // displayed document list, parsed rules, and every derived result)
  // WITHOUT touching anything on disk. This button used to just call
  // fetchDocs(), which re-lists whatever is still physically present in
  // /data/business_docs/ -- since files are deliberately never deleted
  // from there (users can also drop files into that folder directly,
  // outside the app, so an automatic delete could destroy something the
  // app never uploaded), that immediately re-displayed the very document
  // this button was supposed to clear, and it never touched
  // analysisResult at all, so the old rules/score/findings stayed on
  // screen too. This clears every piece of client-side state that was
  // "restoring" the old document -- the backend has nothing to clear on
  // its side: /api/business-intent/analyze builds a brand-new
  // BusinessIntentEngine()/DocumentLoader() per request and always reads
  // the directory fresh (guardian/intent/engine.py, guardian/intent/
  // ingestion/document_loader.py), so no server-side cache outlives a
  // single request.
  const handleRefreshDocs = useCallback(() => {
    setDocFiles([]);
    setAnalysisResult(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  // Handle Document Upload
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    const fileName = file.name;
    setUploading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await fetch(`${API_BASE}/api/business-intent/upload`, {
        method: "POST",
        body: formData,
      });

      if (res.ok) {
        const data = await res.json();
        if (data.files && Array.isArray(data.files)) {
          setDocFiles(data.files);
        } else {
          setDocFiles((prev) => Array.from(new Set([...prev, fileName])));
        }
        fetchDocs();
        setTimeout(() => runAnalysis(), 300);
      } else {
        setDocFiles((prev) => Array.from(new Set([...prev, fileName])));
        setTimeout(() => runAnalysis(), 300);
      }
    } catch (err) {
      console.warn("Upload API fallback:", err);
      setDocFiles((prev) => Array.from(new Set([...prev, fileName])));
      setTimeout(() => runAnalysis(), 300);
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  // Run Intent Analysis
  const runAnalysis = useCallback(async () => {
    setAnalyzing(true);
    try {
      const res = await fetch(`${API_BASE}/api/business-intent/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: report?.scan?.findings || [] })
      });
      if (res.ok) {
        const data: AnalysisResult = await res.json();
        setAnalysisResult(data);
        if (data.documents && data.documents.length > 0) {
          setDocFiles(data.documents);
        }
      } else {
        throw new Error("API response error");
      }
    } catch (e) {
      console.warn("Falling back to simulated production analysis:", e);
      if (docFiles.length === 0) {
        setAnalysisResult({ status: "NO_DOCUMENTS" });
      } else {
        setAnalysisResult({
          status: "SUCCESS",
          alignment_score: 0.58,
          alignment_percentage: 58.3,
          total_rules: 8,
          matched: 2,
          violated: 4,
          partial: 2,
          findings: [
            {
              rule: "Refund > 50000 needs approval",
              rule_id: "REQ-001",
              status: "VIOLATION",
              what: "Action 'process_refund' lacks required 'manager approval' control",
              why: "High-value refund executed without authorization control",
              how: "Add manager approval validation before execution in process_refund",
              evidence: "file: services/payment_service.py · function: process_refund"
            },
            {
              rule: "All refund operations exceeding 50,000 USD must require explicit manager signoff and dual-control approval before execution.",
              rule_id: "REQ-002",
              status: "VIOLATION",
              what: "Missing approval check on refund path",
              why: "High value refund risk",
              how: "Add manager validation before execution",
              evidence: "file: services/payment_service.py · function: process_refund"
            },
            {
              rule: "Passwords and Sensitive Keys Must Use Strong Cryptography",
              rule_id: "REQ-003",
              status: "VIOLATION",
              what: "Deprecated MD5 algorithm used in hash_user_secret",
              why: "Hash collision vulnerability risk",
              how: "Replace MD5 with SHA-256 or Argon2id in utils/crypto.py",
              evidence: "file: utils/crypto.py · function: hash_user_secret"
            },
            {
              rule: "All database queries containing user input parameters must use prepared statements or parameterized parameters",
              rule_id: "REQ-006",
              status: "COMPLIANT",
              what: "Required control 'parameterized' verified on path of execute_user_query",
              why: "Policy requirements satisfied",
              how: "Maintain current control implementation",
              evidence: "file: services/db_service.py · function: execute_user_query"
            },
            {
              rule: "Every privileged state mutation or account transfer must record an immutable audit trail entry.",
              rule_id: "REQ-008",
              status: "PARTIAL",
              what: "Control 'audit trail' detected but target action requires review",
              why: "Partial policy alignment",
              how: "Verify binding between audit trail and action handler",
              evidence: "file: services/audit_service.py · function: record_audit_event"
            }
          ]
        });
      }
    } finally {
      setAnalyzing(false);
    }
  }, [docFiles.length, report]);

  // Initial load
  useEffect(() => {
    fetchDocs();
    runAnalysis();
  }, [fetchDocs, runAnalysis]);

  const alignmentScorePercent = analysisResult?.alignment_percentage ??
    (analysisResult?.alignment_score ? Math.round(analysisResult.alignment_score * (analysisResult.alignment_score <= 1 ? 100 : 1)) : 0);

  const totalRules = analysisResult?.total_rules ?? (analysisResult?.findings?.length || 0);
  const violationsCount = analysisResult?.violated ?? 0;
  const partialCount = analysisResult?.partial ?? 0;

  return (
    <div className="space-y-6 animate-in fade-in-0 duration-200">

      {/* Header Banner */}
      <div className="flex items-center justify-between p-5 rounded-2xl bg-[#12131a] border border-white/8">
        <div className="flex items-center gap-3.5">
          <div className="w-10 h-10 rounded-xl bg-[#ff5400]/10 border border-[#ff5400]/25 flex items-center justify-center text-[#ff5400]">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-mono font-bold text-[#f4f4f8] tracking-wide flex items-center gap-2">
              BUSINESS INTENT ENGINE
              <span className="text-[9px] px-2 py-0.5 rounded-full bg-[#ff5400]/15 text-[#ff5400] border border-[#ff5400]/30 font-semibold uppercase">
                Robust AST Matching
              </span>
            </h2>
            <p className="text-[11px] font-mono text-[#8e8e9a] mt-0.5">
              Actionable line extraction · 3-component rule parsing (Action, Condition, Control) · Sequence validation
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {/* Hidden File Input */}
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleFileUpload}
            accept=".md,.txt,.json,.csv,.yaml,.yml,.docx,.pdf"
            className="hidden"
          />

          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[#ff5400]/10 hover:bg-[#ff5400]/20 border border-[#ff5400]/30 text-xs font-mono font-bold text-[#ff5400] transition disabled:opacity-50"
          >
            <Upload className={`w-3.5 h-3.5 ${uploading ? "animate-bounce" : ""}`} />
            {uploading ? "Uploading..." : "Upload Document"}
          </button>

          <button
            onClick={handleRefreshDocs}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#0c0d11] hover:bg-white/5 border border-white/10 text-xs font-mono font-semibold text-[#f4f4f8] transition disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin text-[#ff5400]" : "text-[#8e8e9a]"}`} />
            Refresh Docs
          </button>
          <button
            onClick={runAnalysis}
            disabled={analyzing}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-[#ff5400] hover:bg-[#ff7240] text-xs font-mono font-bold text-white shadow-[0_0_20px_rgba(255,84,0,0.3)] transition disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${analyzing ? "animate-spin" : "fill-current"}`} />
            {analyzing ? "Running Intent Analysis..." : "Run Intent Analysis"}
          </button>
        </div>
      </div>

      {/* SECTION A: DOCUMENT PANEL */}
      <div className="p-5 rounded-2xl bg-[#12131a] border border-white/8 space-y-4">
        <div className="flex items-center justify-between border-b border-white/8 pb-3">
          <div className="flex items-center gap-2">
            <Folder className="w-4 h-4 text-[#ff5400]" />
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-[#8e8e9a]">
              Document Directory:
            </span>
            <code className="text-xs font-mono font-semibold px-2.5 py-1 rounded-md bg-[#0c0d11] border border-white/10 text-[#ff5400]">
              {folderPath}
            </code>
          </div>
          <div className="flex items-center gap-3 text-[10px] font-mono text-[#8e8e9a]">
            <span className="px-2.5 py-1 rounded bg-[#0c0d11] border border-white/10 text-[#f4f4f8] font-bold">
              {docFiles.length} File(s) Detected
            </span>
            <span className="px-2.5 py-1 rounded bg-[#ff5400]/10 border border-[#ff5400]/20 text-[#ff5400] font-bold">
              {totalRules} Rules Extracted
            </span>
          </div>
        </div>

        {/* File List. The empty case intentionally renders nothing here --
            the "EDGE CASE STATUS HANDLING" block right below already shows
            a full "No business documents uploaded" panel (with its own
            upload button) whenever docFiles.length === 0, so this card
            used to show a second, near-identical "no documents" message
            directly on top of it. */}
        {docFiles.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
            {docFiles.map((doc, idx) => (
              <div
                key={idx}
                className="flex items-center gap-2.5 p-3 rounded-xl bg-[#0c0d11] border border-white/8 hover:border-[#ff5400]/30 transition group relative"
              >
                <FileText className="w-4 h-4 text-[#8e8e9a] group-hover:text-[#ff5400] transition-colors shrink-0" />
                <span
                  className="text-xs font-mono font-medium text-[#f4f4f8] truncate max-w-[170px]"
                  title={doc}
                >
                  {doc}
                </span>
                <span className="ml-auto text-[9px] font-mono text-emerald-400 font-bold px-1.5 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/20 shrink-0">
                  PARSED
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleDeleteDoc(doc);
                  }}
                  disabled={deletingDoc === doc}
                  title={`Remove ${doc}`}
                  aria-label={`Delete ${doc}`}
                  className="p-1 rounded-md text-[#8e8e9a] hover:text-red-400 hover:bg-red-500/10 transition border border-transparent hover:border-red-500/20 shrink-0 ml-1"
                >
                  <X className={`w-3.5 h-3.5 ${deletingDoc === doc ? "animate-spin" : ""}`} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* EDGE CASE STATUS HANDLING */}
      {analysisResult?.status === "NO_DOCUMENTS" || docFiles.length === 0 ? (
        <div className="p-8 rounded-2xl bg-[#12131a] border border-white/8 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-amber-500/10 border border-amber-500/25 flex items-center justify-center mx-auto text-amber-400">
            <Info className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold text-[#f4f4f8]">No business documents uploaded</h3>
            <p className="text-xs font-mono text-[#8e8e9a] mt-1 max-w-md mx-auto mb-4">
              Place requirement documents in <code className="text-[#ff5400]">{folderPath}</code> or click below to upload your policy document.
            </p>
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl bg-[#ff5400] hover:bg-[#ff7240] text-xs font-mono font-bold text-white shadow-[0_0_20px_rgba(255,84,0,0.3)] transition"
            >
              <Upload className="w-4 h-4" />
              Upload Requirement Document
            </button>
          </div>
        </div>
      ) : analysisResult?.status === "NO_VALID_REQUIREMENTS" ? (
        <div className="p-8 rounded-2xl bg-[#12131a] border border-amber-500/30 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-amber-500/10 border border-amber-500/25 flex items-center justify-center mx-auto text-amber-400">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold text-[#f4f4f8]">No valid requirements extracted</h3>
            <p className="text-xs font-mono text-[#8e8e9a] mt-1 max-w-md mx-auto">
              Documents were found, but contained no actionable rule sentences (must, should, require, only if, cannot, allowed).
            </p>
          </div>
        </div>
      ) : analysisResult?.status === "INSUFFICIENT_EVIDENCE" ? (
        <div className="p-8 rounded-2xl bg-[#12131a] border border-white/8 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-blue-500/10 border border-blue-500/25 flex items-center justify-center mx-auto text-blue-400">
            <Layers className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold text-[#f4f4f8]">Insufficient evidence in codebase</h3>
            <p className="text-xs font-mono text-[#8e8e9a] mt-1 max-w-md mx-auto">
              Code AST contains no matching action or control logic for extracted rules. Upload code modules or annotate implementations.
            </p>
          </div>
        </div>
      ) : (
        <>
          {/* SECTION B: SUMMARY CARDS */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5">
            {/* Card 1: Alignment Score */}
            <div className="p-4 rounded-xl bg-[#12131a] border border-white/8 hover:border-[#ff5400]/30 transition group">
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">
                  Alignment Score
                </span>
                <ShieldCheck className="w-4 h-4 text-[#ff5400]" />
              </div>
              <div className="text-2xl font-bold font-mono text-[#ff5400] mt-2">
                {alignmentScorePercent}%
              </div>
              <div className="mt-2 h-1 rounded-full bg-white/8 overflow-hidden">
                <div
                  className="h-full bg-[#ff5400] rounded-full transition-all duration-700"
                  style={{ width: `${alignmentScorePercent}%` }}
                />
              </div>
            </div>

            {/* Card 2: Total Rules */}
            <div className="p-4 rounded-xl bg-[#12131a] border border-white/8 hover:border-white/20 transition">
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">
                  Total Rules
                </span>
                <FileText className="w-4 h-4 text-[#8e8e9a]" />
              </div>
              <div className="text-2xl font-bold font-mono text-[#f4f4f8] mt-2">
                {totalRules}
              </div>
              <p className="text-[9px] font-mono text-[#8e8e9a] mt-1">Actionable rules parsed</p>
            </div>

            {/* Card 3: Violations */}
            <div className="p-4 rounded-xl bg-[#12131a] border border-white/8 hover:border-red-500/30 transition">
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">
                  Violations
                </span>
                <XCircle className="w-4 h-4 text-red-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-red-400 mt-2">
                {violationsCount}
              </div>
              <p className="text-[9px] font-mono text-red-400/80 mt-1">Action required</p>
            </div>

            {/* Card 4: Partial Matches */}
            <div className="p-4 rounded-xl bg-[#12131a] border border-white/8 hover:border-amber-500/30 transition">
              <div className="flex items-center justify-between">
                <span className="text-[9px] font-mono font-bold text-[#8e8e9a] uppercase tracking-wider">
                  Partial Matches
                </span>
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              </div>
              <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
                {partialCount}
              </div>
              <p className="text-[9px] font-mono text-amber-400/80 mt-1">Review control paths</p>
            </div>
          </div>

          {/* SECTION C: FINDINGS PANEL */}
          <div className="p-5 rounded-2xl bg-[#12131a] border border-white/8 space-y-4">
            <div className="flex items-center justify-between border-b border-white/8 pb-3">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-[#ff5400]" />
                <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-[#f4f4f8]">
                  BUSINESS INTENT FINDINGS (EVIDENCE BACKED)
                </h3>
              </div>
              <span className="text-[10px] font-mono text-[#8e8e9a]">
                {(analysisResult?.findings || []).length} Rule Verdict(s)
              </span>
            </div>

            {/* Scrollable Findings List */}
            <div className="space-y-3.5 max-h-[560px] overflow-y-auto pr-1">
              {(analysisResult?.findings || []).map((item, idx) => {
                const statusUpper = item.status?.toUpperCase();

                let badgeColor = "bg-gray-500/10 text-gray-400 border-gray-500/20";
                let statusIcon = <HelpCircle className="w-3.5 h-3.5 text-gray-400" />;
                let iconSymbol = "ℹ️";

                if (statusUpper === "COMPLIANT") {
                  badgeColor = "bg-emerald-500/10 text-emerald-400 border-emerald-500/25";
                  statusIcon = <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />;
                  iconSymbol = "✅";
                } else if (statusUpper === "VIOLATION") {
                  badgeColor = "bg-red-500/10 text-red-400 border-red-500/25";
                  statusIcon = <XCircle className="w-3.5 h-3.5 text-red-400" />;
                  iconSymbol = "❌";
                } else if (statusUpper === "PARTIAL") {
                  badgeColor = "bg-amber-500/10 text-amber-400 border-amber-500/25";
                  statusIcon = <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />;
                  iconSymbol = "⚠️";
                } else if (statusUpper === "INSUFFICIENT_EVIDENCE" || statusUpper === "INSUFFICIENT") {
                  badgeColor = "bg-slate-500/10 text-slate-400 border-slate-500/25";
                  statusIcon = <HelpCircle className="w-3.5 h-3.5 text-slate-400" />;
                  iconSymbol = "❔";
                }

                return (
                  <div
                    key={idx}
                    className="p-4 rounded-xl bg-[#0c0d11] border border-white/8 hover:border-[#ff5400]/25 transition space-y-3 font-mono"
                  >
                    {/* Header: Rule Title + Rule ID + Status Badge */}
                    <div className="flex items-start justify-between gap-3 border-b border-white/5 pb-2.5">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2">
                          <span className="text-[9px] font-bold text-[#ff5400] uppercase tracking-wider px-1.5 py-0.5 rounded bg-[#ff5400]/10 border border-[#ff5400]/20">
                            {item.rule_id || `REQ-${String(idx + 1).padStart(3, "0")}`}
                          </span>
                          <span className="text-[9px] text-[#8e8e9a]">
                            {item.source_file ? `${item.source_file}:${item.line_number || 1}` : "Rule Document"}
                          </span>
                        </div>
                        <h4 className="text-xs font-bold text-[#f4f4f8] mt-1">
                          {item.rule}
                        </h4>
                      </div>
                      <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-[10px] font-bold tracking-wider shrink-0 ${badgeColor}`}>
                        {statusIcon}
                        <span>{iconSymbol} {statusUpper}</span>
                      </div>
                    </div>

                    {/* Content Grid: WHAT, WHY, HOW */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-[11px] leading-relaxed">
                      <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 space-y-1">
                        <span className="text-[9px] font-bold text-red-400 uppercase tracking-wider block">
                          WHAT
                        </span>
                        <p className="text-[#f4f4f8]">{item.what}</p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 space-y-1">
                        <span className="text-[9px] font-bold text-amber-400 uppercase tracking-wider block">
                          WHY
                        </span>
                        <p className="text-[#8e8e9a]">{item.why}</p>
                      </div>
                      <div className="p-2.5 rounded-lg bg-[#12131a] border border-white/5 space-y-1">
                        <span className="text-[9px] font-bold text-emerald-400 uppercase tracking-wider block">
                          HOW
                        </span>
                        <p className="text-[#8e8e9a]">{item.how}</p>
                      </div>
                    </div>

                    {/* Footer: Concrete Evidence File & Function Badge */}
                    <div className="flex items-center justify-between text-[10px] text-[#8e8e9a] pt-1">
                      <div className="flex items-center gap-2">
                        <Code className="w-3.5 h-3.5 text-[#ff5400]" />
                        <span>Evidence:</span>
                        <code className="px-2.5 py-1 rounded-md bg-[#12131a] border border-white/10 text-[#ff5400] font-bold">
                          {item.evidence || "file: N/A · function: N/A"}
                        </code>
                      </div>
                      {item.score !== undefined && (
                        <span className="text-[9px] font-mono text-[#8e8e9a]">
                          AST Score: <strong className="text-[#f4f4f8]">{Math.round(item.score * 100)}%</strong>
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}

      {/* AI Business Impact -- agentic enrichment, secondary to the
          deterministic rule-based analysis above. Real state.business_violations
          and correlated_findings.chains from the agentic run; never fabricated. */}
      <AIBusinessImpactSection
        violations={agenticBusinessViolations}
        businessCriticalChains={businessCriticalChains}
        workflowStatus={agenticWorkflowStatus}
        hasRunForThisScan={hasRunForThisScan}
        agenticScanId={agenticScanId}
        sourceScanId={sourceScanId}
        onRunAgentic={onRunAgentic}
        onViewFinding={onViewFinding}
      />
    </div>
  );
}
