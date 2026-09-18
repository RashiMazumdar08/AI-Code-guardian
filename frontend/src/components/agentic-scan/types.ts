/**
 * Types for the Agentic Scan view. These mirror the REAL shapes emitted by
 * backend/app/api/v1/agentic_scan.py, which in turn mirrors
 * guardian/orchestrator/state.py::AgentWorkflowState exactly (see
 * _STATE_KEYS / _curated_state in that file) -- nothing here is invented,
 * every field maps to something the backend actually produces.
 *
 * THE DETERMINISTIC SCANNER IS THE SOURCE OF TECHNICAL TRUTH: findings and
 * evidence below are always genuine guardian.core.pipeline.ScanPipeline
 * output, adopted (never re-detected) into the agent graph. Every finding/
 * evidence item carries BOTH its canonical field names (file/line/
 * evidence_ids/id) and legacy alias field names (file_path/line_number/
 * evidence_id/finding_id) -- see backend/app/api/v1/agentic_scan.py's
 * _canonical_finding_with_aliases / _canonical_evidence_with_aliases.
 */

export type AgentStatus = "WAITING" | "RUNNING" | "COMPLETED" | "FAILED" | "SKIPPED";

export const GRAPH_LABELS: Record<string, string> = {
  planner: "Planner",
  repository: "Repository",
  business: "Business",
  security: "Security",
  architecture: "Architecture",
  dependency: "Dependency",
  threat_simulation: "Threat Sim",
  policy: "Policy",
  risk_fusion: "Risk Fusion",
  patch: "Patch Gen",
  validation: "Validation",
};

export interface DeterministicBaseline {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  funnel_metrics?: {
    total_alerts?: number;
    exploitable_count?: number;
    high_priority_count?: number;
    immediate_risk_count?: number;
  };
  /** guardian.core.unified_risk.UnifiedRiskReport -- 0-100, higher is BETTER.
   *  A different scale from AgenticSummary.unified_risk_score (0-10, higher
   *  is worse) -- never collapse the two into a single comparison number. */
  deterministic_overall_risk_score?: number;
  deterministic_security_score?: number;
}

export interface AgenticSummary {
  correlated_risks: number;
  business_violations: number;
  attack_paths: number;
  policy_violations: number;
  remediation_proposals: number;
  validated_patches: number;
  unified_risk_score: number | null;
  risk_level: string | null;
}

/** One row of GET /api/v1/scans -- an existing deterministic scan available to reuse. */
export interface DeterministicScanSummary {
  scan_id: string;
  target?: string;
  scan_mode?: string;
  scan?: { total_findings?: number; by_severity?: Record<string, number> };
  duration_seconds?: number;
  /** Unix seconds. Additive field from backend/app/api/v1/scans.py -- absent on scans taken before this was added. */
  created_at?: number;
}

export interface ScanEvent {
  type: string;
  ts: number;
  agent?: string;
  task?: string;
  duration?: number;
  status?: string;
  error?: string;
  reason?: string;
  repo_url?: string;
  path?: string;
  primary_language?: string;
  total_files?: number;
  frameworks?: string[];
  scan_mode?: string;
  total_findings?: number;
  total_evidence?: number;
  total_patches?: number;
  source_scan_id?: string;
  baseline?: DeterministicBaseline;
  deterministic_baseline?: DeterministicBaseline;
  agentic_summary?: AgenticSummary;
  execution_plan?: ExecutionPlan;
  result?: AgenticAnalysisResult;
  [key: string]: any;
}

export interface NodeRuntime {
  status: AgentStatus;
  task?: string;
  duration?: number;
  error?: string;
  reason?: string;
  startedAt?: number;
  completedAt?: number;
}

export interface ExecutionPlan {
  agent_order: string[];
  parallel_groups: string[][];
  required_agents: string[];
  optional_agents: string[];
  priority: string;
  reason: string;
  expected_inputs?: string[];
  expected_outputs?: string[];
  confidence: number;
}

export interface AgentTraceEntry {
  agent_name: string;
  execution_time: number;
  current_task: string;
  tools_used: string[];
  evidence_ids: string[];
  confidence: number;
  result: { status: string; error?: string };
  errors: string[];
}

export interface FindingItem {
  finding_id: string;
  rule_id: string;
  title?: string;
  category: string;
  severity: string;
  // Canonical (guardian.core.models.Finding.to_dict()) field names:
  file?: string;
  line?: number;
  evidence_ids?: string[];
  cwe?: string;
  owasp?: string;
  source?: string;
  // Legacy alias field names (kept for the agents still built against them):
  file_path: string;
  line_number: number;
  evidence_id?: string;
  snippet?: string;
  description?: string;
  recommendation?: string;
  language?: string | null;
  confidence?: number;
}

export interface EvidenceItem {
  // Canonical (guardian.evidence.models.Evidence.to_dict()) field names:
  id?: string;
  type?: string;
  source?: string;
  snippet?: string;
  symbol?: string;
  operation?: string;
  // Legacy alias field names:
  evidence_id: string;
  finding_id: string;
  file: string;
  line: number;
  code_snippet?: string;
  engine: string;
  confidence?: number;
}

export interface BusinessIntentFinding {
  rule_id: string;
  rule: string;
  status: "COMPLIANT" | "VIOLATION" | "POTENTIAL_VIOLATION" | "PARTIAL" | "INSUFFICIENT_EVIDENCE" | string;
  what?: string;
  why?: string;
  how?: string;
  evidence?: string;
  /** Match confidence (0-1) from guardian/intent/matcher/rule_matcher.py's
   * evaluate_rule() -- real field, not invented; there is no separate
   * per-violation "severity" in the business intent data model, so UI code
   * should use this (labeled as confidence) rather than fabricate one. */
  score?: number;
  source_file?: string;
  line_number?: number;
}

/** Real ThreatSimulationAgent output (guardian/agents/threat_simulation/
 * agent.py) -- one entry per finding the agent judged reachable/severe
 * enough to model (see the is_attack_chain_candidate filter there), not
 * one per finding overall. */
export interface AttackPathItem {
  finding_id: string;
  evidence_id?: string;
  title?: string;
  entry_point: string;
  target_file: string;
  exploitability: number;
  reachability: "DIRECT" | "INDIRECT" | string;
  attack_vector: string;
}

export interface BusinessIntentResults {
  status: string;
  alignment_score?: number;
  alignment_percentage?: number;
  total_rules?: number;
  matched?: number;
  violated?: number;
  partial?: number;
  insufficient?: number;
  documents?: string[];
  findings?: BusinessIntentFinding[];
  agent_reason?: string;
}

export interface RiskScores {
  composite_risk_score: number;
  technical_risk_score: number;
  business_risk_score: number;
  threat_risk_score: number;
  policy_risk_score: number;
  reachability_weight: number;
  confidence_score: number;
  risk_level: string;
}

export interface PatchItem {
  patch_id: string;
  finding_id: string;
  affected_file: string;
  affected_lines: string;
  original_snippet: string;
  suggested_replacement: string;
  explanation: string;
  evidence_ids: string[];
  confidence: number;
  policy_references?: string[];
  business_impact?: string;
  threat_impact?: string;
  validation_status: "PENDING" | "PASSED" | "REJECTED" | string;
  git_diff?: string;
}

export interface ValidationResultItem {
  patch_id: string;
  finding_id: string;
  file: string;
  status: "PASSED" | "REJECTED" | string;
  grounding_passed: boolean;
  syntax_valid: boolean;
  remediation_resolved: boolean;
  issues: string[];
  confidence: number;
}

export interface CuratedState {
  scan_id?: string;
  scan_mode?: string;
  active_agent?: string;
  current_task?: string;
  completed_agents?: string[];
  pending_agents?: string[];
  execution_plan?: ExecutionPlan;
  agent_trace?: AgentTraceEntry[];
  execution_metrics?: {
    total_execution_time?: number;
    agent_runtime?: Record<string, number>;
    number_of_findings?: number;
    number_of_evidence_objects?: number;
  };
  repository_context?: Record<string, any>;
  business_context?: Record<string, any>;
  business_intent_results?: BusinessIntentResults;
  business_violations?: BusinessIntentFinding[];
  security_context?: Record<string, any>;
  architecture_context?: Record<string, any>;
  dependency_context?: {
    total_dependencies?: number;
    direct_dependencies_count?: number;
    transitive_dependencies_count?: number;
    vulnerable_dependencies_count?: number;
    manifest_files?: string[];
    detected_libraries?: { name: string; version: string; ecosystem: string; manifest: string }[];
    cve_list?: any[];
  };
  threat_context?: Record<string, any>;
  policy_results?: Record<string, any>;
  correlated_findings?: {
    total_correlated?: number;
    deduplicated_findings?: FindingItem[];
    chains?: CorrelatedChainItem[];
    evidence_mapping?: Record<string, string[]>;
    [key: string]: any;
  };
  attack_paths?: AttackPathItem[];
  exploitability?: number;
  findings?: FindingItem[];
  evidence?: EvidenceItem[];
  risk_scores?: RiskScores;
  patches?: PatchItem[];
  git_diff?: string;
  remediation_summary?: { total_patches_proposed?: number; files_affected?: string[] };
  developer_explanation?: string;
  validation_report?: { total_validated: number; passed_count: number; rejected_count: number };
  validation_results?: ValidationResultItem[];
  validation_confidence?: number;
  grounding_report?: { total_checked: number; grounded_passed: number };
}

/** Real EvidenceCorrelationService.correlate() chain entries (guardian/
 * evidence/correlation.py) -- built from the same attack_paths the Threat
 * Agent produced, joined with business_context.criticality and any
 * policy_results violations for that finding. `business_criticality` is
 * the repository-wide classification the Business Agent set (not a
 * per-finding value), applied to every chain it touches. */
export interface CorrelatedChainItem {
  chain_id: string;
  title?: string;
  finding_id: string;
  evidence_ids?: string[];
  target_asset: string;
  business_criticality: string;
  policy_violations?: string[];
  exploitability: number;
}

/** One hop in a finding's evidence-traceability chain -- real ids/agent
 * names only (see report_view_model.build_traceability_chain(), Python
 * side); a hop with nothing real to show is omitted rather than padded. */
export interface TraceabilityHop {
  label: "Finding" | "Evidence" | "Agent" | "Remediation" | "Validation" | string;
  value: string;
}

/** Finding -> Evidence -> Agent -> Remediation -> Validation, one entry
 * per finding that has more than a bare "Finding" hop. Backend reuses
 * guardian/reporting/report_view_model.py's build_traceability_chain() --
 * the same logic the Agentic/Unified HTML reports already render -- so
 * this is not a second implementation, just the same chains exposed
 * through the API contract too (v2.1.0 Phase 2). */
export interface TraceabilityChainItem {
  finding_id: string;
  hops: TraceabilityHop[];
}

/** {stage, error} -- same shape the deterministic Security Report's own
 * "Partial Results" section uses (guardian/reporting/html_reporter.py),
 * so both report types can be handled uniformly. Empty unless this run
 * actually recorded a failure. */
export interface AgenticResultError {
  stage: string;
  error: string;
}

/**
 * The canonical read model between the backend AgentWorkflowState and
 * every frontend consumer (Security tab, Business Intent tab, Agentic Scan
 * tab, Reports) -- mirrors backend/app/api/v1/agentic_scan.py's
 * _build_agentic_analysis_result() exactly, bucket for bucket. It is a
 * pure reshaping of the same real fields CuratedState already carries
 * (see that interface above) -- nothing here is computed or invented on
 * the frontend either. Prefer reading from this over raw CuratedState
 * wherever both are available; CuratedState is kept for panels not yet
 * migrated and for the raw execution log.
 */
export interface AgenticAnalysisResult {
  run: {
    agentic_run_id: string;
    base_scan_id: string | null;
    status: string;
    scan_mode?: string;
    started_at?: number;
  };
  /** The repository profile this run was seeded with (root/primary_language/
   * frameworks/etc.) -- stored once at adoption time, not part of
   * AgentWorkflowState itself, so this run's repository context is always
   * available here without a second lookup against the deterministic scan. */
  repository: Record<string, any>;
  execution: {
    active_agent?: string;
    current_task?: string;
    completed_agents: string[];
    pending_agents: string[];
    execution_plan?: ExecutionPlan;
    agent_trace: AgentTraceEntry[];
    execution_metrics?: CuratedState["execution_metrics"];
  };
  /** Deterministic findings/evidence AS ADOPTED into this agentic run --
   * the same real ScanPipeline output CuratedState.findings/evidence
   * carries, scoped here so cross-cutting views (Evidence Traceability)
   * don't need a second raw-state lookup. */
  deterministic_context: {
    findings: FindingItem[];
    evidence: EvidenceItem[];
  };
  security_enrichment: {
    correlated_findings: CuratedState["correlated_findings"];
    attack_paths: AttackPathItem[];
    exploitability?: number;
    security_context: Record<string, any>;
  };
  business_analysis: {
    violations: BusinessIntentFinding[];
    results?: BusinessIntentResults;
  };
  architecture_analysis: Record<string, any>;
  dependency_analysis: CuratedState["dependency_context"];
  threat_analysis: {
    threat_context: Record<string, any>;
    attack_paths: AttackPathItem[];
  };
  policy_analysis: Record<string, any>;
  risk_fusion: {
    risk_scores?: RiskScores;
    correlated_chains: CorrelatedChainItem[];
    evidence_mapping: Record<string, string[]>;
  };
  remediation: {
    patches: PatchItem[];
    remediation_summary?: CuratedState["remediation_summary"];
    git_diff?: string;
    developer_explanation?: string;
  };
  validation: {
    results: ValidationResultItem[];
    report?: CuratedState["validation_report"];
    confidence?: number;
    grounding_report?: CuratedState["grounding_report"];
  };
  /** Real Finding -> Evidence -> Agent -> Remediation -> Validation chains.
   * Empty array, never fabricated hops, when there's nothing real to trace
   * yet (v2.1.0 Phase 2). */
  evidence_traceability: TraceabilityChainItem[];
  /** Same real counts as the sibling top-level AgenticSummary this endpoint
   * already returns (kept for backward compatibility) -- nested here too
   * under the v2.1.0 contract's name, not a second computation
   * (v2.1.0 Phase 2). */
  execution_summary: AgenticSummary;
  /** This run's failure, if any, in the same shape the deterministic
   * Security Report's "Partial Results" section uses. Empty unless the
   * run actually recorded an error (v2.1.0 Phase 2). */
  errors: AgenticResultError[];
}

export interface AgenticScanGraph {
  nodes: string[];
  edges: [string, string][];
}

/** "cancelled" reflects the real backend lifecycle (see
 * backend/app/api/v1/agentic_scan.py::cancel_agentic_scan) -- a genuine,
 * cooperative stop at the next real execution boundary, not a UI-only
 * state. */
export type WorkflowStatus = "idle" | "starting" | "running" | "completed" | "error" | "cancelled";
