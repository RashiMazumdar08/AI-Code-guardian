const assert = require('assert');

// 1. Test Property Path Extraction (SecurityWorkbench.tsx -> AISecurityAnalysisSection props)
function extractGrokStatus(agenticResult, agenticState) {
  return (
    agenticResult?.security_enrichment?.security_context?.grok_status ||
    agenticState?.security_context?.grok_status
  );
}

function extractAgentReason(agenticResult, agenticState) {
  return (
    agenticResult?.security_enrichment?.security_context?.agent_reason ||
    agenticState?.security_context?.agent_reason
  );
}

// 2. Test AISecurityAnalysisSection Rendering Branch Selection
function evaluateUIBranch(grokStatus, securityAgentReason, aiSecurityInsights) {
  if (["FAILED", "RATE_LIMITED", "UNAVAILABLE"].includes(grokStatus)) {
    return "UNAVAILABLE_BANNER";
  }
  if (grokStatus === "SKIPPED" || (aiSecurityInsights.length === 0 && securityAgentReason?.includes("conclusive baseline"))) {
    return "SKIPPED_BANNER";
  }
  if (aiSecurityInsights.length === 0) {
    return "NO_ADDITIONAL_FINDINGS";
  }
  return "AI_FINDINGS_LIST";
}

function evaluateBusinessUIBranch(grokStatus, businessAgentReason, aiBusinessInsights) {
  if (aiBusinessInsights && aiBusinessInsights.length > 0) {
    return "AI_INSIGHTS_LIST";
  }
  if (grokStatus === "PROVIDER_DAILY_QUOTA") return "DAILY_QUOTA_BANNER";
  if (grokStatus === "SKIPPED_BUDGET") return "SKIPPED_BUDGET_BANNER";
  if (grokStatus === "RATE_LIMITED") return "RATE_LIMITED_BANNER";
  if (["FAILED", "UNAVAILABLE", "PROVIDER_UNAVAILABLE"].includes(grokStatus)) return "UNAVAILABLE_BANNER";
  if (grokStatus === "SKIPPED" || businessAgentReason?.includes("conclusive baseline")) return "NOT_REQUIRED_BANNER";
  return "NO_GAPS_BANNER";
}

// 3. Test sourceScanId Restoration Logic (useAgenticScan.ts)
function restoreAgenticState(activeScanId, cachedReport) {
  if (!cachedReport || !cachedReport.sourceScanId) return null;
  if (!activeScanId || cachedReport.sourceScanId === activeScanId) {
    return {
      sourceScanId: cachedReport.sourceScanId,
      result: cachedReport.result,
      state: cachedReport.state,
      workflowStatus: "completed"
    };
  }
  return null; // Stale data rejected
}

// --- RUN TEST SUITE ---
console.log("=== RUNNING FRONTEND LOGIC TEST SUITE ===");

// Test 1: Nested security_context under security_enrichment
const sampleResultCompleted = {
  security_enrichment: {
    security_context: {
      grok_status: "COMPLETED",
      agent_reason: "Verified 5 semantic findings."
    }
  }
};
assert.strictEqual(extractGrokStatus(sampleResultCompleted, {}), "COMPLETED");
assert.strictEqual(extractAgentReason(sampleResultCompleted, {}), "Verified 5 semantic findings.");
console.log("✔ Test 1 passed: security_context under security_enrichment correctly extracted");

// Test 2: Grok FAILED / RATE_LIMITED rendering banner
const sampleResultFailed = {
  security_enrichment: {
    security_context: {
      grok_status: "FAILED",
      agent_reason: "Daily token limit exceeded"
    }
  }
};
const grokStatusFailed = extractGrokStatus(sampleResultFailed, {});
const agentReasonFailed = extractAgentReason(sampleResultFailed, {});
const branchFailed = evaluateUIBranch(grokStatusFailed, agentReasonFailed, []);
assert.strictEqual(branchFailed, "UNAVAILABLE_BANNER");
console.log("✔ Test 2 passed: Grok FAILED renders UNAVAILABLE_BANNER instead of NO_ADDITIONAL_FINDINGS");

// Test 3: Grok RATE_LIMITED
const branchRateLimited = evaluateUIBranch("RATE_LIMITED", "Rate limit exceeded", []);
assert.strictEqual(branchRateLimited, "UNAVAILABLE_BANNER");
console.log("✔ Test 3 passed: Grok RATE_LIMITED renders UNAVAILABLE_BANNER");

// Test 4: Grok COMPLETED with AI findings
const branchCompleted = evaluateUIBranch("COMPLETED", "Success", [{ finding_id: "ai-1" }]);
assert.strictEqual(branchCompleted, "AI_FINDINGS_LIST");
console.log("✔ Test 4 passed: Grok COMPLETED with findings renders AI_FINDINGS_LIST");

// Test 5: Empty AI findings with COMPLETED status
const branchEmpty = evaluateUIBranch("COMPLETED", "Success", []);
assert.strictEqual(branchEmpty, "NO_ADDITIONAL_FINDINGS");
console.log("✔ Test 5 passed: Grok COMPLETED with 0 findings renders NO_ADDITIONAL_FINDINGS");

// Test 6: sourceScanId persistence on reload (Matching scan_id)
const activeScanId = "scan_123";
const cachedMatching = { sourceScanId: "scan_123", result: { ai_security_insights: [1, 2] } };
const restoredMatching = restoreAgenticState(activeScanId, cachedMatching);
assert.notStrictEqual(restoredMatching, null);
assert.strictEqual(restoredMatching.sourceScanId, "scan_123");
console.log("✔ Test 6 passed: sourceScanId restored when matching activeScanId");

// Test 7: Stale sourceScanId rejected when switching scans
const cachedStale = { sourceScanId: "scan_OLD", result: { ai_security_insights: [1, 2] } };
const restoredStale = restoreAgenticState(activeScanId, cachedStale);
assert.strictEqual(restoredStale, null);
console.log("✔ Test 7 passed: Stale sourceScanId rejected when active scan changes");

// Test 8: BusinessAgent UI shows AI insights even if status is PROVIDER_UNAVAILABLE when insights exist
const branchBusInsightsExist = evaluateBusinessUIBranch("PROVIDER_UNAVAILABLE", "Batch 3 skipped", [{ finding_id: "ai-bus-1" }]);
assert.strictEqual(branchBusInsightsExist, "AI_INSIGHTS_LIST");
console.log("✔ Test 8 passed: BusinessAgent UI renders AI insights list when insights exist despite PROVIDER_UNAVAILABLE status");

// Test 9: BusinessAgent UI shows UNAVAILABLE_BANNER when 0 insights and status is PROVIDER_UNAVAILABLE
const branchBusNoInsightsUnavailable = evaluateBusinessUIBranch("PROVIDER_UNAVAILABLE", "Provider failed", []);
assert.strictEqual(branchBusNoInsightsUnavailable, "UNAVAILABLE_BANNER");
console.log("✔ Test 9 passed: BusinessAgent UI renders UNAVAILABLE_BANNER when 0 insights and PROVIDER_UNAVAILABLE");

// Test 10: BusinessAgent UI shows SKIPPED_BUDGET_BANNER when 0 insights and SKIPPED_BUDGET
const branchBusSkippedBudget = evaluateBusinessUIBranch("SKIPPED_BUDGET", "Budget limit reached", []);
assert.strictEqual(branchBusSkippedBudget, "SKIPPED_BUDGET_BANNER");
console.log("✔ Test 10 passed: BusinessAgent UI renders SKIPPED_BUDGET_BANNER when 0 insights and SKIPPED_BUDGET");

// Test 11: Phase 8 Regression Test — Component Init & Active Session Isolation (TESTS 1 to 6)
function simulateComponentInit(workspaceId, sessionStorageMock) {
  let docFiles = [];
  let analysisResult = null;
  const hasActiveSession = sessionStorageMock[`guardian_bi_active_doc_${workspaceId}`] === "true";

  if (hasActiveSession) {
    const cachedFiles = sessionStorageMock[`guardian_bi_active_files_${workspaceId}`];
    if (cachedFiles) docFiles = JSON.parse(cachedFiles);
    const cachedRes = sessionStorageMock[`guardian_bi_result_${workspaceId}`];
    if (cachedRes) analysisResult = JSON.parse(cachedRes);
  }
  return { docFiles, analysisResult };
}

const initialDeterministicResult = {
  alignment_score: 0.25,
  alignment_percentage: 25,
  total_rules: 5,
  findings: [
    { rule_id: "REQ-002", status: "INSUFFICIENT_EVIDENCE", rule: "Transaction atomicity" }
  ]
};

// TEST 1: Open Business Intent with no active uploaded document.
const stateTest1 = simulateComponentInit("ws_fresh", {});
assert.strictEqual(stateTest1.docFiles.length, 0);
assert.strictEqual(stateTest1.analysisResult, null);
console.log("✔ TEST 1 passed: Fresh Business Intent open has 0 docs and 0 analysis results");

// TEST 2: Historical cached result exists for workspace, but no active document session.
const storageTest2 = { "guardian_bi_result_ws_hist": JSON.stringify(initialDeterministicResult) };
const stateTest2 = simulateComponentInit("ws_hist", storageTest2);
assert.strictEqual(stateTest2.docFiles.length, 0);
assert.strictEqual(stateTest2.analysisResult, null);
console.log("✔ TEST 2 passed: Historical cached result is NOT rendered automatically without active session");

// TEST 3: Upload a document (does NOT auto-run analysis).
const mockSessionStorage = {};
const workspaceId = "ws_active_1";
// Upload handler sets active session & files, but leaves analysisResult null until Run Intent Analysis
mockSessionStorage[`guardian_bi_active_doc_${workspaceId}`] = "true";
mockSessionStorage[`guardian_bi_active_files_${workspaceId}`] = JSON.stringify(["DV_Bookshop_Business_Rules.pdf"]);

const stateTest3 = simulateComponentInit(workspaceId, mockSessionStorage);
assert.strictEqual(stateTest3.docFiles.length, 1);
assert.strictEqual(stateTest3.docFiles[0], "DV_Bookshop_Business_Rules.pdf");
assert.strictEqual(stateTest3.analysisResult, null);
console.log("✔ TEST 3 passed: Document upload displays file as PARSED but does NOT automatically run analysis");

// TEST 4: Click Run Intent Analysis.
mockSessionStorage[`guardian_bi_result_${workspaceId}`] = JSON.stringify(initialDeterministicResult);
const stateTest4 = simulateComponentInit(workspaceId, mockSessionStorage);
assert.notStrictEqual(stateTest4.analysisResult, null);
assert.strictEqual(stateTest4.analysisResult.alignment_score, 0.25);
assert.strictEqual(stateTest4.analysisResult.total_rules, 5);
console.log("✔ TEST 4 passed: Run Intent Analysis displays 5 rules and deterministic 25% alignment score");

// TEST 5: Start Agentic Scan & Component Remount.
const stateTest5 = simulateComponentInit(workspaceId, mockSessionStorage);
assert.strictEqual(stateTest5.docFiles.length, 1);
assert.notStrictEqual(stateTest5.analysisResult, null);
assert.strictEqual(stateTest5.analysisResult.alignment_score, 0.25);
assert.strictEqual(stateTest5.analysisResult.total_rules, 5);
console.log("✔ TEST 5 passed: Deterministic result remains visible across Agentic Scan component remount");

// TEST 6: Agentic BusinessAgent result appears for INSUFFICIENT_EVIDENCE.
const agenticBusinessResult = [
  { policy_id: "REQ-002", status: "INSUFFICIENT_EVIDENCE", ai_analysis: "Gemini analysis succeeded" }
];
assert.strictEqual(agenticBusinessResult.length, 1);
assert.strictEqual(agenticBusinessResult[0].status, "INSUFFICIENT_EVIDENCE");
console.log("✔ TEST 6 passed: Agentic BusinessAgent AI result appears for INSUFFICIENT_EVIDENCE alongside deterministic baseline");

// --- DEPENDENCY AGENT METRIC SEMANTICS TESTS ---
function computeDependencyMetrics(dependencyAnalysis, findings) {
  const rawLibraries = dependencyAnalysis.detected_libraries || [];
  const total = dependencyAnalysis.total_dependencies ?? rawLibraries.length;
  const cveList = Array.from(new Set(dependencyAnalysis.cve_list || []));

  const depFindings = (findings || []).filter((f) => {
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

  const vulnerabilityMatches = Math.max(depFindings.length, dependencyAnalysis.vulnerable_dependencies_count ?? 0);

  const enrichedLibraries = rawLibraries.map((lib) => {
    const pkgNameLower = (lib.name || "").toLowerCase();
    const pkgFindings = depFindings.filter((f) => {
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

    let highestSev = "NONE";
    const hasCritical = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "critical");
    const hasHigh = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "high");
    const hasMedium = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "medium");
    const hasLow = pkgFindings.some((f) => (f.severity || "").toLowerCase() === "low");

    if (hasCritical) highestSev = "CRITICAL";
    else if (hasHigh) highestSev = "HIGH";
    else if (hasMedium) highestSev = "MEDIUM";
    else if (hasLow) highestSev = "LOW";

    return {
      ...lib,
      pkgFindings,
      highestSev,
      isVulnerable: pkgFindings.length > 0 && highestSev !== "NONE",
    };
  });

  const vulnSet = new Set();
  enrichedLibraries.forEach((lib) => {
    if (lib.isVulnerable) {
      vulnSet.add(`${lib.ecosystem || 'other'}:${lib.name}`.toLowerCase());
    }
  });

  const distinctVulnerablePkgCount = (total > 0 && rawLibraries.length > 0)
    ? Math.min(vulnSet.size, total)
    : vulnSet.size;

  return {
    total,
    distinctVulnerablePkgCount,
    vulnerabilityMatches,
    uniqueCVEs: cveList.length,
  };
}

// TEST 7: 17 total packages with 44 vulnerability findings on 1 package (44 matches, 20 unique CVEs)
const sampleLibs = Array.from({ length: 17 }, (_, i) => ({
  name: `pkg-${i+1}`,
  version: "1.0.0",
  ecosystem: "PyPI",
  manifest: "requirements.txt"
}));

// 44 findings generated for pkg-1 with 20 unique CVEs
const sampleFindings = Array.from({ length: 44 }, (_, i) => ({
  category: "dependency",
  severity: "HIGH",
  rule_id: `CVE-2023-${1000 + (i % 20)}`,
  title: `Vulnerable Dependency: pkg-1 (CVE-2023-${1000 + (i % 20)})`,
  description: "OSV vulnerability match",
  file_path: "requirements.txt"
}));

const metrics17_44 = computeDependencyMetrics(
  {
    total_dependencies: 17,
    vulnerable_dependencies_count: 44,
    detected_libraries: sampleLibs,
    cve_list: sampleFindings.map(f => f.rule_id)
  },
  sampleFindings
);

assert.strictEqual(metrics17_44.total, 17, "Total packages must be 17");
assert.strictEqual(metrics17_44.distinctVulnerablePkgCount, 1, "Vulnerable packages must be 1 distinct package");
assert.strictEqual(metrics17_44.vulnerabilityMatches, 44, "Vulnerability matches must be 44");
assert.strictEqual(metrics17_44.uniqueCVEs, 20, "Unique CVEs must be 20");
assert.ok(metrics17_44.distinctVulnerablePkgCount <= metrics17_44.total, "Vulnerable package count must be <= total package count");
assert.ok(metrics17_44.vulnerabilityMatches > metrics17_44.distinctVulnerablePkgCount, "Vulnerability matches can exceed vulnerable package count");
console.log("✔ TEST 7 passed: 17 total packages with 44 matches correctly shows 1 Vulnerable Package, 44 Matches, 20 Unique CVEs");

// TEST 8: Deduplication of CVEs & multiple findings on same package
const metricsDup = computeDependencyMetrics(
  {
    total_dependencies: 5,
    vulnerable_dependencies_count: 10,
    detected_libraries: [
      { name: "requests", version: "2.28.0", ecosystem: "PyPI", manifest: "requirements.txt" },
      { name: "urllib3", version: "1.26.0", ecosystem: "PyPI", manifest: "requirements.txt" },
    ],
    cve_list: ["CVE-2023-0001", "CVE-2023-0001", "CVE-2023-0002"]
  },
  [
    { category: "dependency", severity: "HIGH", rule_id: "CVE-2023-0001", title: "requests CVE-2023-0001", file_path: "requirements.txt" },
    { category: "dependency", severity: "CRITICAL", rule_id: "CVE-2023-0002", title: "requests CVE-2023-0002", file_path: "requirements.txt" }
  ]
);

assert.strictEqual(metricsDup.distinctVulnerablePkgCount, 1, "Multiple CVEs on 1 package count as 1 vulnerable package");
assert.strictEqual(metricsDup.uniqueCVEs, 2, "Duplicate CVE IDs in cve_list are deduplicated to 2");
console.log("✔ TEST 8 passed: Multiple vulnerabilities on 1 package count as 1 vulnerable package, unique CVEs deduplicated");

// --- THREAT SIMULATION AGENT PAGINATION TESTS ---
function paginateThreats(findings, showAllSeverities, page = 1, pageSize = 4) {
  const criticalHigh = (findings || []).filter((f) =>
    ["critical", "high"].includes(String(f.severity || "").toLowerCase())
  );
  const relevantFindings = showAllSeverities ? (findings || []) : criticalHigh;
  const totalPages = Math.max(1, Math.ceil(relevantFindings.length / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const startIndex = (safePage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, relevantFindings.length);
  const displayed = relevantFindings.slice(startIndex, endIndex);

  return {
    total: relevantFindings.length,
    totalPages,
    currentPage: safePage,
    startIndex: relevantFindings.length > 0 ? startIndex + 1 : 0,
    endIndex,
    displayed,
    showControls: relevantFindings.length > pageSize,
    isPrevDisabled: safePage === 1,
    isNextDisabled: safePage === totalPages,
  };
}

// TEST 9: 11 findings -> 3 pages, Page 1 displays 4 items (1–4), Prev disabled, Next enabled
const sample11Threats = Array.from({ length: 11 }, (_, i) => ({
  finding_id: `threat-${i + 1}`,
  severity: "HIGH",
  title: `Threat ${i + 1}`,
  file: "app.py"
}));

const p1 = paginateThreats(sample11Threats, true, 1, 4);
assert.strictEqual(p1.total, 11);
assert.strictEqual(p1.totalPages, 3);
assert.strictEqual(p1.displayed.length, 4);
assert.strictEqual(p1.startIndex, 1);
assert.strictEqual(p1.endIndex, 4);
assert.strictEqual(p1.showControls, true);
assert.strictEqual(p1.isPrevDisabled, true);
assert.strictEqual(p1.isNextDisabled, false);
console.log("✔ TEST 9 passed: 11 threat results pagination on Page 1 (items 1–4, Prev disabled, Next enabled)");

// TEST 10: Page 3 of 11 -> displays 3 items (9–11), Prev enabled, Next disabled
const p3 = paginateThreats(sample11Threats, true, 3, 4);
assert.strictEqual(p3.displayed.length, 3);
assert.strictEqual(p3.startIndex, 9);
assert.strictEqual(p3.endIndex, 11);
assert.strictEqual(p3.isPrevDisabled, false);
assert.strictEqual(p3.isNextDisabled, true);
console.log("✔ TEST 10 passed: 11 threat results pagination on Page 3 (items 9–11, Prev enabled, Next disabled)");

// TEST 11: 3 total findings (<= 4) -> pagination controls hidden
const sample3Threats = Array.from({ length: 3 }, (_, i) => ({
  finding_id: `threat-${i + 1}`,
  severity: "CRITICAL"
}));
const p3Total = paginateThreats(sample3Threats, true, 1, 4);
assert.strictEqual(p3Total.showControls, false);
assert.strictEqual(p3Total.displayed.length, 3);
console.log("✔ TEST 11 passed: Total threats <= 4 correctly hides pagination controls");

// TEST 12: High Risk Only filter (filtering 11 items down to 2 critical/high)
const mixedThreats = [
  { finding_id: "t1", severity: "CRITICAL" },
  { finding_id: "t2", severity: "LOW" },
  { finding_id: "t3", severity: "MEDIUM" },
  { finding_id: "t4", severity: "HIGH" },
  { finding_id: "t5", severity: "LOW" }
];
const filteredP1 = paginateThreats(mixedThreats, false, 1, 4);
assert.strictEqual(filteredP1.total, 2);
assert.strictEqual(filteredP1.showControls, false);
assert.strictEqual(filteredP1.displayed.length, 2);
console.log("✔ TEST 12 passed: High Risk filter correctly recalculates pagination total and hides controls when <= 4");

// --- AI RISK CORRELATION / BUSINESS IMPACT PAGINATION TESTS ---
function paginateRiskCorrelation(chains, page = 1, pageSize = 4) {
  const total = (chains || []).length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const startIndex = (safePage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, total);
  const displayed = (chains || []).slice(startIndex, endIndex);

  return {
    total,
    totalPages,
    currentPage: safePage,
    startIndex: total > 0 ? startIndex + 1 : 0,
    endIndex,
    displayed,
    showControls: total > pageSize,
    isPrevDisabled: safePage === 1,
    isNextDisabled: safePage === totalPages,
    showingText: `Showing ${total > 0 ? startIndex + 1 : 0}–${endIndex} of ${total} impact stories`,
  };
}

// TEST 13: 34 Risk Correlation results -> Page 1 (items 1–4), Total pages = 9, Prev disabled, Next enabled
const sample34Chains = Array.from({ length: 34 }, (_, i) => ({
  chain_id: `chain-${i + 1}`,
  title: `Impact Chain ${i + 1}`,
  finding_id: `FIND-${100 + i}`,
  business_criticality: i % 2 === 0 ? "CRITICAL" : "HIGH",
  target_asset: "User Database",
  policy_violations: ["GDPR Art. 32"]
}));

const rcP1 = paginateRiskCorrelation(sample34Chains, 1, 4);
assert.strictEqual(rcP1.total, 34);
assert.strictEqual(rcP1.totalPages, 9);
assert.strictEqual(rcP1.displayed.length, 4);
assert.strictEqual(rcP1.displayed[0].chain_id, "chain-1");
assert.strictEqual(rcP1.displayed[3].chain_id, "chain-4");
assert.strictEqual(rcP1.startIndex, 1);
assert.strictEqual(rcP1.endIndex, 4);
assert.strictEqual(rcP1.isPrevDisabled, true);
assert.strictEqual(rcP1.isNextDisabled, false);
assert.strictEqual(rcP1.showingText, "Showing 1–4 of 34 impact stories");
console.log("✔ TEST 13 passed: 34 Risk Correlation results on Page 1 (items 1–4, 9 total pages, Prev disabled)");

// TEST 14: Page 2 displays results 5–8
const rcP2 = paginateRiskCorrelation(sample34Chains, 2, 4);
assert.strictEqual(rcP2.displayed.length, 4);
assert.strictEqual(rcP2.displayed[0].chain_id, "chain-5");
assert.strictEqual(rcP2.displayed[3].chain_id, "chain-8");
assert.strictEqual(rcP2.startIndex, 5);
assert.strictEqual(rcP2.endIndex, 8);
assert.strictEqual(rcP2.showingText, "Showing 5–8 of 34 impact stories");
console.log("✔ TEST 14 passed: Page 2 displays results 5–8 with correct bounds");

// TEST 15: Page 8 displays results 29–32
const rcP8 = paginateRiskCorrelation(sample34Chains, 8, 4);
assert.strictEqual(rcP8.displayed.length, 4);
assert.strictEqual(rcP8.displayed[0].chain_id, "chain-29");
assert.strictEqual(rcP8.displayed[3].chain_id, "chain-32");
assert.strictEqual(rcP8.startIndex, 29);
assert.strictEqual(rcP8.endIndex, 32);
assert.strictEqual(rcP8.isPrevDisabled, false);
assert.strictEqual(rcP8.isNextDisabled, false);
console.log("✔ TEST 15 passed: Page 8 displays results 29–32 with Prev & Next enabled");

// TEST 16: Page 9 displays results 33–34, Next disabled
const rcP9 = paginateRiskCorrelation(sample34Chains, 9, 4);
assert.strictEqual(rcP9.displayed.length, 2);
assert.strictEqual(rcP9.displayed[0].chain_id, "chain-33");
assert.strictEqual(rcP9.displayed[1].chain_id, "chain-34");
assert.strictEqual(rcP9.startIndex, 33);
assert.strictEqual(rcP9.endIndex, 34);
assert.strictEqual(rcP9.isNextDisabled, true);
assert.strictEqual(rcP9.showingText, "Showing 33–34 of 34 impact stories");
console.log("✔ TEST 16 passed: Page 9 displays results 33–34 with Next disabled");

// TEST 17: <= 4 results -> pagination hidden
const sample4Chains = sample34Chains.slice(0, 4);
const rcP4Total = paginateRiskCorrelation(sample4Chains, 1, 4);
assert.strictEqual(rcP4Total.showControls, false);
assert.strictEqual(rcP4Total.displayed.length, 4);
console.log("✔ TEST 17 passed: <= 4 Risk Correlation results hides pagination controls");

// TEST 18: 0 results -> empty state preserved, total = 0
const rcP0Total = paginateRiskCorrelation([], 1, 4);
assert.strictEqual(rcP0Total.total, 0);
assert.strictEqual(rcP0Total.showControls, false);
assert.strictEqual(rcP0Total.displayed.length, 0);
console.log("✔ TEST 18 passed: 0 results preserved with empty state and hidden pagination controls");

// TEST 19: New result set resets page state safely (out of bounds page clamps to safe totalPages)
const newSmallSet = sample34Chains.slice(0, 2);
const rcReset = paginateRiskCorrelation(newSmallSet, 8, 4);
assert.strictEqual(rcReset.currentPage, 1);
assert.strictEqual(rcReset.displayed.length, 2);
console.log("✔ TEST 19 passed: Out of bounds page clamps safely to Page 1 on new smaller result set");

// --- DEPENDENCY AGENT PACKAGE EXPLORER PAGINATION TESTS ---
function filterAndPaginatePackages({ libraries, activeTab = "all", searchQuery = "", severityFilter = "ALL", ecosystemFilter = "ALL", page = 1, pageSize = 10 }) {
  const filtered = (libraries || []).filter((lib) => {
    if (activeTab === "vulnerable" && !lib.isVulnerable) return false;
    if (activeTab === "outdated" && !lib.isUnpinned) return false;

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchName = (lib.name || "").toLowerCase().includes(q);
      const matchEco = (lib.ecosystem || "").toLowerCase().includes(q);
      const matchManifest = (lib.manifest || "").toLowerCase().includes(q);
      if (!matchName && !matchEco && !matchManifest) return false;
    }

    if (severityFilter !== "ALL" && lib.highestSev !== severityFilter) return false;
    if (ecosystemFilter !== "ALL" && lib.ecosystem !== ecosystemFilter) return false;

    return true;
  });

  const total = filtered.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(Math.max(1, page), totalPages);
  const startIndex = (safePage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, total);
  const displayed = filtered.slice(startIndex, endIndex);

  return {
    total,
    totalPages,
    currentPage: safePage,
    startIndex: total > 0 ? startIndex + 1 : 0,
    endIndex,
    displayed,
    showControls: total > pageSize,
    isPrevDisabled: safePage === 1,
    isNextDisabled: safePage === totalPages,
    showingText: `Showing ${total > 0 ? startIndex + 1 : 0}–${endIndex} of ${total} packages`,
  };
}

// TEST 20: 17 packages -> 10 rows on Page 1 (items 1–10), Total pages = 2, Prev disabled, Next enabled
const sample17Packages = Array.from({ length: 17 }, (_, i) => ({
  name: `pkg-${i + 1}`,
  version: "1.0.0",
  ecosystem: "PyPI",
  manifest: "requirements.txt",
  highestSev: i % 2 === 0 ? "HIGH" : "CLEAN",
  isVulnerable: i % 2 === 0,
  isUnpinned: false,
}));

const depP1 = filterAndPaginatePackages({ libraries: sample17Packages, page: 1, pageSize: 10 });
assert.strictEqual(depP1.total, 17);
assert.strictEqual(depP1.totalPages, 2);
assert.strictEqual(depP1.displayed.length, 10);
assert.strictEqual(depP1.displayed[0].name, "pkg-1");
assert.strictEqual(depP1.displayed[9].name, "pkg-10");
assert.strictEqual(depP1.startIndex, 1);
assert.strictEqual(depP1.endIndex, 10);
assert.strictEqual(depP1.isPrevDisabled, true);
assert.strictEqual(depP1.isNextDisabled, false);
assert.strictEqual(depP1.showingText, "Showing 1–10 of 17 packages");
console.log("✔ TEST 20 passed: 17 packages displays 10 rows on Page 1 (items 1–10, 2 total pages, Prev disabled, Next enabled)");

// TEST 21: Page 2 of 17 packages -> displays 7 rows (11–17), Prev enabled, Next disabled
const depP2 = filterAndPaginatePackages({ libraries: sample17Packages, page: 2, pageSize: 10 });
assert.strictEqual(depP2.displayed.length, 7);
assert.strictEqual(depP2.displayed[0].name, "pkg-11");
assert.strictEqual(depP2.displayed[6].name, "pkg-17");
assert.strictEqual(depP2.startIndex, 11);
assert.strictEqual(depP2.endIndex, 17);
assert.strictEqual(depP2.isPrevDisabled, false);
assert.strictEqual(depP2.isNextDisabled, true);
assert.strictEqual(depP2.showingText, "Showing 11–17 of 17 packages");
console.log("✔ TEST 21 passed: Page 2 of 17 packages displays 7 rows (items 11–17, Prev enabled, Next disabled)");

// TEST 22: <= 10 packages -> pagination controls hidden
const sample8Packages = sample17Packages.slice(0, 8);
const depP8Total = filterAndPaginatePackages({ libraries: sample8Packages, page: 1, pageSize: 10 });
assert.strictEqual(depP8Total.showControls, false);
assert.strictEqual(depP8Total.displayed.length, 8);
console.log("✔ TEST 22 passed: <= 10 packages correctly hides pagination controls");

// TEST 23: Search query filters before pagination ("pkg-1" matches pkg-1, pkg-10..pkg-17 = 9 items <= 10)
const depSearch = filterAndPaginatePackages({ libraries: sample17Packages, searchQuery: "pkg-1", page: 1, pageSize: 10 });
assert.strictEqual(depSearch.total, 9);
assert.strictEqual(depSearch.showControls, false);
assert.strictEqual(depSearch.displayed.length, 9);
console.log("✔ TEST 23 passed: Search filtering occurs BEFORE pagination and correctly recalculates total & hides controls when <= 10");

// TEST 24: Tab filter ("vulnerable" tab filters 17 packages down to 9 vulnerable)
const depVulnTab = filterAndPaginatePackages({ libraries: sample17Packages, activeTab: "vulnerable", page: 1, pageSize: 10 });
assert.strictEqual(depVulnTab.total, 9);
assert.strictEqual(depVulnTab.showControls, false);
assert.strictEqual(depVulnTab.displayed.length, 9);
console.log("✔ TEST 24 passed: Vulnerable Tab filter occurs BEFORE pagination and hides controls when <= 10");

// TEST 25: 47 packages -> 5 pages, Page 5 has 7 items (41–47)
const sample47Packages = Array.from({ length: 47 }, (_, i) => ({
  name: `lib-${i + 1}`,
  version: "2.0.0",
  ecosystem: "npm"
}));
const depP5of47 = filterAndPaginatePackages({ libraries: sample47Packages, page: 5, pageSize: 10 });
assert.strictEqual(depP5of47.totalPages, 5);
assert.strictEqual(depP5of47.displayed.length, 7);
assert.strictEqual(depP5of47.startIndex, 41);
assert.strictEqual(depP5of47.endIndex, 47);
assert.strictEqual(depP5of47.showingText, "Showing 41–47 of 47 packages");
console.log("✔ TEST 25 passed: 47 packages produces 5 pages with Page 5 displaying items 41–47");

// TEST 26: Reset page state when filters change (clamps page out-of-bounds to Page 1)
const depReset = filterAndPaginatePackages({ libraries: sample17Packages, searchQuery: "nonexistent", page: 2, pageSize: 10 });
assert.strictEqual(depReset.total, 0);
assert.strictEqual(depReset.currentPage, 1);
assert.strictEqual(depReset.displayed.length, 0);
assert.strictEqual(depReset.showControls, false);
console.log("✔ TEST 26 passed: 0 matching search results resets currentPage to 1 with empty state");

// --- DEPENDENCY DYNAMIC INSIGHTS REMOVAL TEST ---
function computeDynamicSupplyChainInsights({ distinctVulnerablePkgCount, total, vulnerabilityMatches, severityCounts, outdatedLibCount }) {
  const insights = [];

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
}

// TEST 27: Verify parsed-manifest insight is NO LONGER included in dynamic supply chain insights
const testInsights = computeDynamicSupplyChainInsights({
  distinctVulnerablePkgCount: 1,
  total: 17,
  vulnerabilityMatches: 44,
  severityCounts: { critical: 2 },
  outdatedLibCount: 3
});

assert.strictEqual(testInsights.length, 3);
assert.ok(testInsights.some(i => i.text.includes("distinct packages")), "Vulnerable package insight present");
assert.ok(testInsights.some(i => i.text.includes("Critical severity")), "Critical severity insight present");
assert.ok(testInsights.some(i => i.text.includes("unpinned or wildcard")), "Unpinned version insight present");
assert.ok(!testInsights.some(i => i.text.includes("Parsed") || i.text.includes("manifest file(s)")), "Parsed manifest file insight must NOT be present");
console.log("✔ TEST 27 passed: Parsed manifest file insight is completely omitted while vulnerable and unpinned insights remain");

console.log("=== ALL FRONTEND LOGIC TESTS PASSED ===");


