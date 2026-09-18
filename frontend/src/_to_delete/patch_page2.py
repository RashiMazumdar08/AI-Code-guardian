import sys, io

path = "app/page.tsx"
with io.open(path, "r", encoding="utf-8") as f:
    src = f.read()
orig_len = len(src)

def replace_once(src, old, new, label):
    n = src.count(old)
    if n != 1:
        print(f"FAIL[{label}]: found {n} occurrences (expected 1)")
        sys.exit(1)
    return src.replace(old, new, 1)

def replace_between(src, start_marker, end_marker, new_middle, label, keep_end=True):
    i = src.find(start_marker)
    j = src.find(end_marker)
    if i == -1 or j == -1 or j <= i:
        print(f"FAIL[{label}]: markers not found in order (i={i}, j={j})")
        sys.exit(1)
    tail = end_marker if keep_end else ""
    return src[:i] + new_middle + tail + src[j + len(end_marker):]

# ---------------------------------------------------------------------
# 1. Drop the cyber_dashboard full-screen early-return shortcut -- it now
#    renders inside the normal sidebar shell like every other tab.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''  /* ── Dashboard full-screen shortcut ────────────── */
  if (activeTab === "cyber_dashboard") {
    return <CyberDashboard onNavigatePlatform={() => navigateTo("workspace")} />;
  }


  /* ── Sidebar ─────────────────────────────────────── */''',
    '''  /* ── Sidebar ─────────────────────────────────────── */''',
    "drop cyber_dashboard early return")

# ---------------------------------------------------------------------
# 2. Notification-badge counts, placed right after viewFindingInSecurity
#    (needs `findings`, defined just above it, in scope).
# ---------------------------------------------------------------------
src = replace_once(src,
    '''  const viewFindingInSecurity = useCallback((findingId: string) => {
    const f = findings.find((x: any) => (x.finding_id || x.id) === findingId);
    if (f) {
      setSelectedFinding(f);
      setIsFindingDrawerOpen(true);
    }
    navigateTo("security_compliance", { finding: findingId });
  }, [findings, navigateTo]);''',
    '''  const viewFindingInSecurity = useCallback((findingId: string) => {
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
  const aiBusinessViolationCount = (agentic.result?.business_analysis.violations || []).length;''',
    "notification badge counts")

# ---------------------------------------------------------------------
# 3. Nav button: add notification badges between the label and the
#    active-state chevron.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-[#ff5400]" : "text-[#8e8e9a] group-hover:text-[#f4f4f8]"} transition-colors duration-200`} />
                  <span className="truncate tracking-wide">{tab.label}</span>
                  {isActive && <ChevronRight className="w-3 h-3 ml-auto shrink-0 text-[#ff5400]/60 animate-in fade-in slide-in-from-left-1 duration-200" />}''',
    '''                  <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? "text-[#ff5400]" : "text-[#8e8e9a] group-hover:text-[#f4f4f8]"} transition-colors duration-200`} />
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
                  {isActive && <ChevronRight className="w-3 h-3 ml-auto shrink-0 text-[#ff5400]/60 animate-in fade-in slide-in-from-left-1 duration-200" />}''',
    "nav notification badges")

# ---------------------------------------------------------------------
# 4. TriageFunnel: hide on Dashboard too (it has its own summary cards),
#    not just the now-removed "agentic_scan" tab.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''            {activeTab !== "agentic_scan" && <TriageFunnel metrics={metrics} />}''',
    '''            {activeTab !== "cyber_dashboard" && <TriageFunnel metrics={metrics} />}''',
    "TriageFunnel condition")

# ---------------------------------------------------------------------
# 5. Replace the IDE Workspace + (old standalone) Agentic Scan tab bodies
#    with: a Dashboard tab body, and an IDE Workspace body that adds the
#    "Run Agentic Analysis" trigger button.
# ---------------------------------------------------------------------
new_workspace_and_dashboard = '''              {/* Dashboard */}
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

              '''

src = replace_between(
    src,
    "              {/* IDE Workspace */}",
    "              {/* Mind Map */}",
    new_workspace_and_dashboard,
    "workspace+dashboard block",
)

# ---------------------------------------------------------------------
# 6. Remove the old standalone Overview tab body (absorbed into Dashboard).
# ---------------------------------------------------------------------
src = replace_between(
    src,
    "              {/* Overview */}",
    "              {/* Security & Compliance */}",
    "",
    "remove Overview block",
)

# ---------------------------------------------------------------------
# 7. Remove the old PR Review tab body (parked as future work).
# ---------------------------------------------------------------------
src = replace_between(
    src,
    "              {/* PR Review */}",
    "              {/* Business Intent Tab */}",
    "",
    "remove PR Review block",
)

# ---------------------------------------------------------------------
# 8. Render the Agentic Execution drawer near the other drawers.
# ---------------------------------------------------------------------
src = replace_once(src,
    '''      {/* Drawers */}
      <FindingDrawer finding={selectedFinding} isOpen={isFindingDrawerOpen} onClose={() => setIsFindingDrawerOpen(false)} onDiscussInChat={handleDiscussInChat} />
      <ChatDrawer    isOpen={isChatDrawerOpen}  onClose={() => setIsChatDrawerOpen(false)}  initialContext={chatContext} />
    </>''',
    '''      {/* Drawers */}
      <FindingDrawer finding={selectedFinding} isOpen={isFindingDrawerOpen} onClose={() => setIsFindingDrawerOpen(false)} onDiscussInChat={handleDiscussInChat} />
      <ChatDrawer    isOpen={isChatDrawerOpen}  onClose={() => setIsChatDrawerOpen(false)}  initialContext={chatContext} />

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
    </>''',
    "render AgenticExecutionDrawer")

with io.open(path, "w", encoding="utf-8") as f:
    f.write(src)

print(f"OK: wrote {path} ({orig_len} -> {len(src)} bytes)")
