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

src = replace_once(src,
    '''import AIThreatAnalysisSection from "../components/enrichment/AIThreatAnalysisSection";''',
    '''import AIThreatAnalysisSection from "../components/enrichment/AIThreatAnalysisSection";
import AIRiskCorrelationSection from "../components/enrichment/AIRiskCorrelationSection";''',
    "import AIRiskCorrelationSection")

src = replace_once(src,
    '''                    onRunAgentic={runAgenticForCurrentScan}
                    onViewTrace={viewFindingTrace}
                  />
                </div>
              )}

              {/* Business Intent Tab */}''',
    '''                    onRunAgentic={runAgenticForCurrentScan}
                    onViewTrace={viewFindingTrace}
                  />

                  <AIRiskCorrelationSection
                    chains={agentic.result?.risk_fusion.correlated_chains || []}
                    riskScores={agentic.result?.risk_fusion.risk_scores}
                    workflowStatus={agentic.workflowStatus}
                    hasRunForThisScan={agenticMatchesCurrentScan}
                    onViewFinding={viewFindingInSecurity}
                  />
                </div>
              )}

              {/* Business Intent Tab */}''',
    "render AIRiskCorrelationSection")

with io.open(path, "w", encoding="utf-8") as f:
    f.write(src)

print(f"OK: wrote {path} ({orig_len} -> {len(src)} bytes)")
