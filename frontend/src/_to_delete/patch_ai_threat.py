import sys, io

path = "components/enrichment/AIThreatAnalysisSection.tsx"
with io.open(path, "r", encoding="utf-8") as f:
    src = f.read()
orig_len = len(src)

def replace_once(src, old, new, label):
    n = src.count(old)
    if n != 1:
        print(f"FAIL[{label}]: found {n} occurrences (expected 1)")
        sys.exit(1)
    return src.replace(old, new, 1)

# 1. imports: add ChevronDown-ish toggle icon + PatchDiffViewer
src = replace_once(src,
    '''import React, { useState } from "react";
import { Sparkles, ArrowRight, Play, Loader2, CheckCircle2, XCircle, Clock3 } from "lucide-react";
import type { AttackPathItem, PatchItem, ValidationResultItem, WorkflowStatus } from "../agentic-scan/types";''',
    '''import React, { useState } from "react";
import { Sparkles, ArrowRight, Play, Loader2, CheckCircle2, XCircle, Clock3, Eye, EyeOff } from "lucide-react";
import type { AttackPathItem, PatchItem, ValidationResultItem, WorkflowStatus } from "../agentic-scan/types";
import PatchDiffViewer from "./PatchDiffViewer";''',
    "imports")

# 2. Default state: collapsed by default (spec Section 3: "collapsed by
#    default so deterministic findings remain primary"), plus the new
#    severity toggle.
src = replace_once(src,
    '''  const [open, setOpen] = useState(true);

  const criticalHigh = (findings || []).filter((f) =>
    ["critical", "high"].includes(String(f.severity || "").toLowerCase())
  );''',
    '''  const [open, setOpen] = useState(false);
  // Section 3: "Show threat paths ... only for Critical and High severity
  // findings by default. Add a toggle: 'Show for Medium/Low.'"
  const [showAllSeverities, setShowAllSeverities] = useState(false);

  const criticalHigh = (findings || []).filter((f) =>
    ["critical", "high"].includes(String(f.severity || "").toLowerCase())
  );
  const relevantFindings = showAllSeverities ? (findings || []) : criticalHigh;''',
    "default state + severity toggle state")

# 3. Header: add the severity toggle button next to the collapse chevron.
src = replace_once(src,
    '''          <span className="text-[9px] font-mono text-[#8e8e9a]">(powered by LangGraph Threat Agent)</span>
        </div>
        <span className="text-[10px] font-mono text-[#5c5c68]">{open ? "▾" : "▸"}</span>
      </button>''',
    '''          <span className="text-[9px] font-mono text-[#8e8e9a]">(powered by LangGraph Threat Agent)</span>
        </div>
        <div className="flex items-center gap-3">
          {open && hasRunForThisScan && (
            <button
              onClick={(e) => { e.stopPropagation(); setShowAllSeverities((v) => !v); }}
              className="inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-white/6 text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/10 transition-colors"
            >
              {showAllSeverities ? <EyeOff className="w-2.5 h-2.5" /> : <Eye className="w-2.5 h-2.5" />}
              {showAllSeverities ? "Critical/High only" : "Show for Medium/Low"}
            </button>
          )}
          <span className="text-[10px] font-mono text-[#5c5c68]">{open ? "▾" : "▸"}</span>
        </div>
      </button>''',
    "severity toggle button")

# 4. Body: use relevantFindings instead of criticalHigh; update the empty-
#    state message accordingly.
src = replace_once(src,
    '''              {criticalHigh.length === 0 && (
                <div className="text-[10px] font-mono text-[#5c5c68] text-center py-4">
                  No Critical/High findings requiring AI threat analysis.
                </div>
              )}

              {criticalHigh.map((f) => {''',
    '''              {relevantFindings.length === 0 && (
                <div className="text-[10px] font-mono text-[#5c5c68] text-center py-4">
                  {showAllSeverities ? "No findings to show." : "No Critical/High findings requiring AI threat analysis."}
                </div>
              )}

              {relevantFindings.map((f) => {''',
    "use relevantFindings")

# 5. Evidence Traceability chain line + swap the stage-badge row for the
#    real PatchDiffViewer (Section 5) when a patch exists.
src = replace_once(src,
    '''                    {path ? (
                      <div className="flex items-center gap-1.5 text-[9.5px] font-mono text-[#f4f4f8] flex-wrap">
                        <span className="px-2 py-1 rounded bg-white/6">{path.entry_point}</span>
                        <ArrowRight className="w-3 h-3 text-[#5c5c68]" />
                        <span className="px-2 py-1 rounded bg-white/6 text-[#8e8e9a]">{path.attack_vector}</span>
                        <ArrowRight className="w-3 h-3 text-[#5c5c68]" />
                        <span className="px-2 py-1 rounded bg-violet-500/10 text-violet-300">{path.target_file}</span>
                        <span className="ml-2 text-[8.5px] text-[#8e8e9a]">
                          exploitability (agentic): <b className="text-[#f4f4f8]">{typeof path.exploitability === "number" ? path.exploitability.toFixed(2) : path.exploitability}</b>
                        </span>
                      </div>
                    ) : (
                      <div className="text-[9.5px] font-mono text-[#5c5c68]">No attack path modeled for this finding by the Threat Agent.</div>
                    )}

                    <div className="flex items-center gap-1.5 flex-wrap pt-1 border-t border-white/5">
                      {patch ? (
                        <>
                          <span className="text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-white/8 text-[#8e8e9a]">generated</span>
                          <StageBadge ok={!!validation?.grounding_passed} label={pending ? "grounded: pending" : validation?.grounding_passed ? "grounded" : "not grounded"} pending={pending} />
                          <StageBadge ok={validated} label={pending ? "validated: pending" : validated ? "validated" : "not validated"} pending={pending} />
                        </>
                      ) : (
                        <span className="text-[9.5px] font-mono text-[#5c5c68]">No remediation proposed for this finding.</span>
                      )}
                    </div>
                  </div>
                );
              })}''',
    '''                    {path ? (
                      <div className="flex items-center gap-1.5 text-[9.5px] font-mono text-[#f4f4f8] flex-wrap">
                        <span className="px-2 py-1 rounded bg-white/6">{path.entry_point}</span>
                        <ArrowRight className="w-3 h-3 text-[#5c5c68]" />
                        <span className="px-2 py-1 rounded bg-white/6 text-[#8e8e9a]">{path.attack_vector}</span>
                        <ArrowRight className="w-3 h-3 text-[#5c5c68]" />
                        <span className="px-2 py-1 rounded bg-violet-500/10 text-violet-300">{path.target_file}</span>
                        <span className="ml-2 text-[8.5px] text-[#8e8e9a]">
                          exploitability (agentic): <b className="text-[#f4f4f8]">{typeof path.exploitability === "number" ? path.exploitability.toFixed(2) : path.exploitability}</b>
                        </span>
                      </div>
                    ) : (
                      <div className="text-[9.5px] font-mono text-[#5c5c68]">No attack path modeled for this finding by the Threat Agent.</div>
                    )}

                    {/* Evidence Traceability (Section 3) -- every hop here is
                        a real id/agent name pulled from this finding's own
                        data; a hop that has no real value (no evidence id,
                        no attack path, no patch) is simply not rendered
                        rather than filled with a placeholder. */}
                    {(() => {
                      const evidenceId = (f.evidence_ids && f.evidence_ids[0]) || path?.evidence_id;
                      const hops = [
                        fid,
                        evidenceId,
                        path ? "Threat Agent" : null,
                        patch ? "Patch" : null,
                      ].filter(Boolean) as string[];
                      if (hops.length < 2) return null;
                      return (
                        <div className="flex items-center gap-1.5 text-[8.5px] font-mono text-[#5c5c68] flex-wrap pt-1">
                          <span className="text-[#5c5c68]/70 uppercase tracking-wider">trace:</span>
                          {hops.map((h, i) => (
                            <React.Fragment key={i}>
                              {i > 0 && <ArrowRight className="w-2.5 h-2.5" />}
                              <span className="text-[#8e8e9a]">{h}</span>
                            </React.Fragment>
                          ))}
                        </div>
                      );
                    })()}

                    <div className="pt-1 border-t border-white/5">
                      {patch ? (
                        <PatchDiffViewer patch={patch} validation={validation} />
                      ) : (
                        <span className="text-[9.5px] font-mono text-[#5c5c68]">No remediation proposed for this finding.</span>
                      )}
                    </div>
                  </div>
                );
              })}''',
    "evidence trace + patch diff viewer")

# 6. StageBadge is no longer used (replaced by PatchDiffViewer's own
#    StatusChain) -- drop it and its now-unused icon imports for cleanliness.
src = replace_once(src,
    '''function StageBadge({ ok, label, pending }: { ok: boolean; label: string; pending?: boolean }) {
  if (pending) {
    return (
      <span className="inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded bg-white/8 text-[#8e8e9a]">
        <Clock3 className="w-2.5 h-2.5" /> {label}
      </span>
    );
  }
  return (
    <span className={`inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${ok ? "bg-emerald-500/15 text-emerald-400" : "bg-white/8 text-[#8e8e9a]"}`}>
      {ok ? <CheckCircle2 className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />} {label}
    </span>
  );
}

''',
    '',
    "drop unused StageBadge")

src = replace_once(src,
    '''import { Sparkles, ArrowRight, Play, Loader2, CheckCircle2, XCircle, Clock3, Eye, EyeOff } from "lucide-react";''',
    '''import { Sparkles, ArrowRight, Play, Loader2, Eye, EyeOff } from "lucide-react";''',
    "prune unused icon imports")

# 7. `pending`/`validated` were only ever consumed by the now-removed
#    StageBadge calls -- PatchDiffViewer computes its own equivalents
#    internally from the same patch/validation objects.
src = replace_once(src,
    '''                const validation = patch ? validationByPatch.get(patch.patch_id) : undefined;
                const pending = !!patch && patch.validation_status === "PENDING" && !validation;
                const validated = !!patch && patch.validation_status === "PASSED";

                return (''',
    '''                const validation = patch ? validationByPatch.get(patch.patch_id) : undefined;

                return (''',
    "drop unused pending/validated")

with io.open(path, "w", encoding="utf-8") as f:
    f.write(src)

print(f"OK: wrote {path} ({orig_len} -> {len(src)} bytes)")
