"use client";

import React, { useState } from "react";
import { Copy, Check, Clock3, CheckCircle2, XCircle } from "lucide-react";
import type { PatchItem, ValidationResultItem } from "../agentic-scan/types";

/**
 * Minimal, dependency-free line diff (LCS-based). Good enough for the
 * short snippets patches actually cover -- avoids pulling in a new
 * library (react-diff-viewer / prismjs) purely for this, per the spec's
 * own fallback: "a simple before/after code block with line highlights
 * is acceptable". Classifies each line as unchanged / removed / added
 * rather than painting the whole snippet red/green, which would make an
 * unrelated one-line patch look like every line changed.
 */
function diffLines(a: string[], b: string[]): { left: { text: string; changed: boolean }[]; right: { text: string; changed: boolean }[] } {
  const n = a.length, m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const left: { text: string; changed: boolean }[] = [];
  const right: { text: string; changed: boolean }[] = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      left.push({ text: a[i], changed: false });
      right.push({ text: b[j], changed: false });
      i++; j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      left.push({ text: a[i], changed: true });
      i++;
    } else {
      right.push({ text: b[j], changed: true });
      j++;
    }
  }
  while (i < n) { left.push({ text: a[i], changed: true }); i++; }
  while (j < m) { right.push({ text: b[j], changed: true }); j++; }
  return { left, right };
}

function CodePane({ lines, startLine, variant }: { lines: { text: string; changed: boolean }[]; startLine: number; variant: "removed" | "added" }) {
  return (
    <div className="rounded-lg bg-[#0c0d11] border border-white/8 overflow-x-auto">
      <table className="w-full text-[10px] font-mono leading-relaxed">
        <tbody>
          {lines.length === 0 ? (
            <tr><td className="px-3 py-2 text-[#5c5c68]">—</td></tr>
          ) : (
            lines.map((l, idx) => (
              <tr
                key={idx}
                className={l.changed ? (variant === "removed" ? "bg-red-500/10" : "bg-emerald-500/10") : ""}
              >
                <td className="w-8 px-2 text-right text-[#5c5c68] select-none border-r border-white/5">{startLine + idx}</td>
                <td className={`px-2 whitespace-pre ${l.changed ? (variant === "removed" ? "text-red-300" : "text-emerald-300") : "text-[#8e8e9a]"}`}>
                  {l.changed && (variant === "removed" ? "− " : "+ ")}
                  {l.text || " "}
                </td>
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

function StatusChain({ patch, validation }: { patch: PatchItem; validation?: ValidationResultItem }) {
  const grounded = !!validation?.grounding_passed;
  const validated = patch.validation_status === "PASSED";
  const pending = patch.validation_status === "PENDING" && !validation;

  const Step = ({ label, ok, done }: { label: string; ok: boolean; done: boolean }) => (
    <span className={`inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-1.5 py-0.5 rounded ${
      !done ? "bg-white/8 text-[#8e8e9a]" : ok ? "bg-emerald-500/15 text-emerald-400" : "bg-red-500/15 text-red-400"
    }`}>
      {!done ? <Clock3 className="w-2.5 h-2.5" /> : ok ? <CheckCircle2 className="w-2.5 h-2.5" /> : <XCircle className="w-2.5 h-2.5" />}
      {label}
    </span>
  );

  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <Step label="GENERATED" ok done />
      <Step label="GROUNDED" ok={grounded} done={!pending} />
      <Step label="VALIDATED" ok={validated} done={!pending} />
    </div>
  );
}

export interface PatchDiffViewerProps {
  patch: PatchItem;
  validation?: ValidationResultItem;
}

/**
 * Side-by-side diff for one proposed patch (Section 5). Reads directly
 * from the real PatchItem the Patch Agent produced
 * (original_snippet / suggested_replacement) -- never regenerates or
 * guesses at a diff. affected_lines is a real "start-end" or single-line
 * string from the scanner; parsed only to number the panes, falling back
 * to line 1 if it isn't parseable rather than guessing.
 */
export function PatchDiffViewer({ patch, validation }: PatchDiffViewerProps) {
  const [copied, setCopied] = useState(false);

  const startLine = (() => {
    const m = String(patch.affected_lines || "").match(/(\d+)/);
    return m ? parseInt(m[1], 10) : 1;
  })();

  const originalLines = (patch.original_snippet || "").split("\n");
  const replacementLines = (patch.suggested_replacement || "").split("\n");
  const { left, right } = diffLines(originalLines, replacementLines);

  const ext = patch.affected_file?.split(".").pop() || "";

  const handleCopy = async () => {
    const text = patch.git_diff || patch.suggested_replacement || "";
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // Clipboard API can be unavailable (permissions, non-secure context)
      // -- fail silently rather than throwing in the UI.
    }
  };

  const handleDownload = () => {
    const text = patch.git_diff || `--- a/${patch.affected_file}\n+++ b/${patch.affected_file}\n${patch.suggested_replacement || ""}`;
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${patch.patch_id || "patch"}.patch`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-2 pt-1">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <StatusChain patch={patch} validation={validation} />
        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-2 py-1 rounded bg-white/6 text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/10 transition-colors"
          >
            {copied ? <Check className="w-2.5 h-2.5 text-emerald-400" /> : <Copy className="w-2.5 h-2.5" />}
            {copied ? "Copied" : "Copy Patch"}
          </button>
          <button
            onClick={handleDownload}
            className="inline-flex items-center gap-1 text-[8.5px] font-mono font-bold uppercase px-2 py-1 rounded bg-white/6 text-[#8e8e9a] hover:text-[#f4f4f8] hover:bg-white/10 transition-colors"
          >
            Download .patch
          </button>
        </div>
      </div>

      <div className="text-[9px] font-mono text-[#5c5c68]">
        {patch.affected_file}:{patch.affected_lines} <span className="text-[#5c5c68]/70">({ext || "text"})</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        <div>
          <div className="text-[8px] font-mono font-bold uppercase text-red-400/80 mb-1">Original</div>
          <CodePane lines={left} startLine={startLine} variant="removed" />
        </div>
        <div>
          <div className="text-[8px] font-mono font-bold uppercase text-emerald-400/80 mb-1">Patched</div>
          <CodePane lines={right} startLine={startLine} variant="added" />
        </div>
      </div>

      {patch.explanation && (
        <p className="text-[9.5px] font-mono text-[#8e8e9a] leading-relaxed pt-1 border-t border-white/5">
          {patch.explanation}
        </p>
      )}
    </div>
  );
}

export default PatchDiffViewer;
