"use client";

import React, { useRef, useEffect, useCallback } from "react";
import Editor, { useMonaco } from "@monaco-editor/react";
import { Loader2 } from "lucide-react";

interface VSCodeEditorProps {
  content: string;
  language?: string;
  findings?: any[];
  onChange?: (value: string) => void;
  readOnly?: boolean;
}

export default function VSCodeEditor({
  content,
  language = "plaintext",
  findings = [],
  onChange,
  readOnly = false,
}: VSCodeEditorProps) {
  const monaco = useMonaco();
  const editorRef = useRef<any>(null);
  const decorationsRef = useRef<string[]>([]);

  /* ── Apply decorations (threat lines in red, fix suggestions in green) ── */
  const applyDecorations = useCallback(() => {
    if (!monaco || !editorRef.current) return;
    const editor = editorRef.current;
    const model = editor.getModel();
    if (!model) return;

    const newDecorations: any[] = [];

    findings.forEach((f) => {
      const lineNum = f.line || f.line_number || 1;
      const hasFix  = !!(f.remediation_patch || f.recommendation);
      const sev     = f.severity?.toUpperCase();

      /* Threat line: highlight ONLY the specific line in subtle red background + red border marker */
      newDecorations.push({
        range: new monaco.Range(lineNum, 1, lineNum, 1),
        options: {
          isWholeLine: true,
          className: sev === "CRITICAL"
            ? "vuln-line-critical"
            : sev === "HIGH"
            ? "vuln-line-high"
            : "vuln-line-medium",
          glyphMarginClassName: "vuln-glyph-red",
          glyphMarginHoverMessage: { value: `**Security Threat (${f.severity})**: ${f.category}` },
          overviewRuler: {
            color: "#ef4444",
            position: 1,
          },
        },
      });

      /* Fix suggestion: display the replacement fix in clean GREEN inline ghost text */
      if (hasFix) {
        const fixText = (f.remediation_patch || f.recommendation || "")
          .split("\n")[0]
          .trim();

        if (fixText) {
          newDecorations.push({
            range: new monaco.Range(lineNum, 1, lineNum, 1),
            options: {
              after: {
                content: `  ➜ Fix: ${fixText.slice(0, 65)}`,
                inlineClassName: "fix-suggestion-green",
              },
            },
          });
        }
      }
    });

    /* Set VSCode inline markers (squiggles) for threats */
    const markers = findings.map((f) => ({
      startLineNumber: f.line || f.line_number || 1,
      startColumn: 1,
      endLineNumber:  f.line || f.line_number || 1,
      endColumn: 9999,
      message: `⚠ [THREAT ${f.severity}] ${f.category}${f.cwe ? ` (${f.cwe})` : ""}\n\n${f.reason || f.description || ""}\n\nRecommended Fix: ${f.recommendation || f.remediation_patch || "N/A"}`,
      severity: monaco.MarkerSeverity.Error,
    }));
    monaco.editor.setModelMarkers(model, "security-threats", markers);

    decorationsRef.current = editor.deltaDecorations(decorationsRef.current, newDecorations);
  }, [monaco, findings]);

  useEffect(() => {
    applyDecorations();
  }, [applyDecorations, content]);

  /* Inject CSS styles for threat (red) and fix (green) */
  useEffect(() => {
    if (!monaco) return;
    const styleId = "vscode-security-decorations";
    if (document.getElementById(styleId)) return;

    const style = document.createElement("style");
    style.id = styleId;
    style.textContent = `
      /* Threat lines in code: ONLY the line in red */
      .vuln-line-critical { background: rgba(239, 68, 68, 0.18) !important; border-left: 3px solid #ef4444 !important; }
      .vuln-line-high     { background: rgba(249, 115, 22, 0.15) !important; border-left: 3px solid #f97316 !important; }
      .vuln-line-medium   { background: rgba(245, 158, 11, 0.14) !important; border-left: 3px solid #f59e0b !important; }

      /* Gutter dot for threat */
      .vuln-glyph-red::before {
        content: '●';
        color: #ef4444;
        font-size: 10px;
        line-height: 21px;
        display: block;
        text-align: center;
      }

      /* Fix suggestion in clean GREEN ghost text */
      .fix-suggestion-green {
        color: #22c55e !important;
        font-style: italic;
        font-weight: 600;
        opacity: 0.85;
        font-size: 12px;
        margin-left: 12px;
      }
    `;
    document.head.appendChild(style);
  }, [monaco]);

  return (
    <div className="h-full w-full flex flex-col" style={{ background: "#1e1e1e" }}>
      <Editor
        height="100%"
        language={language}
        theme="vs-dark"
        value={content}
        onChange={(v) => onChange?.(v ?? "")}
        options={{
          readOnly,
          minimap:              { enabled: true, side: "right" },
          scrollBeyondLastLine: false,
          fontSize:             13,
          fontFamily:           "'JetBrains Mono', 'Cascadia Code', 'Fira Code', monospace",
          fontLigatures:        true,
          lineHeight:           21,
          wordWrap:             "off",
          renderWhitespace:     "selection",
          glyphMargin:          true,
          folding:              true,
          lineNumbers:          "on",
          lineDecorationsWidth: 8,
          renderLineHighlight:  "all",
          scrollbar: {
            vertical:             "visible",
            horizontal:           "visible",
            verticalScrollbarSize: 8,
            horizontalScrollbarSize: 8,
          },
          suggest:            { showIcons: true },
          cursorBlinking:     "smooth",
          cursorSmoothCaretAnimation: "on",
          bracketPairColorization: { enabled: true },
          smoothScrolling:    true,
          overviewRulerBorder: false,
          overviewRulerLanes:  3,
          padding:            { top: 8, bottom: 8 },
        }}
        onMount={(editor) => {
          editorRef.current = editor;
          setTimeout(applyDecorations, 150);
        }}
        loading={
          <div className="flex items-center justify-center h-full gap-3 text-slate-400" style={{ background: "#1e1e1e" }}>
            <Loader2 className="w-5 h-5 animate-spin text-[#ff5400]" />
            <span className="text-[11px] font-mono">Loading editor...</span>
          </div>
        }
      />
    </div>
  );
}
