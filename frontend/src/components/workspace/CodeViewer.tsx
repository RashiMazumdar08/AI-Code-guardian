"use client";

import React, { useRef, useEffect } from "react";
import Editor, { useMonaco } from "@monaco-editor/react";
import { Loader2 } from "lucide-react";

interface CodeViewerProps {
  content: string;
  language?: string;
  findings?: any[];
  onChange?: (value: string | undefined) => void;
  readOnly?: boolean;
}

export default function CodeViewer({ content, language = "javascript", findings = [], onChange, readOnly = false }: CodeViewerProps) {
  const monaco = useMonaco();
  const editorRef = useRef<any>(null);

  useEffect(() => {
    if (monaco && editorRef.current) {
      const model = editorRef.current.getModel();
      if (!model) return;

      const markers = findings.map(f => {
        let severity = monaco.MarkerSeverity.Info;
        switch (f.severity?.toUpperCase()) {
          case "CRITICAL": severity = monaco.MarkerSeverity.Error; break;
          case "HIGH": severity = monaco.MarkerSeverity.Error; break;
          case "MEDIUM": severity = monaco.MarkerSeverity.Warning; break;
          case "LOW": severity = monaco.MarkerSeverity.Info; break;
        }

        return {
          startLineNumber: f.line || f.line_number || 1,
          startColumn: 1,
          endLineNumber: f.line || f.line_number || 1,
          endColumn: 1000,
          message: `${f.category || f.title}\n\n${f.reason || f.description}\nSeverity: ${f.severity}`,
          severity: severity,
        };
      });

      monaco.editor.setModelMarkers(model, "vulnerabilities", markers);
    }
  }, [monaco, findings, content]);

  return (
    <div className="h-full w-full bg-[#1e1e1e] flex flex-col">
      <div className="flex-1 overflow-hidden relative">
        <Editor
          height="100%"
          language={language}
          theme="vs-dark"
          value={content}
          onChange={onChange}
          options={{
            readOnly: readOnly,
            minimap: { enabled: true },
            scrollBeyondLastLine: false,
            fontSize: 14,
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            wordWrap: "on",
            renderWhitespace: "selection",
          }}
          onMount={(editor) => {
            editorRef.current = editor;
          }}
          loading={
            <div className="flex items-center justify-center h-full text-slate-400">
              <Loader2 className="w-6 h-6 animate-spin mr-2" />
              Loading editor...
            </div>
          }
        />
      </div>
    </div>
  );
}
