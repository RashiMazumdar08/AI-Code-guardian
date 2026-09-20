"use client";

import React from "react";
import RepoInput from "./RepoInput";
import FileTreeSidebar from "./FileTreeSidebar";
import CodeViewer from "./CodeViewer";
import VulnerabilityPanel from "./VulnerabilityPanel";
import ScanProgressPanel from "./ScanProgressPanel";
import { Loader2 } from "lucide-react";
import { useScanState } from "../../context/ScanStateContext";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface IDEWorkspaceProps {
  onScanComplete?: (scanResult: any, scanId?: string) => void;
}

export default function IDEWorkspace({ onScanComplete }: IDEWorkspaceProps) {
  const {
    scanPhase,
    scanId,
    setScanId,
    fileTree,
    selectedFilePath,
    setSelectedFilePath,
    fileContent,
    setFileContent,
    findings,
    setFindings,
    scanFindingsMap,
    setScanFindingsMap,
    startScan,
    updateScanPhase,
    completeScan,
  } = useScanState();

  const isScanning = ["FETCHING", "WALKING", "PARSING", "SCANNING"].includes(scanPhase);

  const saveStateToStorage = (
    newScanId: string | null,
    newTree: any | null,
    newMap: Record<string, any[]>,
    newPath: string | null = selectedFilePath,
    newContent: string = fileContent,
    newFindings: any[] = findings
  ) => {
    try {
      if (newScanId) sessionStorage.setItem("guardian_scan_id", newScanId);
      if (newTree) sessionStorage.setItem("guardian_file_tree", JSON.stringify(newTree));
      if (newMap) sessionStorage.setItem("guardian_findings_map", JSON.stringify(newMap));
      if (newPath) sessionStorage.setItem("guardian_selected_path", newPath);
      if (newContent) sessionStorage.setItem("guardian_file_content", newContent);
      if (newFindings) sessionStorage.setItem("guardian_file_findings", JSON.stringify(newFindings));
    } catch (e) {
      console.warn("Failed to save workspace state to sessionStorage:", e);
    }
  };

  const handleScan = async (target: string, isUrl: boolean, aiEnabled: boolean) => {
    startScan();
    const generatedScanId = `scan_${Date.now()}`;
    setScanId(generatedScanId);

    try {
      const payload: any = {
        scan_id: generatedScanId,
        scan_mode: "precision",
        enable_ai: aiEnabled,
      };

      if (isUrl) {
        payload.repo_url = target;
      } else {
        payload.target_path = target;
      }

      updateScanPhase("FETCHING");
      const res = await fetch(`${API_BASE}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        let errMsg = "Scan failed";
        try {
          const errData = await res.json();
          if (errData.detail) {
            errMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
          }
        } catch (e) {}
        throw new Error(errMsg);
      }

      updateScanPhase("PARSING");
      const data = await res.json();
      const newScanId = data.scan_id;

      // Extract findings and map by file path
      const allFindings = data.result?.scan?.findings || data.result?.findings || [];
      const map: Record<string, any[]> = {};
      allFindings.forEach((f: any) => {
        const p = f.file?.replace(/\\/g, "/");
        if (!p) return;
        if (!map[p]) map[p] = [];
        map[p].push(f);
      });
      setScanFindingsMap(map);

      if (onScanComplete) {
        onScanComplete(data.result, newScanId);
      }

      // Fetch File Tree
      let fetchedTree: any | null = null;
      const treeRes = await fetch(`${API_BASE}/api/v1/files/tree?scan_id=${newScanId}`);
      if (treeRes.ok) {
        fetchedTree = await treeRes.json();
      }

      const initialMsg = "Select a file to view its security findings.";
      completeScan(newScanId, fetchedTree, map);
      setFileContent(initialMsg);

      saveStateToStorage(newScanId, fetchedTree, map, null, initialMsg, []);

    } catch (err: any) {
      console.error("Scan execution error:", err);
      completeScan("", null, {});
      setFileContent(`// Error occurred during scan:\n// ${err.message || "Check console for details."}`);
    }
  };

  const handleSelectFile = async (path: string) => {
    setSelectedFilePath(path);
    const fileFindings = scanFindingsMap[path] || [];
    setFindings(fileFindings);
    setFileContent("// Loading file...");

    if (scanId) {
      try {
        const res = await fetch(`${API_BASE}/api/v1/files/content?scan_id=${scanId}&path=${encodeURIComponent(path)}`);
        if (res.ok) {
          const data = await res.json();
          setFileContent(data.content);
          saveStateToStorage(scanId, fileTree, scanFindingsMap, path, data.content, fileFindings);
        } else {
          setFileContent("// Failed to load file content.");
        }
      } catch (err) {
        setFileContent("// Error loading file content.");
      }
    }
  };

  const handleApplyFix = async (finding: any) => {
    const lines = fileContent.split('\n');
    const lineNum = finding.line_number || finding.line || 1;
    if (!lineNum || lineNum > lines.length) return;

    const originalLine = lines[lineNum - 1];
    const indentMatch = originalLine.match(/^(\s*)/);
    const indent = indentMatch ? indentMatch[1] : "";
    const trimmed = originalLine.trim();

    let replacement = originalLine;

    try {
      const res = await fetch(`${API_BASE}/api/v1/findings/autofix`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code_snippet: trimmed || finding.snippet || "",
          category: finding.category || finding.title || "",
          cwe: finding.cwe || finding.cwe_id || "",
          recommendation: finding.recommendation || finding.remediation || "",
          file_path: selectedFilePath || "",
          line: lineNum,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        if (data.fixed_code && data.fixed_code !== trimmed) {
          replacement = `${indent}${data.fixed_code}`;
        }
      }
    } catch (e) {
      console.warn("Backend autofix call failed, using client-side rule transformer:", e);
    }

    if (replacement === originalLine) {
      const cat = (finding.category || finding.title || "").toLowerCase();
      const cwe = (finding.cwe || finding.cwe_id || "").toUpperCase();

      if (cat.includes("sql") || cwe === "CWE-89") {
        if (trimmed.includes("+")) {
          replacement = `${indent}cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))`;
        } else {
          replacement = originalLine.replace(/execute\((.*?)\)/, 'execute("SELECT * FROM users WHERE id = %s", (user_input,))');
        }
      } else if (cat.includes("crypto") || cat.includes("md5") || cat.includes("sha1") || cwe === "CWE-327") {
        let fixed = trimmed.replace("hashlib.md5", "hashlib.sha256").replace("hashlib.sha1", "hashlib.sha256").replace("MD5", "SHA-256");
        replacement = `${indent}${fixed}`;
      } else if (cat.includes("tls") || cat.includes("ssl") || cat.includes("verify") || cwe === "CWE-295") {
        let fixed = trimmed.replace(/verify\s*=\s*False/i, "verify=True").replace(/_create_unverified_context/i, "create_default_context");
        replacement = `${indent}${fixed}`;
      } else if (cat.includes("secret") || cat.includes("password") || cwe === "CWE-798") {
        const varMatch = trimmed.match(/^([a-zA-Z0-9_]+)\s*=\s*["'].*?["']/);
        if (varMatch) {
          replacement = `${indent}${varMatch[1]} = os.getenv("${varMatch[1].toUpperCase()}", "")`;
        } else {
          replacement = `${indent}SECRET_KEY = os.getenv("SECRET_KEY", "")`;
        }
      } else if (finding.remediation_patch) {
        replacement = `${indent}${finding.remediation_patch.trim()}`;
      } else {
        replacement = `${indent}${trimmed}  # remediated: ${finding.category || "security-fix"}`;
      }
    }

    lines[lineNum - 1] = replacement;
    const updatedContent = lines.join('\n');
    setFileContent(updatedContent);

    if (scanId && selectedFilePath) {
      saveStateToStorage(scanId, fileTree, scanFindingsMap, selectedFilePath, updatedContent, findings);
    }
  };

  const getLanguageFromPath = (path: string | null) => {
    if (!path) return "javascript";
    const ext = path.split(".").pop()?.toLowerCase();
    switch (ext) {
      case "py": return "python";
      case "ts":
      case "tsx": return "typescript";
      case "js":
      case "jsx": return "javascript";
      case "java": return "java";
      case "json": return "json";
      case "md": return "markdown";
      case "html": return "html";
      case "css": return "css";
      default: return "plaintext";
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-160px)] gap-4">
      <div className="shrink-0">
        <RepoInput onScan={handleScan} isScanning={isScanning} />
      </div>
      <div className="flex-1 flex overflow-hidden rounded-xl bg-[#0c0d11] border border-white/8">
        {/* File Tree Sidebar */}
        <div className="w-60 shrink-0 overflow-hidden">
          {isScanning ? (
            <ScanProgressPanel
              scanId={scanId}
              apiBase={API_BASE}
              isScanning={isScanning}
            />
          ) : (
            <FileTreeSidebar
              tree={fileTree}
              onSelectFile={handleSelectFile}
              selectedPath={selectedFilePath}
            />
          )}
        </div>

        {/* Code Viewer (Center) */}
        <div className="flex-1 overflow-hidden border-l border-white/8 flex flex-col">
          <div className="px-4 py-2.5 border-b border-white/8 bg-[#12131a] flex items-center gap-2 shrink-0">
            <span className="w-2 h-2 rounded-full bg-[#ff5400]/50" />
            <span className="text-xs font-mono text-[#8e8e9a] truncate">
              {selectedFilePath || "NO FILE SELECTED"}
            </span>
          </div>
          <div className="flex-1 overflow-hidden">
            <CodeViewer
              content={fileContent}
              language={getLanguageFromPath(selectedFilePath)}
              findings={findings}
              onChange={(val) => setFileContent(val || "")}
              readOnly={false}
            />
          </div>
        </div>

        {/* Vulnerability Panel (Right) */}
        {selectedFilePath && (
          <VulnerabilityPanel
            findings={findings}
            fileName={selectedFilePath.split("/").pop() || selectedFilePath}
            onApplyFix={handleApplyFix}
          />
        )}
      </div>
    </div>
  );
}
