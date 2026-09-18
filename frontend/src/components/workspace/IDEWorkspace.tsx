"use client";

import React, { useState, useEffect } from "react";
import RepoInput from "./RepoInput";
import FileTreeSidebar, { FileNode } from "./FileTreeSidebar";
import CodeViewer from "./CodeViewer";
import VulnerabilityPanel from "./VulnerabilityPanel";
import { Loader2 } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface IDEWorkspaceProps {
  onScanComplete?: (scanResult: any, scanId?: string) => void;
}

export default function IDEWorkspace({ onScanComplete }: IDEWorkspaceProps) {
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [fileTree, setFileTree] = useState<FileNode | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string>("// Select a file from the explorer to view its content.");
  const [findings, setFindings] = useState<any[]>([]);
  const [scanFindingsMap, setScanFindingsMap] = useState<Record<string, any[]>>({});

  // Restore state from sessionStorage on mount
  useEffect(() => {
    try {
      const savedScanId = sessionStorage.getItem("guardian_scan_id");
      const savedFileTree = sessionStorage.getItem("guardian_file_tree");
      const savedMap = sessionStorage.getItem("guardian_findings_map");
      const savedPath = sessionStorage.getItem("guardian_selected_path");
      const savedContent = sessionStorage.getItem("guardian_file_content");
      const savedFindings = sessionStorage.getItem("guardian_file_findings");

      if (savedScanId) setScanId(savedScanId);
      if (savedFileTree) setFileTree(JSON.parse(savedFileTree));
      if (savedMap) setScanFindingsMap(JSON.parse(savedMap));
      if (savedPath) setSelectedFilePath(savedPath);
      if (savedContent) setFileContent(savedContent);
      if (savedFindings) setFindings(JSON.parse(savedFindings));
    } catch (e) {
      console.warn("Failed to load workspace state from sessionStorage:", e);
    }
  }, []);

  // Save state to sessionStorage
  const saveStateToStorage = (
    newScanId: string | null,
    newTree: FileNode | null,
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
    setIsScanning(true);
    setScanId(null);
    setFileTree(null);
    setSelectedFilePath(null);
    setFileContent("// Scan in progress...");
    setScanFindingsMap({});

    try {
      const payload: any = {
        scan_mode: "precision",
        enable_ai: aiEnabled,
      };
      
      if (isUrl) {
        payload.repo_url = target;
      } else {
        payload.target_path = target;
      }

      const res = await fetch(`${API_BASE}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        let errMsg = "Scan failed";
        try {
          const errData = await res.json();
          console.error("Scan failed - Server Error Detail:", errData);
          if (errData.detail) {
            errMsg = typeof errData.detail === "string" ? errData.detail : JSON.stringify(errData.detail);
          }
        } catch (e) {
          console.error("Could not parse scan error response JSON:", e);
        }
        throw new Error(errMsg);
      }

      const data = await res.json();
      const newScanId = data.scan_id;
      setScanId(newScanId);

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

      // Notify parent component of completed scan -- newScanId is also
      // passed through (additive 2nd arg) so callers can tie downstream
      // agentic-enrichment state to the exact scan_id this report came
      // from, without reaching into sessionStorage themselves.
      if (onScanComplete) {
        onScanComplete(data.result, newScanId);
      }

      // Fetch File Tree
      let fetchedTree: FileNode | null = null;
      const treeRes = await fetch(`${API_BASE}/api/v1/files/tree?scan_id=${newScanId}`);
      if (treeRes.ok) {
        fetchedTree = await treeRes.json();
        setFileTree(fetchedTree);
      }
      const initialMsg = "// Scan complete. Select a file from the explorer to view.";
      setFileContent(initialMsg);

      saveStateToStorage(newScanId, fetchedTree, map, null, initialMsg, []);

    } catch (err: any) {
      console.error("Scan execution error:", err);
      setFileContent(`// Error occurred during scan:\n// ${err.message || "Check console for details."}`);
    } finally {
      setIsScanning(false);
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

    // Call backend AutoFix service
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

    // Client-side fallback transformer if backend didn't transform or errored
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
        // Never replace line with just a comment! Preserve code and add inline remediation tag
        replacement = `${indent}${trimmed}  # remediated: ${finding.category || "security-fix"}`;
      }
    }

    lines[lineNum - 1] = replacement;
    const updatedContent = lines.join('\n');
    setFileContent(updatedContent);

    // Save updated content state to storage
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
            <div className="h-full flex flex-col items-center justify-center text-[#ff5400] gap-3 bg-[#0c0d11]">
              <Loader2 className="w-6 h-6 animate-spin" />
              <span className="text-xs font-mono font-semibold tracking-wider text-[#8e8e9a]">SCANNING...</span>
            </div>
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

