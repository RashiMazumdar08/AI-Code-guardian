"use client";

import React, { createContext, useContext, useState, useEffect } from "react";
import type { FileNode } from "../components/workspace/FileTreeSidebar";

export type ScanPhase =
  | "IDLE"
  | "FETCHING"
  | "WALKING"
  | "PARSING"
  | "SCANNING"
  | "COMPLETE"
  | "AGENTIC_RUNNING"
  | "AGENTIC_COMPLETE";

interface ScanStateContextType {
  scanPhase: ScanPhase;
  setScanPhase: (phase: ScanPhase) => void;
  scanId: string | null;
  setScanId: (id: string | null) => void;
  fileTree: FileNode | null;
  setFileTree: (tree: FileNode | null) => void;
  selectedFilePath: string | null;
  setSelectedFilePath: (path: string | null) => void;
  fileContent: string;
  setFileContent: (content: string) => void;
  findings: any[];
  setFindings: (findings: any[]) => void;
  scanFindingsMap: Record<string, any[]>;
  setScanFindingsMap: (map: Record<string, any[]>) => void;
  // State machine helper methods
  startScan: () => void;
  updateScanPhase: (phase: ScanPhase) => void;
  completeScan: (scanId: string, tree: FileNode | null, map: Record<string, any[]>) => void;
  startAgentic: () => void;
  completeAgentic: () => void;
  resetScan: () => void;
}

const ScanStateContext = createContext<ScanStateContextType | undefined>(undefined);

export const ScanStateProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [scanPhase, setScanPhase] = useState<ScanPhase>("IDLE");
  const [scanId, setScanId] = useState<string | null>(null);
  const [fileTree, setFileTree] = useState<FileNode | null>(null);
  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [fileContent, setFileContent] = useState<string>("Select a file to view its security findings.");
  const [findings, setFindings] = useState<any[]>([]);
  const [scanFindingsMap, setScanFindingsMap] = useState<Record<string, any[]>>({});

  // On mount, restore persisted scan state if available
  useEffect(() => {
    try {
      const savedScanId = sessionStorage.getItem("guardian_scan_id");
      const savedFileTree = sessionStorage.getItem("guardian_file_tree");
      const savedMap = sessionStorage.getItem("guardian_findings_map");

      if (savedScanId && savedFileTree) {
        setScanId(savedScanId);
        setFileTree(JSON.parse(savedFileTree));
        if (savedMap) setScanFindingsMap(JSON.parse(savedMap));
        setScanPhase("COMPLETE");
      }
    } catch (e) {
      console.warn("ScanStateContext: Failed to restore state from sessionStorage:", e);
    }
  }, []);

  const startScan = () => {
    setScanPhase("FETCHING");
    setScanId(null);
    setFileTree(null);
    setSelectedFilePath(null);
    setFileContent("// Scan in progress...");
    setScanFindingsMap({});
    setFindings([]);
  };

  const updateScanPhase = (phase: ScanPhase) => {
    setScanPhase(phase);
  };

  const completeScan = (newScanId: string, tree: FileNode | null, map: Record<string, any[]>) => {
    setScanId(newScanId);
    setFileTree(tree);
    setScanFindingsMap(map);
    setScanPhase("COMPLETE");
    if (!selectedFilePath) {
      setFileContent("Select a file to view its security findings.");
    }
  };

  const startAgentic = () => {
    setScanPhase("AGENTIC_RUNNING");
  };

  const completeAgentic = () => {
    setScanPhase("AGENTIC_COMPLETE");
  };

  const resetScan = () => {
    setScanPhase("IDLE");
    setScanId(null);
    setFileTree(null);
    setSelectedFilePath(null);
    setFileContent("Select a file to view its security findings.");
    setFindings([]);
    setScanFindingsMap({});
  };

  return (
    <ScanStateContext.Provider
      value={{
        scanPhase,
        setScanPhase,
        scanId,
        setScanId,
        fileTree,
        setFileTree,
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
        startAgentic,
        completeAgentic,
        resetScan,
      }}
    >
      {children}
    </ScanStateContext.Provider>
  );
};

export const useScanState = () => {
  const context = useContext(ScanStateContext);
  if (!context) {
    // Provide a safe fallback if accessed outside ScanStateProvider
    return {
      scanPhase: "IDLE" as ScanPhase,
      setScanPhase: () => {},
      scanId: null,
      setScanId: () => {},
      fileTree: null,
      setFileTree: () => {},
      selectedFilePath: null,
      setSelectedFilePath: () => {},
      fileContent: "Select a file to view its security findings.",
      setFileContent: () => {},
      findings: [],
      setFindings: () => {},
      scanFindingsMap: {},
      setScanFindingsMap: () => {},
      startScan: () => {},
      updateScanPhase: () => {},
      completeScan: () => {},
      startAgentic: () => {},
      completeAgentic: () => {},
      resetScan: () => {},
    };
  }
  return context;
};
