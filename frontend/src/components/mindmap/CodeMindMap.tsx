"use client";

import React, { useState, useEffect, useCallback, useMemo } from "react";
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  BackgroundVariant,
  Panel,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";

import { nodeTypes } from "./nodes";
import { getLayoutedElements } from "./layout";
import { MindMapData, MindMapNodeType, MindMapNodeData } from "./types";
import { defaultMindMapData } from "./defaultData";
import MindMapDetailPanel from "./MindMapDetailPanel";
import {
  Search,
  Filter,
  RefreshCw,
  Layers,
  Folder,
  FileCode,
  Code2,
  ShieldAlert,
  Loader2,
  Maximize2,
} from "lucide-react";

interface CodeMindMapProps {
  data?: MindMapData;
  isLoading?: boolean;
}

export const CodeMindMap: React.FC<CodeMindMapProps> = ({ data = { nodes: [], edges: [] }, isLoading = false }) => {
  const [selectedNode, setSelectedNode] = useState<Node<MindMapNodeData> | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<string>("all");
  const [collapsedNodes, setCollapsedNodes] = useState<Record<string, boolean>>({});
  const [layoutDirection, setLayoutDirection] = useState<"TB" | "LR">("TB");

  // Toggle collapse handler for folder nodes
  const handleToggleCollapse = useCallback((nodeId: string) => {
    setCollapsedNodes((prev) => ({
      ...prev,
      [nodeId]: !prev[nodeId],
    }));
  }, []);

  // Process raw input nodes and filter collapsed branches
  const rawNodes: Node<MindMapNodeData>[] = useMemo(() => {
    return (data.nodes || []).map((n) => ({
      id: n.id,
      type: n.type,
      data: {
        ...n.data,
        isCollapsed: !!collapsedNodes[n.id],
        onToggleCollapse: handleToggleCollapse,
      },
      position: n.position || { x: 0, y: 0 },
    }));
  }, [data.nodes, collapsedNodes, handleToggleCollapse]);

  // Compute node severity map for edges and stats
  const nodeSeverityMap = useMemo(() => {
    const map: Record<string, "critical" | "high" | "medium" | "low" | null> = {};
    (data.nodes || []).forEach((n) => {
      let sev: "critical" | "high" | "medium" | "low" | null = null;
      if (n.type === "finding" || n.data.severity) {
        sev = (n.data.severity || "high").toLowerCase() as any;
      } else if (Array.isArray(n.data.findings) && n.data.findings.length > 0) {
        let highest: "critical" | "high" | "medium" | "low" = "low";
        for (const f of n.data.findings) {
          const s = (f.severity || "").toLowerCase();
          if (s === "critical") { highest = "critical"; break; }
          if (s === "high") highest = "high";
          else if (s === "medium" && highest !== "high") highest = "medium";
        }
        sev = highest;
      } else if (typeof n.data.riskScore === "number" && n.data.riskScore > 0) {
        if (n.data.riskScore >= 80) sev = "critical";
        else if (n.data.riskScore >= 50) sev = "high";
        else if (n.data.riskScore >= 20) sev = "medium";
        else sev = "low";
      }
      map[n.id] = sev;
    });
    return map;
  }, [data.nodes]);

  // Dynamic summary counts from actual data
  const summaryStats = useMemo(() => {
    let critical = 0;
    let high = 0;
    let medium = 0;
    let low = 0;
    let totalFindings = 0;

    (data.nodes || []).forEach((n) => {
      if (n.type === "finding") {
        totalFindings++;
        const s = (n.data.severity || "high").toLowerCase();
        if (s === "critical") critical++;
        else if (s === "high") high++;
        else if (s === "medium") medium++;
        else low++;
      } else if (Array.isArray(n.data.findings)) {
        totalFindings += n.data.findings.length;
        n.data.findings.forEach((f: any) => {
          const s = (f.severity || "").toLowerCase();
          if (s === "critical") critical++;
          else if (s === "high") high++;
          else if (s === "medium") medium++;
          else low++;
        });
      }
    });

    return { totalFindings, critical, high, medium, low };
  }, [data.nodes]);

  const rawEdges: Edge[] = useMemo(() => {
    return (data.edges || []).map((e) => {
      const targetSev = nodeSeverityMap[e.target] || nodeSeverityMap[e.source];
      const isAffected = targetSev !== null;

      let stroke = "#94A3B8";
      let strokeWidth = 1.5;

      if (isAffected) {
        strokeWidth = 2;
        switch (targetSev) {
          case "critical": stroke = "#C62828"; break;
          case "high": stroke = "#E76500"; break;
          case "medium": stroke = "#E5A11A"; break;
          case "low":
          default: stroke = "#2563EB"; break;
        }
      }

      return {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        animated: isAffected,
        style: {
          stroke,
          strokeWidth,
        },
      };
    });
  }, [data.edges, nodeSeverityMap]);

  // Compute filtered nodes & edges
  const { visibleNodes, visibleEdges } = useMemo(() => {
    let filteredNodes = rawNodes;

    // Apply Search Filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filteredNodes = filteredNodes.filter(
        (n) =>
          n.data.label.toLowerCase().includes(q) ||
          (n.data.path && n.data.path.toLowerCase().includes(q))
      );
    }

    // Apply Type Filter
    if (typeFilter !== "all") {
      if (typeFilter === "function") {
        const funcNodes = rawNodes.filter((n) => n.type === "function");
        const funcIds = new Set(funcNodes.map((n) => n.id));
        const connectedIds = new Set<string>(funcIds);
        rawEdges.forEach((e) => {
          if (funcIds.has(e.source)) connectedIds.add(e.target);
          if (funcIds.has(e.target)) connectedIds.add(e.source);
        });
        filteredNodes = filteredNodes.filter((n) => connectedIds.has(n.id));
      } else if (typeFilter === "finding") {
        const findingNodes = rawNodes.filter((n) => n.type === "finding");
        const findingIds = new Set(findingNodes.map((n) => n.id));
        const connectedIds = new Set<string>(findingIds);
        rawEdges.forEach((e) => {
          if (findingIds.has(e.source)) connectedIds.add(e.target);
          if (findingIds.has(e.target)) connectedIds.add(e.source);
        });
        filteredNodes = filteredNodes.filter((n) => connectedIds.has(n.id));
      } else {
        filteredNodes = filteredNodes.filter((n) => n.type === typeFilter);
      }
    }

    const validIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = rawEdges.filter(
      (e) => validIds.has(e.source) && validIds.has(e.target)
    );

    return { visibleNodes: filteredNodes, visibleEdges: filteredEdges };
  }, [rawNodes, rawEdges, searchQuery, typeFilter]);

  // Auto Layout using Dagre
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(() => {
    if (visibleNodes.length === 0) return { nodes: [], edges: [] };
    return getLayoutedElements(visibleNodes, visibleEdges, layoutDirection);
  }, [visibleNodes, visibleEdges, layoutDirection]);

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutedNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutedEdges);

  useEffect(() => {
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [layoutedNodes, layoutedEdges, setNodes, setEdges]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    setSelectedNode(node as Node<MindMapNodeData>);
  }, []);

  if (isLoading) {
    return (
      <div className="w-full h-[650px] bg-[#062B5C] rounded-2xl flex flex-col items-center justify-center text-[#0064D8] gap-3 border border-[#174A85]">
        <Loader2 className="w-8 h-8 animate-spin text-[#0070F2]" />
        <span className="text-sm font-semibold tracking-wide text-[#B8CCE2]">Building Unified AST Mind Map...</span>
      </div>
    );
  }

  return (
    <div className="relative w-full h-[680px] bg-[#062B5C] rounded-2xl overflow-hidden shadow-xl border border-[#174A85]">
      
      {/* React Flow Component */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        fitView
        colorMode="dark"
        attributionPosition="bottom-left"
        className="!bg-[#041F42]"
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255, 255, 255, 0.22)" />
        <Controls className="!bg-[#0F172A] !border !border-slate-700 !text-white !rounded-xl !p-1 backdrop-blur-md shadow-md [&>button]:!bg-[#1E293B] [&>button]:!border-slate-700 [&>button]:!text-white [&>button:hover]:!bg-[#2563EB]" />
        <MiniMap
          position="bottom-right"
          zoomable
          pannable
          style={{
            width: 200,
            height: 135,
            backgroundColor: "#0F172A",
            borderRadius: "12px",
            border: "1px solid #334155",
            boxShadow: "0 8px 24px rgba(0, 0, 0, 0.4)",
          }}
          maskColor="rgba(15, 23, 42, 0.85)"
          nodeStrokeColor="#FFFFFF"
          nodeStrokeWidth={2}
          nodeColor={(node) => {
            switch (node.type) {
              case "folder": return "#2563EB";
              case "file": return "#FFFFFF";
              case "function": return "#818cf8";
              case "finding": return "#ef4444";
              default: return "#FFFFFF";
            }
          }}
        />

        {/* Top Control Bar Panel */}
        <Panel position="top-left" className="flex flex-wrap items-center gap-3 bg-[#0F172A]/90 p-3 rounded-2xl border border-slate-700 m-3 z-10 shadow-lg">
          
          {/* Search Input */}
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 absolute left-3 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search AST nodes or paths..."
              className="bg-[#1E293B] border border-slate-700 pl-8 pr-3 py-1.5 rounded-xl text-xs text-white placeholder:text-slate-400 focus:outline-none focus:border-[#2563EB] w-56"
            />
          </div>

          {/* Node Type Selector */}
          <div className="flex items-center gap-1.5">
            {[
              { id: "all", label: "All" },
              { id: "folder", label: "Folders", icon: Folder },
              { id: "file", label: "Files", icon: FileCode },
              { id: "function", label: "Functions", icon: Code2 },
              { id: "finding", label: "Findings", icon: ShieldAlert },
            ].map((filter) => (
              <button
                key={filter.id}
                onClick={() => setTypeFilter(filter.id)}
                className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition flex items-center gap-1.5 ${
                  typeFilter === filter.id
                    ? "bg-[#2563EB] text-white font-bold"
                    : "bg-[#1E293B] text-slate-300 hover:text-white border border-slate-700"
                }`}
              >
                {filter.icon && <filter.icon className="w-3 h-3" />}
                {filter.label}
              </button>
            ))}
          </div>

          {/* Layout Switcher */}
          <button
            onClick={() => setLayoutDirection((prev) => (prev === "TB" ? "LR" : "TB"))}
            className="bg-[#1E293B] hover:bg-[#2563EB] text-white border border-slate-700 text-xs px-3 py-1.5 rounded-xl font-medium transition flex items-center gap-1.5"
            title="Toggle Top-Down / Left-Right Layout"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#38BDF8]" />
            Layout: {layoutDirection === "TB" ? "Vertical" : "Horizontal"}
          </button>

          {/* Legend & Real Summary Strip */}
          <div className="flex flex-wrap items-center gap-2.5 text-[9.5px] font-mono border-t border-slate-700 pt-2 mt-1 w-full text-white">
            {/* Legend Items */}
            <div className="flex items-center gap-2 pr-2 border-r border-slate-700">
              <span className="flex items-center gap-1 text-[#B8CCE2]">
                <span className="w-2 h-2 rounded-full bg-white border border-[#CBD5E1]" /> Unaffected
              </span>
              <span className="flex items-center gap-1 text-[#B8CCE2]">
                <span className="w-3.5 h-0.5 bg-[#2563EB] rounded" /> Affected Path
              </span>
              <span className="px-1.5 py-0.5 rounded font-bold bg-[#FFF1F2] text-[#C62828] border border-[#C62828]">
                CRITICAL
              </span>
              <span className="px-1.5 py-0.5 rounded font-bold bg-[#FFF5EB] text-[#E76500] border border-[#E76500]">
                HIGH
              </span>
              <span className="px-1.5 py-0.5 rounded font-bold bg-[#FFF9ED] text-[#B47800] border border-[#E5A11A]">
                MEDIUM
              </span>
              <span className="px-1.5 py-0.5 rounded font-bold bg-[#F4F8FF] text-[#2563EB] border border-[#3B82F6]">
                LOW
              </span>
            </div>

            {/* Real Summary Stats */}
            <div className="flex items-center gap-2 text-[#D9E8F8]">
              <span className="font-bold text-white">{summaryStats.totalFindings} Finding{summaryStats.totalFindings === 1 ? "" : "s"}</span>
              {summaryStats.critical > 0 && <span className="text-[#F87171] font-bold">{summaryStats.critical} Critical</span>}
              {summaryStats.high > 0 && <span className="text-[#FB923C] font-bold">{summaryStats.high} High</span>}
              {summaryStats.medium > 0 && <span className="text-[#FBBF24] font-bold">{summaryStats.medium} Medium</span>}
              {summaryStats.low > 0 && <span className="text-[#60A5FA] font-bold">{summaryStats.low} Low</span>}
            </div>
          </div>
        </Panel>
      </ReactFlow>

      {/* Empty State Overlay */}
      {nodes.length === 0 && !isLoading && (
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center p-6 bg-black/40 backdrop-blur-sm z-10">
          <FileCode className="w-12 h-12 text-indigo-400/60 mb-3" />
          <h4 className="text-base font-bold text-slate-200">
            {searchQuery ? "No Matching Nodes" : "No Active Repository Mind Map"}
          </h4>
          <p className="text-xs text-slate-400 max-w-sm mt-1 mb-4 leading-relaxed">
            {searchQuery
              ? `No AST graph nodes match your search query "${searchQuery}".`
              : "Run a scan in the IDE Workspace tab to dynamically generate the AST topology mind map graph."}
          </p>
          {searchQuery && (
            <button
              onClick={() => {
                setSearchQuery("");
                setTypeFilter("all");
              }}
              className="px-4 py-2 glass-button rounded-xl text-xs font-semibold text-white"
            >
              Reset Filters
            </button>
          )}
        </div>
      )}

      {/* Node Details Sidebar Panel */}
      <MindMapDetailPanel node={selectedNode} onClose={() => setSelectedNode(null)} />
    </div>
  );
};

export default CodeMindMap;
