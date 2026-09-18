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

  const rawEdges: Edge[] = useMemo(() => {
    return (data.edges || []).map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      label: e.label,
      animated: e.type === "call" || e.type === "dependency",
      style: {
        stroke: e.type === "dependency" ? "#ef4444" : e.type === "call" ? "#3b82f6" : "#475569",
        strokeWidth: 1.5,
      },
    }));
  }, [data.edges]);

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
      <div className="w-full h-[650px] glass-panel rounded-2xl flex flex-col items-center justify-center text-blue-400 gap-3 border border-slate-800">
        <Loader2 className="w-8 h-8 animate-spin text-blue-500" />
        <span className="text-sm font-semibold tracking-wide text-slate-300">Building Unified AST Mind Map...</span>
      </div>
    );
  }

  return (
    <div className="relative w-full h-[680px] glass-panel rounded-2xl overflow-hidden shadow-xl border border-slate-800">
      
      {/* React Flow Component */}
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        fitView
        attributionPosition="bottom-left"
        className="bg-transparent"
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="rgba(255, 255, 255, 0.08)" />
        <Controls className="!bg-slate-900/90 !border-slate-800 !text-slate-300 !rounded-xl !p-1 backdrop-blur-md shadow-md" />
        <MiniMap
          position="bottom-right"
          zoomable
          pannable
          style={{
            width: 200,
            height: 135,
            backgroundColor: "rgba(15, 23, 42, 0.9)",
            borderRadius: "12px",
            border: "1px solid rgba(255, 255, 255, 0.1)",
            boxShadow: "0 8px 24px rgba(0, 0, 0, 0.4)",
          }}
          maskColor="rgba(15, 23, 42, 0.75)"
          nodeStrokeColor="#3b82f6"
          nodeStrokeWidth={1.5}
          nodeColor={(node) => {
            switch (node.type) {
              case "folder": return "#3b82f6";
              case "file": return "#64748b";
              case "function": return "#818cf8";
              case "finding": return "#ef4444";
              default: return "#94a3b8";
            }
          }}
        />

        {/* Top Control Bar Panel */}
        <Panel position="top-left" className="flex flex-wrap items-center gap-3 glass-panel p-3 rounded-2xl border border-cyan-500/30 m-3 z-10">
          
          {/* Search Input */}
          <div className="relative flex items-center">
            <Search className="w-3.5 h-3.5 absolute left-3 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search AST nodes or paths..."
              className="glass-input pl-8 pr-3 py-1.5 rounded-xl text-xs text-slate-100 placeholder:text-slate-500 focus:outline-none w-56"
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
                    ? "glass-button text-white"
                    : "glass-card text-slate-400 hover:text-slate-200"
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
            className="glass-card hover:bg-white/10 text-slate-300 text-xs px-3 py-1.5 rounded-xl font-medium transition flex items-center gap-1.5"
            title="Toggle Top-Down / Left-Right Layout"
          >
            <RefreshCw className="w-3.5 h-3.5 text-indigo-400" />
            Layout: {layoutDirection === "TB" ? "Vertical" : "Horizontal"}
          </button>
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
