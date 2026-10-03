export type MindMapNodeType = 'folder' | 'file' | 'function' | 'class' | 'module' | 'finding';

export interface MindMapNodeData {
  label: string;
  path?: string;
  language?: string;
  riskScore?: number;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  codePreview?: string;
  findings?: any[];
  isCollapsed?: boolean;
  onToggleCollapse?: (id: string) => void;
  [key: string]: unknown;
}

export interface RawMindMapNode {
  id: string;
  type: MindMapNodeType;
  data: MindMapNodeData;
  position?: { x: number; y: number };
}

export interface RawMindMapEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  type?: 'import' | 'call' | 'dependency' | 'default';
}

export interface MindMapData {
  nodes: RawMindMapNode[];
  edges: RawMindMapEdge[];
}

export type NodeSeverity = "critical" | "high" | "medium" | "low" | null;

export function getNodeSeverityStyle(data: MindMapNodeData, type?: string, isSelected?: boolean) {
  if (isSelected) {
    return {
      isAffected: false,
      severity: null as NodeSeverity,
      count: 0,
      containerClass: "bg-[#EAF3FF] border-2 border-[#0064D8] text-[#0B1F33] shadow-[0_4px_12px_rgba(0,100,216,0.18)] hover:bg-[#DCEBFF] hover:border-[#0055B8]",
      badgeClass: "bg-[#0064D8] text-white border border-[#0064D8]",
      indicatorColor: "#0064D8",
    };
  }

  let severity: NodeSeverity = null;
  let count = 0;

  if (type === "finding" || data.severity) {
    severity = (data.severity || "high").toLowerCase() as NodeSeverity;
    count = 1;
  } else if (Array.isArray(data.findings) && data.findings.length > 0) {
    count = data.findings.length;
    let highest: NodeSeverity = "low";
    for (const f of data.findings) {
      const s = (f.severity || "").toLowerCase();
      if (s === "critical") { highest = "critical"; break; }
      if (s === "high") { highest = "high"; }
      else if (s === "medium" && highest !== "high") { highest = "medium"; }
    }
    severity = highest;
  } else if (typeof data.riskScore === "number" && data.riskScore > 0) {
    if (data.riskScore >= 80) severity = "critical";
    else if (data.riskScore >= 50) severity = "high";
    else if (data.riskScore >= 20) severity = "medium";
    else severity = "low";
  }

  if (!severity) {
    return {
      isAffected: false,
      severity: null as NodeSeverity,
      count: 0,
      containerClass: "bg-[#FFFFFF] border border-[#CBD5E1] text-[#0B1F33] shadow-xs hover:bg-[#F8FAFC] hover:border-[#94A3B8]",
      badgeClass: "bg-[#F1F5F9] text-[#4F6480] border border-[#CBD5E1]",
      indicatorColor: "#CBD5E1",
    };
  }

  switch (severity) {
    case "critical":
      return {
        isAffected: true,
        severity: "critical" as const,
        count,
        containerClass: "bg-[#FFF1F2] border-2 border-[#C62828] text-[#0B1F33] shadow-[0_4px_12px_rgba(198,40,40,0.12)] hover:bg-[#FFE4E6] hover:border-[#B71C1C]",
        badgeClass: "bg-[#FFF1F2] text-[#C62828] border border-[#C62828]",
        indicatorColor: "#C62828",
      };
    case "high":
      return {
        isAffected: true,
        severity: "high" as const,
        count,
        containerClass: "bg-[#FFF5EB] border-2 border-[#E76500] text-[#0B1F33] shadow-[0_4px_12px_rgba(231,101,0,0.12)] hover:bg-[#FFEAD5] hover:border-[#D85700]",
        badgeClass: "bg-[#FFF5EB] text-[#E76500] border border-[#E76500]",
        indicatorColor: "#E76500",
      };
    case "medium":
      return {
        isAffected: true,
        severity: "medium" as const,
        count,
        containerClass: "bg-[#FFF9ED] border-2 border-[#E5A11A] text-[#0B1F33] shadow-[0_4px_12px_rgba(229,161,26,0.12)] hover:bg-[#FFF0D4] hover:border-[#D4900F]",
        badgeClass: "bg-[#FFF9ED] text-[#B47800] border border-[#E5A11A]",
        indicatorColor: "#E5A11A",
      };
    case "low":
    default:
      return {
        isAffected: true,
        severity: "low" as const,
        count,
        containerClass: "bg-[#F4F8FF] border-2 border-[#3B82F6] text-[#0B1F33] shadow-[0_4px_12px_rgba(59,130,246,0.12)] hover:bg-[#EAF2FF] hover:border-[#2563EB]",
        badgeClass: "bg-[#F4F8FF] text-[#2563EB] border border-[#3B82F6]",
        indicatorColor: "#3B82F6",
      };
  }
}

