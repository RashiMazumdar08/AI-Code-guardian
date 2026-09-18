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
