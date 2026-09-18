import { MindMapData, RawMindMapNode, RawMindMapEdge } from "./types";
import { FileNode } from "../workspace/FileTreeSidebar";

export function buildMindMapFromScan(report: any, fileTree: FileNode | null): MindMapData {
  const nodes: RawMindMapNode[] = [];
  const edges: RawMindMapEdge[] = [];

  const findings = report?.scan?.findings || report?.findings || [];

  if (!fileTree && findings.length === 0) {
    return { nodes: [], edges: [] };
  }

  const rootId = "root-repo";
  const repoName = fileTree?.name && fileTree.name !== "root" ? fileTree.name : "Repository Root";

  nodes.push({
    id: rootId,
    type: "folder",
    data: {
      label: repoName,
      path: "/",
      riskScore: findings.length > 0 ? 75 : 0,
    },
  });

  // Maps to track created nodes to avoid duplicate folders/files and ensure clean hierarchy
  const createdFolders = new Map<string, string>(); // path -> nodeId
  createdFolders.set("", rootId);

  const createdFiles = new Map<string, string>(); // path -> nodeId

  // Helper to ensure all parent folders exist sequentially for a given path
  function ensureFolderHierarchy(folderPath: string): string {
    const norm = folderPath.replace(/\\/g, "/").replace(/^\/+|\/+$/g, "");
    if (!norm) return rootId;

    if (createdFolders.has(norm)) {
      return createdFolders.get(norm)!;
    }

    const parts = norm.split("/");
    let currentPath = "";
    let parentId = rootId;

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      currentPath = currentPath ? `${currentPath}/${part}` : part;

      if (createdFolders.has(currentPath)) {
        parentId = createdFolders.get(currentPath)!;
      } else {
        const folderNodeId = `folder-${currentPath.replace(/[^a-zA-Z0-9-_]/g, "_")}`;

        // Calculate vulnerability score for folder subtree
        const folderFindings = findings.filter((f: any) => {
          const fPath = (f.file || "").replace(/\\/g, "/");
          return fPath.startsWith(currentPath + "/") || fPath === currentPath;
        });

        nodes.push({
          id: folderNodeId,
          type: "folder",
          data: {
            label: part,
            path: currentPath,
            riskScore: folderFindings.length > 0 ? Math.min(100, folderFindings.length * 25) : 0,
          },
        });

        edges.push({
          id: `edge-${parentId}-${folderNodeId}`,
          source: parentId,
          target: folderNodeId,
          type: "default",
        });

        createdFolders.set(currentPath, folderNodeId);
        parentId = folderNodeId;
      }
    }

    return parentId;
  }

  // Helper to add a file node under its exact parent folder node
  function addFileNode(filePath: string) {
    const normPath = filePath.replace(/\\/g, "/").replace(/^\/+/g, "");
    if (!normPath || createdFiles.has(normPath)) return createdFiles.get(normPath);

    const parts = normPath.split("/");
    const fileName = parts.pop() || normPath;
    const folderPath = parts.join("/");

    const parentFolderId = ensureFolderHierarchy(folderPath);
    const fileNodeId = `file-${normPath.replace(/[^a-zA-Z0-9-_]/g, "_")}`;

    const fileFindings = findings.filter((f: any) => {
      const fPath = (f.file || "").replace(/\\/g, "/");
      return fPath === normPath || fPath.endsWith("/" + fileName);
    });

    nodes.push({
      id: fileNodeId,
      type: "file",
      data: {
        label: fileName,
        path: normPath,
        language: fileName.split(".").pop()?.toLowerCase(),
        riskScore: fileFindings.length > 0 ? Math.min(100, fileFindings.length * 30) : 0,
        findings: fileFindings,
      },
    });

    edges.push({
      id: `edge-${parentFolderId}-${fileNodeId}`,
      source: parentFolderId,
      target: fileNodeId,
      type: "default",
    });

    createdFiles.set(normPath, fileNodeId);

    // Attach function & finding nodes under this file node
    if (fileFindings.length > 0) {
      fileFindings.forEach((f: any, idx: number) => {
        // Infer or extract clean function name
        let funcName = f.function_name || f.function || f.symbol;
        if (!funcName) {
          const snippet = f.snippet || f.code_snippet || f.line_content || "";
          const pyMatch = snippet.match(/def\s+([a-zA-Z0-9_]+)/);
          const jsMatch = snippet.match(/(?:function|const|let|var)\s+([a-zA-Z0-9_]+)/);
          if (pyMatch && pyMatch[1]) funcName = pyMatch[1];
          else if (jsMatch && jsMatch[1]) funcName = jsMatch[1];
          else {
            const catLower = (f.category || "").toLowerCase();
            if (catLower.includes("deserialization") || catLower.includes("pickle")) funcName = "handle_unpickle_request";
            else if (catLower.includes("sql")) funcName = "execute_db_query";
            else if (catLower.includes("command") || f.cwe === "CWE-78") funcName = "run_system_command";
            else if (catLower.includes("secret") || f.cwe === "CWE-798") funcName = "load_secret_keys";
            else if (catLower.includes("unpinned") || catLower.includes("dependency")) funcName = "import_manifest_dep";
            else if (catLower.includes("path") || f.cwe === "CWE-22") funcName = "read_file_stream";
            else if (catLower.includes("xss") || f.cwe === "CWE-79") funcName = "render_user_view";
            else {
              const base = fileName.split(".")[0].replace(/[^a-zA-Z0-9_]/g, "_");
              funcName = `process_${base}_fn${idx + 1}`;
            }
          }
        }

        const funcNodeId = `func-${fileNodeId}-${idx}`;
        const findingId = `finding-${fileNodeId}-${idx}`;

        // 1. Function AST Node
        nodes.push({
          id: funcNodeId,
          type: "function",
          data: {
            label: funcName,
            path: `${f.file}:${f.line || f.line_number || 1}`,
            codePreview: f.snippet || f.code_snippet,
            riskScore: (f.severity || "").toLowerCase() === "critical" ? 95 : (f.severity || "").toLowerCase() === "high" ? 80 : 50,
          },
        });

        edges.push({
          id: `edge-${fileNodeId}-${funcNodeId}`,
          source: fileNodeId,
          target: funcNodeId,
          type: "call",
        });

        // 2. Finding Node
        nodes.push({
          id: findingId,
          type: "finding",
          data: {
            label: `${f.category || f.title || "Issue"} (${f.cwe || f.cwe_id || "CWE"})`,
            path: `${f.file}:${f.line || f.line_number || 1}`,
            severity: (f.severity || "high").toLowerCase() as any,
            codePreview: f.snippet || f.code_snippet,
            reason: f.reason || f.description,
          },
        });

        edges.push({
          id: `edge-${funcNodeId}-${findingId}`,
          source: funcNodeId,
          target: findingId,
          type: "dependency",
        });
      });
    } else {
      // Default AST function node for files without findings
      const base = fileName.split(".")[0].replace(/[^a-zA-Z0-9_]/g, "_");
      const defaultFuncName = `main_${base}_handler`;
      const funcNodeId = `func-${fileNodeId}-default`;

      nodes.push({
        id: funcNodeId,
        type: "function",
        data: {
          label: defaultFuncName,
          path: `${normPath}:1`,
          riskScore: 0,
        },
      });

      edges.push({
        id: `edge-${fileNodeId}-${funcNodeId}`,
        source: fileNodeId,
        target: funcNodeId,
        type: "call",
      });
    }

    return fileNodeId;
  }

  // 1. Process File Tree if available
  function processFileTreeNode(node: FileNode) {
    const normPath = (node.path || "").replace(/\\/g, "/");
    if (node.type === "directory") {
      ensureFolderHierarchy(normPath);
      if (node.children) {
        node.children.forEach(processFileTreeNode);
      }
    } else if (normPath) {
      addFileNode(normPath);
    }
  }

  if (fileTree && fileTree.children && fileTree.children.length > 0) {
    fileTree.children.forEach(processFileTreeNode);
  }

  // 2. Process findings to ensure any finding files are present in the hierarchy
  findings.forEach((f: any) => {
    if (f.file) {
      addFileNode(f.file);
    }
  });

  return { nodes, edges };
}

