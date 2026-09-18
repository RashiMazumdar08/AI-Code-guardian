import { NodeTypes } from "@xyflow/react";
import FolderNode from "./FolderNode";
import FileNode from "./FileNode";
import FunctionNode from "./FunctionNode";
import ClassNode from "./ClassNode";
import ModuleNode from "./ModuleNode";
import FindingNode from "./FindingNode";

export const nodeTypes: NodeTypes = {
  folder: FolderNode as any,
  file: FileNode as any,
  function: FunctionNode as any,
  class: ClassNode as any,
  module: ModuleNode as any,
  finding: FindingNode as any,
};

export { FolderNode, FileNode, FunctionNode, ClassNode, ModuleNode, FindingNode };
