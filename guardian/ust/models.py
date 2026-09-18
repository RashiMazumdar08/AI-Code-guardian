"""
Unified Syntax Tree (UST) — Data Models
=======================================
The UST is the platform's language-independent representation of source
code. Every language plugin normalises its Tree-sitter parse tree into
these structures, so every downstream engine (security, quantum,
business intent) analyses ONE shape regardless of whether the file was
Python, Java, JavaScript/TypeScript or Rust.

Design rules
------------
* Nothing here imports Tree-sitter, `ast`, or any language-specific
  module — the models must stay usable when no parser is installed.
* A UST node carries enough metadata to ground an Evidence item without
  re-reading the source: file, span, name, symbol, arguments, enclosing
  function, imports in scope, and semantic tags.
* Node identity is stable (`node_id`) so evidence can reference a node
  across runs of an unchanged file.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Iterator, Optional


class USTNodeType(str, Enum):
    """Language-independent node vocabulary.

    Structural types come first, then semantic types that a normalizer or
    tagger may attach when it recognises a well-known API shape.
    """

    # -- structure ----------------------------------------------------
    REPOSITORY = "repository"
    MODULE = "module"                  # one file
    IMPORT = "import"
    CLASS = "class"
    FUNCTION = "function"              # includes methods
    PARAMETER = "parameter"
    VARIABLE = "variable"
    ASSIGNMENT = "assignment"
    CALL = "call"
    OBJECT_CREATION = "object_creation"
    CONDITIONAL = "conditional"
    LOOP = "loop"
    RETURN = "return"
    EXCEPTION_HANDLING = "exception_handling"
    LITERAL = "literal"
    ANNOTATION = "annotation"          # decorators / annotations / attributes

    # -- semantic (attached by taggers) --------------------------------
    CRYPTO_OPERATION = "crypto_operation"
    API_ENDPOINT = "api_endpoint"
    DATABASE_OPERATION = "database_operation"
    AUTHORIZATION_CHECK = "authorization_check"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceSpan:
    """1-based line numbers, 0-based columns (Tree-sitter convention)."""

    start_line: int = 0
    start_column: int = 0
    end_line: int = 0
    end_column: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    def contains_line(self, line: int) -> bool:
        return self.start_line <= line <= (self.end_line or self.start_line)


@dataclass
class USTNode:
    """A single normalised syntax node.

    Only `type`, `language` and `file` are mandatory; everything else is
    best-effort and may legitimately be empty when a language's grammar
    does not expose it. Engines must treat missing metadata as "unknown",
    never as "absent" — that distinction is what keeps AI claims honest.
    """

    type: USTNodeType
    language: str
    file: str
    span: SourceSpan = field(default_factory=SourceSpan)

    name: str = ""                       # e.g. "processRefund"
    symbol: str = ""                     # fully-qualified, e.g. "Cipher.getInstance"
    snippet: str = ""                    # source text of this node (bounded)

    arguments: list[str] = field(default_factory=list)
    literals: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)

    enclosing_function: str = ""
    enclosing_class: str = ""
    parent_id: str = ""

    # semantics -------------------------------------------------------
    security_tags: list[str] = field(default_factory=list)
    crypto_tags: list[str] = field(default_factory=list)
    business_tags: list[str] = field(default_factory=list)

    control_flow: dict[str, Any] = field(default_factory=dict)   # e.g. {"in_conditional": True}
    data_flow: dict[str, Any] = field(default_factory=dict)      # e.g. {"tainted": True, "sources": [...]}
    metadata: dict[str, Any] = field(default_factory=dict)

    node_id: str = field(default="", init=False)

    def __post_init__(self) -> None:
        if isinstance(self.type, str) and not isinstance(self.type, USTNodeType):
            try:
                self.type = USTNodeType(self.type)
            except ValueError:
                self.type = USTNodeType.UNKNOWN
        basis = (f"{self.file}:{self.span.start_line}:{self.span.start_column}:"
                 f"{self.type.value}:{self.symbol or self.name}")
        self.node_id = hashlib.sha256(basis.encode()).hexdigest()[:16]

    # -- convenience ---------------------------------------------------
    @property
    def line(self) -> int:
        return self.span.start_line

    @property
    def column(self) -> int:
        return self.span.start_column

    def has_tag(self, tag: str) -> bool:
        return tag in self.security_tags or tag in self.crypto_tags or tag in self.business_tags

    def to_dict(self) -> dict:
        return {
            "node_id": self.node_id,
            "type": self.type.value,
            "language": self.language,
            "file": self.file,
            "span": self.span.to_dict(),
            "name": self.name,
            "symbol": self.symbol,
            "snippet": self.snippet,
            "arguments": self.arguments,
            "literals": self.literals,
            "parameters": self.parameters,
            "enclosing_function": self.enclosing_function,
            "enclosing_class": self.enclosing_class,
            "security_tags": self.security_tags,
            "crypto_tags": self.crypto_tags,
            "business_tags": self.business_tags,
            "control_flow": self.control_flow,
            "data_flow": self.data_flow,
            "metadata": self.metadata,
        }

    def describe(self) -> str:
        """One compact line for LLM context — no raw source dumping."""
        where = f"{self.file}:{self.span.start_line}"
        what = self.symbol or self.name or self.type.value
        args = f"({', '.join(self.arguments[:4])})" if self.arguments else ""
        fn = f" in {self.enclosing_function}()" if self.enclosing_function else ""
        return f"[{self.type.value}] {what}{args}{fn} @ {where}"

    def to_cache_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value if isinstance(self.type, USTNodeType) else self.type
        d["span"] = self.span.to_dict()
        return d

    @classmethod
    def from_cache_dict(cls, data: dict) -> 'USTNode':
        if "type" in data:
            try:
                data["type"] = USTNodeType(data["type"])
            except ValueError:
                data["type"] = USTNodeType.UNKNOWN
        if "span" in data and isinstance(data["span"], dict):
            data["span"] = SourceSpan(**data["span"])
        
        # Remove init=False fields if they snuck in
        if "node_id" in data:
            del data["node_id"]
            
        return cls(**data)


@dataclass
class USTFile:
    """Normalised representation of one source file."""

    path: str
    language: str
    nodes: list[USTNode] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    parser: str = "unknown"          # "tree-sitter" | "python-ast" | "regex" | "none"
    parse_error: str = ""
    line_count: int = 0

    @property
    def ok(self) -> bool:
        return not self.parse_error

    def of_type(self, *types: USTNodeType) -> list[USTNode]:
        wanted = set(types)
        return [n for n in self.nodes if n.type in wanted]

    def functions(self) -> list[USTNode]:
        return self.of_type(USTNodeType.FUNCTION)

    def calls(self) -> list[USTNode]:
        return self.of_type(USTNodeType.CALL, USTNodeType.OBJECT_CREATION)

    def function_at(self, line: int) -> Optional[USTNode]:
        """Innermost function whose span contains `line`."""
        best: Optional[USTNode] = None
        for fn in self.functions():
            if fn.span.contains_line(line):
                if best is None or fn.span.start_line > best.span.start_line:
                    best = fn
        return best

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "language": self.language,
            "parser": self.parser,
            "parse_error": self.parse_error,
            "line_count": self.line_count,
            "imports": self.imports,
            "node_count": len(self.nodes),
        }

    def to_cache_dict(self) -> dict:
        d = asdict(self)
        d["nodes"] = [n.to_cache_dict() for n in self.nodes]
        return d

    @classmethod
    def from_cache_dict(cls, data: dict) -> 'USTFile':
        if "nodes" in data:
            data["nodes"] = [USTNode.from_cache_dict(n) for n in data["nodes"]]
        return cls(**data)


@dataclass
class UST:
    """Repository-level unified syntax tree: a collection of USTFiles."""

    root: str = ""
    files: dict[str, USTFile] = field(default_factory=dict)
    # Dev-diagnostic only, populated by the most recent
    # USTBuilder.build_repository() call: {"hits", "misses", "hit_rate",
    # "read_ms", "write_ms"}. Not persisted -- to_cache_dict()/
    # from_cache_dict() deliberately don't round-trip it, since it
    # describes one build, not the UST's identity.
    cache_stats: dict = field(default_factory=dict)

    def add(self, ust_file: USTFile) -> None:
        self.files[ust_file.path] = ust_file

    def __iter__(self) -> Iterator[USTFile]:
        return iter(self.files.values())

    def __len__(self) -> int:
        return len(self.files)

    @property
    def nodes(self) -> Iterator[USTNode]:
        for f in self.files.values():
            yield from f.nodes

    def of_type(self, *types: USTNodeType) -> list[USTNode]:
        wanted = set(types)
        return [n for n in self.nodes if n.type in wanted]

    def by_language(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.files.values():
            out[f.language] = out.get(f.language, 0) + 1
        return out

    def by_parser(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.files.values():
            out[f.parser] = out.get(f.parser, 0) + 1
        return out

    def failed_files(self) -> list[str]:
        return [f.path for f in self.files.values() if f.parse_error]

    def summary(self) -> dict:
        node_types: dict[str, int] = {}
        total = 0
        for n in self.nodes:
            node_types[n.type.value] = node_types.get(n.type.value, 0) + 1
            total += 1
        return {
            "files": len(self.files),
            "nodes": total,
            "languages": self.by_language(),
            "parsers": self.by_parser(),
            "node_types": node_types,
            "parse_failures": len(self.failed_files()),
        }

    def to_cache_dict(self) -> dict:
        return {
            "root": self.root,
            "files": {k: v.to_cache_dict() for k, v in self.files.items()}
        }

    @classmethod
    def from_cache_dict(cls, data: dict) -> 'UST':
        files_data = data.get("files", {})
        files = {k: USTFile.from_cache_dict(v) for k, v in files_data.items()}
        return cls(root=data.get("root", ""), files=files)
