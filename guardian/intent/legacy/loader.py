"""
Business Intent Engine — Loader
================================
Loads requirement sources and normalises them into `Requirement` objects.

Supported formats
-----------------
- .xlsx / .xls   (Jira User Stories, custom sheets)
- .csv           (any tabular export)
- .json          (Jira export, custom)
- .yaml / .yml   (OpenAPI 3.x, custom)
- .md            (BRD, SRS, Confluence export)
- .txt           (plain text)
- .pdf           (extracted via pypdf, falls back to plain text if pypdf missing)
- .docx          (extracted via python-docx, falls back to plain text if missing)
- Unknown ext    → treated as plain text (graceful fallback, no crash)

Public API
----------
    loader = RequirementLoader()
    requirements = loader.load(path_or_dict)
    requirements = loader.load_directory(dir_path)
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Union

from guardian.intent.legacy.models import Requirement

try:
    import yaml
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

from guardian.compat_pandas import pd, PANDAS_AVAILABLE as _PANDAS_AVAILABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slug(text: str, max_len: int = 60) -> str:
    return re.sub(r"\s+", "_", text.strip())[:max_len]


def _extract_acceptance_criteria(text: str) -> list[str]:
    criteria = []
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^[-*•]\s+(?:given|when|then|ac:|criteria:|\d+\.)", stripped, re.I):
            criteria.append(stripped.lstrip("-*•123456789. "))
        elif re.match(r"^\d+\.\s+.{10,}", stripped):
            criteria.append(stripped)
        # semicolon-separated inline criteria (matches real dataset pattern)
        elif ";" in stripped and len(stripped) > 20:
            for part in stripped.split(";"):
                part = part.strip()
                if len(part) > 8:
                    criteria.append(part)
    return criteria


def _safe_str(val) -> str:
    """Convert any cell value to a non-null string."""
    if val is None:
        return ""
    try:
        import math
        if isinstance(val, float) and math.isnan(val):
            return ""
    except Exception:
        pass
    return str(val).strip()


# ---------------------------------------------------------------------------
# Excel / CSV parsers
# ---------------------------------------------------------------------------

# Column name aliases: maps various possible header names → canonical field
_COL_ALIASES = {
    "id":          ["story_id", "id", "issue_id", "key", "pr_id", "build_id"],
    "title":       ["title", "summary", "name", "subject"],
    "content":     ["business_intent", "description", "body", "comment", "content", "story"],
    "acceptance":  ["acceptance_criteria", "criteria", "ac", "acceptance criteria"],
    "priority":    ["priority", "severity", "criticality"],
    "tags":        ["epic", "labels", "tags", "component", "category"],
    "status":      ["status", "state", "decision"],
}


def _find_col(columns: list[str], field: str) -> str | None:
    """Return the first column name that matches a known alias for `field`."""
    lower_cols = {c.lower().strip(): c for c in columns}
    for alias in _COL_ALIASES.get(field, []):
        if alias in lower_cols:
            return lower_cols[alias]
    return None


def _df_to_requirements(df, source_id: str, source_type: str) -> list[Requirement]:
    cols = df.columns.tolist()
    col_id      = _find_col(cols, "id")
    col_title   = _find_col(cols, "title")
    col_content = _find_col(cols, "content")
    col_ac      = _find_col(cols, "acceptance")
    col_priority= _find_col(cols, "priority")
    col_tags    = _find_col(cols, "tags")

    out = []
    for i, row in df.iterrows():
        req_id  = _safe_str(row[col_id])   if col_id    else f"{source_id}_{i}"
        title   = _safe_str(row[col_title]) if col_title else req_id
        content = _safe_str(row[col_content]) if col_content else ""

        # Build acceptance criteria from dedicated column or extract from content
        if col_ac:
            raw_ac = _safe_str(row[col_ac])
            ac = _extract_acceptance_criteria(raw_ac) or ([raw_ac] if raw_ac else [])
        else:
            ac = _extract_acceptance_criteria(content)

        priority = _safe_str(row[col_priority]) if col_priority else "Medium"
        tags_raw = _safe_str(row[col_tags])     if col_tags     else ""
        tags     = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []

        # Full content = title + business intent text + AC for richer extraction
        full_content = "\n".join(filter(None, [title, content, "; ".join(ac)]))

        out.append(Requirement(
            source_id=req_id or f"{source_id}_{i}",
            source_type=source_type,
            title=title or f"Requirement {i}",
            content=full_content,
            acceptance_criteria=ac,
            tags=tags,
            metadata={"priority": priority, "row_index": i},
        ))
    return out


def _parse_xlsx(path: Path) -> list[Requirement]:
    if not _PANDAS_AVAILABLE:
        raise ImportError("pandas + openpyxl required for Excel loading. pip install pandas openpyxl")

    # Try common sheet names used in the project datasets; fall back to sheet 0
    xl = pd.ExcelFile(path)
    sheet_names = xl.sheet_names
    preferred = ["UserStories", "PRReviews", "Commits", "Sheet", "Sheet1", "Requirements"]
    target_sheet = next((s for s in preferred if s in sheet_names), sheet_names[0])

    df = pd.read_excel(path, sheet_name=target_sheet)
    df = df.fillna("")
    return _df_to_requirements(df, path.stem, "xlsx")


def _parse_csv(path: Path) -> list[Requirement]:
    if _PANDAS_AVAILABLE and hasattr(pd, "read_csv"):
        df = pd.read_csv(path, encoding="utf-8", encoding_errors="replace").fillna("")
        return _df_to_requirements(df, path.stem, "csv")
    import csv
    with path.open("r", encoding="utf-8", errors="replace") as f:
        reader = list(csv.DictReader(f))
    df = pd.DataFrame(reader)
    return _df_to_requirements(df, path.stem, "csv")


# ---------------------------------------------------------------------------
# JSON / YAML / Markdown / Text parsers (unchanged logic, same as before)
# ---------------------------------------------------------------------------

def _parse_json(path: Path) -> list[Requirement]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        data = [data]
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        content_parts = [
            item.get("description", ""),
            item.get("summary", ""),
            item.get("story", ""),
            item.get("content", ""),
            item.get("business_intent", ""),
        ]
        content = "\n".join(p for p in content_parts if p)
        ac_raw = item.get("acceptance_criteria", item.get("acceptanceCriteria", []))
        ac = _extract_acceptance_criteria(ac_raw) if isinstance(ac_raw, str) else [str(a) for a in ac_raw]
        out.append(Requirement(
            source_id=str(item.get("id", item.get("key", path.stem))),
            source_type="jira",
            title=str(item.get("title", item.get("summary", path.stem))),
            content=content,
            acceptance_criteria=ac,
            tags=item.get("labels", item.get("tags", [])),
            metadata={k: v for k, v in item.items() if k not in
                      ("description","summary","story","content","business_intent",
                       "acceptance_criteria","acceptanceCriteria")},
        ))
    return out


def _parse_openapi(data: dict, source_id: str) -> list[Requirement]:
    out = []
    for path_url, methods in data.get("paths", {}).items():
        for method, spec in methods.items():
            if not isinstance(spec, dict):
                continue
            description = spec.get("description", spec.get("summary", ""))
            content = f"{method.upper()} {path_url}\n{description}"
            out.append(Requirement(
                source_id=f"{source_id}::{method.upper()}:{path_url}",
                source_type="openapi",
                title=f"{method.upper()} {path_url}",
                content=content,
                acceptance_criteria=[f"Security: {s}" for s in spec.get("security", [])],
                tags=spec.get("tags", []),
                metadata={"method": method.upper(), "path": path_url},
            ))
    return out


def _parse_yaml(path: Path) -> list[Requirement]:
    if not _YAML_AVAILABLE:
        raise ImportError("pyyaml required for YAML/OpenAPI loading. pip install pyyaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and ("openapi" in data or "swagger" in data):
        return _parse_openapi(data, path.stem)
    if isinstance(data, list):
        out = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            content = item.get("description", item.get("content", str(item)))
            out.append(Requirement(
                source_id=str(item.get("id", f"{path.stem}_{i}")),
                source_type="yaml",
                title=str(item.get("title", f"Requirement {i}")),
                content=content,
                acceptance_criteria=_extract_acceptance_criteria(content),
                tags=item.get("tags", []),
                metadata=item,
            ))
        return out
    return []


def _parse_markdown(path: Path) -> list[Requirement]:
    text = path.read_text(encoding="utf-8")
    sections = re.split(r"^#{2,3}\s+", text, flags=re.MULTILINE)
    out = []
    for i, section in enumerate(sections):
        if len(section.strip()) < 20:
            continue
        lines = section.strip().splitlines()
        title = lines[0].strip() if lines else f"Section_{i}"
        content = "\n".join(lines[1:]).strip() if len(lines) > 1 else section
        out.append(Requirement(
            source_id=f"{path.stem}::{_slug(title)}",
            source_type="markdown",
            title=title,
            content=content,
            acceptance_criteria=_extract_acceptance_criteria(content),
        ))
    return out or [Requirement(
        source_id=path.stem, source_type="markdown", title=path.stem,
        content=text, acceptance_criteria=_extract_acceptance_criteria(text),
    )]


def _parse_text(path: Path) -> list[Requirement]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    return [Requirement(
        source_id=path.stem, source_type="text", title=path.stem,
        content=text, acceptance_criteria=_extract_acceptance_criteria(text),
    )]


def _parse_pdf(path: Path) -> list[Requirement]:
    """Extract text from a PDF via pypdf. Falls back to plain-text read
    (garbage for a real PDF, but never crashes) if pypdf isn't installed."""
    text = ""
    try:
        import pypdf
        reader = pypdf.PdfReader(str(path))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
    except ImportError:
        print(f"[RequirementLoader] pypdf not installed — cannot properly extract "
              f"text from {path}. Run: pip install pypdf")
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        print(f"[RequirementLoader] Failed to extract text from PDF {path}: {exc}")
        text = path.read_text(encoding="utf-8", errors="ignore")

    return [Requirement(
        source_id=path.stem, source_type="pdf", title=path.stem,
        content=text, acceptance_criteria=_extract_acceptance_criteria(text),
    )]


def _parse_docx(path: Path) -> list[Requirement]:
    """Extract text from a DOCX via python-docx. Falls back to plain-text
    read (garbage for a real DOCX, but never crashes) if it isn't installed."""
    text = ""
    try:
        import docx
        doc = docx.Document(str(path))
        text = "\n".join(p.text for p in doc.paragraphs if p.text.strip())
    except ImportError:
        print(f"[RequirementLoader] python-docx not installed — cannot properly "
              f"extract text from {path}. Run: pip install python-docx")
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        print(f"[RequirementLoader] Failed to extract text from DOCX {path}: {exc}")
        text = path.read_text(encoding="utf-8", errors="ignore")

    return [Requirement(
        source_id=path.stem, source_type="docx", title=path.stem,
        content=text, acceptance_criteria=_extract_acceptance_criteria(text),
    )]


# ---------------------------------------------------------------------------
# Extension map + public loader
# ---------------------------------------------------------------------------

EXTENSION_MAP = {
    ".xlsx": _parse_xlsx,
    ".xls":  _parse_xlsx,
    ".csv":  _parse_csv,
    ".json": _parse_json,
    ".md":   _parse_markdown,
    ".txt":  _parse_text,
    ".yaml": _parse_yaml,
    ".yml":  _parse_yaml,
    ".pdf":  _parse_pdf,
    ".docx": _parse_docx,
}


class RequirementLoader:
    """
    Load one or many requirement documents into normalised `Requirement` objects.
    Designed for extension: subclass and override `_parsers` to add new formats.

    Unknown file extensions are treated as plain text (graceful fallback).
    """

    def __init__(self):
        self._parsers = dict(EXTENSION_MAP)

    def load(self, source: Union[str, Path, dict]) -> list[Requirement]:
        """
        Load from:
          - a file path (str or Path) — any supported format
          - a raw dict  — treated as a single JSON-style requirement
          - unknown extension — graceful plain-text fallback (no crash)
        """
        if isinstance(source, dict):
            content = source.get("description", source.get("content", str(source)))
            return [Requirement(
                source_id=str(source.get("id", "inline")),
                source_type="dict",
                title=str(source.get("title", "Inline Requirement")),
                content=content,
                acceptance_criteria=_extract_acceptance_criteria(content),
                metadata=source,
            )]

        path = Path(source)
        if not path.exists():
            raise FileNotFoundError(
                f"Requirement source not found: {path}\n"
                f"Tip: enter the path to a FILE (e.g. Jira_User_Stories.xlsx), "
                f"not a folder. To load a whole folder use load_directory()."
            )

        # If the user accidentally points at a folder, load all supported
        # files inside it instead of crashing with PermissionError.
        if path.is_dir():
            print(f"[RequirementLoader] '{path}' is a directory — loading all "
                  f"supported requirement files inside it.")
            return self.load_directory(path)

        parser = self._parsers.get(path.suffix.lower())

        if parser is None:
            # Graceful fallback: try plain-text instead of raising
            print(f"[RequirementLoader] Unknown extension '{path.suffix}' — loading as plain text.")
            return _parse_text(path)

        return parser(path)

    def load_directory(self, directory: Union[str, Path]) -> list[Requirement]:
        """Load all supported files from a directory (non-recursive)."""
        directory = Path(directory)
        results: list[Requirement] = []
        for path in sorted(directory.iterdir()):
            if path.is_file():
                try:
                    results.extend(self.load(path))
                except Exception as exc:
                    print(f"[RequirementLoader] Warning: could not load {path}: {exc}")
        return results
