"""
Smart Document Ingestion Module for Business Intent Engine
===========================================================
- Cleans noise (headers/footers, page numbers, dividers).
- Filters actionable requirement lines (must, should, require, only if, cannot, allowed).
- Chunks into structured Requirement objects.
- Caches document parsing results by file mtime & hash for high performance.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def _read_pdf_text(path: Path) -> str:
    """Extract text from a PDF via pypdf. Binary PDF bytes decoded as UTF-8
    (the previous behavior) never contain readable words, so every PDF
    silently produced zero actionable requirements regardless of content."""
    try:
        import pypdf
        reader = pypdf.PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except ImportError:
        log.warning("pypdf not installed — cannot extract text from %s. pip install pypdf", path)
        return ""
    except Exception as exc:  # noqa: BLE001 — a bad PDF must not break the whole scan
        log.warning("Failed to extract text from PDF %s: %s", path, exc)
        return ""


def _read_docx_text(path: Path) -> str:
    """Extract text from a .docx via python-docx (a .docx is a zip of XML,
    not plain text either)."""
    try:
        import docx
        doc = docx.Document(str(path))
        return "\n".join(p.text for p in doc.paragraphs if p.text.strip())
    except ImportError:
        log.warning("python-docx not installed — cannot extract text from %s. pip install python-docx", path)
        return ""
    except Exception as exc:  # noqa: BLE001
        log.warning("Failed to extract text from DOCX %s: %s", path, exc)
        return ""


def _read_document_text(path: Path) -> str:
    """Return a document's text content, dispatching to a real parser for
    binary formats instead of decoding their raw bytes as UTF-8."""
    ext = path.suffix.lower()
    if ext == ".pdf":
        return _read_pdf_text(path)
    if ext == ".docx":
        return _read_docx_text(path)
    return path.read_text(encoding="utf-8", errors="ignore")

# Trigger keywords for actionable business requirements
ACTIONABLE_PATTERNS = re.compile(
    r"(?i)\b(must|should|require|requires|required|only\s+if|cannot|allowed|forbidden|prohibited|shall|mandatory|needs)\b"
)

# Restriction phrasing ("users may access only...", "restricted to admins")
# doesn't contain must/should/shall at all, but is just as much a hard
# requirement — without this, rules phrased this way (often the most
# important ones, e.g. access-control rules) were silently dropped.
RESTRICTION_PATTERNS = re.compile(
    r"(?i)(\bmay\b[^.]{0,60}\bonly\b|\bonly\b[^.]{0,60}\bmay\b|"
    r"\brestricted\s+to\b|\blimited\s+to\b)"
)

# Noise line patterns (headers, footers, page numbers, markdown dividers)
NOISE_PATTERNS = [
    re.compile(r"(?i)^page\s+\d+(\s+of\s+\d+)?$"),
    re.compile(r"^\s*[\-_*]{3,}\s*$"),
    re.compile(r"^\s*#*\s*$"),
    re.compile(r"(?i)^(confidential|draft|internal\s+use\s+only)$"),
]

# A numbered section heading, e.g. "5. AI Code Guardian Validation Rules".
_SECTION_HEADING = re.compile(r"^\s*\d+[\.\)]\s+(.+)$")

# Sections that describe how the ANALYSIS TOOL itself should behave (what a
# finding write-up must cite, suggested chatbot test questions, usage notes)
# rather than a requirement about the application being scanned. Lines in
# these sections can never be "evidenced" by scanning the target repo, so
# treating them as business rules only manufactures guaranteed-insufficient
# verdicts.
_EXCLUDED_SECTION_TITLES = re.compile(
    r"(?i)\b(validation rules|test questions|chatbot|usage note)\b"
)

# A standalone rule-code line, e.g. "BR-001" or "SEC-014" — the chunk
# boundary used by structured business-rule documents (see
# `_extract_structured_blocks` below).
_RULE_CODE_LINE = re.compile(r"^[A-Z]{2,8}-\d{2,4}$")

# The two field labels that bracket a structured rule block's body text
# and its evidence keyword list.
_LABEL_REQUIREMENT = re.compile(r"(?i)^requirement$")
_LABEL_EVIDENCE_TERMS = re.compile(r"(?i)^evidence\s+terms$")

# A title line ending in a severity word, e.g. "Untrusted Input
# Validation   Critical".
_TITLE_SEVERITY = re.compile(r"(?i)\s{2,}(Critical|High|Medium|Low)\s*$")


@dataclass
class Requirement:
    id: str
    text: str
    source: str
    line_number: int
    raw_text: str
    title: str = ""
    severity: str = ""
    evidence_terms: list[str] = field(default_factory=list)


def get_business_docs_dir(custom_path: str | Path | None = None) -> Path:
    """Resolve the business documents directory path."""
    if custom_path:
        p = Path(custom_path)
        p.mkdir(parents=True, exist_ok=True)
        return p

    workspace_root = Path.cwd()
    possible_paths = [
        workspace_root / "data" / "business_docs",
        workspace_root / "AI-Code-Guardian-ai_features" / "data" / "business_docs",
        Path("/data/business_docs"),
        Path("C:/data/business_docs"),
    ]

    for path in possible_paths:
        if path.exists():
            return path

    default_dir = workspace_root / "data" / "business_docs"
    default_dir.mkdir(parents=True, exist_ok=True)
    return default_dir


class DocumentLoader:
    """Smart document loader with cleaning, actionable sentence extraction, and caching."""

    SUPPORTED_EXTENSIONS = {".md", ".txt", ".json", ".csv", ".yaml", ".yml", ".docx", ".pdf"}

    def __init__(self, docs_dir: str | Path | None = None):
        self.docs_dir = get_business_docs_dir(docs_dir)
        self._cache: dict[str, dict[str, Any]] = {}

    def list_documents(self) -> list[dict[str, Any]]:
        """List all business documents in the directory."""
        if not self.docs_dir.exists():
            return []

        docs = []
        for file_path in sorted(self.docs_dir.glob("*")):
            if file_path.is_file() and file_path.suffix.lower() in self.SUPPORTED_EXTENSIONS:
                stat = file_path.stat()
                docs.append({
                    "filename": file_path.name,
                    "path": str(file_path),
                    "size_bytes": stat.st_size,
                    "mtime": stat.st_mtime,
                    "extension": file_path.suffix.lower(),
                })
        return docs

    def _clean_line(self, line: str) -> str:
        """Strip headers, footers, page numbers, and excess whitespace."""
        line_str = line.strip()
        for pattern in NOISE_PATTERNS:
            if pattern.match(line_str):
                return ""
        # Remove header prefixes like ### or 1.2
        cleaned = re.sub(r"^(#+|\d+[\.\)]|\-\s*)\s*", "", line_str)
        # Normalize internal whitespace
        cleaned = re.sub(r"\s+", " ", cleaned)
        return cleaned.strip()

    def _extract_structured_blocks(self, lines: list[str], filename: str) -> list[Requirement] | None:
        """Parse documents laid out as self-contained rule blocks: a
        standalone rule-code line (e.g. "BR-001"), a title(+severity)
        line, a "Requirement" label followed by the requirement body, and
        an "Evidence terms" label followed by a semicolon-separated term
        list.

        Using the rule's own code as the chunk boundary — instead of the
        sentence-punctuation/numbered-heading heuristic below — means
        surrounding tables and prose sections (a "Business Context" table,
        an "Expected Business Intent Interpretation" table, "Testing
        Notes for AI Code Guardian" meta-instructions to the analysis tool
        itself, closing boilerplate, ...) are never mistaken for rules,
        and "Evidence terms" bullet lines can't bleed into the next
        rule's body — both of which previously turned a real 16-rule
        document into 32 garbled/duplicated pseudo-rules.

        Returns None when the document has fewer than 2 rule-code lines
        (i.e. it isn't this kind of document at all), so callers can fall
        back to the sentence-based heuristic for ordinary prose documents.
        """
        code_line_idxs = [i for i, ln in enumerate(lines) if _RULE_CODE_LINE.match(ln.strip())]
        if len(code_line_idxs) < 2:
            return None

        requirements: list[Requirement] = []
        for block_num, start in enumerate(code_line_idxs):
            end = code_line_idxs[block_num + 1] if block_num + 1 < len(code_line_idxs) else len(lines)
            block_lines = [ln.strip() for ln in lines[start + 1:end]]
            block_lines = [ln for ln in block_lines
                            if ln and not any(p.match(ln) for p in NOISE_PATTERNS)]

            rule_code = lines[start].strip()
            title = ""
            severity = ""
            body_lines: list[str] = []
            evidence_terms: list[str] = []
            section = "title"

            for ln in block_lines:
                if _LABEL_REQUIREMENT.match(ln):
                    section = "requirement"
                    continue
                if _LABEL_EVIDENCE_TERMS.match(ln):
                    section = "evidence"
                    continue

                if section == "title" and not title:
                    sev_match = _TITLE_SEVERITY.search(ln)
                    if sev_match:
                        severity = sev_match.group(1).title()
                        title = ln[:sev_match.start()].strip()
                    else:
                        title = ln
                elif section == "requirement" and len(body_lines) < 10:
                    body_lines.append(ln)
                elif section == "evidence" and len(evidence_terms) < 5:
                    # Evidence-terms lines are semicolon-delimited by
                    # convention; a line with no ";" here is virtually
                    # always a page header/footer that bled in across a
                    # PDF page boundary (nothing else separates this block
                    # from the next rule code), so it's skipped rather
                    # than captured as a bogus extra "term".
                    if ";" in ln:
                        evidence_terms.extend(t.strip() for t in ln.split(";") if t.strip())
                        # Evidence-terms is always a single line in this
                        # format; stopping here (rather than continuing to
                        # the end of the block) keeps trailing document
                        # content out — page footers between rules, and,
                        # for the very last rule in a document (which has
                        # no following rule-code line to bound it), entire
                        # unrelated sections that follow the rule list.
                        break

            requirement_text = " ".join(body_lines).strip()
            if not requirement_text:
                # No parseable "Requirement" body under this code — nothing
                # actionable to evaluate, so skip it rather than emitting
                # an empty pseudo-rule.
                continue

            req_id = rule_code
            if any(r.id == req_id for r in requirements):
                # Same rule code reused within one document — keep ids
                # unique rather than silently overwriting one rule with
                # another's evidence.
                req_id = f"{rule_code}#{start + 1}"

            requirements.append(Requirement(
                id=req_id,
                text=requirement_text,
                source=filename,
                line_number=start + 1,
                raw_text=" ".join(block_lines),
                title=title,
                severity=severity,
                evidence_terms=evidence_terms,
            ))

        return requirements or None

    def extract_actionable_requirements(self) -> list[Requirement]:
        """Extract actionable requirements from documents with caching.

        PDFs/DOCX wrap a single sentence across several visual lines, so
        checking each physical line independently (the previous approach)
        regularly truncated a requirement mid-clause — losing exactly the
        word that would have matched. This accumulates lines into a
        sentence buffer until it hits terminal punctuation before testing
        it, and skips sections that describe the analysis tool's own
        behavior rather than a requirement on the scanned application.
        """
        docs = self.list_documents()
        requirements: list[Requirement] = []
        req_counter = 1

        for doc in docs:
            file_path = Path(doc["path"])
            cache_key = f"{doc['path']}_{doc['mtime']}"

            if cache_key in self._cache:
                requirements.extend(self._cache[cache_key]["requirements"])
                continue

            try:
                raw_content = _read_document_text(file_path)
                lines = raw_content.splitlines()
                doc_requirements: list[Requirement] = []

                structured = self._extract_structured_blocks(lines, doc["filename"])
                if structured is not None:
                    # Guard against a rule code colliding with one already
                    # extracted from a *different* uploaded document —
                    # ids must stay stable and unique across the whole
                    # result set, never array-index-based.
                    existing_ids = {r.id for r in requirements}
                    for req in structured:
                        if req.id in existing_ids:
                            req.id = f"{doc['filename']}:{req.id}"
                        existing_ids.add(req.id)
                    doc_requirements = structured
                    self._cache[cache_key] = {"requirements": doc_requirements}
                    requirements.extend(doc_requirements)
                    continue

                in_excluded_section = False
                buffer = ""
                buffer_start_line = 0
                buffer_raw_parts: list[str] = []

                def flush() -> None:
                    nonlocal buffer, buffer_start_line, buffer_raw_parts, req_counter
                    text = buffer.strip()
                    if text and len(text) >= 12 and not in_excluded_section:
                        if (ACTIONABLE_PATTERNS.search(text)
                                or RESTRICTION_PATTERNS.search(text)
                                or text.lower().startswith("rule")):
                            doc_requirements.append(Requirement(
                                id=f"REQ-{req_counter:03d}",
                                text=text,
                                source=doc["filename"],
                                line_number=buffer_start_line,
                                raw_text=" ".join(buffer_raw_parts).strip(),
                            ))
                            req_counter += 1
                    buffer = ""
                    buffer_raw_parts = []

                for idx, raw_line in enumerate(lines, start=1):
                    stripped_raw = raw_line.strip()

                    heading_match = _SECTION_HEADING.match(stripped_raw)
                    if heading_match:
                        # Section boundary: flush whatever sentence was
                        # mid-assembly, then decide if the new section is
                        # in scope at all.
                        flush()
                        in_excluded_section = bool(
                            _EXCLUDED_SECTION_TITLES.search(heading_match.group(1)))
                        continue

                    cleaned = self._clean_line(raw_line)
                    if not cleaned:
                        continue

                    if not buffer:
                        buffer_start_line = idx
                    buffer = f"{buffer} {cleaned}".strip() if buffer else cleaned
                    buffer_raw_parts.append(raw_line.strip())

                    # A line ending in terminal punctuation completes the
                    # sentence being assembled; anything else is a wrapped
                    # continuation and should keep accumulating.
                    if re.search(r"[.!?:]\s*$", cleaned):
                        flush()

                flush()  # trailing partial sentence at end of document

                # Cache extracted requirements for this file
                self._cache[cache_key] = {"requirements": doc_requirements}
                requirements.extend(doc_requirements)

            except Exception as err:
                log.warning(f"Failed to read/extract requirements from {doc['filename']}: {err}")

        return requirements
