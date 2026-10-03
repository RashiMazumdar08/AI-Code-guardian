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
    area: str = ""
    required_control: str = ""
    expected_implementation_behavior: str = ""
    violation_conditions: str = ""
    compliant_conditions: str = ""
    suggested_validation: str = ""


def get_workspace_id(path_or_id: str | Path | None = None) -> str:
    """Derive a deterministic environment/workspace identifier."""
    if not path_or_id:
        return "unbound_workspace"
    p_str = str(path_or_id).strip()
    if not p_str or p_str.lower() in ("default", "unbound", "none", "null"):
        return "unbound_workspace"
    if re.match(r"^[a-zA-Z0-9_\-]+$", p_str) and not any(c in p_str for c in ("/", "\\", ":")):
        return p_str.lower()
    p_res = str(Path(p_str).resolve()).lower()
    return hashlib.sha256(p_res.encode("utf-8")).hexdigest()[:12]


def get_business_docs_dir(custom_path: str | Path | None = None, workspace_id: str | None = None) -> Path:
    """Resolve the business documents directory path, scoped by workspace/environment."""
    if custom_path:
        p = Path(custom_path)
        p.mkdir(parents=True, exist_ok=True)
        return p

    ws_id = get_workspace_id(workspace_id)
    workspace_root = Path.cwd()
    env_dir = workspace_root / "data" / "business_docs" / ws_id
    env_dir.mkdir(parents=True, exist_ok=True)
    return env_dir


class DocumentLoader:
    """Smart document loader with cleaning, actionable sentence extraction, and caching."""

    SUPPORTED_EXTENSIONS = {".md", ".txt", ".json", ".csv", ".yaml", ".yml", ".docx", ".pdf"}

    def __init__(self, docs_dir: str | Path | None = None, workspace_id: str | None = None):
        self.docs_dir = get_business_docs_dir(docs_dir, workspace_id)
        self._cache: dict[str, dict[str, Any]] = {}

    def clear_documents(self) -> None:
        """Clear all documents in this environment's directory and invalidate cache."""
        if self.docs_dir.exists():
            for f in self.docs_dir.glob("*"):
                if f.is_file():
                    try:
                        f.unlink()
                    except Exception as exc:
                        log.warning(f"Failed to unlink {f}: {exc}")
        self._cache.clear()

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

    def _extract_canonical_rule_document(self, lines: list[str], filename: str) -> list[Requirement] | None:
        """Parse documents structured around canonical rule headings like:
        'BR-001 — Parameterized SQL Queries [Critical]' or
        'REQ-001 — Cart Quantity and Inventory Validation'.
        
        Extracts exactly the canonical rule sections, enriches metadata from summary tables,
        splits subsections (Requirement, Expected Evidence, Evidence Terms, Violation/Compliant Conditions, Suggested Validation),
        and excludes non-rule sections (Business Intent Result Semantics, Evidence isolation, Source basis, Repository scope, Evidence policy).
        """
        canonical_pattern = re.compile(
            r"^\s*([A-Z]{2,8}-\d{2,4})\s*[—\-\:\–\−]\s*(.+)$", re.IGNORECASE
        )
        non_rule_pattern = re.compile(
            r"(?i)^\s*(business\s+intent\s+result\s+semantics|evidence\s+isolation|source\s+basis|repository\s+scope|evidence\s+policy|recommended\s+ai\s+code\s+guardian\s+test|source\s+note|repository|testing\s+notes|usage\s+note|appendix|purpose|document\s+metadata)\b"
        )
        
        canonical_indices: list[tuple[int, str, str, str]] = []
        for idx, ln in enumerate(lines):
            stripped = ln.strip()
            m = canonical_pattern.match(stripped)
            if m:
                req_id = m.group(1).upper()
                raw_title = m.group(2).strip()
                severity = ""
                sev_match = re.search(r"\[(Critical|High|Medium|Low)\]$", raw_title, re.IGNORECASE)
                if sev_match:
                    severity = sev_match.group(1).title()
                    raw_title = raw_title[:sev_match.start()].strip()
                canonical_indices.append((idx, req_id, raw_title, severity))
                
        if not canonical_indices:
            return None
            
        first_heading_idx = canonical_indices[0][0]
        
        # Summary table metadata parsing prior to first canonical detailed heading
        summary_meta: dict[str, dict[str, str]] = {}
        summary_lines = [ln.strip() for ln in lines[:first_heading_idx]]
        for i, ln in enumerate(summary_lines):
            m_code = re.match(r"^([A-Z]{2,8}-\d{2,4})$", ln, re.IGNORECASE)
            if m_code:
                rule_code = m_code.group(1).upper()
                field1 = summary_lines[i + 1] if i + 1 < len(summary_lines) else ""
                field2 = summary_lines[i + 2] if i + 2 < len(summary_lines) else ""
                sev = ""
                if field1 in ("Critical", "High", "Medium", "Low"):
                    sev = field1
                elif field2 in ("Critical", "High", "Medium", "Low"):
                    sev = field2
                summary_meta[rule_code] = {"title": field1, "severity": sev}
                    
        requirements: list[Requirement] = []
        for b_idx, (start, req_id, title, heading_severity) in enumerate(canonical_indices):
            end = canonical_indices[b_idx + 1][0] if b_idx + 1 < len(canonical_indices) else len(lines)
            
            # Truncate block if a non-rule section heading appears before next canonical section
            for l_idx in range(start + 1, end):
                if non_rule_pattern.match(lines[l_idx].strip()):
                    end = l_idx
                    break
                    
            block_lines = lines[start + 1:end]
            req_lines, exp_lines, viol_lines, val_lines = [], [], [], []
            evidence_terms: list[str] = []
            curr_sec = "req"
            
            for ln in block_lines:
                s_ln = ln.strip()
                if not s_ln or s_ln.startswith("Page ") or s_ln.startswith("AI Code Guardian") or ("Business Rules" in s_ln and "fixture" in s_ln):
                    continue

                req_lbl = re.match(r"(?i)^(?:business\s+)?requirement(?:\s*\:)?(?:\s+(.*))?$", s_ln)
                exp_lbl = re.match(r"(?i)^expected\s+(?:evidence|implementation\s+behavior|behavior)(?:\s*\:)?(?:\s+(.*))?$", s_ln)
                ev_lbl = re.match(r"(?i)^evidence\s+terms(?:\s*\:)?(?:\s+(.*))?$", s_ln)
                viol_lbl = re.match(r"(?i)^violation\s*/?\s*compliant\s+conditions?(?:\s*\:)?(?:\s+(.*))?$", s_ln) or re.match(r"(?i)^violation\s+conditions?(?:\s*\:)?(?:\s+(.*))?$", s_ln)
                val_lbl = re.match(r"(?i)^suggested\s+validation(?:\s*\:)?(?:\s+(.*))?$", s_ln)

                if req_lbl:
                    curr_sec = "req"
                    if req_lbl.group(1):
                        req_lines.append(req_lbl.group(1).strip())
                    continue
                elif exp_lbl:
                    curr_sec = "exp"
                    if exp_lbl.group(1):
                        exp_lines.append(exp_lbl.group(1).strip())
                    continue
                elif ev_lbl:
                    curr_sec = "evidence"
                    if ev_lbl.group(1):
                        t_str = ev_lbl.group(1).strip()
                        evidence_terms.extend(t.strip() for t in re.split(r"[;,]", t_str) if t.strip() and not t.strip().startswith("AI Code Guardian"))
                    continue
                elif viol_lbl:
                    curr_sec = "viol"
                    if viol_lbl.group(1):
                        viol_lines.append(viol_lbl.group(1).strip())
                    continue
                elif val_lbl:
                    curr_sec = "val"
                    if val_lbl.group(1):
                        val_lines.append(val_lbl.group(1).strip())
                    continue

                if curr_sec == "req":
                    req_lines.append(s_ln)
                elif curr_sec == "exp":
                    exp_lines.append(s_ln)
                elif curr_sec == "evidence":
                    if ";" in s_ln or "," in s_ln:
                        evidence_terms.extend(t.strip() for t in re.split(r"[;,]", s_ln) if t.strip() and not t.strip().startswith("AI Code Guardian"))
                    elif not s_ln.startswith("AI Code Guardian") and not s_ln.startswith("Page "):
                        evidence_terms.append(s_ln)
                elif curr_sec == "viol":
                    viol_lines.append(s_ln)
                elif curr_sec == "val":
                    val_lines.append(s_ln)

            req_text = " ".join(req_lines).strip()
            exp_text = " ".join(exp_lines).strip()
            viol_comp_text = " ".join(viol_lines).strip()
            val_text = " ".join(val_lines).strip()

            violation_cond = ""
            compliant_cond = ""
            if "Violation:" in viol_comp_text or "Compliant:" in viol_comp_text:
                parts = re.split(r"(?i)\b(Violation:|Compliant:)\b", viol_comp_text)
                curr_label = ""
                for p in parts:
                    p_s = p.strip()
                    if p_s.lower() == "violation:":
                        curr_label = "viol"
                    elif p_s.lower() == "compliant:":
                        curr_label = "comp"
                    elif curr_label == "viol":
                        violation_cond += (" " if violation_cond else "") + p_s
                    elif curr_label == "comp":
                        compliant_cond += (" " if compliant_cond else "") + p_s
                violation_cond = violation_cond.strip()
                compliant_cond = compliant_cond.strip()
            else:
                violation_cond = viol_comp_text

            meta = summary_meta.get(req_id, {})
            final_severity = heading_severity or meta.get("severity", "")

            requirements.append(Requirement(
                id=req_id,
                text=req_text or title,
                source=filename,
                line_number=start + 1,
                raw_text=" ".join(block_lines),
                title=title,
                severity=final_severity,
                evidence_terms=evidence_terms,
                area=meta.get("area", ""),
                required_control=meta.get("required_control", ""),
                expected_implementation_behavior=exp_text,
                violation_conditions=violation_cond,
                compliant_conditions=compliant_cond,
                suggested_validation=val_text,
            ))
            
        return requirements or None

    def extract_actionable_requirements(self) -> list[Requirement]:
        """Extract actionable requirements from documents with caching."""
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

                canonical = self._extract_canonical_rule_document(lines, doc["filename"])
                if canonical is not None:
                    existing_ids = {r.id for r in requirements}
                    for req in canonical:
                        if req.id in existing_ids:
                            req.id = f"{doc['filename']}:{req.id}"
                        existing_ids.add(req.id)
                    doc_requirements = canonical
                    self._cache[cache_key] = {"requirements": doc_requirements}
                    requirements.extend(doc_requirements)
                    continue

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
