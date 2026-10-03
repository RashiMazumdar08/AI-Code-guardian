import sys
import os
import re
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from guardian.intent.ingestion.document_loader import _read_document_text

def test_full_parse():
    pdf_path = Path("data/business_docs/DV_Bookshop_Business_Rules.pdf")
    raw_text = _read_document_text(pdf_path)
    lines = raw_text.splitlines()

    _CANONICAL_HEADING = re.compile(r"^\s*(REQ-\d{3,4})\s*[—\-\:]\s*(.+)$", re.IGNORECASE)
    _NON_RULE_SECTION_HEADING = re.compile(
        r"(?i)^\s*(recommended\s+ai\s+code\s+guardian\s+test|source\s+note|repository|testing\s+notes|usage\s+note|appendix)\b"
    )

    canonical_indices = []
    for idx, ln in enumerate(lines):
        m = _CANONICAL_HEADING.match(ln.strip())
        if m:
            canonical_indices.append((idx, m.group(1).upper(), m.group(2).strip()))

    if not canonical_indices:
        print("No canonical headings")
        return

    first_heading_idx = canonical_indices[0][0]

    # Summary table parsing
    summary_meta = {}
    summary_lines = [ln.strip() for ln in lines[:first_heading_idx]]
    for i, ln in enumerate(summary_lines):
        m = re.match(r"^(REQ-\d{3,4})$", ln, re.IGNORECASE)
        if m:
            req_id = m.group(1).upper()
            area = summary_lines[i+1] if i+1 < len(summary_lines) else ""
            ctrl = summary_lines[i+2] if i+2 < len(summary_lines) else ""
            if not _CANONICAL_HEADING.match(area) and not re.match(r"^(REQ-\d{3,4})$", area):
                summary_meta[req_id] = {"area": area, "required_control": ctrl}

    print("Summary table metadata:", summary_meta)

    # Detailed Rule Extraction
    rules = []
    for b_idx, (start, req_id, title) in enumerate(canonical_indices):
        end = canonical_indices[b_idx + 1][0] if b_idx + 1 < len(canonical_indices) else len(lines)
        
        # Check if non-rule section exists before end
        for l_idx in range(start + 1, end):
            if _NON_RULE_SECTION_HEADING.match(lines[l_idx].strip()):
                end = l_idx
                break

        block_lines = lines[start + 1 : end]
        
        # Parse subsections
        req_lines, exp_lines, viol_lines, val_lines = [], [], [], []
        curr_sec = "req"

        for ln in block_lines:
            s_ln = ln.strip()
            if not s_ln or s_ln.startswith("Page ") or "Business Rules" in s_ln and "fixture" in s_ln:
                continue
            if re.match(r"(?i)^business\s+requirement$", s_ln) or re.match(r"(?i)^requirement$", s_ln):
                curr_sec = "req"
                continue
            elif re.match(r"(?i)^expected\s+implementation\s+behavior$", s_ln) or re.match(r"(?i)^implementation\s+behavior$", s_ln):
                curr_sec = "exp"
                continue
            elif re.match(r"(?i)^violation\s*/?\s*compliant\s+conditions?$", s_ln) or re.match(r"(?i)^violation\s+conditions?$", s_ln):
                curr_sec = "viol"
                continue
            elif re.match(r"(?i)^suggested\s+validation", s_ln):
                curr_sec = "val"
                continue

            if curr_sec == "req":
                req_lines.append(s_ln)
            elif curr_sec == "exp":
                exp_lines.append(s_ln)
            elif curr_sec == "viol":
                viol_lines.append(s_ln)
            elif curr_sec == "val":
                val_lines.append(s_ln)

        req_text = " ".join(req_lines).strip()
        exp_text = " ".join(exp_lines).strip()
        viol_comp_text = " ".join(viol_lines).strip()
        val_text = " ".join(val_lines).strip()

        # Split violation / compliant text if combined
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
                    violation_cond += " " + p_s
                elif curr_label == "comp":
                    compliant_cond += " " + p_s
            violation_cond = violation_cond.strip()
            compliant_cond = compliant_cond.strip()
        else:
            violation_cond = viol_comp_text

        meta = summary_meta.get(req_id, {})
        rules.append({
            "id": req_id,
            "title": title,
            "requirement_text": req_text,
            "expected_behavior": exp_text,
            "violation_conditions": violation_cond,
            "compliant_conditions": compliant_cond,
            "suggested_validation": val_text,
            "area": meta.get("area", ""),
            "required_control": meta.get("required_control", ""),
        })

    print(f"\nExtracted Rules ({len(rules)}):")
    for r in rules:
        print(f"\n[{r['id']}] {r['title']}")
        print(f"  Area: {r['area']} | Required Control: {r['required_control']}")
        print(f"  Requirement Text: {r['requirement_text']}")
        print(f"  Expected Behavior: {r['expected_behavior']}")
        print(f"  Violation Conditions: {r['violation_conditions']}")
        print(f"  Compliant Conditions: {r['compliant_conditions']}")

if __name__ == "__main__":
    test_full_parse()
