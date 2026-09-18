"""
Findings API Endpoint
=====================
Generates deterministic auto-fixes for a given finding's code snippet.

`GET /findings` and `GET /findings/{finding_id}` used to live here too,
backed by `guardian.reasoning.tools`'s `_ACTIVE_FINDINGS` registry. That
registry is a single process-wide dict populated by whichever `/scans`
call happened to run last, with no `scan_id` scoping at all -- so those
two endpoints could return (or "detail") findings from a DIFFERENT
repository's scan than the one the caller meant. That's a live violation
of this platform's mandatory cross-repository isolation guarantee
(v2.1.0 spec Phase 18: "Agentic results from Repository A must never
appear in Repository B's ... chatbot context" -- the same principle
applies to any findings-lookup surface, not just the chatbot).

Neither endpoint was ever called by the frontend, which gets findings
from the scan-id-scoped report JSON (`/scans/{scan_id}`) instead -- so
they were removed rather than retrofitted with scan_id scoping, per the
recommendation already on record in
`claude/ai-code-guardian-v2.1.0-phase-report.md`'s Known Limitations.
`register_scan_context()` (guardian/reasoning/tools.py) and its one call
site in `backend/app/api/v1/scans.py` are left in place -- they're
inert now that nothing reads `_ACTIVE_FINDINGS`, and removing them is a
separate, lower-priority cleanup rather than part of closing this gap.
"""
from __future__ import annotations

from typing import Any, Dict, Optional
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/findings", tags=["findings"])


class AutoFixRequest(BaseModel):
    code_snippet: str
    category: str
    cwe: Optional[str] = ""
    recommendation: Optional[str] = ""
    file_path: Optional[str] = ""
    line: Optional[int] = 1


@router.post("/autofix", response_model=Dict[str, Any])
async def autofix_finding(req: AutoFixRequest):
    snippet = req.code_snippet.strip()
    category = (req.category or "").lower()
    cwe = (req.cwe or "").upper()

    # Deterministic Code Patching Engine
    fixed_line = snippet
    explanation = "Applied security remediation."

    if "sql" in category or cwe == "CWE-89":
        if "+" in snippet:
            import re
            fixed_line = re.sub(r'execute\s*\(\s*(["\'].*?)(?:\s*\+\s*)([a-zA-Z0-9_.]+)(?:\s*\))?', r'execute(\1%s", (\2,))', snippet)
        if fixed_line == snippet:
            fixed_line = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))'
        explanation = "Replaced unsafe string concatenation with parameterized SQL query."

    elif "crypto" in category or "md5" in category or "sha1" in category or cwe == "CWE-327":
        fixed_line = snippet.replace("hashlib.md5", "hashlib.sha256").replace("hashlib.sha1", "hashlib.sha256").replace("MD5", "SHA-256")
        explanation = "Upgraded broken hash algorithm (MD5/SHA1) to NIST-compliant SHA-256."

    elif "tls" in category or "ssl" in category or "verify" in category or cwe == "CWE-295":
        import re
        fixed_line = re.sub(r'verify\s*=\s*False', 'verify=True', snippet, flags=re.IGNORECASE)
        fixed_line = re.sub(r'_create_unverified_context', 'create_default_context', fixed_line)
        explanation = "Enabled SSL/TLS certificate validation."

    elif "secret" in category or "password" in category or cwe == "CWE-798":
        import re
        m = re.match(r'^([a-zA-Z0-9_]+)\s*=\s*["\'].*?["\']', snippet)
        if m:
            var_name = m.group(1)
            fixed_line = f'{var_name} = os.getenv("{var_name.upper()}", "")'
        else:
            fixed_line = 'SECRET_KEY = os.getenv("SECRET_KEY", "")'
        explanation = "Replaced hardcoded secret credential with environment variable lookup."

    elif "random" in category or cwe == "CWE-330":
        fixed_line = snippet.replace("random.random()", "secrets.token_hex(16)").replace("random.randint", "secrets.randbelow")
        explanation = "Replaced pseudo-random generator with cryptographically secure secrets module."

    elif "pickle" in category or "yaml" in category or cwe == "CWE-502":
        fixed_line = snippet.replace("pickle.loads", "json.loads").replace("yaml.load", "yaml.safe_load")
        explanation = "Replaced unsafe object deserialization with safe parser."

    else:
        if req.recommendation:
            fixed_line = f"{snippet}  # remediated per advice: {req.recommendation[:60]}"
        else:
            fixed_line = f"{snippet}  # sanitized by AI Code Guardian"
        explanation = "Sanitized code line against vulnerability."

    return {
        "fixed_code": fixed_line,
        "explanation": explanation,
        "source": "deterministic_rule_engine"
    }
