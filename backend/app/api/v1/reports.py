"""
Reports API Endpoint
====================
Provides report rendering, formatting, and file download capabilities (JSON, SARIF, HTML, CSV, PDF, ZIP).
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from typing import Any, Dict, Optional
from fastapi import APIRouter, Body, HTTPException, Query, Response
from fastapi.responses import StreamingResponse

from guardian.core.registry import load_builtin_plugins
from guardian.reasoning.tools import _ACTIVE_FINDINGS
from backend.app.api.v1.scans import _SCANS_STORE

router = APIRouter(prefix="/reports", tags=["reports"])


def _get_latest_report() -> Dict[str, Any]:
    if not _SCANS_STORE:
        return {
            "scan": {
                "target": "Sample Repository",
                "files_scanned": 12,
                "total_findings": len(_ACTIVE_FINDINGS),
                "by_severity": {"Critical": 1, "High": 2, "Medium": 3},
                "by_category": {"SQL Injection": 1, "Weak Crypto": 2},
                "findings": [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in _ACTIVE_FINDINGS.values()],
            },
            "unified_risk": {
                "security_score": 78.5,
                "alignment_score": 90.0,
                "quantum_readiness_score": 85.0,
                "dependency_risk_score": 95.0,
                "overall_risk_score": 82.0,
                "merge_decision": "Warn",
                "dimensions": {
                    "weights": {"security": 0.4, "alignment": 0.3, "quantum": 0.2, "dependencies": 0.1},
                    "security": 78.5, "alignment": 90.0, "quantum": 85.0, "dependencies": 95.0,
                }
            },
            "quantum": {
                "readiness_score": 85.0,
                "total_occurrences": 3,
                "total_algorithms": 2,
                "unresolved_call_sites": 0,
                "entries": [
                    {
                        "algorithm": "MD5",
                        "status": "classically_broken",
                        "occurrences": 2,
                        "operations": ["Hashing"],
                        "files": ["utils/crypto.py"],
                        "migration_target": "SHA-256",
                        "nist_standard": "FIPS 180-4",
                        "rationale": "MD5 is collision-broken",
                    }
                ]
            },
            "business_intent": {
                "status": "analyzed",
                "alignment_score": 90.0,
                "policies": {"checkable": 4, "policies": []},
                "documents": ["SRS.md"],
                "verdicts": [
                    {
                        "verdict": "COMPLIANT",
                        "policy": "Manager approval for high refunds",
                        "requirement": "Refunds above 50,000 require manager approval",
                        "implementations": [{"file": "services/payment.py", "line": 42, "function": "processRefund"}]
                    }
                ]
            }
        }
    latest_key = list(_SCANS_STORE.keys())[-1]
    return _SCANS_STORE[latest_key]


@router.get("/summary", response_model=Dict[str, Any])
async def get_report_summary():
    try:
        return _get_latest_report()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report summary: {str(e)}")


def _render_download(report: Dict[str, Any], format: str):
    """Render `report` (whatever dict is passed in) to a downloadable
    response. Shared by both download routes below so the GET (server-side
    state) and POST (caller-supplied, exact-match) paths behave identically
    once a report dict is in hand."""
    registry = load_builtin_plugins()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if format.lower() == "zip":
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            root = f"acg_scan_{ts}"
            zf.writestr(f"{root}/full_report.json", json.dumps(report, indent=2, default=str))
            for fmt in ("csv", "sarif", "html"):
                reporter = registry.reporter(fmt)
                if reporter:
                    try:
                        zf.writestr(f"{root}/guardian_report{reporter.file_extension}", reporter.render(report))
                    except Exception:
                        pass
        buf.seek(0)
        return StreamingResponse(
            buf,
            media_type="application/zip",
            headers={"Content-Disposition": f"attachment; filename=acg_scan_{ts}.zip"}
        )

    reporter = registry.reporter(format.lower())
    if not reporter and format.lower() != "json":
        raise HTTPException(status_code=400, detail=f"Unsupported format '{format}'.")

    if format.lower() == "json":
        content = json.dumps(report, indent=2, default=str)
        ext = ".json"
        media = "application/json"
    else:
        content = reporter.render(report)
        ext = reporter.file_extension
        media = "application/octet-stream"

    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f"attachment; filename=guardian_report_{ts}{ext}"}
    )


@router.get("/download")
async def download_report(
    format: str = Query("json", description="Format: json, sarif, html, csv, pdf, zip")
):
    """Download the backend's own last-known scan (_SCANS_STORE). This is a
    fallback for bookmarked/shared links -- it is only as fresh as the last
    scan this server process ran, and resets on every restart. The UI itself
    should call POST /reports/download instead, which always matches what's
    on screen."""
    return _render_download(_get_latest_report(), format)


@router.post("/download")
async def download_report_from_payload(
    report: Dict[str, Any] = Body(..., description="The report JSON currently shown in the UI"),
    format: str = Query("json", description="Format: json, sarif, html, csv, pdf, zip"),
):
    """Render a downloadable report from the exact payload the caller
    supplies, instead of whatever this server process last happened to
    scan. This is what the frontend's Download button uses -- it guarantees
    the file always matches the scores and findings on screen, never a
    stale or placeholder server-side result."""
    return _render_download(report, format)


@router.post("/agentic-download")
async def download_agentic_report(
    agentic: Dict[str, Any] = Body(..., description="Curated AgentWorkflowState for the completed agentic run, exactly as the Agentic Scan tab holds it (see useAgenticScan.ts)."),
    deterministic: Optional[Dict[str, Any]] = Body(None, description="The deterministic scan report dict (same shape as _SCANS_STORE entries) to include alongside the agentic sections. Omit for an Agentic-only report."),
    deterministic_scan_id: Optional[str] = Body(
        None,
        description="scan_id of the deterministic scan that fed this agentic run (agentic.source_scan_id). "
                    "Surfaced prominently in the report header so it clearly references the real deterministic "
                    "scan being reasoned over -- proof the agentic layer did not run independently.",
    ),
):
    """Lightweight HTML export for the agentic analysis -- a NEW, separate
    rendering path (guardian/reporting/agentic_html_reporter.py) that does
    not touch guardian/reporting/pdf_reporter.py or any existing
    deterministic reporter. `deterministic` present -> Unified Report
    (deterministic findings + agentic sections); absent -> Agentic Report
    (agentic sections only). Real PDF generation for these two is a later
    pass -- for now this is a clean, printable HTML document."""
    from guardian.reporting.agentic_html_reporter import render_agentic_report_html

    html_content = render_agentic_report_html(agentic, deterministic, deterministic_scan_id)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"guardian_{'unified' if deterministic else 'agentic'}_report_{ts}.html"
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/layman-download")
@router.get("/layman-download")
async def download_layman_report(
    report: Optional[Dict[str, Any]] = Body(None, description="Report JSON currently shown in the UI")
):
    """Generates a plain-English Layman Executive Report in HTML format."""
    from guardian.reporting.layman_reporter import render_layman_report_html
    
    target_report = report or _get_latest_report()
    html_content = render_layman_report_html(target_report)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"guardian_executive_layman_report_{ts}.html"
    return Response(
        content=html_content,
        media_type="text/html",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

