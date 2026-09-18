"""
Scans API Endpoint
==================
Triggers and retrieves repository security scans wrapping `guardian.core.pipeline`.
"""
from __future__ import annotations

import asyncio
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field
import git

from guardian.core.pipeline import ScanPipeline
from guardian.reasoning.tools import register_scan_context
from guardian.intent.ingestion.document_loader import DocumentLoader

router = APIRouter(prefix="/scans", tags=["scans"])

# In-memory scan store (syncs with DB when available)
_SCANS_STORE: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target_path: Optional[str] = Field(None, description="Path to repository or directory to scan.")
    repo_url: Optional[str] = Field(None, description="GitHub repository URL to clone and scan.")
    scan_mode: str = Field("precision", description="Scan mode: 'precision' or 'recall'.")
    enable_ai: bool = Field(False, description="Enable Nemotron AI contextual reasoning.")
    requirements: Optional[List[str]] = Field(None, description="Optional requirements file paths.")


class ScanResponse(BaseModel):
    scan_id: str
    target: str
    scan_mode: str
    status: str
    files_scanned: int
    duration_seconds: float
    total_findings: int
    funnel_metrics: Dict[str, int]
    by_severity: Dict[str, int]
    by_category: Dict[str, int]


import logging
logger = logging.getLogger("guardian.api.scans")

@router.post("", response_model=Dict[str, Any])
async def trigger_scan(request: ScanRequest):
    try:
        if not request.target_path and not request.repo_url:
            raise HTTPException(status_code=400, detail="Must provide either target_path or repo_url.")

        scan_dir = ""
        target_input = (request.repo_url or request.target_path or "").strip()
        from guardian.discovery.github_service import is_github_url, GitHubService

        if request.repo_url or is_github_url(target_input):
            try:
                gh = GitHubService()
                fetched_path = gh.fetch_repository(target_input)
                scan_dir = str(fetched_path)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to clone repository: {str(e)}")
        else:
            scan_dir = request.target_path
            path = Path(scan_dir)
            if not path.exists():
                raise HTTPException(status_code=400, detail=f"Target path '{scan_dir}' does not exist.")

        pipeline = ScanPipeline()
        pipeline.config.enable_ai = request.enable_ai

        # If the caller didn't pass explicit requirement file paths, fall back
        # to whatever has been uploaded via the Business Intent tab so a plain
        # scan still runs real business-intent analysis instead of always
        # hitting the "no_requirements" no-op path.
        business_requirements = request.requirements
        if not business_requirements:
            try:
                business_requirements = [
                    doc["path"] for doc in DocumentLoader().list_documents()
                ] or None
            except Exception as exc:  # noqa: BLE001 — missing docs must not fail the scan
                logger.warning("Could not auto-load business documents for scan: %s", exc)
                business_requirements = None

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: pipeline.scan(
                repo_root=str(scan_dir),
                business_requirements=business_requirements,
            )
        )

        res_dict = result
        res_dict["scan_mode"] = request.scan_mode
        res_dict["target"] = str(scan_dir)
        # Additive only -- purely for the scan picker on the Agentic Scan
        # tab to show a human-readable time instead of just a scan_id.
        # Nothing existing reads/depends on this key being absent.
        res_dict["created_at"] = time.time()
        scan_id = f"scan_{len(_SCANS_STORE) + 1}"
        _SCANS_STORE[scan_id] = res_dict
        
        findings = result.get("scan", {}).get("findings", [])
        register_scan_context(findings)

        return {
            "status": "success",
            "scan_id": scan_id,
            "message": "Scan completed successfully.",
            "result": res_dict
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan execution error: {str(e)}")


@router.get("", response_model=List[Dict[str, Any]])
async def list_scans():
    return [{"scan_id": k, **v} for k, v in _SCANS_STORE.items()]


@router.get("/{scan_id}", response_model=Dict[str, Any])
async def get_scan(scan_id: str):
    if scan_id not in _SCANS_STORE:
        raise HTTPException(status_code=404, detail=f"Scan '{scan_id}' not found.")
    return _SCANS_STORE[scan_id]
