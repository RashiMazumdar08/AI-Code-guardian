"""
FastAPI Router for Business Intent Engine API
=============================================
Provides REST endpoints:
  POST /api/business-intent/analyze
  POST /api/v1/business-intent/analyze
  GET  /api/v1/business-intent/docs
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Query, Form, File, UploadFile
from guardian.intent.engine import BusinessIntentEngine
from guardian.intent.ingestion.document_loader import DocumentLoader, get_business_docs_dir, get_workspace_id

logger = logging.getLogger("guardian.api.business_intent")

_WORKSPACE_BUSINESS_RESULTS: dict[str, dict[str, Any]] = {}


def get_workspace_business_result(workspace_id: str | None) -> dict[str, Any] | None:
    """Retrieve the cached deterministic business intent analysis for a workspace if present."""
    if not workspace_id:
        return None
    ws_id = get_workspace_id(workspace_id)
    return _WORKSPACE_BUSINESS_RESULTS.get(ws_id)


router = APIRouter(tags=["business-intent"])


@router.get("/api/business-intent/result")
@router.get("/business-intent/result")
async def get_business_intent_result_endpoint(
    workspace_id: str | None = Query(None),
    repo_path: str | None = Query(None),
    scan_id: str | None = Query(None)
):
    """Retrieve cached deterministic business intent analysis result for a workspace."""
    ws_id = get_workspace_id(workspace_id or repo_path or scan_id)
    res = get_workspace_business_result(ws_id)
    if res:
        return res
    return {
        "status": "NO_DOCUMENTS",
        "alignment_score": 0.0,
        "total_rules": 0,
        "matched": 0,
        "violated": 0,
        "partial": 0,
        "findings": []
    }


@router.post("/api/business-intent/analyze")
@router.post("/business-intent/analyze")
async def analyze_business_intent(payload: dict[str, Any] = Body(default={})):
    """Runs the Business Intent Engine against uploaded documents in environment-scoped /data/business_docs/{workspace_id}/."""
    try:
        findings = payload.get("findings", [])
        workspace_id = payload.get("workspace_id") or payload.get("repo_path") or payload.get("scan_id")
        ws_id = get_workspace_id(workspace_id)
        engine = BusinessIntentEngine(workspace_id=ws_id)
        result = engine.run(scan_findings=findings, workspace_id=ws_id)
        if ws_id and ws_id != "unbound_workspace":
            _WORKSPACE_BUSINESS_RESULTS[ws_id] = result
        return result
    except Exception as e:
        logger.error(f"Error executing business intent analysis: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": str(e),
            "alignment_score": 0.0,
            "total_rules": 0,
            "matched": 0,
            "violated": 0,
            "partial": 0,
            "findings": []
        }


@router.get("/api/business-intent/docs")
@router.get("/business-intent/docs")
async def list_business_docs(workspace_id: str | None = Query(None), repo_path: str | None = Query(None)):
    """List all documents currently in the environment-scoped /data/business_docs/{workspace_id}/ folder."""
    try:
        ws_id = get_workspace_id(workspace_id or repo_path)
        loader = DocumentLoader(workspace_id=ws_id)
        docs = loader.list_documents()
        docs_dir = get_business_docs_dir(workspace_id=ws_id)
        return {
            "folder_path": str(docs_dir),
            "workspace_id": ws_id,
            "count": len(docs),
            "files": docs
        }
    except Exception as e:
        return {
            "folder_path": "/data/business_docs/",
            "count": 0,
            "files": [],
            "error": str(e)
        }


@router.post("/api/business-intent/upload")
@router.post("/business-intent/upload")
async def upload_business_doc(
    file: UploadFile = File(...),
    workspace_id: str | None = Form(None),
    repo_path: str | None = Form(None)
):
    """Upload a business requirement document directly into environment-scoped /data/business_docs/{workspace_id}/.
    Uploading a new document in an environment replaces previous documents in that environment."""
    try:
        ws_id = get_workspace_id(workspace_id or repo_path)
        if ws_id == "unbound_workspace":
            return {
                "status": "ERROR",
                "message": "An active repository or scan context is required to upload business requirements.",
                "files": []
            }
        loader = DocumentLoader(workspace_id=ws_id)
        # Clear previous documents for this environment so old rules/findings are replaced
        loader.clear_documents()

        docs_dir = get_business_docs_dir(workspace_id=ws_id)
        file_path = docs_dir / file.filename
        content = await file.read()
        file_path.write_bytes(content)
        logger.info(f"Successfully uploaded business doc {file.filename} to {file_path} for workspace {ws_id}")

        # List updated docs
        docs = loader.list_documents()

        return {
            "status": "SUCCESS",
            "filename": file.filename,
            "workspace_id": ws_id,
            "message": f"Successfully uploaded {file.filename} to {docs_dir}",
            "files": [d["filename"] for d in docs]
        }
    except Exception as e:
        logger.error(f"Failed to upload business doc {file.filename}: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": f"Failed to upload document: {str(e)}"
        }


@router.delete("/api/business-intent/docs/{filename:path}")
@router.delete("/business-intent/docs/{filename:path}")
@router.post("/api/business-intent/delete")
@router.post("/business-intent/delete")
async def delete_business_doc(
    filename: str = "",
    workspace_id: str | None = Query(None),
    repo_path: str | None = Query(None),
    payload: dict[str, Any] = Body(default={})
):
    """Deletes a business requirement document from environment-scoped /data/business_docs/{workspace_id}/."""
    target_name = filename or payload.get("filename") or payload.get("file_name")
    ws_id = get_workspace_id(workspace_id or repo_path or payload.get("workspace_id") or payload.get("repo_path"))
    if not target_name:
        return {"status": "ERROR", "message": "Filename parameter required"}

    try:
        docs_dir = get_business_docs_dir(workspace_id=ws_id)
        target_path = docs_dir / Path(target_name).name

        if target_path.exists():
            target_path.unlink()
            logger.info(f"Successfully deleted business doc {target_name} from {target_path} in workspace {ws_id}")

        # Refresh document list
        loader = DocumentLoader(workspace_id=ws_id)
        docs = loader.list_documents()

        return {
            "status": "SUCCESS",
            "filename": target_name,
            "workspace_id": ws_id,
            "message": f"Successfully removed {target_name}",
            "files": [d["filename"] for d in docs]
        }
    except Exception as e:
        logger.error(f"Failed to delete business doc {target_name}: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": f"Failed to delete document: {str(e)}"
        }


