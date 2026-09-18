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

from fastapi import APIRouter, Body
from guardian.intent.engine import BusinessIntentEngine
from guardian.intent.ingestion.document_loader import DocumentLoader, get_business_docs_dir

logger = logging.getLogger("guardian.api.business_intent")

router = APIRouter(tags=["business-intent"])


@router.post("/api/business-intent/analyze")
@router.post("/business-intent/analyze")
async def analyze_business_intent(payload: dict[str, Any] = Body(default={})):
    """Runs the Business Intent Engine against uploaded documents in /data/business_docs/."""
    try:
        findings = payload.get("findings", [])
        engine = BusinessIntentEngine()
        result = engine.run(scan_findings=findings)
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
async def list_business_docs():
    """List all documents currently in the /data/business_docs/ folder."""
    try:
        loader = DocumentLoader()
        docs = loader.list_documents()
        docs_dir = get_business_docs_dir()
        return {
            "folder_path": str(docs_dir),
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


from fastapi import File, UploadFile

@router.post("/api/business-intent/upload")
@router.post("/business-intent/upload")
async def upload_business_doc(file: UploadFile = File(...)):
    """Upload a business requirement document directly into /data/business_docs/."""
    try:
        docs_dir = get_business_docs_dir()
        file_path = docs_dir / file.filename
        content = await file.read()
        file_path.write_bytes(content)
        logger.info(f"Successfully uploaded business doc {file.filename} to {file_path}")

        # List updated docs
        loader = DocumentLoader()
        docs = loader.list_documents()

        return {
            "status": "SUCCESS",
            "filename": file.filename,
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
async def delete_business_doc(filename: str = "", payload: dict[str, Any] = Body(default={})):
    """Deletes a business requirement document from /data/business_docs/."""
    target_name = filename or payload.get("filename") or payload.get("file_name")
    if not target_name:
        return {"status": "ERROR", "message": "Filename parameter required"}

    try:
        docs_dir = get_business_docs_dir()
        target_path = docs_dir / Path(target_name).name

        if target_path.exists():
            target_path.unlink()
            logger.info(f"Successfully deleted business doc {target_name} from {target_path}")

        # Refresh document list
        loader = DocumentLoader()
        docs = loader.list_documents()

        return {
            "status": "SUCCESS",
            "filename": target_name,
            "message": f"Successfully removed {target_name}",
            "files": [d["filename"] for d in docs]
        }
    except Exception as e:
        logger.error(f"Failed to delete business doc {target_name}: {e}", exc_info=True)
        return {
            "status": "ERROR",
            "message": f"Failed to delete document: {str(e)}"
        }


