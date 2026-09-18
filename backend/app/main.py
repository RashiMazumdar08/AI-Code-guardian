"""
AI Code Guardian - Async FastAPI Application
=============================================
REST API Backend wrapping guardian scanner, PostgreSQL/pgvector persistence, and Nemotron AI reasoning.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.v1.agentic_scan import router as agentic_scan_router
from backend.app.api.v1.chat import router as chat_router
from backend.app.api.v1.files import router as files_router
from backend.app.api.v1.findings import router as findings_router
from backend.app.api.v1.reports import router as reports_router
from backend.app.api.v1.scans import router as scans_router
from backend.app.core.config import settings

from contextlib import asynccontextmanager
import logging
from guardian.db.session import init_db

logger = logging.getLogger("guardian.api")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing PostgreSQL database tables...")
    try:
        success = await init_db()
        if success:
            logger.info("PostgreSQL database tables initialized successfully.")
        else:
            logger.info("PostgreSQL unreachable or offline; using in-memory fallback store.")
    except Exception as e:
        logger.warning(f"Database initialization warning: {e}")
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url=f"{settings.API_V1_STR}/docs",
    redoc_url=f"{settings.API_V1_STR}/redoc",
    lifespan=lifespan,
)

# Set up CORS
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        # Content-Disposition isn't on the browser's default CORS-safelisted
        # response headers, so cross-origin fetch() calls (frontend on :3000
        # calling the API on :8000) can't read it unless it's explicitly
        # exposed here. Without this, res.headers.get("Content-Disposition")
        # on the report-download response silently returns null.
        expose_headers=["Content-Disposition"],
    )

from fastapi import Request
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger("guardian.api")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal Server Error: {str(exc)}"},
    )

from backend.app.api.v1.business_intent import router as business_intent_router

# Include v1 Routers
app.include_router(scans_router, prefix=settings.API_V1_STR)
app.include_router(agentic_scan_router, prefix=settings.API_V1_STR)
app.include_router(files_router, prefix=settings.API_V1_STR)
app.include_router(findings_router, prefix=settings.API_V1_STR)
app.include_router(chat_router, prefix=settings.API_V1_STR)
app.include_router(reports_router, prefix=settings.API_V1_STR)
app.include_router(business_intent_router, prefix=settings.API_V1_STR)
app.include_router(business_intent_router)



@app.get("/", tags=["health"])
async def root():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_STR}/docs",
    }
