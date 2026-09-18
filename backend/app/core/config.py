"""
Backend Configuration Settings
==============================
Reads environment variables for FastAPI backend server and guardian integration.
"""
from __future__ import annotations

import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "AI Code Guardian API"
    VERSION: str = "2.1.0"
    # "*" is incompatible with allow_credentials=True (browsers reject the
    # combination for any request that carries credentials), so we pin the
    # actual dev origins instead of wildcarding. Override with a CORS_ORIGINS
    # env var (JSON list) for other setups, e.g. a deployed frontend origin.
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://guardian:guardian_pass@localhost:5432/guardian_db")
    
    # NVIDIA Nemotron 3 Ultra Settings
    NVIDIA_API_KEY: str = ""
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NVIDIA_MODEL: str = "nvidia/nemotron-3-ultra-550b-a55b"
    LLM_TEMPERATURE: float = 1.0
    LLM_MAX_TOKENS: int = 16384

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
