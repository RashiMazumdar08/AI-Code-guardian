"""
AI Code Guardian v3 — Modular Patch Prompt Templates Package
============================================================
"""
from guardian.llm.patch_prompts.auth import AUTH_PATCH_TEMPLATE
from guardian.llm.patch_prompts.crypto import CRYPTO_PATCH_TEMPLATE
from guardian.llm.patch_prompts.secrets import SECRETS_PATCH_TEMPLATE
from guardian.llm.patch_prompts.sql_injection import SQL_INJECTION_PATCH_TEMPLATE
from guardian.llm.patch_prompts.xss import IAC_PATCH_TEMPLATE, XSS_PATCH_TEMPLATE

__all__ = [
    "SQL_INJECTION_PATCH_TEMPLATE",
    "SECRETS_PATCH_TEMPLATE",
    "AUTH_PATCH_TEMPLATE",
    "CRYPTO_PATCH_TEMPLATE",
    "XSS_PATCH_TEMPLATE",
    "IAC_PATCH_TEMPLATE",
]
