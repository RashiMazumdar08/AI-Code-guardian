"""
AI Code Guardian v3 — Hardcoded Secret Patch Prompts
====================================================
"""
SECRETS_PATCH_TEMPLATE = """
Context: Hardcoded Secret in file {file_path} at line {line_number}.
Original Code:
{original_snippet}

Requirements:
- Replace hardcoded credential string with environment variable lookup (e.g. os.environ.get).
- Ensure fallback or error handling is provided if environment variable is missing.
"""
