"""
AI Code Guardian v3 — Authentication & Authorization Patch Prompts
==================================================================
"""
AUTH_PATCH_TEMPLATE = """
Context: Authentication / Access Control Flaw in file {file_path} at line {line_number}.
Original Code:
{original_snippet}

Requirements:
- Add mandatory authorization gate and token verification before executing privileged logic.
"""
