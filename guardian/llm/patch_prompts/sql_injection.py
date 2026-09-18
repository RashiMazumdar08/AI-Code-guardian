"""
AI Code Guardian v3 — SQL Injection Patch Prompts
=================================================
"""
SQL_INJECTION_PATCH_TEMPLATE = """
Context: SQL Injection in file {file_path} at line {line_number}.
Original Code:
{original_snippet}

Requirements:
- Replace raw string concatenation with parameterized SQL queries or ORM methods.
- Preserve original function signatures and return types.
"""
