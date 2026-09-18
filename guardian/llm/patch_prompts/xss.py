"""
AI Code Guardian v3 — XSS & IaC Patch Prompts
=============================================
"""
XSS_PATCH_TEMPLATE = """
Context: Cross-Site Scripting (XSS) in file {file_path} at line {line_number}.
Original Code:
{original_snippet}

Requirements:
- Sanitize and escape un-trusted user input before rendering.
"""

IAC_PATCH_TEMPLATE = """
Context: Infrastructure-as-Code Security Flaw in file {file_path} at line {line_number}.
Original Code:
{original_snippet}

Requirements:
- Restrict broad permissions and enforce TLS/encryption in IaC resource blocks.
"""
