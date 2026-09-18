"""
AI Code Guardian v3 — Cryptographic Patch Prompts
=================================================
"""
CRYPTO_PATCH_TEMPLATE = """
Context: Weak Cryptographic Algorithm in file {file_path} at line {line_number}.
Original Code:
{original_snippet}

Requirements:
- Upgrade weak hashes (MD5, SHA1) to secure primitives (SHA256, bcrypt, Argon2).
"""
