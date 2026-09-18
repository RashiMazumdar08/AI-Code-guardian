"""
AI Code Guardian v3 — Git Diff Generator
=======================================
Generates unified git diff strings for patch proposals without altering disk files.
"""
from __future__ import annotations

import difflib
from typing import List


class GitDiffGenerator:
    """Generates standard Unified Git Diff output from original and replacement code snippets."""

    def generate_unified_diff(
        self,
        file_path: str,
        original_snippet: str,
        replacement_snippet: str
    ) -> str:
        """Computes a unified git diff format string for a target file."""
        orig_lines = original_snippet.splitlines(keepends=True)
        if not orig_lines and original_snippet:
            orig_lines = [original_snippet + "\n"]

        repl_lines = replacement_snippet.splitlines(keepends=True)
        if not repl_lines and replacement_snippet:
            repl_lines = [replacement_snippet + "\n"]

        diff_lines = list(
            difflib.unified_diff(
                orig_lines,
                repl_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                n=3
            )
        )
        return "".join(diff_lines)
