"""
LLM Layer -- Security Reviewer Prompt Builder
=============================================
Loads the production security-reviewer system instructions from
``guardian/llm/prompts/security_reviewer.md`` and constructs
OpenAI-compatible message arrays for NVIDIA Nemotron.

The markdown file is intentionally external to this module so prompt
changes can be reviewed as content changes instead of code changes. This
module owns only loading, validation, context assembly, and context-budget
compression.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

DEFAULT_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "security_reviewer.md"


class PromptLoadError(RuntimeError):
    """Raised when the production security-reviewer prompt cannot be loaded."""


@lru_cache(maxsize=4)
def load_security_reviewer_prompt(prompt_path: str | Path | None = None) -> str:
    """Load the production system instructions from disk.

    The prompt must exist, be non-empty, and include the Section 11 JSON
    contract. Failing fast here prevents the LLM from running with a stale
    or incomplete hardcoded fallback.
    """
    path = Path(prompt_path) if prompt_path is not None else DEFAULT_PROMPT_PATH
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PromptLoadError(f"security reviewer prompt not found: {path}") from exc
    except OSError as exc:
        raise PromptLoadError(f"could not read security reviewer prompt {path}: {exc}") from exc

    text = text.strip()
    if not text:
        raise PromptLoadError(f"security reviewer prompt is empty: {path}")
    required_markers = ("## 11. Required Output Schema", '"findings"', '"executive_summary"')
    missing = [marker for marker in required_markers if marker not in text]
    if missing:
        raise PromptLoadError(
            f"security reviewer prompt {path} is missing required marker(s): {missing}"
        )
    return text


def build_nemotron_payload(
    code_snippet: str,
    file_path: str,
    *,
    prompt_path: str | Path | None = None,
    language: str = "",
    scanner_findings: Optional[list[dict]] = None,
    additional_context: Optional[dict | str] = None,
) -> list[dict]:
    """Build the strict security-review message array for Nemotron.

    Args:
        code_snippet: Target source code or diff fragment.
        file_path: Repository-relative path for the supplied code.
        prompt_path: Optional override for tests or prompt experiments.
        language: Optional language hint.
        scanner_findings: Existing deterministic findings to verify.
        additional_context: Business intent, AST facts, standards, or other
            caller-selected evidence.
    """
    system_prompt = load_security_reviewer_prompt(prompt_path)
    user_prompt = _build_user_review_request(
        code_snippet=code_snippet,
        file_path=file_path,
        language=language,
        scanner_findings=scanner_findings or [],
        additional_context=additional_context,
    )
    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


@dataclass
class SecurityPromptContext:
    """Selected evidence for one security-review request."""

    code_chunk: str = ""
    language: str = ""
    framework: str = ""
    file_path: str = ""

    business_requirement: str = ""
    business_intent: str = ""
    business_policies: list[str] = field(default_factory=list)

    detected_vulnerabilities: list[dict] = field(default_factory=list)
    ast_analysis: str = ""
    call_graph: str = ""
    security_sinks: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)

    owasp_rules: list[str] = field(default_factory=list)
    nist_controls: list[str] = field(default_factory=list)
    rmf_controls: list[str] = field(default_factory=list)
    related_chunks: list[str] = field(default_factory=list)


class SecurityPromptBuilder:
    """Assembles system+user messages under a hard context budget."""

    _PRIORITY = ("code", "vulnerabilities", "requirement", "ast", "standards", "related")

    def __init__(
        self,
        max_context_chars: int = 12_000,
        prompt_path: str | Path | None = None,
    ):
        self.max_context_chars = max_context_chars
        self.prompt_path = prompt_path

    def build(self, ctx: SecurityPromptContext) -> list[dict]:
        sections = self._compress(self._sections(ctx))
        additional_context = {
            "framework": ctx.framework,
            "business_requirement": sections.get("requirement", ""),
            "ast_analysis": sections.get("ast", ""),
            "standards": sections.get("standards", ""),
            "related_code": sections.get("related", ""),
        }
        return build_nemotron_payload(
            code_snippet=sections.get("code", ctx.code_chunk),
            file_path=ctx.file_path,
            prompt_path=self.prompt_path,
            language=ctx.language,
            scanner_findings=ctx.detected_vulnerabilities,
            additional_context={k: v for k, v in additional_context.items() if v},
        )

    def _sections(self, ctx: SecurityPromptContext) -> dict[str, str]:
        out: dict[str, str] = {}

        if ctx.business_requirement or ctx.business_intent or ctx.business_policies:
            parts = []
            if ctx.business_requirement:
                parts.append(ctx.business_requirement)
            if ctx.business_intent:
                parts.append(f"Detected business domain: {ctx.business_intent}")
            if ctx.business_policies:
                parts.append("Applicable policies:\n" +
                             "\n".join(f"- {p}" for p in ctx.business_policies))
            out["requirement"] = "\n".join(parts)

        if ctx.detected_vulnerabilities:
            lines = []
            for finding in ctx.detected_vulnerabilities:
                lines.append(
                    f"- [{finding.get('severity', '?')}] {finding.get('rule_id', '?')} "
                    f"{finding.get('category', '')} at "
                    f"{finding.get('file', '?')}:{finding.get('line', '?')}\n"
                    f"  code: {str(finding.get('snippet', ''))[:160]}\n"
                    f"  scanner recommendation: "
                    f"{str(finding.get('recommendation', ''))[:160]}"
                )
            out["vulnerabilities"] = "\n".join(lines)

        ast_parts = []
        if ctx.ast_analysis:
            ast_parts.append(ctx.ast_analysis)
        if ctx.imports:
            ast_parts.append("Imports: " + ", ".join(ctx.imports[:40]))
        if ctx.security_sinks:
            ast_parts.append("Security sinks reached: " + ", ".join(ctx.security_sinks[:20]))
        if ctx.call_graph:
            ast_parts.append("Call graph:\n" + ctx.call_graph)
        if ast_parts:
            out["ast"] = "\n".join(ast_parts)

        std_parts = []
        if ctx.owasp_rules:
            std_parts.append("OWASP:\n" + "\n".join(f"- {r}" for r in ctx.owasp_rules))
        if ctx.nist_controls:
            std_parts.append("NIST:\n" + "\n".join(f"- {r}" for r in ctx.nist_controls))
        if ctx.rmf_controls:
            std_parts.append("RMF:\n" + "\n".join(f"- {r}" for r in ctx.rmf_controls))
        if std_parts:
            out["standards"] = "\n\n".join(std_parts)

        if ctx.related_chunks:
            out["related"] = "\n---\n".join(ctx.related_chunks)
        if ctx.code_chunk:
            out["code"] = ctx.code_chunk
        return out

    def _compress(self, sections: dict[str, str]) -> dict[str, str]:
        total = sum(len(v) for v in sections.values())
        if total <= self.max_context_chars:
            return sections
        out = dict(sections)
        for key in reversed(self._PRIORITY):
            if key not in out:
                continue
            total = sum(len(v) for v in out.values())
            if total <= self.max_context_chars:
                break
            excess = total - self.max_context_chars
            current = out[key]
            if len(current) <= excess:
                if key in ("code", "vulnerabilities"):
                    out[key] = current[: max(400, len(current) - excess)] + "\n... [truncated]"
                else:
                    del out[key]
            else:
                out[key] = current[: len(current) - excess] + "\n... [truncated]"
        return out


def _build_user_review_request(
    *,
    code_snippet: str,
    file_path: str,
    language: str,
    scanner_findings: list[dict],
    additional_context: dict | str | None,
) -> str:
    blocks = [
        "Review the following target code using the system instructions.",
        "Return exactly one JSON object matching Section 11. Do not add markdown fences.",
        "",
        "Tasks:",
        "1. Verify scanner findings when supplied.",
        "2. Discover additional evidenced vulnerabilities in the target code.",
        "3. Return the complete Section 11 JSON schema.",
        "",
        "Target:",
        f"- file_path: {file_path or '<unknown>'}",
    ]
    if language:
        blocks.append(f"- language: {language}")

    if scanner_findings:
        blocks.extend([
            "",
            "Scanner findings to verify:",
            _json_block(scanner_findings),
        ])

    if additional_context:
        blocks.extend([
            "",
            "Additional evidence/context:",
            _json_block(additional_context) if isinstance(additional_context, dict)
            else str(additional_context),
        ])

    blocks.extend([
        "",
        "Target code:",
        "```" + (language.lower() if language else ""),
        code_snippet or "",
        "```",
    ])
    return "\n".join(blocks)


def _json_block(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)
