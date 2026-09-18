# Nemotron Security Reviewer Integration

## What changed

The LLM analysis pipeline now uses the production security reviewer
instructions stored at `guardian/llm/prompts/security_reviewer.md`.
There is no hardcoded analysis system prompt in Python code.

## Prompt construction

`guardian.llm.prompt_builder.load_security_reviewer_prompt()` loads the
markdown prompt dynamically from disk and validates that the Section 11
JSON schema markers are present.

`guardian.llm.prompt_builder.build_nemotron_payload(code_snippet,
file_path)` returns the OpenAI-compatible message array sent to NVIDIA
Nemotron:

- `system`: the full markdown content of `security_reviewer.md`
- `user`: the file path, optional scanner findings/context, and the
  target code fenced as data

The existing `SecurityPromptBuilder` API remains available for callers
that assemble richer analysis context.

## Nemotron execution

`guardian.llm.nemotron.NemotronLLM.review_code()` is the production code
review entry point. It builds the prompt with `build_nemotron_payload`,
sends it through the configured NVIDIA endpoint, then parses the model
response with `ResponseParser`.

The lower-level `chat()` and `chat_stream()` methods remain available
for existing RAG/chat callers that already provide a complete message
array.

## Strict JSON parsing

`guardian.llm.parser.ResponseParser` now enforces the Section 11 schema:

- required top-level fields
- required `executive_summary` fields
- required `counts_by_severity` keys
- required per-finding fields
- allowed enum values for posture, severity, finding status, and finding
  confidence
- numeric top-level confidence in the `0.0-1.0` range

The parser strips accidental markdown JSON fences before decoding. If
the payload is malformed or deviates from the schema, it returns a
`SecurityAnalysis` with `parse_failed=True` and a descriptive
`parse_error`.

## Guardrails

`GuardrailPipeline.check_response()` now strips accidental markdown JSON
fences before running outbound response validation, matching the strict
JSON-only output requirement.
