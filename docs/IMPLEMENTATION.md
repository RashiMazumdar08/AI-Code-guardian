# Implementation Record — v2.0 → v2.1 Refactor

A record of what was built, what was reused, what was fixed, and what was
deliberately left alone. `ARCHITECTURE.md` describes the resulting design;
this file describes the work and the reasoning behind it.

**Status:** complete. 5 commits on `claude/code-guardian-v2-refactor-e0p2hc`.

| | Before | After |
|---|---|---|
| Tests | 114 passed | **390 passed, 1 skipped** |
| Code representation | Python `ast` + per-language regex | Tree-sitter UST, 5 languages |
| Engine outputs | Per-module, incompatible | Shared `Evidence` + `Finding` |
| LLM integration | 3 ad-hoc call sites (2 broken) | 1 gateway |
| Risk inputs | Severity + confidence | 8 dimensions, provenance-weighted |

57 files changed, 12,321 insertions, 854 deletions. **40 new files, 17
modified, 0 deleted.**

---

## 1. Baseline

The suite was run before any change: **114 passed**. Five apparent failures
were missing optional dependencies (`pandas`, `numpy`), not real breakage —
installing them cleared all five. That number is the regression baseline
every later phase was measured against.

Inspection of the existing code found three modules that could not have been
working:

| Module | Defect |
|---|---|
| `llm/verifier.py` | Imported `LLMGuardrails` (class is `GuardrailPipeline`), called `create_llm(config)` with the wrong signature and `llm.complete()` / `resp.text` — neither on `BaseLLM`. **Raised on import.** |
| `intent/classifier.py::_ai_rerank_pass` | Same `llm.complete()` bug, inside a bare `except`. **Failed silently on every scan** since it was written. |
| `scanner/common/treesitter_engine.py` | Named for Tree-sitter; was stdlib `ast` only, duplicating taint logic already in `_engine.py`. |

All three are addressed below.

---

## 2. What was built

### Phase 2 — Shared models (`guardian/evidence/`, `guardian/core/context.py`)

`Evidence` carries a stable, quotable ID (`E12`) plus a content fingerprint
for deduplication. `EvidenceStore` is the repository-level source of truth:
typed indexes, filtered selection, and `resolve()` which reports unknown IDs
rather than silently dropping them — the primitive that makes fabricated AI
citations detectable.

`RepositoryContext` / `AnalysisContext` are the structures engines exchange
instead of each inventing its own result shape.

`Finding` gained optional `language`, `function`, `end_line`, `column`,
`evidence_ids`, `source`, `reason`, `engine`. All have inert defaults, so
every pre-existing detector and reporter kept working untouched.

### Phase 3 — UST (`guardian/ust/`, 2,255 lines)

Tree-sitter is the parsing foundation. Each language normalizes into one
node vocabulary through a single table-driven walk, so a detector is written
once and works everywhere.

- `parsers.py` — extension → language → cached `Parser`; returns `None`
  (never raises) when a grammar is missing.
- `languages/` — Python, Java, JavaScript, TypeScript/TSX, Rust.
- `tagging.py` — crypto/security/business tags. Algorithm resolution reads
  **string-literal arguments**, so `Cipher.getInstance("AES/ECB/…")` yields
  algorithm *and* mode, while a comment mentioning RSA yields nothing.
- `dataflow.py` — language-independent source→sink taint propagation.
- `fallback.py` — degradation ladder, recorded on `USTFile.parser`:
  `tree-sitter` → `python-ast` → `regex` → `none`.

### Phase 4 — Security engine (`guardian/engines/security.py`)

Flow changed from `rule → vulnerability` to
`rule → candidate evidence → contextual check → finding`. A pattern match
alone is not a finding: a database call becomes SQL injection only when
data-flow shows untrusted input arriving through dynamic string
construction.

Covers injection (SQL/command/eval/deserialization/path), weak and broken
crypto, disabled TLS verification, non-cryptographic RNG in security
contexts, sensitive logging, DOM XSS — across all five languages from one
implementation. Secret detection stays regex + Shannon entropy, where syntax
parsing offers no advantage. Also publishes structural evidence (API
endpoints, authorization checks, database operations) consumed later.

### Phase 5 — Quantum readiness (Layers A/B)

- **A** (`engines/quantum.py`) — discovery via UST call sites, imports and
  dependency evidence.
- **B** (`quantum/classification.py`) — deterministic classification into
  `VULNERABLE / WEAKENED / BROKEN / PQC / SAFE / UNKNOWN` with NIST citations
  (FIPS 203/204/205), CBOM, explainable readiness score.

`UNKNOWN` is a first-class outcome: `Cipher.getInstance(runtimeAlgo)` is
recorded as an unresolved call site, which differs from "no crypto" and from
a guess. A CBOM used for compliance must not blur those.

### Phases 7–9 — Reasoning layer (`guardian/reasoning/`, 1,635 lines)

Built before Phase 6 because Business Intent consumes them.

- `schemas.py` — a finding citing no `evidence_ids` is invalid by
  construction; prose responses are rejected.
- `gateway.py` — `NemotronReasoningService`: the only LLM consumer.
  Credentials, timeouts, retries, cache, token budget, logging, fallback.
  Never raises; a missing key returns `available=False` and the scan
  continues.
- `context.py` — evidence selection and compact packing; the enforcement
  point for "never send the repository".
- `knowledge.py` — evidence-driven RAG: FAISS when present, else a curated
  OWASP/CWE/NIST/FIPS pack (`data/knowledge/`) so the AI layer works offline.
- `validation.py` — evidence-ID, location, algorithm and consistency checks
  producing `AI_VALIDATED` / `AI_SUGGESTED` / `INSUFFICIENT_EVIDENCE`.

### Phase 6 — Business Intent (`guardian/policy/`, `engines/business_intent.py`)

Requirements become testable structures (action + condition + required
control, with currency/magnitude normalisation — 10 lakh, $10,000, 2 crore).
The UST is then read for what the implementing function actually does:
which calls it makes, whether an authorization check sits on the path to the
state change, whether the requirement's threshold appears in a conditional,
whether an audit write happens.

That behaviour is published as evidence **before** any model is consulted,
which is what makes the AI step checkable.

### Phases 10–12 — Integration

Unified risk engine, pipeline rewrite, all five reporters, dashboard
refactor, docs, and 48 end-to-end integration tests.

---

## 3. What was preserved

Nothing was deleted. Explicitly retained and still tested:

- v1 detectors: Python AST taint pass, Java regex bridge, entropy secret
  gate, JS/Rust pattern sets — still run, and are the fallback when no
  grammar is available.
- Regex quantum engine (`quantum/detector|mapper|inventory|scorer`) —
  superseded in the pipeline, retained as a fallback.
- Requirement-alignment engine (`intent/legacy/`), threat intel, RAG
  assistant, `RequirementLoader` (reused unchanged for document loading).
- `report["risk"]` still carries the v1 CRS report; `unified_risk` is
  additive.
- `python main.py scan <path>` still works.

---

## 4. Bugs found and fixed

**Pre-existing** (would have looked functional in review):

1. `llm/verifier.py` — dead on import; rewritten onto the gateway. Triage now
   *demotes and annotates* a suspected false positive rather than suppressing
   it, so a human can disagree.
2. `intent/classifier.py` — silent failure; routed through the gateway and
   constrained so the model may only re-order candidates the deterministic
   classifier produced.
3. `reporting/csv_reporter.py` — the `Finding ID` column read `f.get("id")`,
   a key that does not exist. **Empty in every exported report.**

**Introduced during the refactor, caught by tests:**

4. Gateway computed a context budget but rendered the *untruncated* sections
   — the budget was a no-op.
5. Chained calls (`hashlib.md5(x).hexdigest()`) collapsed to one symbol, so
   crypto detectors fired twice for a single operation.
6. Regex fallback skipped the rest of a line after a declaration, so
   `class A { void f() { Cipher.getInstance("RSA"); } }` produced nothing.
7. Knowledge retrieval matched substrings — `"rsa"` retrieved path-traversal
   guidance via `"traversal"`.
8. Business-intent contextual pass looked for evidence before the pipeline
   published it.

---

## 5. Design decisions

1. **Quantum is a dimension, not a penalty.** Shor-class crypto is
   Info-severity inventory and does not reduce the security score. Keying a
   hard block on it blocked every repository using RSA — which is all of
   them. The gate is opt-in (`enable_quantum_gate`).
2. **A model never sets the final score.** Weights live in
   `core/unified_risk.py`; AI findings are damped by a fixed multiplier and
   capped below deterministic confidence.
3. **"Not found" ≠ "broken".** A policy whose implementation cannot be
   located is `INSUFFICIENT_EVIDENCE`, never a violation, and is excluded
   from the alignment score rather than counted as failure.
4. **Contradiction is rejected, hedging is downgraded.** Naming an algorithm
   absent from the cited evidence is a factual error → rejected. Hedged
   phrasing is over-confidence → `AI_SUGGESTED`.
5. **Provenance is never collapsed.** `DETERMINISTIC` / `AI_VALIDATED` /
   `AI_SUGGESTED` are distinct in every report, the dashboard and the risk
   engine.

### Deviations from the requested plan

- **Phases 7–9 were done before Phase 6.** Business Intent consumes the
  reasoning service; building it first would have meant writing it twice.
- **The legacy regex quantum analyzer is disabled in the pipeline** (the UST
  engine owns that lens) but remains registered and tested as a fallback.

---

## 6. Test coverage — 390 passed, 1 skipped

| File | Tests | Covers |
|---|---:|---|
| `test_ust.py` | 59 | Per-language normalization, tagging, data-flow, full degradation ladder |
| `test_engines.py` | 59 | Security detection across languages, quantum discovery + classification |
| `test_reasoning.py` | 58 | Schema parsing, gateway, RAG, evidence/hallucination validation |
| `test_pipeline_integration.py` | 48 | End-to-end mixed-language repo, unified risk, resilience |
| `test_llm_layer.py` | 43 | LLM provider layer *(pre-existing)* |
| `test_new_engines.py` | 37 | Legacy quantum/intent/threat-intel *(pre-existing)* |
| `test_business_intent.py` | 33 | Policy extraction, behaviour comparison, contextual pass |
| `test_evidence_store.py` | 19 | Evidence model and store |
| `test_scaffold.py` | 15 | Pipeline scaffold *(pre-existing)* |
| `test_ai_grounding.py` | 9 | Grounding *(pre-existing)* |
| `test_security_rule_engine.py` | 7 | v1 rule engine *(pre-existing)* |
| `test_github_service.py` | 4 | GitHub fetch *(pre-existing)* |

Beyond per-component coverage, the suite asserts the properties this design
exists to guarantee: fabricated evidence is rejected, the prompt never
exceeds its budget, a missing API key changes nothing about deterministic
output, an engine failure yields partial rather than absent results, and a
repository with no Tree-sitter grammars still produces findings.

---

## 7. Verified manually

- CLI across all five report formats; `--requirements`, `--ai`, `parsers`
  subcommand; CI gate exit code; `python main.py` backward compatibility.
- Dashboard driven end-to-end in a real browser: uploaded a ZIP plus a
  requirements file, ran a scan, and confirmed all ten tabs render without
  error.
- Simulated a no-Tree-sitter environment: Python retains full AST analysis,
  other languages fall back to regex with discounted confidence, scan
  completes with no errors.

---

## 8. Known limitations

- **Grammars are an optional dependency.** Without `pip install -e ".[ust]"`
  precision drops materially. `python -m guardian parsers` reports coverage.
- **Cross-function taint is not tracked.** Data-flow is intra-procedural; a
  taint path through a helper is not followed.
- **Business-intent matching is name-driven.** A policy is linked to code by
  action/subject vocabulary; a function named unconventionally may not be
  located — reported as `INSUFFICIENT_EVIDENCE`, not silently missed.
- **Dependency and IaC engines were not moved onto the UST.** They still use
  their v1 implementations; their findings are adapted into the evidence
  store but not UST-derived.
- **Layer C (quantum) and the business-intent contextual pass are untested
  against a live endpoint.** Both are covered by tests using an injected
  fake model; no scan in this work had an `NVIDIA_API_KEY`.

---

## 9. Reproducing

```bash
pip install -e ".[ust,dev]"
python -m pytest tests/ -q          # 390 passed, 1 skipped
python -m guardian parsers          # grammar coverage
python -m guardian scan . --format json html --out-dir reports/
```
