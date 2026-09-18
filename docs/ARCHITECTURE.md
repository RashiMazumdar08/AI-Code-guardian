# AI Code Guardian — Architecture

## Design goal

Be a **multi-language, UST-driven, evidence-grounded** analysis platform:
the Unified Syntax Tree understands code structure, deterministic engines
detect evidence, RAG supplies trusted knowledge, Nemotron reasons about
context, guardrails validate every AI claim, and a deterministic risk
engine produces the final assessment.

The previous architecture was Python-AST-centric with per-language regex
bridges, and every module produced its own incompatible output and built
its own LLM prompt. This one has a single code representation, a single
evidence vocabulary and a single door to the model.

## Layout

```
guardian/
├── config.py               Configuration (YAML + defaults). Single source of truth.
├── cli.py / __main__.py    `python -m guardian scan|detect|intent|parsers <path>`
│
├── ust/                    UNIFIED SYNTAX TREE — the code representation
│   ├── models.py           USTNode / USTFile / UST. Stable node IDs, spans,
│   │                       security/crypto/business tags, control- & data-flow
│   ├── parsers.py          Tree-sitter registry: extension → language → cached
│   │                       Parser; returns None (never raises) when a grammar
│   │                       is absent
│   ├── languages/          Table-driven normalizers over one shared walk:
│   │                       python, java, javascript, typescript/tsx, rust
│   ├── tagging.py          Cross-language crypto/security/business tagging;
│   │                       algorithm resolution from string-literal arguments
│   ├── dataflow.py         Language-independent source→sink taint propagation
│   ├── fallback.py         Degradation ladder: stdlib `ast` (Python) → regex
│   └── builder.py          Single entry point; per-file failure is contained
│
├── evidence/               SHARED EVIDENCE STORE — the source of truth
│   ├── models.py           Evidence (stable IDs + fingerprints), EvidenceType,
│   │                       FindingSource, ValidatedFinding
│   └── store.py            Dedup, typed indexes, filtered selection, and
│                           resolve() reporting unknown IDs
│
├── engines/                DETERMINISTIC ANALYSIS
│   ├── base.py             AnalysisEngine contract + run_engine() containment
│   ├── security.py         UST-driven SAST across all languages
│   ├── quantum.py          Layer A crypto discovery + Layer C contextual pass
│   └── business_intent.py  Policy ↔ UST-behaviour comparison
│
├── policy/                 REQUIREMENTS → TESTABLE STRUCTURES
│   ├── models.py           BusinessPolicy: action + condition + required control
│   └── extractor.py        Deterministic structuring; optional LLM assist that
│                           may only restructure text the user supplied
│
├── reasoning/              CONTEXTUAL REASONING — the only LLM consumer
│   ├── gateway.py          NemotronReasoningService: credentials, timeouts,
│   │                       retries, cache, token budget, logging, fallback
│   ├── context.py          Evidence selection + compact packing (enforces
│   │                       "never send the repository")
│   ├── knowledge.py        Evidence-driven RAG: FAISS, else curated pack
│   ├── schemas.py          Structured response schemas + strict validation
│   └── validation.py       Evidence-ID / location / algorithm / consistency
│                           checks → AI_VALIDATED | AI_SUGGESTED | rejected
│
├── core/
│   ├── models.py           Finding / ScanResult / Severity (v1 schema plus
│   │                       optional provenance fields; to_dict stays stable)
│   ├── context.py          RepositoryContext / AnalysisContext
│   ├── interfaces.py       LanguagePlugin / Analyzer / Reporter protocols
│   ├── registry.py         Plugin registry + @register_* decorators
│   ├── pipeline.py         Orchestrator (see flow below)
│   ├── risk.py             v1 CRS risk scorer — unchanged, still emitted
│   └── unified_risk.py     Unified multi-dimensional risk engine
│
├── discovery/              File walking, repository profiling, GitHub fetch
├── quantum/
│   ├── classification.py   Layer B: deterministic algorithm classification,
│   │                       CBOM, explainable readiness score
│   └── detector/mapper/    v1 regex engine — retained as a fallback
│       inventory/scorer
├── scanner/                v1 detectors, retained: Python AST taint pass, Java
│                           regex bridge, entropy secret gate, JS/Rust patterns
├── dependencies/           Manifest parsing + CVE cross-reference
├── infrastructure/         Data-driven IaC catalog
├── intent/                 Domain classifier + v1 requirement-alignment engine
├── threat_intel/           NVD / CISA KEV / OSV collectors, 24h cache
├── llm/                    Provider layer: BaseLLM, Nemotron client, guardrails
├── ai/                     RAG + CodeBERT assistant (chat)
└── reporting/              JSON · SARIF 2.1.0 · HTML · CSV · printable PDF

data/
├── rules/Security_Rules.json   OWASP/CWE rule catalog (severity, IDs, advice)
└── knowledge/                  Curated OWASP/CWE/NIST/FIPS-203-205 pack
```

## Pipeline

```
Repository
  → Discovery                discovery/file_walker.py, repo_detector.py
  → Language detection       ust/parsers.py
  → Tree-sitter parsing      ust/parsers.py
  → UST normalization        ust/languages/*, ust/tagging.py, ust/dataflow.py
  → Static engines           engines/*  +  legacy plugins & analyzers
  → Shared evidence store    evidence/store.py
  → Evidence selection       reasoning/context.py
  → RAG retrieval            reasoning/knowledge.py
  → Nemotron reasoning       reasoning/gateway.py
  → Structured response      reasoning/schemas.py
  → Evidence validation      reasoning/validation.py
  → Unified risk             core/unified_risk.py
  → Reports + dashboard      reporting/, dashboard/
```

## Key decisions

1. **UST, not Python AST.** Tree-sitter is the parsing foundation and every
   language normalizes into one node vocabulary, so a detector is written
   once and works everywhere. `USTFile.parser` records how nodes were
   obtained (`tree-sitter` / `python-ast` / `regex` / `none`) and detectors
   discount confidence accordingly — a regex scan is never presented as a
   parse.

2. **Rule → evidence → finding, not rule → vulnerability.** A pattern match
   produces *evidence*. Whether it becomes a finding depends on context: a
   database call is SQL injection only when data-flow shows untrusted input
   arriving through dynamic string construction. This is why the
   parameterised-query idiom no longer false-positives.

3. **One evidence store.** Every engine publishes observations with stable,
   quotable IDs. This makes AI claims mechanically checkable, makes
   selection explicit (a task asks for the few items it needs), and
   centralises deduplication so two engines observing one line do not
   double-count into the risk score.

4. **One door to the model.** Before, Business Intent and the domain
   classifier each built their own prompt and swallowed their own errors —
   both were calling `llm.complete()`, a method `BaseLLM` does not have, and
   failing silently on every run. `NemotronReasoningService` is now the only
   LLM consumer.

5. **The repository is never sent.** The gateway accepts only pre-rendered
   evidence blocks and enforces a hard character budget, dropping background
   knowledge before evidence and reporting what it dropped. Where the model
   needs to know what code does, it gets UST structure — smaller and more
   precise than source.

6. **Validation is the product, not a nicety.** A model claim passes schema
   validation, evidence-ID validation, source-location validation, algorithm
   validation and consistency checks before it can appear. Fabricated
   evidence IDs, invented algorithms, claims contradicting their evidence
   and unsupported missing-control assertions are rejected. Hedged reasoning
   is downgraded to `AI_SUGGESTED`. AI confidence never reaches 1.0.

7. **Deterministic risk.** Nemotron contributes bounded contextual signals;
   the weights live in `core/unified_risk.py` where they can be reviewed.
   AI-sourced findings are damped by a fixed multiplier.

8. **Quantum is a dimension, not a penalty.** Shor-class crypto is
   Info-severity inventory. Keying a hard block on it blocked every
   repository that uses RSA — which is all of them — so the gate is opt-in
   and quantum readiness scores as its own axis.

9. **`UNKNOWN` is a real answer.** `Cipher.getInstance(runtimeAlgo)` is
   recorded as an unresolved call site. That is materially different from
   "no crypto here" and from a guess, and a CBOM that compliance teams rely
   on must not blur them.

10. **Graceful degradation everywhere.** Missing grammar, engine failure,
    unreachable API, broken RAG index, unparsable file, oversized repo — each
    degrades its own stage, is recorded in `report["errors"]`, and the scan
    returns partial results.

## Adding a language

1. Add a grammar row to `ust/parsers._GRAMMARS` and the extensions to
   `EXTENSION_LANGUAGE`.
2. Add a normalizer in `ust/languages/` declaring which grammar node types
   mean function, call, import, and so on.
3. Register it in `ust/builder.NORMALIZERS`.

Nothing else changes: every engine, tag catalog and detector already works
against the UST.

## Backward compatibility

- `python main.py scan <path>` still works (delegates to the new CLI).
- `Finding.to_dict()` keeps its existing keys; the provenance fields are
  additive with inert defaults.
- `report["risk"]` still carries the v1 CRS report; `report["unified_risk"]`
  is the new one.
- v1 detectors (Python AST taint pass, Java regex bridge, entropy secret
  gate, JS/Rust patterns), the regex quantum engine, the requirement
  alignment engine, threat intel and the RAG assistant are all retained and
  still exercised by their original tests.

## Testing

385 tests. Beyond per-component coverage, the suite asserts the properties
this design exists to guarantee: fabricated evidence is rejected, the
prompt never grows past its budget, a missing API key changes nothing about
deterministic output, an engine failure yields partial rather than absent
results, and a repository with no Tree-sitter grammars still produces
findings.
