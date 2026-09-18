# AI Code Guardian

A **multi-language, UST-driven, evidence-grounded** code analysis platform.

Tree-sitter parses your repository into a Unified Syntax Tree; deterministic
engines detect security, cryptographic, dependency and configuration
evidence; RAG supplies trusted OWASP/NIST/PQC knowledge; NVIDIA Nemotron
reasons about context; guardrails validate every AI claim against real code
evidence; and a deterministic risk engine produces the final assessment.

**Supported languages:** Python · Java · JavaScript · TypeScript/TSX · Rust
(additional languages are one grammar row plus one normalizer)

---

## Pipeline

```
Repository
  → Repository discovery          discovery/file_walker.py
  → Language detection            ust/parsers.py
  → Tree-sitter parsing           ust/parsers.py
  → UST normalization             ust/languages/*
  → Static engines                engines/{security,quantum,business_intent}.py
      + dependency / IaC          dependencies/, infrastructure/
  → Shared evidence store         evidence/store.py
  → Relevant evidence selection   reasoning/context.py
  → RAG retrieval                 reasoning/knowledge.py
  → NVIDIA Nemotron reasoning     reasoning/gateway.py
  → Structured response           reasoning/schemas.py
  → Evidence + hallucination validation   reasoning/validation.py
  → Unified risk engine           core/unified_risk.py
  → Recommendations
  → Reports + dashboard           reporting/, dashboard/
```

Three properties hold throughout:

1. **Deterministic detection stays deterministic.** No model decides whether
   a vulnerability exists. Rules and the UST do that; the model reasons about
   context.
2. **Nothing is claimed without evidence.** Every finding cites stable
   evidence IDs (`E12`), and an AI claim citing evidence that does not exist —
   or contradicting the evidence it cites — is rejected, not downgraded.
3. **Failure is partial, never total.** A missing grammar, a failing engine,
   an unreachable API or a broken index degrades that stage alone.

---

## Quick start

```bash
pip install -e ".[ust]"        # core + Tree-sitter grammars (recommended)

python -m guardian scan /path/to/repo --format json sarif html --out-dir reports/
python -m guardian scan /path/to/repo --requirements docs/requirements.md
python -m guardian scan /path/to/repo --sandbox       # scan an isolated workspace copy
python -m guardian scan /path/to/repo --knowledge     # include graph/vector knowledge summary
python -m guardian parsers                # show grammar coverage
python -m guardian detect /path/to/repo   # repository profile only
python -m guardian intent  /path/to/repo  # business-domain verdict only
```

CI gating:

```bash
python -m guardian scan . --format sarif --fail-on-severity High
```

Exit code 1 when findings at or above the threshold exist; upload the
`.sarif` to GitHub/GitLab code scanning.

### Install options

| Extra | Adds |
|---|---|
| `[ust]` | Tree-sitter grammars — **recommended**, materially better precision |
| `[dashboard]` | Streamlit UI |
| `[ai]` | Nemotron client + local embeddings + FAISS |
| `[docs]` | PDF/DOCX requirement ingestion |
| `[all]` | everything |

Without `[ust]` the platform still runs: Python falls back to the stdlib
`ast` parser (full taint analysis retained) and other languages to a regex
scanner, with confidence scored down accordingly. `python -m guardian
parsers` reports exactly what is available.

---

## What each engine does

### Security engine — `guardian/engines/security.py`
Consumes the UST, not raw lines. The flow is
`rule → candidate evidence → contextual check → finding`, so a match alone
is not a finding:

```python
cursor.execute(query)                 # evidence: a database operation
q = "SELECT ... " + user_input        # evidence: taint flow into it
                                      # → SQL Injection finding, citing both
cursor.execute("... = %s", (user,))   # bound parameter → no finding
```

Covers injection (SQL/command/eval/deserialization/path), weak and broken
cryptography, disabled TLS verification, non-cryptographic RNG in security
contexts, sensitive logging and DOM XSS — across every supported language
from one implementation. Secret detection stays regex + Shannon entropy,
where syntax parsing offers no advantage.

### Quantum readiness — `guardian/engines/quantum.py`, `guardian/quantum/classification.py`
Three layers:

* **A — Discovery.** Crypto operations found through UST call sites, imports
  and dependency evidence. A comment mentioning RSA yields nothing;
  `Cipher.getInstance(runtimeAlgo)` yields an *unresolved* call site, which
  is neither "no crypto" nor a guess.
* **B — Classification.** Deterministic rules map algorithms to
  `VULNERABLE / WEAKENED / BROKEN / PQC / SAFE / UNKNOWN` with NIST citations
  (FIPS 203/204/205), producing a CBOM and an explainable readiness score.
* **C — Context.** Nemotron assesses purpose, business impact and migration
  urgency. It is never asked whether RSA exists — Layer A proved that.

Shor-class usage is reported as **Info-severity inventory**: using RSA today
is a migration-planning item, not a live vulnerability. PQC merge gating is
opt-in (`enable_quantum_gate`).

### Business intent — `guardian/engines/business_intent.py`
Requirements become testable structures, and the code is read to see whether
it implements them:

```
"Refunds above ₹50,000 require manager approval."
        ↓ policy extraction
{action: refund, condition: amount > 50000, required_control: authorization}
        ↓ UST behavioural analysis of processRefund()
calls: refundRepository.save, paymentGateway.refund
authorization checks: NONE FOUND          ← evidence E42
threshold comparison on 'amount': NONE    ← evidence E43
        ↓
VIOLATION — citing E42, E43
```

Verdicts are `COMPLIANT / VIOLATION / POTENTIAL_VIOLATION /
INSUFFICIENT_EVIDENCE`. A requirement whose implementation cannot be located
is `INSUFFICIENT_EVIDENCE` — never a violation, because "we could not find
it" is not "it is broken".

Requirements load from TXT, MD, PDF, DOCX, JSON, YAML, CSV and XLSX.

---

## AI layer (optional)

```bash
pip install -e ".[ai]"
cp .env.example .env          # set NVIDIA_API_KEY=nvapi-...
python -m guardian scan /path/to/repo --ai --requirements reqs.md
```

Every model interaction goes through one service —
`guardian.reasoning.NemotronReasoningService` — which owns credentials,
timeouts, retries, caching, the token budget, logging and fallback.

**The whole repository is never sent.** The gateway accepts only
pre-selected evidence and enforces a hard character budget; when a prompt is
too large it drops background knowledge before evidence and reports what it
dropped. Secrets are redacted before transmission. Embeddings run locally.

**Every AI finding is validated before it is shown:**

| Outcome | Meaning |
|---|---|
| `DETERMINISTIC` | proven by rules or the UST |
| `AI_VALIDATED` | model claim; evidence, file, line, function and algorithm all check out |
| `AI_SUGGESTED` | grounded but not fully corroborated — confidence-capped at 0.6 |
| `INSUFFICIENT_EVIDENCE` | rejected; recorded with the reason, never shown as a finding |

Rejected outright: fabricated evidence IDs, invented algorithms, claims that
contradict the evidence they cite, and missing-control assertions with no
behavioural evidence. AI confidence never reaches 1.0 — only deterministic
detection does.

Without a key, the scan runs normally and reports the AI layer as
unavailable.

> ⚠️ Nemotron is a hosted API: the evidence and any snippet selected for
> analysis leave your network. Secrets are redacted first
> (`guardian/llm/guardrails.py`).

---

## Dashboard

```bash
pip install -e ".[dashboard]"
streamlit run dashboard/app.py
```

Upload a repository (ZIP, individual files, or a GitHub URL) plus optional
requirement and policy documents, then work through
**Overview → Security → Business Intent → Quantum → Dependencies → IaC →
Risk → Recommendations → Reports**. Static, AI-validated and AI-suggested
findings are visually distinguished and filterable, and the UST structure
and evidence behind each finding are exposed for explainability.

---

## Reports

JSON · SARIF 2.1.0 · HTML · CSV · printable PDF — each carrying category,
severity, confidence, language, file, line, function, evidence IDs, reason,
recommendation and provenance.

---

## Configuration

Copy `config/default.yaml`, edit, pass with `--config`. Every engine is a
toggle; nothing is hardcoded to any repository.

## Tests

```bash
pip install -e ".[dev,ust]" && python -m pytest tests/ -q
```

385 tests covering UST normalization per language, the degradation ladder,
the evidence store, static→evidence conversion, business intent, quantum
discovery and classification, structured LLM parsing, invalid-evidence and
hallucination rejection, API and RAG failure, unsupported languages,
malformed sources and mixed-language repositories.

See `docs/ARCHITECTURE.md` for the full design.
