# AI Code Guardian — System Architecture & Technical Specification

> **AI Code Guardian** is a multi-language, UST-driven, evidence-grounded code analysis, security auditing, post-quantum cryptography (PQC) readiness checking, business-intent compliance, and vulnerability assessment platform.

---

## 1. Executive Summary & Core Philosophy

AI Code Guardian combines deterministic parsing, static analysis, policy extraction, RAG-enhanced threat intelligence, and AI reasoning (via NVIDIA Nemotron) into a unified platform. 

The architecture is built on three strict principles:

1. **Deterministic Detection Stays Deterministic:** No AI model decides whether a vulnerability exists. Parsing rules and the **Unified Syntax Tree (UST)** perform deterministic detection; the AI model is strictly reserved for contextual reasoning and impact analysis.
2. **Evidence-Grounded Verification:** Every finding cites stable, unique evidence IDs (e.g., `E12`). Any AI claim citing non-existent evidence or contradicting its evidence is automatically rejected by strict guardrails.
3. **Graceful Partial Degradation:** A missing language grammar, an unreachable API, or a missing index degrades that specific stage alone; the scan proceeds and produces valid partial results instead of crashing.

---

## 2. Technology Stack

### Backend & Core Analysis Engine
- **Language:** Python 3.10+
- **API Framework:** FastAPI (Async REST API backend in `backend/`)
- **ORM & Database:** SQLModel / SQLAlchemy with AsyncPG for PostgreSQL and `pgvector` extension for vector storage
- **Configuration:** PyYAML (`config/default.yaml`)
- **CLI Framework:** Python standard `argparse` / Click (`guardian/cli.py`)

### Parsing & Syntax Tree (UST)
- **Primary AST Parser:** Tree-sitter (`tree-sitter` python bindings)
- **Supported Grammars:** Python (`tree-sitter-python`), Java (`tree-sitter-java`), JavaScript (`tree-sitter-javascript`), TypeScript/TSX (`tree-sitter-typescript`), Rust (`tree-sitter-rust`)
- **Fallback Parsers:** Python `ast` module (for Python standard library fallback) and regex-based pattern normalizer (for unparsed languages)

### AI, Reasoning & RAG Layer
- **LLM Gateway:** NVIDIA Nemotron API (via OpenAI SDK client & custom REST gateway)
- **Vector Search & RAG:** FAISS (`faiss-cpu`), Local Embeddings (`sentence-transformers`), CodeBERT (`transformers`/torch fallback)
- **Document Parsers:** `pypdf`, `python-docx`, JSON, YAML, Markdown, CSV, XLSX (for reading compliance policies and business requirement documents)

### Frontend Dashboard
- **Framework:** Next.js 14 (React 18, TypeScript, App Router)
- **Styling:** TailwindCSS, PostCSS, Lucide React icons
- **Code Editor:** `@monaco-editor/react` (Monaco Editor integration)
- **Flow & Graph Visualizations:** `@xyflow/react` (React Flow v12), `dagre` (graph layouting)

### Reporting & CI/CD
- **Formats:** JSON, SARIF 2.1.0 (for GitHub/GitLab Code Scanning), HTML, CSV, PDF (`reportlab`)
- **Testing:** Pytest (385+ automated unit and integration tests)
- **Containerization:** Docker (`docker-compose.yml`)

---

## 3. Comprehensive Directory & Folder Structure

```
AI-Code-Guardian/
├── Architecture.md             <-- System architecture specification (this file)
├── README.md                   <-- Main README and quick start guide
├── main.py                     <-- Backward-compatible root CLI entrypoint
├── pyproject.toml              <-- Build system, dependencies, CLI scripts
├── requirements.txt            <-- Core dependencies list
├── requirements_ai.txt         <-- AI/RAG optional dependencies list
├── docker-compose.yml          <-- Containerized orchestration setup
├── backend/                    <-- Async FastAPI REST backend app
│   ├── app/
│   │   ├── main.py             <-- FastAPI application initialization, CORS, middleware
│   │   ├── core/
│   │   │   └── config.py       <-- API settings & database configurations
│   │   └── api/v1/             <-- API v1 route handlers
│   │       ├── scans.py        <-- Scan initiation & status endpoints
│   │       ├── findings.py     <-- Vulnerability & evidence retrieval endpoints
│   │       ├── files.py        <-- File tree & content inspection endpoints
│   │       ├── chat.py         <-- RAG AI Assistant chat endpoint
│   │       └── reports.py      <-- Report downloading endpoints
├── frontend/                   <-- Next.js 14 Web Application UI
│   ├── package.json            <-- Frontend dependencies (Next.js, Tailwind, React Flow)
│   ├── next.config.js          <-- Next.js config
│   └── src/
│       ├── app/                <-- App router pages (`globals.css`, `layout.tsx`, `page.tsx`)
│       └── components/         <-- UI components
│           ├── chat/           <-- Interactive AI Security Chat Assistant component
│           ├── cyberlock/      <-- Security posture & risk metrics dashboard
│           ├── editor/         <-- Monaco editor for viewing vulnerable code & line markers
│           ├── mindmap/        <-- Graph visualizer (@xyflow/react) for UST/Dependency nodes
│           ├── scan/           <-- Scan launcher & real-time progress bar
│           └── workspace/      <-- File tree explorer & workspace context viewer
├── guardian/                   <-- Core Python Engine Package
│   ├── cli.py                  <-- CLI command-line handler (`python -m guardian`)
│   ├── config.py               <-- YAML configuration parser & global settings loader
│   ├── ust/                    <-- Unified Syntax Tree (UST) Engine
│   │   ├── models.py           <-- USTNode, USTFile, UST data models & node IDs
│   │   ├── parsers.py          <-- Tree-sitter registry & grammar loader
│   │   ├── tagging.py          <-- Cross-language crypto/security/business semantic tags
│   │   ├── dataflow.py         <-- Inter-procedural source-to-sink taint analysis
│   │   ├── fallback.py         <-- Degradation ladder (Stdlib AST / Regex scanner)
│   │   ├── builder.py          <-- Master UST builder & file AST worker
│   │   └── languages/          <-- Language-specific AST normalizers
│   │       ├── base.py         <-- Base class for language normalizers
│   │       ├── python_lang.py  <-- Python AST normalizer
│   │       ├── java_lang.py    <-- Java AST normalizer
│   │       ├── javascript_lang.py <-- JS/TS AST normalizer
│   │       └── rust_lang.py    <-- Rust AST normalizer
│   ├── evidence/               <-- Shared Evidence Store
│   │   ├── models.py           <-- Evidence data models, stable IDs (E1, E2...), fingerprints
│   │   └── store.py            <-- Centralized evidence deduplication, indexing, and lookup
│   ├── engines/                <-- Deterministic Analysis Engines
│   │   ├── base.py             <-- Base engine abstract class
│   │   ├── security.py         <-- UST-driven SAST (SQLi, XSS, Path Traversal, Secrets, etc.)
│   │   ├── quantum.py          <-- Layer A Post-Quantum Crypto (PQC) call-site discovery
│   │   └── business_intent.py  <-- Policy requirement vs UST control flow comparison
│   ├── policy/                 <-- Business Policy Ingestion
│   │   ├── models.py           <-- BusinessPolicy models (Action, Condition, Control)
│   │   └── extractor.py        <-- Extraction of rules from PDF, MD, TXT, DOCX, CSV
│   ├── reasoning/              <-- AI Contextual Reasoning Layer
│   │   ├── gateway.py          <-- NemotronReasoningService (API rate limits, tokens, cache)
│   │   ├── context.py          <-- Compact evidence selector (enforces character budget)
│   │   ├── knowledge.py        <-- OWASP/NIST knowledge pack RAG retriever
│   │   ├── schemas.py          <-- Strict Pydantic response validation schemas
│   │   └── validation.py       <-- Hallucination detection & evidence validation guardrails
│   ├── quantum/                <-- Quantum Readiness Engine
│   │   ├── classification.py   <-- Layer B: NIST FIPS 203/204/205 classification & CBOM
│   │   ├── detector.py         <-- Crypto call-site scanner fallback
│   │   └── inventory.py        <-- Cryptographic bill of materials (CBOM) generator
│   ├── core/                   <-- System Core & Pipeline Management
│   │   ├── pipeline.py         <-- Master orchestrator executing scan stages
│   │   ├── models.py           <-- ScanResult, Finding, Severity models
│   │   ├── context.py          <-- RepositoryContext & analysis state
│   │   ├── registry.py         <-- Engine & plugin registry
│   │   ├── risk.py             <-- Legacy CRS risk calculation engine
│   │   └── unified_risk.py     <-- Multi-dimensional unified risk scorer
│   ├── discovery/              <-- Repository Walker & Profiler
│   │   ├── file_walker.py      <-- Recursive file system scanner with gitignore respect
│   │   ├── repo_detector.py    <-- Tech-stack & project type identification
│   │   └── github_service.py   <-- Remote GitHub repository cloner
│   ├── dependencies/           <-- Dependency Vulnerability Engine
│   │   ├── parsers.py          <-- Parsers for requirements.txt, pom.xml, package.json, etc.
│   │   └── analyzer.py         <-- CVE cross-referencing for external libraries
│   ├── infrastructure/         <-- Infrastructure as Code (IaC) Engine
│   │   ├── rules.py            <-- Security rules for Dockerfile, K8s, Terraform
│   │   └── analyzer.py         <-- Misconfiguration scanner for cloud infrastructure
│   ├── intent/                 <-- Domain Classification & Legacy Intent
│   │   ├── classifier.py       <-- Project domain categorization (e.g. Fintech, Healthcare)
│   │   └── domains.py          <-- Domain keyword mapping
│   ├── threat_intel/           <-- Live Threat Intelligence Integration
│   │   ├── collector.py        <-- Fetcher for NVD, CISA KEV, OSV databases
│   │   ├── cache.py            <-- 24-hour cache layer for threat feeds
│   │   └── models.py           <-- Threat intelligence models
│   ├── llm/                    <-- Low-level LLM Interface & Security Guardrails
│   │   ├── guardrails.py       <-- Secret & PII redactor before LLM invocation
│   │   ├── nemotron.py         <-- Low-level Nemotron LLM HTTP client
│   │   └── prompt_builder.py   <-- Structured prompt formatter
│   ├── ai/                     <-- Code Assistant & RAG Pipeline
│   │   ├── rag_pipeline.py     <-- Full repository indexer & semantic search pipeline
│   │   ├── chatbot.py          <-- Interactive security Q&A conversational agent
│   │   └── vector_store.py     <-- FAISS index & vector database manager
│   ├── reporting/              <-- Report Formatters
│   │   ├── json_reporter.py    <-- Raw JSON report output
│   │   ├── sarif.py            <-- OASIS SARIF 2.1.0 standard output
│   │   ├── html_reporter.py    <-- Standalone interactive HTML report generator
│   │   ├── pdf_reporter.py     <-- PDF executive summary report generator
│   │   └── csv_reporter.py     <-- CSV export for tabular tools
│   └── db/                     <-- Persistence Layer
│       ├── session.py          <-- PostgreSQL connection pool setup
│       └── models.py           <-- Database ORM tables for scans and findings
├── config/
│   └── default.yaml            <-- Default system rules & thresholds configuration
├── data/
│   ├── rules/
│   │   └── Security_Rules.json <-- Security rule catalog mapped to OWASP / CWE
│   └── knowledge/              <-- Curated OWASP, NIST, and PQC knowledge base
├── docs/                       <-- Architectural & documentation specs
├── reports/                    <-- Output folder where generated reports are saved
└── tests/                      <-- Automated Pytest test suite (385+ tests)
```

---

## 4. Operational Flow & Processing Pipeline

The end-to-end operational flow of an AI Code Guardian scan follows an 11-stage pipeline:

```
[Target Repository]
       │
       ▼
 1. Discovery & Profiling ────► Identifies files, gitignore filters, tech stack & domain
       │
       ▼
 2. UST Parsing & Normalization ──► Tree-sitter parses Python, Java, JS, TS, Rust into Unified Syntax Tree
       │                             (Falls back to stdlib AST or regex if grammar missing)
       │
       ▼
 3. Deterministic Static Engines ─► Security Engine (SAST + Taint Flow)
       │                             Quantum Engine (Layer A: PQC Call Discovery)
       │                             Business Intent Engine (Control Flow Verification)
       │                             Dependencies & IaC Engines (CVE & Config Audit)
       │
       ▼
 4. Shared Evidence Store ─────► Collects observations with stable IDs (`E1`, `E2`, ...)
       │                             Deduplicates findings across engines
       │
       ▼
 5. Policy & Requirements ─────► Extracts policy controls from PDF/MD/DOCX/CSV specs
       │
       ▼
 6. Context Selection & RAG ───► Selects relevant evidence blocks fitting prompt budget
       │                             Retrieves OWASP/NIST standards via FAISS vector store
       │
       ▼
 7. NVIDIA Nemotron AI Pass ───► Reasons about impact, business context & mitigation
       │                             (Redacts secrets & PII before network transmission)
       │
       ▼
 8. Evidence Guardrails ──────► Validates AI claims against real code evidence:
       │                             - Validated -> AI_VALIDATED
       │                             - Uncorroborated -> AI_SUGGESTED (confidence capped at 0.6)
       │                             - Hallucinated / Fabricated evidence -> REJECTED
       │
       ▼
 9. Unified Risk Engine ───────► Computes multi-dimensional risk score across Security, PQC, Policy & Dependencies
       │
       ▼
10. Report Generation ─────────► Generates JSON, SARIF, HTML, CSV, PDF reports
       │
       ▼
11. Dashboard / REST API ──────► Serves Next.js UI & FastAPI REST endpoints for user exploration
```

---

## 5. Key Engine Descriptions & Modules

### 5.1 Unified Syntax Tree (UST) — `guardian/ust/`
Instead of running separate AST parsers or regex scanners for each language, Tree-sitter parses raw source files into concrete syntax trees, which are normalized into a single `USTNode` hierarchy. 
- A single security rule written against the UST automatically works across Python, Java, JavaScript, TypeScript, and Rust.
- Inter-procedural dataflow (`guardian/ust/dataflow.py`) tracks taint sources (e.g., HTTP params, user input) to taint sinks (e.g., SQL queries, system calls, command execution).

### 5.2 Deterministic Engines — `guardian/engines/`
- **Security Engine (`security.py`):** Operates on the UST to find SQL injection, XSS, Command Injection, Insecure Deserialization, Path Traversal, Sensitive Logging, and Weak Cryptography.
- **Quantum Engine (`quantum.py` & `guardian/quantum/`):**
  - **Layer A (Discovery):** UST site scanning locates cryptographic algorithms and unresolved dynamic calls.
  - **Layer B (Classification):** Maps algorithms deterministically to NIST PQC standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA) and produces a Cryptographic Bill of Materials (CBOM).
  - **Layer C (Context):** Evaluates business criticality and migration timelines for legacy algorithms (e.g. RSA, ECC).
- **Business Intent Engine (`business_intent.py`):** Converts compliance specifications into testable assertions and checks whether the code enforces required authorization, thresholds, and logging controls.

### 5.3 Shared Evidence Store — `guardian/evidence/`
Centralized repository where all engines record observations with immutable evidence IDs (`E1`, `E2`, etc.) and code location fingerprints. Prevents double-counting in risk scores and provides strict evidence grounding for AI analysis.

### 5.4 AI Contextual Reasoning & Validation Guardrails — `guardian/reasoning/`
- **Nemotron Reasoning Service:** Gateway handling API communication with NVIDIA Nemotron.
- **Context Budget Manager:** Ensures entire repositories are never sent; only selected evidence snippets fitting character budgets are sent.
- **Strict Validation Guardrails:** Every AI finding is checked. If the model invents a non-existent line number, fabricates an evidence ID, or contradicts the AST evidence, the finding is discarded (`INSUFFICIENT_EVIDENCE`). Validated model insights are marked as `AI_VALIDATED`, while uncorroborated suggestions are capped at `AI_SUGGESTED`.

### 5.5 Unified Risk Engine — `guardian/core/unified_risk.py`
Computes an objective, explainable risk score combining:
- SAST vulnerability severities
- Dependency CVE exploitability
- Post-Quantum readiness gaps
- Policy violation severity
- AI-sourced finding confidence weighting

---

## 6. Verification & Test Suite

The platform includes over **385 automated unit and integration tests** located in `tests/`:
- UST normalization tests across all supported languages.
- Fallback degradation tests (e.g., ensuring scans succeed when Tree-sitter grammars are missing).
- Anti-hallucination & invalid evidence rejection tests.
- Report formatting & SARIF schema validity tests.
- RAG vector retrieval & threat intelligence cache tests.

Run tests using:
```bash
python -m pytest tests/ -q
```
