# AI Code Guardian 2.0 — Complete End-to-End Technical Documentation

## Executive Summary
**AI Code Guardian 2.0** is an enterprise-grade, repository-agnostic application security platform built for 100% local execution with optional cloud/local AI enrichment. It performs Static Application Security Testing (SAST), Software Composition Analysis (SCA), Infrastructure-as-Code (IaC) structural scanning, Post-Quantum Cryptography (PQC) readiness assessment, Business Intent classification, and Composite Risk Scoring (CRS).

This document provides a comprehensive end-to-end record of every component, file change, function specification, bug fix, architectural decision, and future expansion path implemented in the project.

---

## 🏗️ Architecture & Data Flow

```
[ User / CI System / Web Dashboard ]
                 │
                 ▼
         Target Type Input
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
   GitHub URL         Local Directory / Zip
   (GitHubService)    (FileWalker & Detector)
        │                 │
        └────────┬────────┘
                 ▼
      ScanPipeline Orchestrator
                 │
  ┌──────────────┼──────────────┬──────────────┬──────────────┬──────────────┐
  ▼              ▼              ▼              ▼              ▼              ▼
SAST Engine   SCA Engine     IaC Engine     Quantum Engine  Intent Domain  Threat Intel
(AST Taint &  (13 Manifest   (Structural    (CBOM & FIPS    Classifier     (NVD/CISA/OSV
 Secrets)      Lockfiles)     PyYAML AST)    203/204/205)   + AI Rerank)   Cache)
  │              │              │              │              │              │
  └──────────────┴──────────────┼──────────────┴──────────────┴──────────────┘
                                ▼
                   Finding Aggregation & Dedup
                                │
                                ▼
                   Composite Risk Score (CRS)
                                │
                                ▼
                   AI Vulnerability Verifier
                   (Nemotron False Positive Triage)
                                │
                                ▼
                   Multi-Format Reporters
            (JSON / SARIF / HTML / CSV / PDF)
                                │
                                ▼
                   Streamlit Dashboard & AI Chat
```

---

## 📁 File-by-File Technical Implementation & Function Reference

---

### 1. Configuration & Engine Core (`guardian/config.py`, `guardian/core/`)

#### 📄 [guardian/config.py](file:///Users/prajwalkajale/Documents/acg2/guardian/config.py)
* **Purpose**: Serves as the single source of configuration truth for the entire application.
* **Key Additions & Changes**:
  * Added `.venv-app` to `DEFAULT_IGNORE_DIRS` alongside `.venv`, `.git`, `node_modules`, `dist`, `build`.
  * **Why**: Prevents `FileWalker` from scanning thousands of third-party python dependency ASTs inside Streamlit's virtualenv, eliminating deep recursion errors and slow scans.
* **Functions & Dataclasses**:
  * `GuardianConfig`: Dataclass containing filesystem limits (`max_files=200,000`, `max_file_bytes=2MB`), analysis toggles (`enable_dependencies`, `enable_infrastructure`, `enable_quantum`, `enable_intent`, `enable_ai`), and risk thresholds.
  * `load(path, **overrides)`: Class method loading YAML config files with CLI override precedence.

#### 📄 [guardian/core/interfaces.py](file:///Users/prajwalkajale/Documents/acg2/guardian/core/interfaces.py)
* **Purpose**: Defines standard Python `Protocol` interfaces for system components.
* **Protocols**:
  * `LanguagePlugin`: Standard contract for language scanners (`scan_source(source, file_label)`).
  * `Analyzer`: Standard contract for domain analyzers (`analyze(repo_root, files)`).
  * `Reporter`: Standard contract for report format renderers (`render(report_dict)`).
  * `IntentClassifier`: Contract for domain classifiers.

#### 📄 [guardian/core/registry.py](file:///Users/prajwalkajale/Documents/acg2/guardian/core/registry.py)
* **Purpose**: Decoupled, decorator-driven plugin registry.
* **Key Functions**:
  * `@register_language(name)`: Registers language plugin class.
  * `@register_analyzer(name)`: Registers analyzer class.
  * `@register_reporter(name)`: Registers output reporter class.
  * `load_builtin_plugins()`: Idempotent initializer importing built-in plugins (including `csv_reporter` and `pdf_reporter`).

#### 📄 [guardian/core/pipeline.py](file:///Users/prajwalkajale/Documents/acg2/guardian/core/pipeline.py)
* **Purpose**: Master orchestrator executing the end-to-end scan pipeline.
* **Key Additions**:
  * Intercepts GitHub URLs/slugs via `is_github_url(repo_root)` and invokes `GitHubService.fetch_repository()`.
* **Flow**: `Discovery` $\rightarrow$ `Repository Profile` $\rightarrow$ `Language Plugins` $\rightarrow$ `Dependency Analysis` $\rightarrow$ `Infrastructure Analysis` $\rightarrow$ `Quantum Analysis` $\rightarrow$ `Business Intent` $\rightarrow$ `Risk Scoring` $\rightarrow$ `Report Dictionary`.

#### 📄 [guardian/core/risk.py](file:///Users/prajwalkajale/Documents/acg2/guardian/core/risk.py)
* **Purpose**: Calculates the Composite Risk Score (CRS) and automated merge decisions.
* **Metrics Computed**:
  * `Security Score` (0-100 based on severity-weighted findings).
  * `Alignment Score` (0-100 based on requirement coverage).
  * `Overall Risk Score` (Weighted combination).
  * `Merge Decision`: Returns `ALLOW`, `WARN - Merge Allowed`, or `BLOCK`.

---

### 2. Repository Discovery & GitHub Integration (`guardian/discovery/`)

#### 📄 [guardian/discovery/file_walker.py](file:///Users/prajwalkajale/Documents/acg2/guardian/discovery/file_walker.py)
* **Purpose**: Safe filesystem traversal and file classification.
* **Key Additions**:
  * Added `pnpm-lock.yaml`, `poetry.lock`, `pipfile.lock` to `MANIFEST_NAMES`.
* **Functions**:
  * `walk(root)`: Lazy generator yielding files while respecting `ignore_dirs`, symlink inode cycle detection, and file size limits.
  * `discover(root, source_extensions)`: Classifies files into `source`, `manifests`, `infrastructure`, `docs`, and `other`.

#### 📄 [guardian/discovery/repo_detector.py](file:///Users/prajwalkajale/Documents/acg2/guardian/discovery/repo_detector.py)
* **Purpose**: Detects language distribution percentages, frameworks (Flask, Django, Spring, React, Streamlit), build tools (pip, maven, npm, cargo), and architecture (backend, frontend, monorepo).

#### 📄 [guardian/discovery/github_service.py](file:///Users/prajwalkajale/Documents/acg2/guardian/discovery/github_service.py)
* **Purpose**: Fetches GitHub repositories directly from URLs or `owner/repo` slugs.
* **Functions**:
  * `is_github_url(target: str) -> bool`: Validates if string is a GitHub URL or slug.
  * `parse_github_url(target: str) -> (owner, repo, ref)`: Extracts repository parameters.
  * `GitHubService.fetch_repository(target, token)`:
    1. Executes shallow `git clone --depth 1` (with `--branch` if specified).
    2. Fallback: Downloads HTTP Zipball from `https://api.github.com/repos/{owner}/{repo}/zipball/{ref}` using optional `GITHUB_TOKEN`.
  * **Why**: Allows instant scanning of remote repositories without requiring manual git clones.

---

### 3. SAST & Universal AST Engine (`guardian/scanner/`)

#### 📄 [guardian/scanner/common/treesitter_engine.py](file:///Users/prajwalkajale/Documents/acg2/guardian/scanner/common/treesitter_engine.py)
* **Purpose**: Provides AST node parsing and static data-flow taint analysis.
* **Classes & Functions**:
  * `PythonASTTaintAnalyzer(ast.NodeVisitor)`: AST visitor tracking tainted variable assignments from sources (`request.args`, `sys.argv`, `input`) to sinks (`execute()`, `os.system()`, `eval()`).
  * `_is_tainted_expr(node, depth)`: Recursively checks if an expression contains tainted variables. Includes a **recursion depth bound (`depth > 30`)** to prevent stack overflow.
  * `_get_attr_name(node, depth)`: Resolves qualified attribute names with depth limiting.
  * `analyze_python_ast(source, file_label)`: Entry point with null-byte (`\x00`) sanitization and exception wrapping.

#### 📄 [guardian/scanner/_engine.py](file:///Users/prajwalkajale/Documents/acg2/guardian/scanner/_engine.py)
* **Purpose**: Core SecurityRuleEngine containing entropy secret filtering and Python taint passes.
* **Bug Fix Made**:
  * Added `if "\x00" in text: text = text.replace("\x00", "")` and added `ValueError` exception handling around `ast.parse(text)`.
  * **Why**: Fixed `ValueError: source code string cannot contain null bytes` when non-UTF-8 or binary files were processed.

#### 📄 [guardian/scanner/python/plugin.py](file:///Users/prajwalkajale/Documents/acg2/guardian/scanner/python/plugin.py)
* **Updates**: Integrated `analyze_python_ast` from `treesitter_engine.py` into the scan pipeline.

#### 📄 [guardian/scanner/javascript/plugin.py](file:///Users/prajwalkajale/Documents/acg2/guardian/scanner/javascript/plugin.py)
* **Updates**: Added DOM-XSS patterns (`innerHTML`, `outerHTML`, `document.write`), React `dangerouslySetInnerHTML`, Node `child_process.exec`, Express `res.send`, and path traversal rules.

#### 📄 [guardian/scanner/rust/plugin.py](file:///Users/prajwalkajale/Documents/acg2/guardian/scanner/rust/plugin.py)
* **Features**: Scans Rust backend idioms (actix, axum, sqlx, diesel). Ignores test fixtures (`#[cfg(test)]`) to eliminate secret false positives in unit tests.

---

### 4. Dependency Analysis / SCA (`guardian/dependencies/`)

#### 📄 [guardian/dependencies/parsers.py](file:///Users/prajwalkajale/Documents/acg2/guardian/dependencies/parsers.py)
* **Purpose**: Extracts dependencies and version constraints across ecosystems.
* **Added Parsers**:
  * `parse_cargo_lock(path)`: Rust `Cargo.lock` parser.
  * `parse_gemfile_lock(path)`: Ruby `Gemfile.lock` parser.
  * `parse_composer_lock(path)`: PHP `composer.lock` parser.
  * `parse_go_sum(path)`: Go `go.sum` checksum parser.
  * `parse_yarn_lock(path)` / `pnpm-lock.yaml`: JavaScript lockfile parsers.
  * `parse_pipfile_lock(path)` & `parse_poetry_lock(path)`: Python lockfile parsers.

#### 📄 [guardian/dependencies/analyzer.py](file:///Users/prajwalkajale/Documents/acg2/guardian/dependencies/analyzer.py)
* **Purpose**: Identifies unpinned dependencies and queries OSV vulnerability database via threat intel collectors.

---

### 5. Infrastructure-as-Code Engine (`guardian/infrastructure/`)

#### 📄 [guardian/infrastructure/analyzer.py](file:///Users/prajwalkajale/Documents/acg2/guardian/infrastructure/analyzer.py)
* **Purpose**: Scans IaC deployment files.
* **Key Enhancements**:
  * Added `_analyze_yaml_ast` and `_check_k8s_spec`: Performs **structural AST object inspection** (`PyYAML`) over Kubernetes manifests and Docker Compose files.
  * Inspects nested dictionary keys (`spec.hostNetwork`, `securityContext.privileged`, `securityContext.runAsUser`) with 0.95+ confidence.

#### 📄 [guardian/infrastructure/rules.py](file:///Users/prajwalkajale/Documents/acg2/guardian/infrastructure/rules.py)
* **Catalog**: Data-driven rule catalog for Dockerfiles, Kubernetes, Terraform, and CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins).

---

### 6. Business Intent & AI Re-Ranking (`guardian/intent/`)

#### 📄 [guardian/intent/classifier.py](file:///Users/prajwalkajale/Documents/acg2/guardian/intent/classifier.py)
* **Purpose**: Classifies codebase business domain into a 14-domain taxonomy.
* **Key Enhancements**:
  * Added `_ai_rerank_pass(repo_root, verdict)`: When AI is enabled, feeds top-3 candidate domain verdicts and README text to NVIDIA Nemotron to refine domain confidence and reasoning.

#### 📄 [guardian/intent/domains.py](file:///Users/prajwalkajale/Documents/acg2/guardian/intent/domains.py)
* Vocabulary taxonomy covering Banking/Fintech, Healthcare/HIPAA, E-Commerce, Cybersecurity, ERP/CRM, etc.

---

### 7. Post-Quantum Cryptography & CBOM (`guardian/quantum/`)

#### 📄 [guardian/quantum/__init__.py](file:///Users/prajwalkajale/Documents/acg2/guardian/quantum/__init__.py)
* **Fix**: Added `from __future__ import annotations` at the top of the file.
* **Why**: Fixed `TypeError: unsupported operand type(s) for |: 'type' and 'NoneType'` in Python 3.9 environments.

#### 📄 [guardian/quantum/detector.py`, `inventory.py`, `mapper.py`, `scorer.py](file:///Users/prajwalkajale/Documents/acg2/guardian/quantum/detector.py)
* Detects legacy cryptographic algorithms (RSA, ECC, AES-128, MD5, SHA-1) and maps them to FIPS 203/204/205 Post-Quantum Cryptography (PQC) standards (ML-KEM, ML-DSA, SLH-DSA), outputting a Cryptographic Bill of Materials (CBOM).

---

### 8. AI Layer, Guardrails & Triage (`guardian/llm/`, `guardian/ai/`)

#### 📄 [guardian/llm/verifier.py](file:///Users/prajwalkajale/Documents/acg2/guardian/llm/verifier.py)
* **Purpose**: Automated AI vulnerability verification engine.
* **Functions**:
  * `AIFindingVerifier.verify_findings(repo_root, findings)`: Extracts code context windows around High/Critical findings, redacts secrets via guardrails, and asks NVIDIA Nemotron to verify exploitability vs false positives.

#### 📄 [guardian/llm/guardrails.py](file:///Users/prajwalkajale/Documents/acg2/guardian/llm/guardrails.py)
* **Purpose**: Security boundary enforcing outbound secret redaction (NVIDIA keys, AWS keys, connection strings) and inbound anti-hallucination validation.

#### 📄 [guardian/ai/rag_pipeline.py](file:///Users/prajwalkajale/Documents/acg2/guardian/ai/rag_pipeline.py)
* **Key Enhancements**:
  * Added `_get_conversational_response(question)`: Fast-path pattern matcher for casual greetings (`hi`, `hello`, `who are you`, `thanks`).
  * **Why**: Returns short 1-sentence replies instantly (**0 ms latency**, **0 LLM token cost**), bypassing expensive RAG context building and eliminating confusing "no evidence found" disclaimers.

#### 📄 [guardian/ai/prompt_builder.py](file:///Users/prajwalkajale/Documents/acg2/guardian/ai/prompt_builder.py)
* **Updates**: Enforces concise, direct markdown responses in `_SYSTEM_TEMPLATE`.

---

### 9. Multi-Format Reporting (`guardian/reporting/`)

#### 📄 [guardian/reporting/csv_reporter.py](file:///Users/prajwalkajale/Documents/acg2/guardian/reporting/csv_reporter.py)
* Renders findings in tabular CSV format for SIEM/SOC tools.

#### 📄 [guardian/reporting/pdf_reporter.py](file:///Users/prajwalkajale/Documents/acg2/guardian/reporting/pdf_reporter.py)
* Renders executive printable HTML/PDF reports with scorecards and severity matrices.

---

### 10. CLI & Streamlit Dashboard (`guardian/cli.py`, `dashboard/`)

#### 📄 [guardian/cli.py](file:///Users/prajwalkajale/Documents/acg2/guardian/cli.py)
* Unified CLI supporting `python -m guardian scan <target> --format json sarif html csv pdf`, `detect`, and `intent` over both local directories and GitHub URLs.

#### 📄 [dashboard/app.py](file:///Users/prajwalkajale/Documents/acg2/dashboard/app.py)
* **Updates**: Added `from __future__ import annotations`, replaced `Path | None` with `Optional[Path]`, added **GitHub Repository URL** input field, and integrated GitHub fetching into scan trigger.

#### 📄 [dashboard/chat_page.py](file:///Users/prajwalkajale/Documents/acg2/dashboard/chat_page.py)
* Interactive Streamlit RAG Copilot interface.

---

## 🧪 Verification & Test Log

The complete test suite was executed:

```bash
pytest tests/ -v
```

### Test Results Summary:
* **Total Tests**: 115
* **Passed**: 114
* **Skipped**: 1 (Optional live Excel/Jira integration test requiring openpyxl)
* **Execution Time**: 3.25 seconds

---

## 🚀 Future Roadmap & Possibilities ("What Else We Can Do")

1. **Tree-sitter Native Bindings (UAST Engine)**
   * Compile language grammars (`tree-sitter-python`, `tree-sitter-javascript`, `tree-sitter-go`, `tree-sitter-rust`, `tree-sitter-java`) for full C-extension AST query execution across complex codebases.

2. **Automated Pull Request Remediation Bot**
   * Create a GitHub Action / GitLab CI pipeline bot that automatically comments on Pull Requests with inline code fixes and SARIF annotations.

3. **Air-Gapped Local LLM Provider**
   * Add local LLM backends (Ollama, vLLM, or Llama.cpp) to `guardian/llm/factory.py` to enable 100% air-gapped AI triage without external API calls.

4. **IDE Extensions (VS Code & JetBrains Plugins)**
   * Package the `guardian` CLI engine into a VS Code extension for real-time security diagnostics in the editor.
