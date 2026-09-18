# 🛡️ AI Code Guardian

> **Multi-Language, UST-Driven, Multi-Agent & Evidence-Grounded Code Security Platform**

AI Code Guardian is an enterprise-grade code analysis and security threat detection platform. It combines **Tree-sitter Unified Syntax Trees (UST)**, **deterministic static engines**, **LangGraph multi-agent workflows**, and **NVIDIA Nemotron LLM reasoning** with strict **evidence-validation guardrails** to deliver zero-hallucination security analysis, business intent verification, and automated vulnerability remediation.

---

## 🌟 Key Capabilities & Highlights

* **Unified Syntax Tree (UST) Parsing**: Language-agnostic AST normalization across **Python**, **Java**, **JavaScript**, **TypeScript/TSX**, and **Rust**, with automatic stdlib AST and regex fallback ladders.
* **Deterministic Security Engine**: Zero-false-positive taint tracking for SQL injection, Command injection, Path traversal, Deserialization, DOM XSS, Insecure Deserialization, and Shannon entropy secret detection.
* **Business Intent Alignment Engine**: Converts policy documents (`.pdf`, `.docx`, `.md`, `.txt`, `.xlsx`, `.csv`) into structured control rules, producing an **AST Alignment Score (0–100%)** and **WHAT / WHY / HOW** remediation guides.
* **LangGraph Multi-Agent Orchestration**: Specialized agents (**Security**, **Business**, **Dependency/IaC**, **Orchestrator**) performing multi-hop correlated threat chain analysis linking low-level code bugs to high-value business assets.
* **Zero-Hallucination AI Guardrails**: Every LLM claim must cite validated evidence IDs (`E12`, `E43`). Unbacked claims are strictly rejected rather than downgraded.
* **Modern Full-Stack Experience**: Clean **FastAPI** backend with REST endpoints and a cyberpunk **Next.js** web dashboard with interactive multi-persona AI Copilot (**Developer**, **Executive**, **Red Teamer**).

---

## 🆕 What's New & Recent Enhancements

### 1. 💬 Structured Rich Markdown & Flex Cards in AI Copilot
* **Non-Overflowing Card Layout**: Replaced dense, wide Markdown tables with structured, responsive flex cards in the chat drawer (`ChatDrawer.tsx`).
* **Color-Coded Severity Pills**: Automated rendering of `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, and `[LOW]` badges in dedicated visual pill tags.
* **Mono Code Blocks & Evidence Badges**: Code snippets and file source citations are styled with dark mono code blocks and evidence source pins (`📌 Evidence Sources`).
* **Internal Marker Sanitization**: System tags (e.g. `<<CONTEXT_START>>`) are automatically scrubbed from responses.

### 2. 📊 Enriched Business Intent UI & AST Alignment Score
* **3-Part Findings Breakdown**: Each requirement violation provides **WHAT** failed, **WHY** it poses a risk, and **HOW** to remediate it.
* **Collapsible AI Business Impact Accordion**: Integrates the LangGraph Business Agent (`AIBusinessImpactSection.tsx`) to surface multi-hop correlated risk chains affecting business logic.
* **Deep Linking**: Clickable chains navigate directly to the underlying technical finding in the Security tab.

### 3. 🚀 Complete REST API & Agentic Scanner Service
* FastAPI endpoints (`/api/v1/agentic_scan`, `/api/v1/business_intent`, `/api/v1/chat`, `/api/v1/scans`) for seamless integration with external IDEs, CI/CD pipelines, and web UIs.

---

## 🏗️ Architecture & Processing Pipeline

```
                     ┌─────────────────────────────────────────┐
                     │          Source Code Repository         │
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │ Repository Discovery & Language Parser  │ (ust/parsers.py)
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │  Unified Syntax Tree (UST) Normalizer   │ (ust/languages/*)
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                               Deterministic Engines                               │
 ├─────────────────────────┬─────────────────────────────┬───────────────────────────┤
 │ Security Engine         │ Business Intent Engine      │ Dependency / IaC Engine   │
 │ (Taint & Secrets)       │ (Requirement Control Rules) │ (CVE & Config Audit)      │
 └─────────┬───────────────┴──────────────┬──────────────┴──────────────┬────────────┘
           │                              │                             │
           └──────────────────────────────┼─────────────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │         Shared Evidence Store           │ (evidence/store.py)
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                     LangGraph Multi-Agent & RAG Layer                             │
 ├───────────────────────────┬──────────────────────────────┬────────────────────────┤
 │ Context Selection & RAG   │ NVIDIA Nemotron Reasoning    │ Multi-Agent Workflow   │
 │ (FAISS + Vector Store)    │ (character budget redaction) │ (Security, Business)   │
 └───────────────────────────┴──────────────┬───────────────┴────────────────────────┘
                                            │
                                            ▼
                     ┌─────────────────────────────────────────┐
                     │   Evidence & Hallucination Guardrails   │ (reasoning/validation.py)
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
                     ┌─────────────────────────────────────────┐
                     │   Unified Risk Engine & Remediation     │ (core/unified_risk.py)
                     └────────────────────┬────────────────────┘
                                          │
                                          ▼
 ┌───────────────────────────────────────────────────────────────────────────────────┐
 │                                  Output Interfaces                                │
 ├───────────────────────────┬──────────────────────────────┬────────────────────────┤
 │ CLI Reports               │ FastAPI Backend REST API     │ Next.js Web Dashboard  │
 │ (JSON, SARIF, HTML, PDF)  │ (http://localhost:8000)      │ (http://localhost:3000)│
 └───────────────────────────┴──────────────┴───────────────┴────────────────────────┘
```

---

## 🧱 Key Engine Modules

### 1. 🛡️ Security Engine (`guardian/engines/security.py`)
Parses the UST to trace taint flows from untrusted inputs (sources) to dangerous execution calls (sinks).
* **Vulnerability Types**: SQL Injection, Command Execution, Unsafe Eval, Path Traversal, Insecure Deserialization, DOM XSS, Weak Crypto, and Disabled TLS.
* **Secret Detection**: Regex matching combined with Shannon Entropy analysis for API keys, tokens, and private keys.

### 2. 📋 Business Intent & Policy Engine (`guardian/engines/business_intent.py`)
Converts functional requirements and security policies into actionable rule structures:
$$\text{Requirement} \longrightarrow \{\text{action}, \text{condition}, \text{required\_control}\}$$
* **AST Control Verification**: Checks whether required authorization, input validation, or audit controls exist in the UST node of target functions.
* **Verdicts**: `COMPLIANT`, `VIOLATION`, `PARTIAL`, `INSUFFICIENT_EVIDENCE`.
* **Output**: Calculates overall **Alignment Score** and provides **WHAT / WHY / HOW** guides for every flagged gap.

### 3. 🤖 Multi-Agent Orchestration & Guardrails (`guardian/agents/`, `guardian/llm/guardrails.py`)
Uses LangGraph to coordinate specialized agents:
* **Security Agent**: Deep-dives into technical code vulnerabilities.
* **Business Agent**: Correlates technical flaws with financial, regulatory, and business operational risks.
* **Validation Guardrails**: Validates all AI claims against physical evidence records. AI claim statuses:
  - `DETERMINISTIC`: Verified by static rule/UST parsing.
  - `AI_VALIDATED`: AI reasoning backed 100% by code facts and evidence IDs.
  - `AI_SUGGESTED`: Grounded claim with partial corroboration (confidence capped at 0.6).
  - `INSUFFICIENT_EVIDENCE`: Rejected claim (never shown as a finding).

---

## ⚡ Quick Start & Installation

### Prerequisites
* **Python**: 3.10 or higher
* **Node.js**: 18.0 or higher (for web dashboard)
* **API Key** *(Optional)*: NVIDIA API key for Nemotron LLM reasoning (`NVIDIA_API_KEY`)

### 1. Installation Options

```bash
# Clone the repository
git clone https://github.com/your-org/ai_features.main.git
cd ai_features-main

# Core + Tree-sitter grammars (Recommended)
pip install -e ".[ust]"

# Full installation (CLI + Streamlit + AI + Docs)
pip install -e ".[all]"
```

**Available Install Extras**:

| Extra | Description |
|---|---|
| `[ust]` | Recommended. Enables Tree-sitter AST grammars for maximum precision. |
| `[ai]` | NVIDIA Nemotron gateway, local embeddings, and FAISS vector store. |
| `[dashboard]` | Streamlit fallback UI. |
| `[docs]` | Ingestion support for PDF, DOCX, and XLSX requirement files. |
| `[all]` | Installs all dependencies. |

---

### 2. Running via Command-Line Interface (CLI)

```bash
# Basic repository security scan
python -m guardian scan /path/to/repo --format json sarif html --out-dir reports/

# Scan repository against a Business Requirement document
python -m guardian scan /path/to/repo --requirements docs/requirements.md

# CI/CD Gating (exit code 1 on High/Critical findings)
python -m guardian scan . --format sarif --fail-on-severity High

# Check tree-sitter language parser status
python -m guardian parsers
```

---

### 3. Running the Full Stack (FastAPI + Next.js Dashboard)

#### Step 1: Start the Backend Service
```bash
cd backend
pip install -r requirements.txt
python main.py
# Backend API runs at http://localhost:8000
```

#### Step 2: Start the Web Dashboard
```bash
cd frontend
npm install
npm run dev
# Frontend Dashboard runs at http://localhost:3000
```

---

## 🌐 REST API Endpoints Overview

The FastAPI backend exposes a rich set of REST API endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/scans/run` | `POST` | Initiates a standard UST repository scan. |
| `/api/v1/agentic_scan/run` | `POST` | Triggers a full multi-agent LangGraph workflow. |
| `/api/v1/agentic_scan/{id}` | `GET` | Retrieves real-time agent execution status and correlated risk chains. |
| `/api/v1/business_intent/analyze` | `POST` | Uploads requirements and evaluates code AST alignment. |
| `/api/v1/chat/completions` | `POST` | Multi-persona AI copilot query endpoint (Developer, Executive, Red Teamer). |
| `/api/v1/findings/` | `GET` | Returns filterable findings by severity, category, or file. |
| `/api/v1/reports/export` | `POST` | Exports scan reports in JSON, SARIF 2.1.0, HTML, CSV, or PDF format. |

---

## 💻 Web Dashboard Experience

The Next.js dashboard provides a modern cyberpunk interface tailored for security teams and software engineers:

1. **📊 Security Overview**: High-level posture, total findings count, severity breakdowns, and language distribution.
2. **🛡️ Vulnerability Workbench**: Detailed static and AI-validated security findings with inline code snippets and remediation instructions.
3. **📋 Business Intent Tab**: Requirement coverage metrics, AST Alignment Score meter, and **WHAT/WHY/HOW** compliance breakdowns.
4. **🧠 Mind Map Visualizer**: Interactive node graph mapping repository structure to security findings and business assets.
5. **🤖 Agentic Workbench**: Real-time visualization of LangGraph agents executing threat modeling and patch generation.
6. **💬 Interactive Multi-Persona Copilot**: Side-drawer AI assistant with tailored personas:
   - **Developer**: Focuses on concrete code fixes and refactoring.
   - **Executive**: Summarizes financial, operational, and compliance risks.
   - **Red Teamer**: Explains exploitability, attack vectors, and proof-of-concept steps.

---

## 🧪 Testing & Verification

Run the comprehensive test suite:

```bash
pip install -e ".[dev,ust]"
python -m pytest tests/ -q
```

**Test Coverage Highlights**:
* UST normalization across Python, Java, JS/TS, and Rust.
* Degradation ladders (Tree-sitter $\rightarrow$ stdlib AST $\rightarrow$ Regex).
* Deterministic rule accuracy and evidence store integrity.
* Business intent parsing and AST condition matching.
* AI guardrails, hallucination rejection, and structured response parsing.

---

## 📁 Repository Structure

```
ai_features-main/
├── backend/                  # FastAPI REST API Backend
│   └── app/
│       ├── api/v1/           # API Routers (agentic_scan, business_intent, chat, scans, reports)
│       └── main.py           # Backend entrypoint (Port 8000)
├── frontend/                 # Next.js Web Dashboard
│   ├── src/
│   │   ├── app/              # Next.js App Router pages
│   │   └── components/       # UI Components (Security, Intent, Chat, Mindmap, Agentic)
│   └── package.json
├── guardian/                 # Core AI Code Guardian Engine
│   ├── agents/               # LangGraph Multi-Agent Workflows (Security, Business)
│   ├── discovery/            # Repository file discovery & language detection
│   ├── engines/              # Deterministic engines (Security, Business Intent)
│   ├── evidence/             # Evidence Store & Correlated Risk Chain builder
│   ├── llm/                  # NVIDIA Nemotron LLM gateway & Redaction Guardrails
│   ├── reasoning/            # RAG Knowledge retrieval & Hallucination validation
│   ├── reporting/            # Report generators (SARIF, JSON, HTML, PDF)
│   └── ust/                  # Tree-sitter Unified Syntax Tree normalizers
├── config/                   # Configuration files (default.yaml)
├── docs/                     # Architectural design specifications & guidelines
├── reports/                  # Generated security scan reports
├── tests/                    # Pytest test suite
└── pyproject.toml            # Project configuration & package extras
```

---

## 📄 License & Standards

Designed and built in accordance with **OWASP Top 10** and **SARIF 2.1.0** specifications.
