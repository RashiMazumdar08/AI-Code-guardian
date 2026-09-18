# Phase 1 Migration Document — Safe Sandbox & Repository Profiling

> **Phase Status**: Completed  
> **Verification Result**: 395 passed, 1 skipped in 5.91s (`pytest tests/ -q`)

---

## 1. Overview of Phase 1 Additions

Phase 1 introduces **Safe Execution Boundaries** via Docker/Process Sandbox isolation, enhanced **Repository Profiling** (entry point and public API route detection), and **Unified Syntax Tree (UST) Tagging Extensions** for entry points and authorization gates.

---

## 2. Directory Tree of Added & Modified Files

```
AI-Code-Guardian/
├── docs/
│   └── phases/
│       └── phase1.md                         [NEW] Documentation for Phase 1 migration
├── phases/
│   └── phase1.md                         [NEW] Mirror Phase 1 documentation
├── guardian/
│   ├── discovery/
│   │   └── repo_detector.py                  [MODIFY] Added entry points, detected endpoints, security markers & framework signatures
│   ├── sandbox/                              [NEW DIRECTORY]
│   │   ├── __init__.py                       [NEW] Sandbox package exports
│   │   ├── config.py                         [NEW] SandboxConfig (CPU/Mem limits, read-only, network isolation, secret redaction)
│   │   └── docker_runner.py                  [NEW] DockerSandboxRunner (Docker container execution & process-isolated fallback)
│   └── ust/
│       └── tagging.py                        [MODIFY] Added entry_point tagging pattern in business_tags_for
└── tests/
    ├── test_repo_detector_v3.py              [NEW] Unit tests for enhanced repository profiler
    └── test_sandbox.py                       [NEW] Unit tests for sandbox config, environment sanitization & fallback execution
```

---

## 3. Detail of New & Modified Files

### 3.1 New Modules & Files Added

1. **[`guardian/sandbox/config.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/sandbox/config.py)**
   - **Functionality**: Defines `SandboxConfig` dataclass to enforce security bounds during repository scanning.
   - **Key Features**:
     - Resource caps: `cpu_limit` (default 2.0 cores), `memory_limit` (default 4GB).
     - Isolation settings: `read_only=True`, `network_disabled=True`, `timeout_seconds=300`.
     - Automatic secret redaction: Redacts AWS keys, NVIDIA API keys, OpenAI keys, DB passwords, and custom authorization headers before running subprocesses or containers.

2. **[`guardian/sandbox/docker_runner.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/sandbox/docker_runner.py)**
   - **Functionality**: Manages containerized and process-isolated sandbox execution.
   - **Key Features**:
     - `is_docker_available`: Detects live Docker engine.
     - `_run_in_docker`: Launches container with `--cpus`, `--memory`, `:ro` volume mount, and `--network=none`.
     - `_run_in_process_sandbox`: Fallback process sandbox that creates an isolated temporary copy of the repository and executes commands with sanitized environment variables.
     - `prepare_isolated_workspace`: Safely clones repository files into a temporary workspace for non-destructive analysis.

3. **[`guardian/sandbox/__init__.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/sandbox/__init__.py)**
   - Exports `SandboxConfig`, `DockerSandboxRunner`, and `SandboxExecutionError`.

4. **[`tests/test_sandbox.py`](file:///d:/CDAC/AI-Code-Guardian/tests/test_sandbox.py)**
   - Verifies environment redaction, default sandbox limits, process fallback execution, and isolated workspace creation.

5. **[`tests/test_repo_detector_v3.py`](file:///d:/CDAC/AI-Code-Guardian/tests/test_repo_detector_v3.py)**
   - Verifies FastAPI, entry point, endpoint route, and security marker detection.

---

### 3.2 Existing Files Modified

1. **[`guardian/discovery/repo_detector.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/discovery/repo_detector.py)**
   - **What was changed**: Extended `RepositoryProfile` dataclass with `entry_points`, `detected_endpoints`, and `security_markers`.
   - **Functionality added**: Framework signature expanded (FastAPI, NestJS, Spring Boot, Actix-web, LangChain/AI Agents, PyTorch); added regex patterns for entry points (`if __name__ == '__main__'`, `main()`, `@SpringBootApplication`) and public API route annotations (`@app.get`, `@GetMapping`).

2. **[`guardian/ust/tagging.py`](file:///d:/CDAC/AI-Code-Guardian/guardian/ust/tagging.py)**
   - **What was changed**: Added `ENTRYPOINT_PATTERNS_TAG` regex pattern to `business_tags_for`.
   - **Functionality added**: Tags AST function nodes with `"entry_point"` for downstream graph building and planner agent prioritization.

---

## 4. Verification Summary

* Executed Pytest suite across all existing and new tests:
  ```bash
  pytest tests/ -q
  ```
* Output: `395 passed, 1 skipped in 5.91s`. Zero regressions.
