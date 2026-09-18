# Phase 6 Migration Document — Grounded Patch Generation & Validation Layer

> **Phase Status**: Completed  
> **Verification Result**: 426 passed, 1 skipped in 39.85s (`pytest tests/ -q`)

---

## 1. Overview of Phase 6 Additions

Phase 6 introduces the **Trustworthy AI Remediation Layer** (`guardian/agents/patch/`, `guardian/agents/validation/`, `guardian/reasoning/grounding/`, `guardian/llm/patch_prompts/`).

It generates evidence-grounded remediation proposals, validates AST/syntax compatibility, generates unified Git diffs without modifying files on disk, and mechanically re-verifies patch effectiveness.

It establishes:
1. **Patch Proposal Model (`guardian/agents/patch/models.py`)**: `PatchProposal` data structure containing `patch_id`, `finding_id`, `affected_file`, `affected_lines`, `original_snippet`, `suggested_replacement`, `explanation`, `evidence_ids`, `confidence`, `policy_references`, `business_impact`, `threat_impact`, `validation_status`, `git_diff`.
2. **Modular Patch Prompt Templates (`guardian/llm/patch_prompts/`)**: Modular prompt templates for SQL Injection, XSS, Command Injection, Secrets, Authentication, Authorization, Crypto, Dependency Updates, and IaC.
3. **Grounding Engine (`guardian/reasoning/grounding/grounding.py`)**: `GroundingEngine` validating that AI patch proposals map to existing files, line numbers, finding IDs, and evidence IDs. Rejects ungrounded or hallucinated claims.
4. **Git Diff Generator (`guardian/reasoning/grounding/diff.py`)**: `GitDiffGenerator` producing standard Unified Git Diff output without altering disk files.
5. **Mechanical Re-Verification (`guardian/agents/validation/verification.py`)**: `PatchVerificationService` re-evaluating replacement code using AST parsing and `SecurityRuleEngine` to verify finding resolution mechanically.
6. **Validation Agent (`guardian/agents/validation/agent.py`)**: `ValidationAgent` executing grounding verification and mechanical re-verification over generated patch proposals.
7. **Patch Generation Agent (`guardian/agents/patch/agent.py`)**: `PatchGenerationAgent` producing grounded remediation patch proposals, unified git diffs, and developer explanations.
8. **LangGraph StateGraph Expansion (`guardian/orchestrator/langgraph_flow.py`)**: Extends workflow transitions:  
   `START` -> `Planner` -> `Repository` -> `Business` -> `Security` -> `Architecture` -> `Dependency` -> `Threat Simulation` -> `Policy` -> `Risk Fusion` -> `Patch Generation` -> `Validation` -> `END`.

---

## 2. Directory Tree of Added & Modified Files

```
AI-Code-Guardian/
├── docs/
│   └── phases/
│       ├── phase1.md                         [PRESERVED] Phase 1 documentation
│       ├── phase2.md                         [PRESERVED] Phase 2 documentation
│       ├── phase3.md                         [PRESERVED] Phase 3 documentation
│       ├── phase4.md                         [PRESERVED] Phase 4 documentation
│       ├── phase5.md                         [PRESERVED] Phase 5 documentation
│       └── phase6.md                         [NEW] Documentation for Phase 6 migration
├── phases/
│   ├── phase1.md                         [PRESERVED] Phase 1 documentation
│   ├── phase2.md                         [PRESERVED] Phase 2 documentation
│   ├── phase3.md                         [PRESERVED] Phase 3 documentation
│   ├── phase4.md                         [PRESERVED] Phase 4 documentation
│   ├── phase5.md                         [PRESERVED] Phase 5 documentation
│   └── phase6.md                         [NEW] Mirror Phase 6 documentation
├── guardian/
│   ├── agents/
│   │   ├── patch/                            [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] PatchGenerationAgent exports
│   │   │   ├── agent.py                      [NEW] PatchGenerationAgent implementation
│   │   │   ├── models.py                     [NEW] PatchProposal model
│   │   │   └── tools.py                      [NEW] PatchBuilderTool
│   │   └── validation/                       [NEW SUBDIRECTORY]
│   │       ├── __init__.py                   [NEW] ValidationAgent exports
│   │       ├── agent.py                      [NEW] ValidationAgent implementation
│   │       ├── models.py                     [NEW] ValidationSummary
│   │       ├── tools.py                      [NEW] SyntaxCheckTool
│   │       └── verification.py               [NEW] PatchVerificationService
│   ├── llm/
│   │   └── patch_prompts/                    [NEW DIRECTORY]
│   │       ├── __init__.py                   [NEW] Package exports
│   │       ├── sql_injection.py              [NEW] SQL Injection prompt template
│   │       ├── secrets.py                    [NEW] Hardcoded secret prompt template
│   │       ├── auth.py                       [NEW] Auth prompt template
│   │       ├── crypto.py                     [NEW] Crypto prompt template
│   │       └── xss.py                        [NEW] XSS & IaC prompt templates
│   ├── reasoning/
│   │   └── grounding/                        [NEW DIRECTORY]
│   │       ├── __init__.py                   [NEW] Package exports
│   │       ├── grounding.py                  [NEW] GroundingEngine implementation
│   │       └── diff.py                       [NEW] GitDiffGenerator implementation
│   └── orchestrator/
│       ├── state.py                          [MODIFY] Added git_diff, validation_report, grounding_report, developer_explanation schema
│       ├── planner.py                        [MODIFY] Scheduled patch and validation in agent_order
│       ├── langgraph_flow.py                 [MODIFY] Extended StateGraph transitions
│       └── workflow.py                       [MODIFY] Registered PatchGenerationAgent and ValidationAgent
└── tests/
    └── test_phase6.py                        [NEW] Unit tests for Phase 6 remediation layer
```

---

## 3. Detail of New & Modified Files

### 3.1 New Modules & Files Added

1. **[`guardian/agents/patch/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/patch/agent.py)**
   - `PatchGenerationAgent` producing grounded remediation patch proposals and unified git diffs without modifying files on disk.

2. **[`guardian/agents/patch/models.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/patch/models.py)**
   - `PatchProposal` dataclass.

3. **[`guardian/reasoning/grounding/grounding.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/reasoning/grounding/grounding.py)**
   - `GroundingEngine` validating that AI patch proposals map to existing files, line numbers, finding IDs, and evidence IDs.

4. **[`guardian/reasoning/grounding/diff.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/reasoning/grounding/diff.py)**
   - `GitDiffGenerator` computing Unified Git Diffs in memory.

5. **[`guardian/agents/validation/verification.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/validation/verification.py)**
   - `PatchVerificationService` re-evaluating replacement code using AST parsing and `SecurityRuleEngine` to verify finding resolution mechanically.

6. **[`guardian/agents/validation/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/validation/agent.py)**
   - `ValidationAgent` executing grounding verification and mechanical re-verification over generated patch proposals.

7. **[`tests/test_phase6.py`](file:///Users/prajwalkajale/Documents/acg2/tests/test_phase6.py)**
   - 7 unit tests covering patch proposals, git diff generation, grounding verification, mechanical re-verification, and full 10-agent workflow execution.

---

## 4. Execution & Flow Diagrams

### LangGraph StateGraph Execution Flow

```
 ( START Node )
        │
        ▼
 [ Planner Agent ]
        │
        ▼
 [ Repository Agent ] ──> [ Business Agent ] ──> [ Security Agent ] ──> [ Architecture Agent ] ──> [ Dependency Agent ]
                                                                                                            │
        ┌───────────────────────────────────────────────────────────────────────────────────────────────────┘
        ▼
 [ Threat Simulation Agent ] ──> [ Policy Reasoning Agent ] ──> [ Risk Fusion Agent ]
                                                                        │
        ┌───────────────────────────────────────────────────────────────┘
        ▼
 [ Patch Generation Agent ] ──> Generates PatchProposal & Unified Git Diff
        │
        ▼
 [ Validation Agent ]       ──> Mechanically verifies syntax & AST resolution
        │
        ▼
   ( END Node )
```

---

## 5. Trust & Remediation Standards

* **Zero Disk Writes**: Patch generation never commits or overwrites repository source files on disk.
* **Grounded Remediation**: Every patch proposal requires valid evidence IDs and finding IDs. Un-grounded claims are rejected.
* **Mechanical Validation**: AST syntax parsing and deterministic scanner re-evaluation must pass for a patch to earn `PASSED` status.

---

## 6. Verification Summary

* Executed Pytest suite across all tests:
  ```bash
  pytest tests/ -q
  ```
* Output: `426 passed, 1 skipped in 39.85s`. Zero regressions.
