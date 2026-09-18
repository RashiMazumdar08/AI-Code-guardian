# Phase 5 Migration Document — Multi-Agent Intelligence Layer

> **Phase Status**: Completed  
> **Verification Result**: 419 passed, 1 skipped in 39.14s (`pytest tests/ -q`)

---

## 1. Overview of Phase 5 Additions

Phase 5 introduces the **Collaborative Intelligence Layer** (`guardian/agents/threat_simulation/`, `guardian/agents/policy/`, `guardian/agents/risk/`, `guardian/policies/`, `guardian/evidence/correlation.py`, `guardian/agents/shared/consensus.py`).

It performs grounded reasoning over deterministic evidence gathered in Phases 1–4 without hallucinating vulnerabilities or fabricating attack paths.

It establishes:
1. **Threat Simulation Agent (`guardian/agents/threat_simulation/`)**: Evaluates exploitability, reachability, attack chains, auth bypass, and data exposure grounded strictly in deterministic findings and evidence IDs.
2. **Policy Reasoning Agent (`guardian/agents/policy/`)**: Assesses findings against company policies and compliance standards (OWASP, NIST, PCI-DSS) loaded via `PolicyPackManager`.
3. **Policy Pack Manager (`guardian/policies/`)**: Manages YAML/JSON policy pack loading, validation, organization profiles, rule resolution, and versioning (`policy.yaml`, `security.yaml`, `organization.json`, `compliance.yaml`).
4. **Risk Fusion Agent (`guardian/agents/risk/`)**: Wraps and extends `UnifiedRiskEngine` to compute technical, business, threat, and policy risk scores into a unified composite risk profile.
5. **Evidence Correlation Service (`guardian/evidence/correlation.py`)**: Deduplicates findings, maps evidence chains, and correlates business criticality with attack paths.
6. **Reasoning Consensus (`guardian/agents/shared/consensus.py`)**: Computes multi-agent consensus confidence across security, architecture, threat, and policy steps.
7. **Knowledge Service Expansion (`guardian/knowledge/services/knowledge_service.py`)**: Extends `KnowledgeService` facade with policy, business, and threat context retrieval, evidence lookups, graph traversals, and patch context queries.
8. **LangGraph StateGraph Expansion (`guardian/orchestrator/langgraph_flow.py`)**: Extends workflow transitions:  
   `START` -> `Planner` -> `Repository` -> `Business` -> `Security` -> `Architecture` -> `Dependency` -> `Threat Simulation` -> `Policy` -> `Risk Fusion` -> `END`.

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
│       └── phase5.md                         [NEW] Documentation for Phase 5 migration
├── phases/
│   ├── phase1.md                         [PRESERVED] Phase 1 documentation
│   ├── phase2.md                         [PRESERVED] Phase 2 documentation
│   ├── phase3.md                         [PRESERVED] Phase 3 documentation
│   ├── phase4.md                         [PRESERVED] Phase 4 documentation
│   └── phase5.md                         [NEW] Mirror Phase 5 documentation
├── guardian/
│   ├── agents/
│   │   ├── shared/                           [MODIFY] Added ThreatContext, PolicyResults, RiskProfile, CorrelatedFindings & ReasoningConsensus
│   │   ├── threat_simulation/                [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] ThreatSimulationAgent exports
│   │   │   ├── agent.py                      [NEW] ThreatSimulationAgent implementation
│   │   │   ├── models.py                     [NEW] ThreatModelSummary
│   │   │   └── tools.py                      [NEW] AttackChainTool
│   │   ├── policy/                           [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] PolicyAgent exports
│   │   │   ├── agent.py                      [NEW] PolicyAgent implementation
│   │   │   ├── models.py                     [NEW] PolicyEvaluationSummary
│   │   │   └── tools.py                      [NEW] ComplianceValidatorTool
│   │   └── risk/                             [NEW SUBDIRECTORY]
│   │       ├── __init__.py                   [NEW] RiskFusionAgent exports
│   │       ├── agent.py                      [NEW] RiskFusionAgent implementation
│   │       ├── models.py                     [NEW] RiskCompositeSummary
│   │       └── tools.py                      [NEW] RiskWeightTool
│   ├── policies/                             [NEW DIRECTORY]
│   │   ├── __init__.py                       [NEW] Package exports
│   │   ├── schema.py                         [NEW] PolicyRule & PolicyPack schemas
│   │   ├── loader.py                         [NEW] YAML/JSON PolicyLoader
│   │   └── manager.py                        [NEW] PolicyPackManager
│   ├── evidence/
│   │   └── correlation.py                    [NEW] EvidenceCorrelationService
│   ├── knowledge/
│   │   └── services/
│   │       └── knowledge_service.py          [MODIFY] Added policy/threat retrieval, evidence lookup & graph traversal APIs
│   └── orchestrator/
│       ├── state.py                          [MODIFY] Added threat_context, policy_results, risk_scores, correlated_findings schema
│       ├── planner.py                        [MODIFY] Scheduled Phase 5 agents in agent_order
│       ├── langgraph_flow.py                 [MODIFY] Extended StateGraph transitions
│       └── workflow.py                       [MODIFY] Registered Phase 5 intelligence agents
└── tests/
    └── test_phase5.py                        [NEW] Unit tests for Phase 5 intelligence layer
```

---

## 3. Detail of New & Modified Files

### 3.1 New Modules & Files Added

1. **[`guardian/agents/threat_simulation/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/threat_simulation/agent.py)**
   - `ThreatSimulationAgent` models attack paths, exploitability, and reachability grounded in evidence IDs.

2. **[`guardian/agents/policy/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/policy/agent.py)**
   - `PolicyAgent` evaluates security findings against active policy packs using `PolicyPackManager`.

3. **[`guardian/agents/risk/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/risk/agent.py)**
   - `RiskFusionAgent` computes unified composite risk scores, evidence correlation, and reasoning consensus.

4. **[`guardian/policies/manager.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/policies/manager.py)**
   - `PolicyPackManager` registers, parses, and evaluates YAML/JSON policy packs.

5. **[`guardian/evidence/correlation.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/evidence/correlation.py)**
   - `EvidenceCorrelationService` deduplicates findings and maps evidence to attack chains.

6. **[`guardian/agents/shared/consensus.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/shared/consensus.py)**
   - `ReasoningConsensus` calculates multi-agent confidence across grounding evidence and agent traces.

7. **[`tests/test_phase5.py`](file:///Users/prajwalkajale/Documents/acg2/tests/test_phase5.py)**
   - 7 unit tests covering threat simulation, policy evaluation, risk fusion, evidence correlation, consensus engine, knowledge service extensions, and full workflow.

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
 [ Threat Simulation Agent ] ──> Evaluates attack paths & exploitability
        │
        ▼
 [ Policy Reasoning Agent ]  ──> Evaluates OWASP / NIST / Company policy packs
        │
        ▼
 [ Risk Fusion Agent ]       ──> Calculates composite risk, evidence correlation, & consensus confidence
        │
        ▼
   ( END Node )
```

---

## 5. Agent Responsibilities & Reasoning Bounds

* **Grounded Reasoning**: Intelligence agents reason strictly over evidence from deterministic engines. Zero hallucinated findings.
* **Threat Simulation**: Calculates exploitability and attack paths without running external exploits or code scanners.
* **Policy Evaluation**: Evaluates compliance rules without re-running SAST engines.
* **Risk Fusion**: Integrates technical, business, threat, and policy risks into a single composite score.

---

## 6. Verification Summary

* Executed Pytest suite across all tests:
  ```bash
  pytest tests/ -q
  ```
* Output: `419 passed, 1 skipped in 39.14s`. Zero regressions.
