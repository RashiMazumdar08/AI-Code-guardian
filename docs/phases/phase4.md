# Phase 4 Migration Document — Core Specialist Analysis Agents

> **Phase Status**: Completed  
> **Verification Result**: 412 passed, 1 skipped in 33.48s (`pytest tests/ -q`)

---

## 1. Overview of Phase 4 Additions

Phase 4 introduces the first generation of **Specialist Analysis Agents** (`guardian/agents/`), functioning as intelligent deterministic wrappers around the platform's core engines (repository profiling, business intent, security scanners, knowledge graphs, and dependency analyzers).

It establishes:
1. **Base Agent Framework (`guardian/agents/base/`)**: `BaseAgent` class providing uniform execution, trace logging (`AgentTrace`), metrics tracking (`ExecutionMetrics`), event distribution (`EventBus`), and tool integration (`ToolRegistry`).
2. **Shared Context Models (`guardian/agents/shared/`)**: Strongly-typed structures (`RepositoryContext`, `BusinessContextObject`, `SecurityContext`, `ArchitectureContext`, `DependencyContext`) stored directly in `AgentWorkflowState`.
3. **Repository Agent (`guardian/agents/repository/`)**: Deterministically aggregates repository topology, entry points, public APIs, auth modules, DB layers, and high-risk paths into `repository_context`.
4. **Business Agent (`guardian/agents/business/`)**: Wraps Business Intent Engine to categorize domain, criticality, compliance frameworks, and critical assets into `business_context`.
5. **Security Agent (`guardian/agents/security/`)**: Wraps deterministic security scanner engine (`SecurityRuleEngine`). Collects findings, normalizes attributes, links evidence grounding objects, and updates `security_context`. Zero LLM calls.
6. **Architecture Agent (`guardian/agents/architecture/`)**: Uses Knowledge Graph / Neo4j and UST context to derive service boundaries, authentication flows, database relationships, and trust boundaries into `architecture_context`.
7. **Dependency Agent (`guardian/agents/dependency/`)**: Wraps `DependencyAnalyzer` to parse manifests (`requirements.txt`, `package.json`, `pom.xml`, `Cargo.toml`), track dependency inventories, and flag CVE vulnerabilities into `dependency_context`.
8. **LangGraph StateGraph Expansion (`guardian/orchestrator/langgraph_flow.py`)**: Extends workflow transitions:  
   `START` -> `Planner` -> `Repository` -> `Business` -> `Security` -> `Architecture` -> `Dependency` -> `END`.

---

## 2. Directory Tree of Added & Modified Files

```
AI-Code-Guardian/
├── docs/
│   └── phases/
│       ├── phase1.md                         [PRESERVED] Phase 1 documentation
│       ├── phase2.md                         [PRESERVED] Phase 2 documentation
│       ├── phase3.md                         [PRESERVED] Phase 3 documentation
│       └── phase4.md                         [NEW] Documentation for Phase 4 migration
├── phases/
│   ├── phase1.md                         [PRESERVED] Phase 1 documentation
│   ├── phase2.md                         [PRESERVED] Phase 2 documentation
│   ├── phase3.md                         [PRESERVED] Phase 3 documentation
│   └── phase4.md                         [NEW] Mirror Phase 4 documentation
├── guardian/
│   ├── agents/                               [NEW DIRECTORY]
│   │   ├── __init__.py                       [NEW] Package exports
│   │   ├── base/                             [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] Base package exports
│   │   │   ├── agent.py                      [NEW] BaseAgent abstract class
│   │   │   └── models.py                     [NEW] AgentResult dataclass
│   │   ├── shared/                           [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] Shared context package exports
│   │   │   └── context.py                    [NEW] Typed context objects
│   │   ├── repository/                       [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] RepositoryAgent package exports
│   │   │   ├── agent.py                      [NEW] RepositoryAgent implementation
│   │   │   ├── models.py                     [NEW] RepositorySummary model
│   │   │   └── tools.py                      [NEW] RepositoryScanTool helper
│   │   ├── business/                         [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] BusinessAgent package exports
│   │   │   ├── agent.py                      [NEW] BusinessAgent implementation
│   │   │   ├── models.py                     [NEW] BusinessDomainClassification model
│   │   │   └── tools.py                      [NEW] DomainRuleTool helper
│   │   ├── security/                         [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] SecurityAgent package exports
│   │   │   ├── agent.py                      [NEW] SecurityAgent implementation
│   │   │   ├── models.py                     [NEW] SecurityScanSummary model
│   │   │   └── tools.py                      [NEW] NormalizedFindingTool helper
│   │   ├── architecture/                     [NEW SUBDIRECTORY]
│   │   │   ├── __init__.py                   [NEW] ArchitectureAgent package exports
│   │   │   ├── agent.py                      [NEW] ArchitectureAgent implementation
│   │   │   ├── models.py                     [NEW] ArchitectureTopology model
│   │   │   └── tools.py                      [NEW] TopologyGraphTool helper
│   │   └── dependency/                       [NEW SUBDIRECTORY]
│   │       ├── __init__.py                   [NEW] DependencyAgent package exports
│   │       ├── agent.py                      [NEW] DependencyAgent implementation
│   │       ├── models.py                     [NEW] DependencyInventory model
│   │       └── tools.py                      [NEW] OSVLookupTool helper
│   └── orchestrator/
│       ├── state.py                          [MODIFY] Added repository, architecture, dependency, security context schema
│       ├── planner.py                        [MODIFY] Dynamic agent discovery via AgentRegistry
│       ├── langgraph_flow.py                 [MODIFY] Expanded StateGraph transitions
│       └── workflow.py                       [MODIFY] Registered 5 core specialist agents
└── tests/
    └── test_agents.py                        [NEW] Unit tests for all Phase 4 specialist agents
```

---

## 3. Detail of New & Modified Files

### 3.1 New Modules & Files Added

1. **[`guardian/agents/base/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/base/agent.py)**
   - `BaseAgent` abstract class handling lifecycle execution, timer metrics, event emissions (`TaskScheduled`, `TaskCompleted`), trace records (`AgentTrace`), and state propagation.

2. **[`guardian/agents/shared/context.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/shared/context.py)**
   - Typed context structures: `RepositoryContext`, `BusinessContextObject`, `SecurityContext`, `ArchitectureContext`, `DependencyContext`.

3. **[`guardian/agents/repository/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/repository/agent.py)**
   - `RepositoryAgent` deterministic aggregator for frameworks, entry points, public APIs, auth modules, DB layers, and high-risk paths.

4. **[`guardian/agents/business/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/business/agent.py)**
   - `BusinessAgent` wrapping Business Intent classification engines to populate `business_context`.

5. **[`guardian/agents/security/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/security/agent.py)**
   - `SecurityAgent` executing `SecurityRuleEngine` and normalizing findings, linking evidence IDs, and updating `security_context`.

6. **[`guardian/agents/architecture/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/architecture/agent.py)**
   - `ArchitectureAgent` extracting service boundaries, trust boundaries, auth flows, and DB interactions.

7. **[`guardian/agents/dependency/agent.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/agents/dependency/agent.py)**
   - `DependencyAgent` wrapping `DependencyAnalyzer` to parse package manifests and record dependency inventories and CVE findings.

8. **[`tests/test_agents.py`](file:///Users/prajwalkajale/Documents/acg2/tests/test_agents.py)**
   - 6 unit tests validating individual agent outputs, context creation, trace records, and full multi-agent workflow execution.

---

## 4. Execution & State Diagrams

### LangGraph StateGraph Execution Flow

```
[ Scan Request ]
        │
        ▼
 ( START Node )
        │
        ▼
 [ Planner Agent ] ──> Generates ExecutionPlan & Agent Order
        │
        ▼
 [ Repository Agent ] ──> Populates repository_context
        │
        ▼
 [ Business Agent ] ──> Populates business_context
        │
        ▼
 [ Security Agent ] ──> Populates findings, evidence, security_context
        │
        ▼
 [ Architecture Agent ] ──> Populates architecture_context
        │
        ▼
 [ Dependency Agent ] ──> Populates dependency_context & dependency findings
        │
        ▼
   ( END Node )
        │
        ▼
[ Final AgentWorkflowState ]
```

---

## 5. Agent Responsibilities & Isolation Standards

* **Wrapper Design**: Agents wrap deterministic platform capabilities (`SecurityRuleEngine`, `DependencyAnalyzer`, `BusinessIntentEngine`, `RepositoryDetector`).
* **Zero Direct Communication**: Specialist agents never call each other; all information passes through `AgentWorkflowState`.
* **Zero Artificial Vulnerabilities**: Findings originate exclusively from deterministic analysis engines; agents do not invent issues.
* **Preparedness for Phase 5**: Phase 4 completes the core analysis pipeline, creating normalized context objects for future reasoning and simulation agents (`Threat Simulation`, `Policy Agent`, `Risk Fusion`, `Patch Generator`, `Validation Agent`).

---

## 6. Verification Summary

* Executed Pytest suite across all tests:
  ```bash
  pytest tests/ -q
  ```
* Output: `412 passed, 1 skipped in 33.48s`. Zero regressions.
