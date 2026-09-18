# Phase 3 Migration Document — LangGraph Orchestration & Shared Workflow State

> **Phase Status**: Completed  
> **Verification Result**: 406 passed, 1 skipped in 33.12s (`pytest tests/ -q`)

---

## 1. Overview of Phase 3 Additions

Phase 3 introduces the **AI Orchestration Layer** for **AI Code Guardian v3**, creating the execution engine, shared workflow memory, agent registry, tool registry, pub/sub event bus, execution tracing, and LangGraph workflow state transitions.

It establishes:
1. **Orchestrator Package (`guardian/orchestrator/`)**: Modular engine providing multi-agent orchestration infrastructure.
2. **Shared Workflow State (`guardian/orchestrator/state.py`)**: `AgentWorkflowState` single source of truth containing 22 required fields for cross-agent communication.
3. **LangGraph StateGraph Workflow (`guardian/orchestrator/langgraph_flow.py`)**: StateGraph engine executing `START` -> `Planner` -> `END` with placeholder nodes for future specialist agents.
4. **Planner Agent (`guardian/orchestrator/planner.py`)**: `PlannerAgent` reading profile, business intent, policies, graph, and semantic context to generate strategic `ExecutionPlan` without scanning vulnerabilities directly.
5. **Agent Registry (`guardian/orchestrator/registry.py`)**: Dynamic plugin registry for agent registration and discovery without hardcoded dependencies.
6. **Tool Registry (`guardian/orchestrator/tools.py`)**: `ToolRegistry` wrapping system capabilities (`KnowledgeTool`, `BusinessIntentTool`, `PolicyTool`, `RiskTool`, `RepositoryGraphTool`, `SemanticSearchTool`, `ParserTool`, `EvidenceTool`, `ReportTool`, `ValidationTool`).
7. **Event Bus (`guardian/orchestrator/events.py`)**: Pub/sub event system publishing `WorkflowStarted`, `PlannerCompleted`, `TaskScheduled`, `TaskCompleted`, `WorkflowCompleted`, `FindingCreated`, `FindingUpdated`.
8. **Execution Traces & Metrics (`guardian/orchestrator/state.py`)**: `AgentTrace` and `ExecutionMetrics` telemetry structures recorded directly in `AgentWorkflowState`.

---

## 2. Directory Tree of Added & Modified Files

```
AI-Code-Guardian/
├── docs/
│   └── phases/
│       ├── phase1.md                         [PRESERVED] Phase 1 documentation
│       ├── phase2.md                         [PRESERVED] Phase 2 documentation
│       └── phase3.md                         [NEW] Documentation for Phase 3 migration
├── phases/
│   ├── phase1.md                         [PRESERVED] Phase 1 documentation
│   ├── phase2.md                         [PRESERVED] Phase 2 documentation
│   └── phase3.md                         [NEW] Mirror Phase 3 documentation
├── guardian/
│   ├── knowledge/
│   │   └── graph/
│   │       └── builder.py                    [MODIFY] Fixed macOS path resolution in relative_to
│   └── orchestrator/                         [NEW DIRECTORY]
│       ├── __init__.py                       [NEW] Package exports
│       ├── state.py                          [NEW] AgentWorkflowState, AgentTrace, ExecutionMetrics
│       ├── events.py                         [NEW] EventBus and event hierarchy
│       ├── tools.py                          [NEW] BaseTool and ToolRegistry abstractions
│       ├── registry.py                       [NEW] AgentRegistry dynamic plugin loader
│       ├── planner.py                        [NEW] ExecutionPlan & PlannerAgent implementation
│       ├── langgraph_flow.py                 [NEW] LangGraph StateGraph engine & node bindings
│       └── workflow.py                       [NEW] OrchestratorWorkflow top-level facade
└── tests/
    └── test_orchestrator.py                  [NEW] Unit tests for state, planner, registries, events, and metrics
```

---

## 3. Detail of New & Modified Files

### 3.1 New Modules & Files Added

1. **[`guardian/orchestrator/state.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/state.py)**
   - Defines `AgentWorkflowState` TypedDict containing all 22 required state attributes: `scan_id`, `repository_profile`, `repository_graph`, `semantic_context`, `business_context`, `policy_context`, `knowledge_context`, `retrieved_documents`, `current_task`, `execution_plan`, `active_agent`, `completed_agents`, `pending_agents`, `findings`, `evidence`, `risk_scores`, `validation_results`, `patches`, `reports`, `agent_trace`, `execution_metrics`.
   - Provides `AgentTrace` and `ExecutionMetrics` schema and `create_initial_state(...)` initializer.

2. **[`guardian/orchestrator/events.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/events.py)**
   - Pub/sub `EventBus` supporting handler subscriptions and synchronous event publishing. Includes event types: `WorkflowStarted`, `PlannerCompleted`, `TaskScheduled`, `TaskCompleted`, `WorkflowCompleted`, `FindingCreated`, `FindingUpdated`.

3. **[`guardian/orchestrator/tools.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/tools.py)**
   - `ToolRegistry` and concrete tool wrappers (`KnowledgeTool`, `BusinessIntentTool`, `PolicyTool`, `RiskTool`, `RepositoryGraphTool`, `SemanticSearchTool`, `ParserTool`, `EvidenceTool`, `ReportTool`, `ValidationTool`).

4. **[`guardian/orchestrator/registry.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/registry.py)**
   - `AgentRegistry` handling dynamic registration, retrieval, and discovery of agent classes.

5. **[`guardian/orchestrator/planner.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/planner.py)**
   - `ExecutionPlan` dataclass and `PlannerAgent`. Generates execution strategy, updates state, records trace records and runtime metrics, and emits `PlannerCompleted` event.

6. **[`guardian/orchestrator/langgraph_flow.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/langgraph_flow.py)**
   - Compiles LangGraph `StateGraph` linking `START` -> `Planner` -> `END` with placeholder node definitions for future specialist agents.

7. **[`guardian/orchestrator/workflow.py`](file:///Users/prajwalkajale/Documents/acg2/guardian/orchestrator/workflow.py)**
   - Top-level `OrchestratorWorkflow` facade binding state creation, tool/agent registries, event bus, and LangGraph workflow invocation.

8. **[`tests/test_orchestrator.py`](file:///Users/prajwalkajale/Documents/acg2/tests/test_orchestrator.py)**
   - 6 unit tests covering state initialization, event bus, tool registry, agent registry, planner execution, and StateGraph workflow.

---

## 4. Execution & State Diagrams

### Workflow Execution Diagram

```
[ Scan Initiated ]
        │
        ▼
[ OrchestratorWorkflow ]
        │
        ├──────────────────────┬──────────────────────┐
        ▼                      ▼                      ▼
  ToolRegistry           AgentRegistry             EventBus
        │                      │                      │
        └──────────────────────┼──────────────────────┘
                               ▼
                    [ LangGraph StateGraph ]
                               │
                               ▼
                        ( START Node )
                               │
                               ▼
                       [ Planner Agent ]
                               │
                               ▼
                        ( END Node )
                               │
                               ▼
                    [ Final Workflow State ]
```

### State Transition Diagram

```
[ Raw Inputs ] ──> [ create_initial_state ] ──> [ AgentWorkflowState (IDLE) ]
                                                         │
                                                         ▼
                                                [ Planner Node ]
                                                         │
                                                         ├─ Update execution_plan
                                                         ├─ Append pending_agents
                                                         ├─ Append agent_trace
                                                         └─ Update execution_metrics
                                                         │
                                                         ▼
                                                [ StateGraph (END) ]
```

---

## 5. Design Decisions & Future Integration

* **Clean Orchestration Separation**: LangGraph controls flow state only; deterministic engines (UST parsers, KnowledgeService, Intent engines) retain ground-truth logic.
* **Strict Communication Boundaries**: Specialist agents never communicate directly; all data passes through `AgentWorkflowState`.
* **Zero Hardcoded Imports**: Agent discovery passes exclusively through `AgentRegistry`. System capabilities pass exclusively through `ToolRegistry`.
* **Future Plug-and-Play**: Phase 4+ specialist agents (`security`, `architecture`, `threat_simulation`, `policy`, `patch`, etc.) drop into `StateGraph` without altering the orchestration engine.

---

## 6. Verification Summary

* Executed Pytest suite across all tests:
  ```bash
  pytest tests/ -q
  ```
* Output: `406 passed, 1 skipped in 33.12s`. Zero regressions.
