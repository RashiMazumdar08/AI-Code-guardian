"""
AI Code Guardian v3 — Shared Workflow State
============================================
Single source of truth for multi-agent LangGraph workflow execution.
Every future agent communicates exclusively through this shared state.
"""
from __future__ import annotations

import time
from typing import Annotated, Any, Dict, List, Optional, TypedDict

from langgraph.graph.message import add_messages


class AgentTrace(TypedDict, total=False):
    """Execution trace record for an agent step."""
    agent_name: str
    execution_time: float
    current_task: str
    tools_used: List[str]
    evidence_ids: List[str]
    confidence: float
    result: Dict[str, Any]
    errors: List[str]


class ExecutionMetrics(TypedDict, total=False):
    """Performance and telemetry metrics across workflow execution."""
    total_execution_time: float
    agent_runtime: Dict[str, float]
    tool_runtime: Dict[str, float]
    retrieval_latency: float
    graph_query_latency: float
    embedding_retrieval_latency: float
    number_of_findings: int
    number_of_policies_applied: int
    number_of_evidence_objects: int


class AgentWorkflowState(TypedDict, total=False):
    """
    Master state schema passed between LangGraph nodes.
    Single source of truth across all AI agents in AI Code Guardian v3.
    """
    messages: Annotated[list[Any], add_messages]
    scan_mode: str
    scan_id: str
    repository_profile: Dict[str, Any]
    repository_graph: Dict[str, Any]
    semantic_context: Dict[str, Any]
    business_context: Dict[str, Any]
    business_intent_results: Dict[str, Any]
    business_violations: List[Dict[str, Any]]
    policy_context: Dict[str, Any]
    knowledge_context: Dict[str, Any]
    retrieved_documents: List[Dict[str, Any]]
    current_task: str
    execution_plan: Dict[str, Any]
    active_agent: str
    completed_agents: List[str]
    pending_agents: List[str]
    findings: List[Dict[str, Any]]
    evidence: List[Dict[str, Any]]
    risk_scores: Dict[str, Any]
    validation_results: List[Dict[str, Any]]
    patches: List[Dict[str, Any]]
    reports: List[Dict[str, Any]]
    repository_context: Dict[str, Any]
    architecture_context: Dict[str, Any]
    dependency_context: Dict[str, Any]
    security_context: Dict[str, Any]
    threat_context: Dict[str, Any]
    policy_results: Dict[str, Any]
    correlated_findings: Dict[str, Any]
    attack_paths: List[Dict[str, Any]]
    exploitability: float
    git_diff: str
    validation_report: Dict[str, Any]
    grounding_report: Dict[str, Any]
    remediation_summary: Dict[str, Any]
    developer_explanation: str
    validation_confidence: float
    agent_trace: List[AgentTrace]
    execution_metrics: ExecutionMetrics


def create_initial_state(
    scan_id: str,
    repository_profile: Optional[Dict[str, Any]] = None,
    business_context: Optional[Dict[str, Any]] = None,
    policy_context: Optional[Dict[str, Any]] = None,
    repository_context: Optional[Dict[str, Any]] = None,
    findings: Optional[List[Dict[str, Any]]] = None,
    evidence: Optional[List[Dict[str, Any]]] = None,
    threat_context: Optional[Dict[str, Any]] = None,
    policy_results: Optional[Dict[str, Any]] = None,
    scan_mode: str = "full_scan",
) -> AgentWorkflowState:
    """Creates a pristine, fully-initialized AgentWorkflowState dictionary."""
    return {
        "messages": [],
        "scan_mode": scan_mode,
        "scan_id": scan_id,
        "repository_profile": repository_profile or {},
        "repository_graph": {},
        "semantic_context": {},
        "business_context": business_context or {},
        "business_intent_results": {},
        "business_violations": [],
        "policy_context": policy_context or {},
        "knowledge_context": {},
        "repository_context": repository_context or {},
        "architecture_context": {},
        "dependency_context": {},
        "security_context": {},
        "threat_context": threat_context or {},
        "policy_results": policy_results or {},
        "correlated_findings": {},
        "attack_paths": [],
        "exploitability": 0.0,
        "git_diff": "",
        "validation_report": {},
        "grounding_report": {},
        "remediation_summary": {},
        "developer_explanation": "",
        "validation_confidence": 0.0,
        "retrieved_documents": [],
        "current_task": "INITIALIZATION",
        "execution_plan": {},
        "active_agent": "IDLE",
        "completed_agents": [],
        "pending_agents": [],
        "findings": findings or [],
        "evidence": evidence or [],
        "risk_scores": {},
        "validation_results": [],
        "patches": [],
        "reports": [],
        "agent_trace": [],
        "execution_metrics": {
            "total_execution_time": 0.0,
            "agent_runtime": {},
            "tool_runtime": {},
            "retrieval_latency": 0.0,
            "graph_query_latency": 0.0,
            "embedding_retrieval_latency": 0.0,
            "number_of_findings": 0,
            "number_of_policies_applied": 0,
            "number_of_evidence_objects": 0,
        },
    }
