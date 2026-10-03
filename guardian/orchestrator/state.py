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


def merge_list(a: Optional[List[Any]], b: Optional[List[Any]]) -> List[Any]:
    """Reducer merging list items cleanly without duplicate finding/insight IDs during parallel node execution."""
    if not a:
        return list(b or [])
    if not b:
        return list(a or [])
    seen = set()
    result = []
    for item in list(a) + list(b):
        if isinstance(item, dict):
            item_id = item.get("finding_id") or item.get("id") or item.get("patch_id") or item.get("rule_id") or item.get("insight_id")
            if not item_id:
                title = str(item.get("title") or item.get("category") or "")
                reason = str(item.get("reason") or item.get("description") or item.get("explanation") or "")
                file_path = str(item.get("file") or item.get("file_path") or "")
                line_val = str(item.get("line") or item.get("line_number") or 0)
                func_val = str(item.get("function") or item.get("affected_function") or "")
                if title or reason or file_path:
                    import hashlib
                    content_basis = f"{title}|{reason}|{file_path}|{line_val}|{func_val}"
                    item_id = f"CONTENT_HASH:{hashlib.md5(content_basis.encode('utf-8', errors='ignore')).hexdigest()}"

            if item_id:
                if item_id in seen:
                    continue
                seen.add(item_id)
        result.append(item)
    return result


def merge_dict(a: Optional[Dict[str, Any]], b: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Reducer merging dictionary fields cleanly during parallel node execution."""
    res = dict(a or {})
    res.update(b or {})
    return res


def pick_first(a: Optional[Any], b: Optional[Any]) -> Any:
    """Reducer picking the updated non-empty value if provided, or keeping the existing value."""
    if b is not None and b != "":
        return b
    if a is not None:
        return a
    return b


class AgentWorkflowState(TypedDict, total=False):
    """
    Master state schema passed between LangGraph nodes.
    Single source of truth across all AI agents in AI Code Guardian v3.
    """
    messages: Annotated[list[Any], add_messages]
    scan_mode: Annotated[str, pick_first]
    scan_id: Annotated[str, pick_first]
    repository_profile: Annotated[Dict[str, Any], merge_dict]
    repository_graph: Annotated[Dict[str, Any], merge_dict]
    semantic_context: Annotated[Dict[str, Any], merge_dict]
    business_context: Annotated[Dict[str, Any], merge_dict]
    business_intent_results: Annotated[Dict[str, Any], merge_dict]
    business_violations: Annotated[List[Dict[str, Any]], merge_list]
    policy_context: Annotated[Dict[str, Any], merge_dict]
    knowledge_context: Annotated[Dict[str, Any], merge_dict]
    retrieved_documents: Annotated[List[Dict[str, Any]], merge_list]
    current_task: Annotated[str, pick_first]
    execution_plan: Annotated[Dict[str, Any], merge_dict]
    active_agent: Annotated[str, pick_first]
    completed_agents: Annotated[List[str], merge_list]
    pending_agents: Annotated[List[str], merge_list]
    findings: Annotated[List[Dict[str, Any]], merge_list]
    evidence: Annotated[List[Dict[str, Any]], merge_list]
    risk_scores: Annotated[Dict[str, Any], merge_dict]
    validation_results: Annotated[List[Dict[str, Any]], merge_list]
    patches: Annotated[List[Dict[str, Any]], merge_list]
    reports: Annotated[List[Dict[str, Any]], merge_list]
    repository_context: Annotated[Dict[str, Any], merge_dict]
    architecture_context: Annotated[Dict[str, Any], merge_dict]
    dependency_context: Annotated[Dict[str, Any], merge_dict]
    security_context: Annotated[Dict[str, Any], merge_dict]
    threat_context: Annotated[Dict[str, Any], merge_dict]
    policy_results: Annotated[Dict[str, Any], merge_dict]
    correlated_findings: Annotated[Dict[str, Any], merge_dict]
    attack_paths: Annotated[List[Dict[str, Any]], merge_list]
    exploitability: Annotated[float, pick_first]
    git_diff: Annotated[str, pick_first]
    validation_report: Annotated[Dict[str, Any], merge_dict]
    grounding_report: Annotated[Dict[str, Any], merge_dict]
    remediation_summary: Annotated[Dict[str, Any], merge_dict]
    developer_explanation: Annotated[str, pick_first]
    validation_confidence: Annotated[float, pick_first]
    agent_trace: Annotated[List[AgentTrace], merge_list]
    agent_trace_log: Annotated[List[Dict[str, Any]], merge_list]
    execution_metrics: Annotated[ExecutionMetrics, merge_dict]
    ai_security_insights: Annotated[List[Dict[str, Any]], merge_list]
    ai_architecture_insights: Annotated[List[Dict[str, Any]], merge_list]
    ai_dependency_insights: Annotated[List[Dict[str, Any]], merge_list]
    ai_threat_insights: Annotated[List[Dict[str, Any]], merge_list]
    ai_business_insights: Annotated[List[Dict[str, Any]], merge_list]
    ai_validation_breakdown: Annotated[List[Dict[str, Any]], merge_list]


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
    business_intent_results: Optional[Dict[str, Any]] = None,
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
        "business_intent_results": business_intent_results or {},
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
