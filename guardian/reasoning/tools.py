"""
Nemotron Function Calling & Tools Interface
===========================================
Tool declarations and handlers for structured tool calling by Nemotron reasoning models.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

import json
from pathlib import Path

log = logging.getLogger(__name__)

# Registry of active scan findings & evidence for tool execution
_ACTIVE_FINDINGS: Dict[str, Any] = {}
_SECURITY_KNOWLEDGE: List[Dict[str, Any]] = []

def _ensure_knowledge_loaded():
    global _SECURITY_KNOWLEDGE
    if not _SECURITY_KNOWLEDGE:
        knowledge_file = (
            Path(__file__).resolve().parent.parent.parent
            / "data" / "knowledge" / "security_knowledge.json"
        )
        if knowledge_file.is_file():
            try:
                _SECURITY_KNOWLEDGE = json.loads(knowledge_file.read_text(encoding="utf-8"))
            except Exception as e:
                log.warning("Could not auto-load security knowledge json: %s", e)

# Auto-load on module import
_ensure_knowledge_loaded()


def register_scan_context(findings: List[Any], knowledge: Optional[List[Dict[str, Any]]] = None) -> None:
    """Register active scan context for tool queries."""
    global _ACTIVE_FINDINGS, _SECURITY_KNOWLEDGE
    
    _ACTIVE_FINDINGS = {}
    for f in findings:
        fid = getattr(f, "finding_id", None) if not isinstance(f, dict) else f.get("finding_id")
        if not fid:
            fid = getattr(f, "id", None) if not isinstance(f, dict) else f.get("id")
        if not fid:
            fid = f"f_{len(_ACTIVE_FINDINGS) + 1}"
        _ACTIVE_FINDINGS[fid] = f
            
    if knowledge:
        _SECURITY_KNOWLEDGE = knowledge
    else:
        _ensure_knowledge_loaded()


def get_finding_detail(finding_id: str) -> Dict[str, Any]:
    """Retrieve comprehensive details of a specific finding by finding_id."""
    finding = _ACTIVE_FINDINGS.get(finding_id)
    if not finding:
        return {"error": f"Finding ID '{finding_id}' not found in active scan context."}

    if hasattr(finding, "to_dict"):
        return finding.to_dict()
    return dict(finding)


def query_security_knowledge(query: str) -> List[Dict[str, Any]]:
    """Query OWASP/CWE/NIST security knowledge rules for relevant guidance."""
    _ensure_knowledge_loaded()
    query_lower = query.lower()
    query_terms = [t for t in query_lower.split() if len(t) > 2]
    
    results = []
    for item in _SECURITY_KNOWLEDGE:
        title = str(item.get("title", "")).lower()
        standard = str(item.get("standard", "")).lower()
        content = str(item.get("content", "")).lower()
        topics = [str(t).lower() for t in item.get("topics", [])]
        
        haystack = f"{title} {standard} {content} {' '.join(topics)}"
        
        score = 0
        for term in query_terms:
            if term in topics:
                score += 3
            elif term in haystack:
                score += 1
                
        if score > 0 or not query_terms:
            results.append((score, item))
            
    results.sort(key=lambda x: -x[0])
    matched = [r[1] for r in results[:5]]
    return matched if matched else _SECURITY_KNOWLEDGE[:2]


def get_active_findings_context(limit: int = 5) -> str:
    """Format active scan findings into grounded prompt evidence lines."""
    if not _ACTIVE_FINDINGS:
        return "No active repository scan findings currently registered."
    
    lines = []
    for fid, f in list(_ACTIVE_FINDINGS.items())[:limit]:
        cat = getattr(f, "category", None) or (f.get("category") if isinstance(f, dict) else "") or (f.get("title") if isinstance(f, dict) else "Vulnerability")
        sev = getattr(f, "severity", None) or (f.get("severity") if isinstance(f, dict) else "High")
        file_path = getattr(f, "file", None) or (f.get("file") if isinstance(f, dict) else "unknown")
        line_no = getattr(f, "line", None) or (f.get("line") if isinstance(f, dict) else 1)
        cwe = getattr(f, "cwe", None) or (f.get("cwe") if isinstance(f, dict) else "")
        snippet = getattr(f, "snippet", None) or (f.get("snippet") if isinstance(f, dict) else "")
        reason = getattr(f, "reason", None) or (f.get("reason") if isinstance(f, dict) else "")
        
        entry = f"- [{sev}] {cat} ({cwe}) at {file_path}:{line_no}"
        if snippet:
            entry += f"\n  Code: `{snippet.strip()}`"
        if reason:
            entry += f"\n  Reason: {reason}"
        lines.append(entry)
        
    return "\n".join(lines)


def get_scan_funnel_summary(scan_id: str = "latest") -> Dict[str, Any]:
    """Retrieve summary funnel metrics for a given scan."""
    total = len(_ACTIVE_FINDINGS)
    
    exploitable = 0
    high_priority = 0
    immediate_risk = 0
    
    for f in _ACTIVE_FINDINGS.values():
        is_exploit = getattr(f, "is_exploitable", False) if not isinstance(f, dict) else f.get("is_exploitable", False)
        sev = getattr(f, "severity", "") if not isinstance(f, dict) else f.get("severity", "")
        
        if is_exploit:
            exploitable += 1
        if sev in ("Critical", "High"):
            high_priority += 1
        if is_exploit and sev in ("Critical", "High"):
            immediate_risk += 1

    return {
        "scan_id": scan_id,
        "total_alerts": total,
        "exploitable_count": exploitable,
        "high_priority_count": high_priority,
        "immediate_risk_count": immediate_risk,
    }


NEMOTRON_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "get_finding_detail",
            "description": "Retrieve comprehensive details, AST nodes, and evidence for a specific finding ID.",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": "The unique stable SHA-1 finding ID."
                    }
                },
                "required": ["finding_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_security_knowledge",
            "description": "Search standard OWASP, CWE, and NIST security rule catalogs and advice.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query terms or CWE ID (e.g., 'SQL Injection' or 'CWE-89')."
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_scan_funnel_summary",
            "description": "Retrieve high-level triage funnel statistics (total, exploitable, high-priority counts).",
            "parameters": {
                "type": "object",
                "properties": {
                    "scan_id": {
                        "type": "string",
                        "description": "Scan identifier or 'latest'."
                    }
                },
                "required": ["scan_id"]
            }
        }
    }
]
