"""
Regression tests for Reasoning Gateway & BusinessAgent JSON parsing.
Ensures reasoning models emitting thinking prose before a JSON object
are parsed safely without producing fake insights on missing JSON.
"""
from __future__ import annotations

import pytest
from guardian.reasoning.schemas import parse_business_intent_response, extract_json

def test_pure_json_parsing():
    raw_json = '''{
      "summary": "Evaluation completed.",
      "findings": [
        {
          "policy_id": "REQ-002",
          "verdict": "VIOLATION",
          "confidence": 0.95,
          "reason": "Unparameterized SQL query detected.",
          "recommendation": "Use parameterized queries.",
          "missing_control": "parameterized_query",
          "file": "app.py",
          "line": 677,
          "function": "login",
          "evidence_ids": ["E1"]
        }
      ]
    }'''

    response = parse_business_intent_response(raw_json)
    assert response.ok is True
    assert len(response.findings) == 1
    finding = response.findings[0]
    assert finding.extras["verdict"] == "VIOLATION"
    assert finding.extras["policy_id"] == "REQ-002"
    assert finding.evidence_ids == ["E1"]

def test_reasoning_prose_followed_by_json_parsing():
    raw_text = '''Here's a thinking process:

1. Analyze User Input:
   - Policy: REQ-001 - Session Timeout
   - Code: app.py line 20 sets session.permanent = True

2. Conclusion:
   - Session timeout is partially implemented.

{"summary": "Partial implementation", "findings": [{"policy_id": "REQ-001", "verdict": "PARTIAL", "confidence": 0.9, "reason": "Session timeout partially configured", "recommendation": "Set explicit lifetime", "missing_control": "", "file": "app.py", "line": 20, "function": "init", "evidence_ids": ["E2"]}]}'''

    response = parse_business_intent_response(raw_text)
    assert response.ok is True
    assert len(response.findings) == 1
    finding = response.findings[0]
    assert finding.extras["verdict"] == "PARTIAL"
    assert finding.extras["policy_id"] == "REQ-001"

def test_reasoning_prose_without_json_returns_error():
    raw_text = '''Here's a thinking process:

1. Analyze User Input:
   - Policy: REQ-003
   - I am thinking about how to evaluate this policy...
   - No JSON object is ever produced here.'''

    response = parse_business_intent_response(raw_text)
    assert response.ok is False
    assert len(response.findings) == 0
    assert "response contained no JSON object" in response.problems
