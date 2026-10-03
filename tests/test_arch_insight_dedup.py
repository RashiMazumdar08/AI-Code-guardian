import pytest
from guardian.orchestrator.state import merge_list

def test_arch_insight_single_item_repeated_merge():
    """A. One ArchitectureAgent insight remains exactly one item after repeated merge_list operations."""
    insight = {
        "id": "ARCH-INSIGHT-a1b2c3d4e5f6",
        "insight_id": "ARCH-INSIGHT-a1b2c3d4e5f6",
        "title": "Public Gateway Exposure",
        "reason": "Direct connection without auth",
        "file": "backend/app/api/v1/agentic_scan.py",
        "line": 55,
        "function": "_build_agentic_analysis_result"
    }
    state = [insight]
    # Simulate 5 subsequent node passes in LangGraph
    for _ in range(5):
        state = merge_list(state, [insight])
    assert len(state) == 1
    assert state[0]["id"] == "ARCH-INSIGHT-a1b2c3d4e5f6"

def test_arch_insight_same_stable_id_deduplicated():
    """B. The same insight with the same stable ID is deduplicated."""
    insight1 = {
        "id": "ARCH-INSIGHT-112233445566",
        "title": "Auth Bypass Risk",
        "reason": "Missing auth check",
        "file": "app.py"
    }
    insight2 = {
        "id": "ARCH-INSIGHT-112233445566",
        "title": "Auth Bypass Risk",
        "reason": "Missing auth check",
        "file": "app.py"
    }
    merged = merge_list([insight1], [insight2])
    assert len(merged) == 1
    assert merged[0]["id"] == "ARCH-INSIGHT-112233445566"

def test_arch_insight_different_insights_both_retained():
    """C. Two genuinely different architecture insights are both retained."""
    insight1 = {
        "id": "ARCH-INSIGHT-111111111111",
        "title": "Public Gateway Exposure",
        "reason": "Direct connection without auth",
        "file": "backend/app/api/v1/agentic_scan.py",
        "line": 55
    }
    insight2 = {
        "id": "ARCH-INSIGHT-222222222222",
        "title": "Unencrypted Database Channel",
        "reason": "DB interaction uses plaintext TLS settings",
        "file": "backend/app/db/session.py",
        "line": 12
    }
    merged = merge_list([insight1], [insight2])
    assert len(merged) == 2
    assert merged[0]["id"] == "ARCH-INSIGHT-111111111111"
    assert merged[1]["id"] == "ARCH-INSIGHT-222222222222"

def test_merge_list_content_fallback_deduplication():
    """Fallback deduplication when dict lacks explicit ID key."""
    raw_insight = {
        "title": "Public Gateway Exposure",
        "reason": "Direct connection without auth",
        "file": "backend/app/api/v1/agentic_scan.py",
        "line": 55
    }
    state = [raw_insight]
    for _ in range(5):
        state = merge_list(state, [dict(raw_insight)])
    assert len(state) == 1

def test_merge_list_existing_behavior_unchanged():
    """D. Existing merge_list behavior for other finding types is unchanged."""
    finding1 = {"finding_id": "FIND-001", "rule_id": "CWE-89", "title": "SQL Injection"}
    finding2 = {"finding_id": "FIND-002", "rule_id": "CWE-79", "title": "XSS"}
    finding1_dup = {"finding_id": "FIND-001", "rule_id": "CWE-89", "title": "SQL Injection"}

    merged = merge_list([finding1], [finding2, finding1_dup])
    assert len(merged) == 2
    assert [f["finding_id"] for f in merged] == ["FIND-001", "FIND-002"]
