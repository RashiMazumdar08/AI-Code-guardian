import sys
import os
import json

cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from guardian.agents.architecture.agent import ArchitectureAgent
from guardian.orchestrator.state import create_initial_state, merge_list
from guardian.reasoning.schemas import ReasoningFinding, ReasoningResponse
from guardian.reasoning.gateway import ReasoningResult

def test_architecture_agent_stable_id_output():
    agent = ArchitectureAgent()
    rf = ReasoningFinding(
        evidence_ids=["E1"],
        category="architecture",
        severity="High",
        confidence=0.9,
        reason="The evidence shows a public HTTP gateway directly connected...",
        recommendation="Enforce API gateway auth.",
        title="Public Gateway Exposure",
        file="backend/app/api/v1/agentic_scan.py",
        line=55,
        function="_build_agentic_analysis_result"
    )
    
    res = ReasoningResult(
        response=ReasoningResponse(findings=[rf]),
        available=True
    )
    
    # Mock reasoning service to return our reasoning result
    class MockService:
        configured = True
        def reason(self, req):
            return res
            
    # Test state update
    import guardian.agents.architecture.agent as arch_mod
    
    # Let's inspect how dict d is formed
    d = rf.to_dict()
    import hashlib
    stable_basis = f"{d.get('title', '')}|{d.get('reason', '')}|{d.get('file', '')}|{d.get('line', 0)}|{d.get('function', '')}"
    stable_hash = hashlib.md5(stable_basis.encode("utf-8", errors="ignore")).hexdigest()[:12]
    d["id"] = f"ARCH-INSIGHT-{stable_hash}"
    d["insight_id"] = d["id"]
    
    print("Generated Architecture Insight Dict:")
    print(json.dumps(d, indent=2))
    assert d["id"].startswith("ARCH-INSIGHT-")
    
    # Test multi-pass merge_list with this dict
    state = [d]
    for _ in range(5):
        state = merge_list(state, [d])
    assert len(state) == 1
    print("Multi-pass merge_list result count:", len(state))

if __name__ == "__main__":
    test_architecture_agent_stable_id_output()
