"""
Audit Diagnostic 4: Escalation Behavior Verification
"""
from guardian.intent.semantic.evidence_fusion import EvidenceFusionEngine

def main():
    print("=== AUDIT 4: ESCALATION BEHAVIOR VERIFICATION ===")
    fusion = EvidenceFusionEngine()

    statuses = ["COMPLIANT", "VIOLATION", "PARTIAL", "INSUFFICIENT_EVIDENCE"]
    for st in statuses:
        det_res = {
            "rule_id": f"TEST-{st}",
            "rule": f"Requirement for {st}",
            "status": st,
            "score": 0.9 if st in ("COMPLIANT", "VIOLATION") else 0.5,
        }
        fused = fusion.fuse_rule_result(det_res, top_k=3)
        print(f"Status: {st:22s} -> Semantic Search Performed: {fused.semantic_retrieval_performed}")

if __name__ == "__main__":
    main()
