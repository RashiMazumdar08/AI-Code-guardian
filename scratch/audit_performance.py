"""
Audit Diagnostic 10: Performance Measurement
"""
import time
from pathlib import Path

from guardian.intent.engine import BusinessIntentEngine
from guardian.intent.matcher.rule_matcher import RuleMatcher
from guardian.intent.parser.rule_parser import ParsedRule

def main():
    print("=== AUDIT 10: PERFORMANCE MEASUREMENT ===")
    repo_root = Path.cwd()
    docs_dir = repo_root / "data" / "business_docs"

    # Run A: Deterministic Only (enable_semantic=False)
    t0 = time.perf_counter()
    engine_det = BusinessIntentEngine(docs_dir=docs_dir, use_llm=False)
    engine_det.matcher.enable_semantic = False
    res_a = engine_det.run()
    time_a_ms = (time.perf_counter() - t0) * 1000.0

    # Run B: Deterministic + Semantic Retrieval (enable_semantic=True)
    t1 = time.perf_counter()
    engine_sem = BusinessIntentEngine(docs_dir=docs_dir, use_llm=False)
    engine_sem.matcher.enable_semantic = True
    res_b = engine_sem.run()
    time_b_ms = (time.perf_counter() - t1) * 1000.0

    print(f"Run A (Deterministic only): {time_a_ms:.2f} ms")
    print(f"Run B (Deterministic + Semantic): {time_b_ms:.2f} ms")
    print(f"Semantic indexing + retrieval overhead: {time_b_ms - time_a_ms:.2f} ms")

    # Inspect metrics from first PARTIAL finding
    findings_b = res_b.get("findings", [])
    sem_searches = sum(1 for f in findings_b if f.get("semantic_retrieval_performed"))
    cand_count = sum(len(f.get("semantic_candidates", [])) for f in findings_b)

    print(f"Total Rules Analyzed: {res_b.get('total_rules')}")
    print(f"Semantic Searches Performed: {sem_searches}")
    print(f"Semantic Candidates Retrieved: {cand_count}")
    print(f"LLM Calls Made (use_llm=False): 0")

if __name__ == "__main__":
    main()
