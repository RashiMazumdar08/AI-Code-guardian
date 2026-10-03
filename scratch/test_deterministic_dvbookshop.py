"""
Direct test of Deterministic Business Intent Engine against DV-Bookshop repository
"""
from pathlib import Path
import json

from guardian.intent.engine import BusinessIntentEngine

def main():
    repo_root = Path.cwd()
    docs_dir = repo_root / "data" / "business_docs"

    print(f"=== Testing Deterministic BusinessIntentEngine ===")
    print(f"Repo Root: {repo_root}")
    print(f"Docs Dir: {docs_dir}")

    engine = BusinessIntentEngine(docs_dir=docs_dir, use_llm=False)
    result = engine.run()

    print(f"\nStatus: {result.get('status')}")
    print(f"Total Rules: {result.get('total_rules')}")
    print(f"Matched: {result.get('matched')}")
    print(f"Violated: {result.get('violated')}")
    print(f"Partial: {result.get('partial')}")
    print(f"Insufficient: {result.get('insufficient')}")

    print("\n--- Detailed Rule Findings ---")
    for f in result.get("findings", []):
        r_id = f.get("rule_id") or "UNKNOWN"
        status = f.get("status")
        score = f.get("score")
        matched_file = f.get("matched_file")
        matched_fn = f.get("matched_function")
        what = f.get("what")
        print(f"[{r_id}] Status: {status} | Score: {score} | File: {matched_file} | Function: {matched_fn}")
        print(f"    What: {what}")
        missing = f.get("missing_controls") or f.get("missing_control")
        if missing:
            print(f"    Missing Controls: {missing}")

if __name__ == "__main__":
    main()
