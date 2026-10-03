import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))

from guardian.intent.ingestion.document_loader import DocumentLoader
from guardian.intent.parser.rule_parser import RuleParser
from guardian.intent.matcher.rule_matcher import RuleMatcher

def test_scan():
    pdf_path = Path("data/business_docs/DV_Bookshop_Business_Rules.pdf")
    loader = DocumentLoader(docs_dir=pdf_path.parent)
    reqs = loader.extract_actionable_requirements()
    print(f"Extracted requirements count: {len(reqs)}")
    for r in reqs:
        print(f"[{r.id}] Title: {r.title}")
        print(f"  Area: {r.area} | Control: {r.required_control}")
        print(f"  Text: {r.text}")
        if r.expected_implementation_behavior:
            print(f"  Exp Behavior: {r.expected_implementation_behavior}")
        if r.violation_conditions:
            print(f"  Viol Cond: {r.violation_conditions}")

    parser = RuleParser()
    rules = parser.parse_all(reqs)
    matcher = RuleMatcher()
    eval_results = matcher.evaluate_all(rules, findings=[])
    print(f"\nEvaluated results count: {len(eval_results)}")
    for res in eval_results:
        print(f"[{res['rule_id']}] {res['title']} => Status: {res['status']}")

if __name__ == "__main__":
    test_scan()
