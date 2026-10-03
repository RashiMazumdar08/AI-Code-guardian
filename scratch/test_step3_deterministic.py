import sys
import os
sys.path.insert(0, os.path.abspath("."))

import json
from pathlib import Path
from guardian.scanner._engine import SecurityRuleEngine

fixture_path = Path("tests/fixtures/semantic_authorization_gap.py")
engine = SecurityRuleEngine()
result = engine.scan_file(fixture_path)

print(f"--- DETERMINISTIC SCAN RESULTS ---")
print(f"Target: {result.target}")
print(f"Files Scanned: {result.files_scanned}")
print(f"Findings Count: {len(result.findings)}")

for idx, f in enumerate(result.findings, 1):
    print(f"\nFinding #{idx}:")
    print(f"  Rule ID: {getattr(f, 'rule_id', None)}")
    print(f"  Title/Category: {getattr(f, 'category', None)}")
    print(f"  Severity: {getattr(f, 'severity', None)}")
    print(f"  File: {getattr(f, 'file', None)}")
    print(f"  Line: {getattr(f, 'line', None)}")
    print(f"  Snippet: {getattr(f, 'snippet', None)}")
    print(f"  Recommendation: {getattr(f, 'recommendation', None)}")
