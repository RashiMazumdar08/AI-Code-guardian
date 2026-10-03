import json
import sys
from pathlib import Path

repo_root = Path.cwd()
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from backend.app.api.v1.agentic_scan import _SCANS

def main():
    print("=== INSPECTING IN-MEMORY AGENTIC SCANS ===")
    print(f"Total scans in _SCANS: {len(_SCANS)}")
    for sid, rec in _SCANS.items():
        state = rec.get("state", {})
        insights = state.get("ai_business_insights", [])
        print(f"\nScan ID: {sid} | Status: {rec.get('status')}")
        print(f"Completed Agents: {state.get('completed_agents', [])}")
        print(f"AI Business Insights Count: {len(insights)}")
        for i, ins in enumerate(insights):
            print(f"  Insight {i+1}: rule={ins.get('rule_id')} verdict={ins.get('verdict')} reason={ins.get('reason')[:60]}...")

if __name__ == "__main__":
    main()
