import sys, json
sys.path.insert(0, ".")
from guardian.core.pipeline import ScanPipeline
from guardian.reporting.agentic_html_reporter import render_agentic_report_html
from guardian.reporting import report_view_model as rvm

pipeline = ScanPipeline()
report = pipeline.scan("guardian")  # scan the guardian package itself -- real, substantial, multi-file

scan = report.get("scan", {}) or {}
findings = scan.get("findings", []) or []
by_sev = scan.get("by_severity", {}) or {}
total = scan.get("total_findings", len(findings))

print("=== REAL SCAN RESULT ===")
print("total_findings:", total, " len(findings):", len(findings))
print("by_severity:", by_sev)
print("sum(by_severity):", sum(by_sev.values()))

# Cross-check: group_findings_by_severity must account for EVERY valid
# finding, dropping only genuinely malformed ones (no finding_id/rule_id).
groups = rvm.group_findings_by_severity(findings, "")
grouped_total = sum(len(items) for _, items in groups)
malformed = [f for f in findings if not rvm.is_valid_finding(f)]
print("grouped_total:", grouped_total, " malformed (excluded):", len(malformed))
assert grouped_total + len(malformed) == len(findings), "COUNT MISMATCH: findings lost outside malformed filter"
assert grouped_total == len(findings) or malformed, "silently dropped findings with no malformed excuse"

# Cross-check every finding_id in the raw findings is present somewhere in
# the grouped output (no silent substitution/renaming).
raw_ids = {f.get("finding_id") for f in findings if isinstance(f, dict) and f.get("finding_id")}
grouped_ids = {f.get("finding_id") for _, items in groups for f in items if f.get("finding_id")}
missing_ids = raw_ids - grouped_ids
print("finding_ids missing from grouped output:", missing_ids)
assert not missing_ids, f"IDs disappeared: {missing_ids}"

# Render the Unified report from this real deterministic report (agentic
# side left empty/idle -- this run has no agentic pass) and confirm the
# deterministic section's own severity counts match report["scan"].
agentic_state_empty = {"scan_id": "no_agentic_run"}
html_out = render_agentic_report_html(agentic_state_empty, report, "real_scan_1")
with open("/tmp/real_unified_report.html", "w") as f:
    f.write(html_out)

for sev_key, sev_label in rvm.SEVERITY_LABEL.items():
    real_count = by_sev.get(sev_label, by_sev.get(sev_label.upper(), 0)) or 0
    marker = f"{sev_label} ({real_count})"  # renderer title-cases via SEVERITY_LABEL, e.g. "Critical (5)"
    if real_count > 0:
        assert marker in html_out, f"severity count for {sev_label} not rendered as expected ({marker} not found)"

print("html length:", len(html_out))
print("ALL REAL-SCAN COUNT ASSERTIONS PASSED")

# Dump a compact summary for manual eyeballing too.
print(json.dumps({"total": total, "by_severity": by_sev, "categories": list(scan.get("by_category", {}).keys())[:10]}, indent=2))
