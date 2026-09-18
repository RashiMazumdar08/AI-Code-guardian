"""
AI Code Guardian 2.0 — CLI
Usage:
    python -m guardian scan <path> [--format json sarif html] [--out-dir reports/]
                                   [--config config/default.yaml]
                                   [--alignment-score 75]
                                   [--fail-on-severity High]
    python -m guardian detect <path>          # repository profile only
    python -m guardian intent <path>          # business-domain verdict only
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="guardian", description="AI Code Guardian 2.0")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Full pipeline scan")
    p_scan.add_argument("path")
    p_scan.add_argument("--format", nargs="+", default=["json"],
                        choices=["json", "sarif", "html", "csv", "pdf"])
    p_scan.add_argument("--out-dir", default=".")
    p_scan.add_argument("--config", default=None)
    p_scan.add_argument("--alignment-score", type=float, default=None)
    p_scan.add_argument("--fail-on-severity", default=None,
                        choices=SEVERITY_ORDER[1:])
    p_scan.add_argument("--requirements", nargs="+", default=None, metavar="FILE",
                        help="business requirement documents (txt/md/pdf/docx/"
                             "json/yaml/csv/xlsx) to compare the code against")
    p_scan.add_argument("--ai", action="store_true",
                        help="enable NVIDIA Nemotron contextual reasoning "
                             "(requires NVIDIA_API_KEY)")
    p_scan.add_argument("--sandbox", action="store_true",
                        help="scan an isolated copy of the repository")
    p_scan.add_argument("--knowledge", action="store_true",
                        help="build repository knowledge graph and semantic document index")

    for name in ("detect", "intent"):
        p = sub.add_parser(name)
        p.add_argument("path")

    sub.add_parser("parsers", help="Show Tree-sitter grammar availability")

    args = parser.parse_args(argv)

    from guardian.config import GuardianConfig
    from guardian.core.registry import load_builtin_plugins

    if args.command == "parsers":
        from guardian.ust import parsers as ust_parsers
        availability = ust_parsers.availability()
        print(json.dumps({
            "tree_sitter_installed": ust_parsers.tree_sitter_available(),
            "grammars": availability,
            "extensions": sorted(ust_parsers.supported_extensions()),
        }, indent=2))
        missing = [lang for lang, ok in availability.items() if not ok]
        if missing:
            print(f"\nMissing grammars: {', '.join(missing)}", file=sys.stderr)
            print("Install with: pip install "
                  + " ".join(f"tree_sitter_{m.replace('tsx', 'typescript')}"
                             for m in sorted(set(missing))), file=sys.stderr)
            print("UST falls back to AST/regex parsing for these languages.",
                  file=sys.stderr)
        return 0

    from guardian.discovery.github_service import is_github_url, GitHubService
    target_path = GitHubService().fetch_repository(args.path) if is_github_url(args.path) else Path(args.path)

    if args.command == "detect":
        from guardian.discovery.file_walker import FileWalker
        from guardian.discovery.repo_detector import RepositoryDetector
        cfg = GuardianConfig.load()
        files = list(FileWalker(cfg).walk(target_path))
        profile = RepositoryDetector().detect(target_path, files)
        print(json.dumps(profile.to_dict(), indent=2))
        return 0

    if args.command == "intent":
        from guardian.intent.classifier import DomainClassifier
        verdict = DomainClassifier().classify(target_path)
        print(json.dumps(verdict.to_dict(), indent=2))
        return 0

    # ---- scan --------------------------------------------------------
    cfg = GuardianConfig.load(args.config, fail_on_severity=args.fail_on_severity)
    if args.ai:
        cfg.enable_ai = True
    if args.sandbox:
        cfg.enable_sandbox = True
    if args.knowledge:
        cfg.enable_knowledge = True
    registry = load_builtin_plugins()
    from guardian.core.pipeline import ScanPipeline

    pipeline = ScanPipeline(cfg, registry)
    print(f"Scanning {args.path} ...")
    report = pipeline.scan(args.path, alignment_score=args.alignment_score,
                           business_requirements=args.requirements)

    scan = report["scan"]
    risk = report.get("unified_risk") or report["risk"]
    repo = report["repository"]
    ust = report.get("ust", {})

    print(f"\nRepository:   {repo['primary_language']} "
          f"{'/'.join(repo['architecture'])} "
          f"[{', '.join(repo['frameworks']) or 'no framework detected'}]")
    if report.get("business_domain"):
        bd = report["business_domain"]
        print(f"Domain:       {bd['domain']} ({bd['confidence']:.0%} confidence)")
    print(f"Files:        {scan['files_scanned']} source scanned "
          f"({report['discovery']['infrastructure_files']} infra, "
          f"{report['discovery']['manifest_files']} manifests)")
    if ust:
        parser_summary = ", ".join(f"{k}={v}" for k, v in (ust.get("parsers") or {}).items())
        print(f"UST:          {ust.get('nodes', 0)} nodes over {ust.get('files', 0)} files "
              f"[{parser_summary or 'none'}]")
    print(f"Evidence:     {report.get('evidence', {}).get('total', 0)} items")
    print(f"Findings:     {scan['total_findings']}  {scan['by_severity']}")

    ai_findings = sum(1 for f in scan["findings"] if f.get("source", "").startswith("AI"))
    if ai_findings:
        print(f"              ({ai_findings} AI-validated, "
              f"{scan['total_findings'] - ai_findings} deterministic)")

    print(f"Security:     {risk['security_score']:.1f}/100")
    print(f"Alignment:    {risk['alignment_score']:.1f}/100")
    if "quantum_readiness_score" in risk:
        print(f"Quantum:      {risk['quantum_readiness_score']:.1f}/100")
    print(f"Overall:      {risk['overall_risk_score']:.1f}/100")
    print(f"Decision:     {risk['merge_decision']}")

    bi = report.get("business_intent") or {}
    if bi.get("status") == "analyzed":
        counts: dict[str, int] = {}
        for verdict in bi.get("verdicts", []):
            counts[verdict["verdict"]] = counts.get(verdict["verdict"], 0) + 1
        print(f"Intent:       {counts}")
    elif bi.get("status") == "no_requirements":
        print("Intent:       no requirements supplied (--requirements FILE ...)")

    ai_status = report.get("ai") or {}
    if ai_status.get("enabled") and not ai_status.get("configured"):
        print(f"AI:           unavailable — {ai_status.get('unavailable_reason') or ai_status.get('reason')}")
    elif ai_status.get("configured"):
        print(f"AI:           {ai_status.get('model')} "
              f"({ai_status.get('calls', 0)} calls, {ai_status.get('failures', 0)} failed)")

    if report.get("errors"):
        print(f"\nPartial results: {len(report['errors'])} stage(s) failed "
              f"(see report 'errors').", file=sys.stderr)

    sandbox = report.get("sandbox") or {}
    if sandbox.get("enabled"):
        print(f"Sandbox:      isolated workspace ({sandbox.get('mode', 'copy')})")

    knowledge = report.get("knowledge") or {}
    if knowledge.get("enabled"):
        print(f"Knowledge:    graph nodes={knowledge.get('graph', {}).get('nodes', 0)}, "
              f"indexed docs={knowledge.get('documents_indexed', 0)}")

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for fmt in args.format:
        reporter = registry.reporter(fmt)
        if reporter is None:
            print(f"  ! no reporter registered for {fmt}", file=sys.stderr)
            continue
        out = out_dir / f"guardian_report{reporter.file_extension}"
        out.write_text(reporter.render(report), encoding="utf-8")
        print(f"Report:       {out}")

    # CI gate
    if cfg.fail_on_severity:
        threshold = SEVERITY_ORDER.index(cfg.fail_on_severity)
        worst = max((SEVERITY_ORDER.index(s) for s in scan["by_severity"]
                     if s in SEVERITY_ORDER), default=-1)
        if worst >= threshold:
            print(f"\nFAIL: findings at or above {cfg.fail_on_severity} severity.")
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
