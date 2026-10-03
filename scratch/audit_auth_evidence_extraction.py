import sys
import os
import json

cwd = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(cwd, ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

def inspect_auth_extraction_capabilities():
    print("=" * 80)
    print("AUDITING DETERMINISTIC AUTH EVIDENCE EXTRACTION & COVERAGE CAPABILITIES")
    print("=" * 80)

    from guardian.discovery.repo_detector import RepositoryDetector
    from guardian.intent.matcher.rule_matcher import RuleMatcher
    from pathlib import Path

    # 1. Run RepositoryDetector over workspace files
    workspace_path = Path(project_root)
    ignore_dirs = {".venv", "node_modules", ".git", "__pycache__", "build", "dist", ".acg_workspaces", ".pytest_cache", "_to_delete"}
    exts = {".py", ".ts", ".tsx", ".js", ".jsx", ".java", ".go"}
    
    files = []
    for root, dirs, f_list in os.walk(workspace_path):
        dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]
        for f in f_list:
            p = Path(root) / f
            if p.suffix.lower() in exts:
                files.append(p)

    detector = RepositoryDetector()
    profile = detector.detect(workspace_path, files)
    profile_dict = profile.to_dict()

    print("\n1. REPOSITORY DETECTOR PROFILE DATA:")
    print("  detected_endpoints count:", len(profile_dict.get("detected_endpoints", [])))
    print("  detected_endpoints sample (first 10):", profile_dict.get("detected_endpoints", [])[:10])
    print("  security_markers:", profile_dict.get("security_markers", []))
    print("  entry_points count:", len(profile_dict.get("entry_points", [])))

    # Check if endpoint metadata (authenticated vs unauthenticated) exists in profile_dict
    has_endpoint_auth_metadata = any(isinstance(ep, dict) for ep in profile_dict.get("detected_endpoints", []))
    print("  Does detected_endpoints contain per-endpoint auth metadata? ", has_endpoint_auth_metadata)

    # 2. RuleMatcher Workspace AST Profiles
    print("\n2. RULE MATCHER AST WORKSPACE PROFILES:")
    ws_profiles = RuleMatcher._profiles_from_workspace(workspace_path)
    print("  Total AST Function Profiles:", len(ws_profiles))
    
    auth_controls = ["auth", "jwt", "login", "permission", "role", "authorize", "bearer", "session", "depends", "security"]
    endpoint_profiles_with_auth = []
    endpoint_profiles_without_auth = []

    for wp in ws_profiles:
        # Check if function looks like an API endpoint / route handler
        snippet_lower = (wp.function_name + " " + wp.code_snippet).lower()
        is_route = any(k in snippet_lower for k in ["@app.route", "@router.", "@get", "@post", "@put", "@delete", "@patch", "apirouter"])
        if is_route:
            has_auth = any(ac in snippet_lower for ac in auth_controls)
            if has_auth:
                endpoint_profiles_with_auth.append(wp)
            else:
                endpoint_profiles_without_auth.append(wp)

    print(f"  Route Endpoints detected in AST: {len(endpoint_profiles_with_auth) + len(endpoint_profiles_without_auth)}")
    print(f"    - With Auth Controls / Decorators: {len(endpoint_profiles_with_auth)}")
    print(f"    - Without Auth Controls / Decorators: {len(endpoint_profiles_without_auth)}")

    print("\n  Sample Endpoint WITH Auth Control:")
    for wp in endpoint_profiles_with_auth[:3]:
        print(f"    File: {wp.file}:{wp.line} | Function: {wp.function_name} | Controls: {wp.controls}")

    print("\n  Sample Endpoint WITHOUT Auth Control:")
    for wp in endpoint_profiles_without_auth[:3]:
        print(f"    File: {wp.file}:{wp.line} | Function: {wp.function_name} | Controls: {wp.controls}")

if __name__ == "__main__":
    inspect_auth_extraction_capabilities()
