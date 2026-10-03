import sys
import os
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))
from guardian.intent.ingestion.document_loader import DocumentLoader, get_business_docs_dir, get_workspace_id

def trace_isolation():
    print("==================================================")
    print("WORKSPACE IDENTITY & FILESYSTEM ISOLATION TRACE")
    print("==================================================")

    # 1. Test null / default workspace ID
    ws_null = get_workspace_id(None)
    ws_default_str = get_workspace_id("default")
    dir_null = get_business_docs_dir(workspace_id=None)
    dir_default_str = get_business_docs_dir(workspace_id="default")

    print(f"Null workspace_id resolved ID: '{ws_null}'")
    print(f"'default' workspace_id resolved ID: '{ws_default_str}'")
    print(f"Null workspace_id physical dir: {dir_null}")
    print(f"'default' workspace_id physical dir: {dir_default_str}")

    # 2. Test Environment A (e.g. repo path /projects/repo_a)
    repo_a = "/projects/repo_a"
    ws_a = get_workspace_id(repo_a)
    dir_a = get_business_docs_dir(workspace_id=repo_a)
    print(f"\nEnvironment A ('{repo_a}') resolved ID: '{ws_a}'")
    print(f"Environment A physical dir: {dir_a}")

    # 3. Test Environment B (fresh environment without repo_path yet -> passes undefined / 'default')
    repo_b_fresh = "default"
    ws_b_fresh = get_workspace_id(repo_b_fresh)
    dir_b_fresh = get_business_docs_dir(workspace_id=repo_b_fresh)
    print(f"\nEnvironment B (Fresh, unset repo_path) resolved ID: '{ws_b_fresh}'")
    print(f"Environment B physical dir: {dir_b_fresh}")

    # 4. Check contents of default directory vs scoped directory
    print("\nFiles in Environment A dir:", [f.name for f in dir_a.glob("*") if f.is_file()])
    print("Files in Default dir:", [f.name for f in dir_b_fresh.glob("*") if f.is_file()])
    print("Files in root data/business_docs:", [f.name for f in Path("data/business_docs").glob("*") if f.is_file()])

if __name__ == "__main__":
    trace_isolation()
