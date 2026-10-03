"""
Audit Diagnostic: DocumentLoader Rules Extraction Trace
"""
from pathlib import Path
from guardian.intent.ingestion.document_loader import DocumentLoader

def main():
    docs_dir = Path.cwd() / "data" / "business_docs"
    loader = DocumentLoader(docs_dir=docs_dir)
    docs = loader.list_documents()
    print(f"Documents found in {docs_dir}: {[d['filename'] for d in docs]}")
    
    reqs = loader.extract_actionable_requirements()
    print(f"Total actionable requirements extracted: {len(reqs)}")
    for r in reqs:
        print(f"  - ID: {r.id} | Title: {r.title or r.text[:60]}")

if __name__ == "__main__":
    main()
