"""
Audit Diagnostic 2: Controlled Semantic Retrieval Behavior
"""
import tempfile
from pathlib import Path

from guardian.intent.semantic.code_index import CodeSemanticIndex
from guardian.intent.semantic.semantic_retriever import SemanticRetriever

def main():
    print("=== AUDIT 2: CONTROLLED SEMANTIC RETRIEVAL BEHAVIOR ===")

    code_a = """
def process_order_a(request):
    amount = request.get("price")
    charge(amount)
"""

    code_b = """
def process_order_b(input_data):
    customer_value = input_data["cost"]
    payment_processor.pay(customer_value)
"""

    code_c = """
def send_notification(user):
    send_email(user)
"""

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        (tmp_path / "mod_a.py").write_text(code_a, encoding="utf-8")
        (tmp_path / "mod_b.py").write_text(code_b, encoding="utf-8")
        (tmp_path / "mod_c.py").write_text(code_c, encoding="utf-8")

        retriever = SemanticRetriever(workspace_dir=tmp_path)
        query = "Authoritative checkout price calculation and charge payment"
        results = retriever.search(query=query, top_k=3)

        print(f"Query: '{query}'")
        for r in results:
            print(f"  Match: {r.match_id} | Function: {r.function} | File: {r.file} | Similarity: {r.similarity:.4f}")

if __name__ == "__main__":
    main()
