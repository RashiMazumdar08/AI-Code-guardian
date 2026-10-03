"""
Audit Diagnostic 1: Embedding Path Verification
"""
from pathlib import Path
import numpy as np

from guardian.intent.semantic.code_index import CodeSemanticIndex, CodeChunkRepresentation
from guardian.intent.semantic.semantic_retriever import SemanticRetriever

def main():
    print("=== AUDIT 1: EMBEDDING PATH VERIFICATION ===")
    
    # Check sentence-transformers availability
    st_available = False
    try:
        import sentence_transformers
        st_available = True
    except ImportError:
        st_available = False
    
    print(f"sentence-transformers installed: {st_available}")
    
    # Test LocalEmbedder instantiation
    try:
        from guardian.ai.local_embedder import LocalEmbedder
        embedder = LocalEmbedder()
        print(f"LocalEmbedder created: model_name={embedder.model_name}, dim={embedder.dim}")
        print(f"LocalEmbedder is_available: {embedder.is_available}")
    except Exception as e:
        print(f"LocalEmbedder exception: {e}")
        
    # Test CodeSemanticIndex on current workspace
    index = CodeSemanticIndex.get_or_create(Path.cwd())
    print(f"Total indexed chunks: {len(index.chunks)}")
    if index._vectors is not None and len(index._vectors) > 0:
        print(f"Vector matrix shape: {index._vectors.shape}")
        # Check normalization (norm of each vector should be approx 1.0)
        norms = np.linalg.norm(index._vectors, axis=1)
        mean_norm = float(np.mean(norms))
        min_norm = float(np.min(norms))
        max_norm = float(np.max(norms))
        print(f"Vector norms — mean: {mean_norm:.4f}, min: {min_norm:.4f}, max: {max_norm:.4f}")

if __name__ == "__main__":
    main()
