"""
Unified Syntax Tree (UST)
=========================
Tree-sitter-backed, language-independent code representation.

    from guardian.ust import USTBuilder, USTNodeType

    ust = USTBuilder().build_repository(repo_root, source_files)
    for call in ust.of_type(USTNodeType.CALL):
        ...

Supported today: Python, Java, JavaScript, TypeScript/TSX, Rust.
Adding a language requires one grammar row in `guardian.ust.parsers` and
one normalizer in `guardian.ust.languages`.
"""
from guardian.ust.builder import USTBuilder, build_ust, default_builder  # noqa: F401
from guardian.ust.models import (  # noqa: F401
    UST, SourceSpan, USTFile, USTNode, USTNodeType,
)
from guardian.ust.parsers import (  # noqa: F401
    availability, language_for_path, supported_extensions, supported_languages,
    tree_sitter_available,
)

__all__ = [
    "UST", "USTBuilder", "USTFile", "USTNode", "USTNodeType", "SourceSpan",
    "build_ust", "default_builder", "availability", "language_for_path",
    "supported_extensions", "supported_languages", "tree_sitter_available",
]
