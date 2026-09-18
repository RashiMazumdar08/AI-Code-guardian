"""
UST Builder
===========
The single entry point that turns source into a Unified Syntax Tree.

    source -> Tree-sitter parse -> language normalizer -> tagging
           -> data-flow -> USTFile

Degradation ladder (never raises to the caller):

    1. Tree-sitter grammar for the language              (parser="tree-sitter")
    2. Python only: stdlib `ast`                         (parser="python-ast")
    3. Any language: line-oriented regex scanner         (parser="regex")
    4. Unsupported/binary/unreadable file                (parser="none")

Every USTFile records which rung it landed on, so downstream engines can
weight confidence honestly instead of pretending a regex scan is a parse.
"""
from __future__ import annotations

import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Iterable, Optional

from guardian.ust import parsers
from guardian.ust.dataflow import analyze_file
from guardian.ust.fallback import python_ast_ust, regex_ust
from guardian.ust.languages.base import LanguageNormalizer
from guardian.ust.languages.java_lang import JavaNormalizer
from guardian.ust.languages.javascript_lang import JavaScriptNormalizer, TypeScriptNormalizer
from guardian.ust.languages.python_lang import PythonNormalizer
from guardian.ust.languages.rust_lang import RustNormalizer
from guardian.ust.models import UST, USTFile
from guardian.ust.tagging import tag_file

log = logging.getLogger(__name__)

#: language key -> normalizer factory. Adding a language = one row here
#: plus one row in `parsers._GRAMMARS`.
NORMALIZERS: dict[str, type[LanguageNormalizer] | object] = {
    "python": PythonNormalizer,
    "java": JavaNormalizer,
    "javascript": JavaScriptNormalizer,
    "typescript": TypeScriptNormalizer,
    "tsx": TypeScriptNormalizer,
    "rust": RustNormalizer,
}

MAX_SOURCE_BYTES = 2_000_000


def _normalizer_for(language: str) -> Optional[LanguageNormalizer]:
    factory = NORMALIZERS.get(language)
    if factory is None:
        return None
    if language in ("javascript",):
        return JavaScriptNormalizer("javascript")
    if language == "typescript":
        return TypeScriptNormalizer("typescript")
    if language == "tsx":
        return TypeScriptNormalizer("typescript")
    return factory()  # type: ignore[operator]


def _parse_worker(args: tuple) -> tuple[str, dict]:
    """Runs inside a ProcessPoolExecutor worker (see
    USTBuilder.build_repository). Takes and returns only plain, picklable
    data -- no instance state, UST objects, or tree-sitter handles cross
    the process boundary. Never raises: on any failure it returns the
    same error-carrying USTFile shape build_source() itself would."""
    source, label, language, enable_dataflow, enable_tagging, promote_semantic_types = args
    builder = USTBuilder(enable_dataflow=enable_dataflow,
                         enable_tagging=enable_tagging,
                         promote_semantic_types=promote_semantic_types)
    try:
        ust_file = builder.build_source(source, label, language)
    except Exception as exc:  # noqa: BLE001 — a worker crash must degrade, not kill the pool
        ust_file = USTFile(path=label, language=language, parser="none", parse_error=str(exc))
    return label, ust_file.to_cache_dict()


class USTBuilder:
    """Builds USTFiles and repository-level USTs."""

    def __init__(self, *, enable_dataflow: bool = True,
                 enable_tagging: bool = True,
                 promote_semantic_types: bool = False) -> None:
        self.enable_dataflow = enable_dataflow
        self.enable_tagging = enable_tagging
        self.promote_semantic_types = promote_semantic_types

    # ------------------------------------------------------------------
    def build_source(self, source: str, file_label: str,
                     language: str = "") -> USTFile:
        """Build a UST for one file's text. Never raises."""
        language = language or parsers.language_for_path(file_label)
        if not language:
            return USTFile(path=file_label, language="unknown", parser="none",
                           parse_error="unsupported language",
                           line_count=len(source.splitlines()))
        if len(source.encode("utf-8", errors="ignore")) > MAX_SOURCE_BYTES:
            return USTFile(path=file_label, language=language, parser="none",
                           parse_error="file exceeds UST size limit",
                           line_count=len(source.splitlines()))

        ust_file = self._parse(source, file_label, language)

        if self.enable_tagging and ust_file.nodes:
            try:
                tag_file(ust_file, promote=self.promote_semantic_types)
            except Exception as exc:  # noqa: BLE001 — tagging must never kill a scan
                log.debug("tagging failed for %s: %s", file_label, exc)
        if self.enable_dataflow and ust_file.nodes:
            try:
                analyze_file(ust_file)
            except Exception as exc:  # noqa: BLE001
                log.debug("data-flow pass failed for %s: %s", file_label, exc)
        return ust_file

    def build_file(self, path: Path, file_label: str = "",
                   language: str = "") -> USTFile:
        label = file_label or str(path)
        try:
            source = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            return USTFile(path=label, language=language or parsers.language_for_path(path),
                           parser="none", parse_error=f"unreadable: {exc}")
        return self.build_source(source, label, language)

    def build_repository(self, root: Path | str, files: Iterable[Path],
                         relative: bool = True, *,
                         max_workers: Optional[int] = None,
                         cache_ttl: Optional[int] = None) -> UST:
        """Build the repository-level UST. Per-file failures are recorded
        on the USTFile, never propagated — a partial UST is still useful.

        Caching is per-file and content-hash-addressed (see
        RedisManager.hash_file_content): a file whose content is
        unchanged reuses its cached UST regardless of path/mtime/which
        repository it's in, and a changed file invalidates only itself
        instead of the whole repository's cache in one shot. Cache-miss
        files are parsed with a bounded process pool (UST_MAX_WORKERS /
        max_workers), since Tree-sitter parsing is CPU-bound -- a single
        miss, or max_workers<=1, parses inline instead, since spawning a
        pool for one file only adds overhead. Any pool failure (e.g. a
        multiprocessing restriction in the host environment) falls back
        to sequential parsing rather than failing the scan.
        """
        root_path = Path(root)
        if max_workers is None:
            max_workers = int(os.getenv("UST_MAX_WORKERS", "4"))
        if cache_ttl is None:
            cache_ttl = int(os.getenv("CACHE_TTL", "86400"))

        from guardian.cache.redis_manager import RedisManager
        redis_mgr = RedisManager()

        ust = UST(root=str(root_path))
        hits = misses = 0
        read_ms = write_ms = 0.0

        # -- resolve each file's label/content, check the per-file cache --
        pending: list[tuple[str, str, str, str]] = []  # (label, source, language, cache_key)
        for fp in files:
            language = parsers.language_for_path(fp)
            if not language:
                continue
            label = str(fp)
            if relative:
                try:
                    label = str(Path(fp).resolve().relative_to(root_path.resolve()))
                except (ValueError, OSError):
                    label = str(fp)
            try:
                source = Path(fp).read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                ust.add(USTFile(path=label, language=language, parser="none",
                                parse_error=f"unreadable: {exc}"))
                misses += 1
                continue

            cache_key = f"ust:file:{language}:{RedisManager.hash_file_content(source)}"
            cached = None
            if redis_mgr.enabled:
                t = time.perf_counter()
                cached = redis_mgr.get_json(cache_key)
                read_ms += (time.perf_counter() - t) * 1000

            if cached:
                try:
                    ust_file = USTFile.from_cache_dict(cached)
                    ust_file.path = label  # same content, possibly seen under a different path
                    ust.add(ust_file)
                    hits += 1
                    continue
                except Exception as exc:  # noqa: BLE001
                    log.debug("failed to deserialize cached USTFile for %s: %s", label, exc)

            misses += 1
            pending.append((label, source, language, cache_key))

        # -- parse cache misses, bounded-parallel when it's worth it --------
        parsed: list[tuple[str, USTFile]] = []
        if len(pending) > 1 and max_workers > 1:
            try:
                worker_args = [
                    (source, label, language, self.enable_dataflow,
                     self.enable_tagging, self.promote_semantic_types)
                    for label, source, language, _ in pending
                ]
                with ProcessPoolExecutor(max_workers=max_workers) as pool:
                    for (label, _, _, _), (_, ust_dict) in zip(
                            pending, pool.map(_parse_worker, worker_args)):
                        parsed.append((label, USTFile.from_cache_dict(ust_dict)))
            except Exception as exc:  # noqa: BLE001 — multiprocessing must never kill a scan
                log.warning("parallel UST parsing unavailable (%s); falling back to sequential", exc)
                parsed = []

        if not parsed and pending:
            for label, source, language, _ in pending:
                try:
                    ust_file = self.build_source(source, label, language)
                except Exception as exc:  # noqa: BLE001 — belt and braces
                    log.warning("UST build failed for %s: %s", label, exc)
                    ust_file = USTFile(path=label, language=language, parser="none",
                                       parse_error=str(exc))
                parsed.append((label, ust_file))

        cache_keys = {label: key for label, _, _, key in pending}
        for label, ust_file in parsed:
            ust.add(ust_file)
            if redis_mgr.enabled and ust_file.ok:
                t = time.perf_counter()
                redis_mgr.set_json(cache_keys[label], ust_file.to_cache_dict(), ttl=cache_ttl)
                write_ms += (time.perf_counter() - t) * 1000

        ust.cache_stats = {
            "hits": hits,
            "misses": misses,
            "hit_rate": round(hits / (hits + misses), 3) if (hits + misses) else 0.0,
            "read_ms": round(read_ms, 1),
            "write_ms": round(write_ms, 1),
        }
        return ust

    # ------------------------------------------------------------------
    def _parse(self, source: str, file_label: str, language: str) -> USTFile:
        tree = parsers.parse(source, language)
        if tree is not None:
            normalizer = _normalizer_for(language)
            if normalizer is not None:
                try:
                    nodes, imports = normalizer.normalize(tree, source, file_label)
                    ust_file = USTFile(
                        path=file_label,
                        language=parsers.normalizer_language(language),
                        nodes=nodes, imports=imports, parser="tree-sitter",
                        line_count=len(source.splitlines()))
                    root = getattr(tree, "root_node", None)
                    if root is not None and getattr(root, "has_error", False):
                        # Tree-sitter recovered from syntax errors: keep the
                        # partial tree but record that it is partial.
                        ust_file.parse_error = ""
                        ust_file.line_count = len(source.splitlines())
                        for node in ust_file.nodes:
                            node.metadata.setdefault("partial_parse", True)
                    return ust_file
                except Exception as exc:  # noqa: BLE001
                    log.debug("normalizer failed for %s (%s); falling back", file_label, exc)

        # -- fallbacks --------------------------------------------------
        if language == "python":
            fallback = python_ast_ust(source, file_label)
            if fallback is not None and (fallback.nodes or fallback.parse_error):
                if fallback.nodes:
                    return fallback
        return regex_ust(source, file_label,
                         parsers.normalizer_language(language))


#: Shared default builder — cheap to construct, but callers that need
#: custom toggles should make their own.
default_builder = USTBuilder()


def build_ust(source: str, file_label: str, language: str = "") -> USTFile:
    """Module-level convenience wrapper around the default builder."""
    return default_builder.build_source(source, file_label, language)
