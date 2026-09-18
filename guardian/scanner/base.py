"""
Scanner plugin base. Language plugins wrap the battle-tested detectors
in guardian/scanner/_engine.py (ported intact from v1, incl. Shannon
entropy secret filtering and the Python taint pass) behind the
LanguagePlugin contract. Migrating each pattern set into its own plugin
module is a follow-up refactor; the contract already isolates callers
from that move.
"""
from __future__ import annotations

from guardian.core.models import Finding
from guardian.scanner._engine import SecurityRuleEngine

_shared_engine = SecurityRuleEngine()


class EngineBackedPlugin:
    """Base for plugins that delegate to the legacy engine by language key."""

    name: str = ""
    extensions: tuple[str, ...] = ()
    _engine_language: str = ""

    def scan_source(self, source: str, file_label: str) -> list[Finding]:
        return _shared_engine.scan_source(source, file_label, language=self._engine_language)
