"""Java language plugin — regex-bridge detectors (SQLi, XSS, secrets w/
entropy filter, weak crypto, broken auth, path traversal, sensitive
logging). Tree-sitter UAST upgrade is the planned next step; the plugin
contract shields the pipeline from that change."""
from guardian.core.registry import register_language
from guardian.scanner.base import EngineBackedPlugin


@register_language
class JavaPlugin(EngineBackedPlugin):
    name = "java"
    extensions = (".java",)
    _engine_language = "java"
