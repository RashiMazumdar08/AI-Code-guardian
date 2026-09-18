"""
UST Data-Flow Pass
==================
Language-independent taint propagation over normalised UST nodes.

Because the UST records, for every call and assignment, the *text* of its
arguments plus the enclosing function, we can run a useful source→sink
analysis without a per-language IR:

    1. seed taint from parameters whose names look like external input
       and from calls tagged `source` (request.args.get, getParameter,
       os.environ.get, ...);
    2. propagate through assignments whose right-hand side mentions a
       tainted identifier (covers concatenation, f-strings, template
       literals, format!(), String.format — all of which keep the
       identifier visible in the expression text);
    3. clear taint when the value passes through a `sanitizer` call;
    4. flag any `sink:*` call whose arguments still mention a tainted
       identifier.

This is intentionally an over-approximation of reachability and an
under-approximation of precision — it is a *confidence signal*, recorded
on `USTNode.data_flow`, not a proof. Deterministic rules decide what to
report; the flag raises confidence and feeds reachability into risk
scoring.
"""
from __future__ import annotations

from typing import Iterable

from guardian.ust.languages.base import collect_identifiers
from guardian.ust.models import USTFile, USTNode, USTNodeType

#: Parameter/variable names that usually carry external input.
_INPUT_NAME_HINTS = (
    "request", "req", "input", "param", "params", "query", "body", "payload",
    "user", "userinput", "form", "arg", "argv", "data", "raw", "untrusted",
    "external", "client", "http", "headers", "cookie", "upload", "filename",
)

_MAX_ITERATIONS = 6


def _looks_like_input(name: str) -> bool:
    lowered = name.lower().lstrip("&*").split(":")[0].strip()
    return any(hint in lowered for hint in _INPUT_NAME_HINTS)


def _identifier_of(target: str) -> str:
    """First identifier of an assignment target (`self.x`, `let mut y`, `const z`)."""
    ids = [t for t in collect_identifiers(target)
           if t and not t[0].isdigit() and t not in {"let", "mut", "const", "var",
                                                     "final", "static", "this", "self"}]
    if not ids:
        return ""
    # keep source order rather than set order
    for token in target.replace(".", " ").replace(":", " ").split():
        token = token.strip("&*()[]{},;")
        if token in ids:
            return token
    return sorted(ids)[0]


def analyze_file(ust_file: USTFile) -> USTFile:
    """Annotate `data_flow` on every node of one file (in place)."""
    by_function: dict[str, list[USTNode]] = {}
    for node in ust_file.nodes:
        by_function.setdefault(node.enclosing_function, []).append(node)

    functions = {fn.name: fn for fn in ust_file.functions() if fn.name}

    for fn_name, nodes in by_function.items():
        tainted: set[str] = set()
        # Variables whose taint arrived through *dynamic string construction*
        # (concatenation, format!, f-string, template literal). Passing a
        # tainted value as a bound query parameter is safe; splicing it into
        # the query text is not, and only this set distinguishes the two.
        dynamic_taint: set[str] = set()

        fn_node = functions.get(fn_name)
        if fn_node is not None:
            for param in fn_node.parameters:
                ident = _identifier_of(param)
                if ident and _looks_like_input(param):
                    tainted.add(ident)

        # fixed point: assignments can be observed before their use
        for _ in range(_MAX_ITERATIONS):
            changed = False
            for node in nodes:
                if node.type is USTNodeType.CALL and "source" in node.security_tags:
                    # `x = request.args.get(...)` handled via the assignment below,
                    # but a bare source call still marks its own result as tainted.
                    if not node.data_flow.get("is_source"):
                        node.data_flow["is_source"] = True
                        changed = True

                if node.type is USTNodeType.ASSIGNMENT:
                    target = _identifier_of(node.name)
                    if not target:
                        continue
                    value = " ".join(node.arguments)
                    value_ids = collect_identifiers(value)
                    from_source = _mentions_source(value, nodes, node)
                    from_tainted = bool(value_ids & tainted)
                    sanitised = _mentions_sanitizer(value, nodes, node)
                    if (from_source or from_tainted) and not sanitised:
                        if target not in tainted:
                            tainted.add(target)
                            changed = True
                        node.data_flow["tainted"] = True
                        propagates_dynamically = (
                            _looks_concatenated(value)
                            or bool(value_ids & dynamic_taint))
                        if propagates_dynamically and target not in dynamic_taint:
                            dynamic_taint.add(target)
                            node.data_flow["dynamic_expression"] = True
                            changed = True
                    elif sanitised and target in tainted:
                        tainted.discard(target)
                        dynamic_taint.discard(target)
                        node.data_flow["sanitized"] = True
                        changed = True
            if not changed:
                break

        # final sink evaluation
        for node in nodes:
            if node.type not in (USTNodeType.CALL, USTNodeType.OBJECT_CREATION,
                                 USTNodeType.DATABASE_OPERATION):
                continue
            sink_tags = [t for t in node.security_tags if t.startswith("sink:")]
            if not sink_tags:
                continue
            sink_kind = sink_tags[0].split(":", 1)[1]

            # Only the *first* argument builds the dangerous payload (the SQL
            # text, the command line, the path). Later arguments are bound
            # parameters / options — `execute("... = %s", (user_input,))` is
            # the correct, safe idiom and must not be reported.
            primary = node.arguments[0] if node.arguments else ""
            if _is_pure_literal(primary):
                continue

            arg_ids = collect_identifiers(primary)
            hits = sorted(arg_ids & tainted)
            dynamic_hits = sorted(arg_ids & dynamic_taint)
            concatenated = _looks_concatenated(primary)

            if hits and not _mentions_sanitizer(primary, nodes, node) \
                    and (concatenated or dynamic_hits):
                node.data_flow.update({
                    "tainted": True,
                    "sink": sink_kind,
                    "tainted_variables": hits[:6],
                    "dynamic_expression": bool(concatenated or dynamic_hits),
                })
            elif concatenated:
                node.data_flow.update({
                    "dynamic_expression": True,
                    "sink": sink_kind,
                })

        if tainted:
            for node in nodes:
                node.data_flow.setdefault("function_tainted_vars", sorted(tainted)[:8])

    return ust_file


def _mentions_source(text: str, nodes: Iterable[USTNode], current: USTNode) -> bool:
    """True when `text` invokes a call that this file tagged as a taint source."""
    from guardian.ust.tagging import TAINT_SOURCES
    if TAINT_SOURCES.search(text):
        return True
    return any(n.symbol and n.symbol in text and "source" in n.security_tags
               for n in nodes if n is not current)


def _mentions_sanitizer(text: str, nodes: Iterable[USTNode], current: USTNode) -> bool:
    from guardian.ust.tagging import SANITIZERS
    if SANITIZERS.search(text):
        return True
    return any(n.symbol and n.symbol in text and "sanitizer" in n.security_tags
               for n in nodes if n is not current)


def _is_pure_literal(text: str) -> bool:
    """A single quoted string with nothing spliced into it."""
    text = text.strip()
    if len(text) < 2 or text[0] not in "\"'`" or text[-1] != text[0]:
        return False
    inner = text[1:-1]
    return "${" not in inner and "{}" not in inner and "+" not in inner


def _looks_concatenated(text: str) -> bool:
    """Dynamic string construction — the shape most injection bugs take."""
    if "+" in text and ('"' in text or "'" in text):
        return True
    if "${" in text or "{}" in text or "%s" in text or "%d" in text:
        return True
    if "f\"" in text or "f'" in text:
        return True
    if ".format(" in text or "String.format" in text or "format!" in text:
        return True
    return False
