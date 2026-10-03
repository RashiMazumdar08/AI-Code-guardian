"""
Deterministic Business Evidence Analyzer
========================================
Performs LLM-free Python AST, control-flow, data-flow, inter-procedural,
and specialized business control analysis for AI Code Guardian.
"""
from __future__ import annotations

import ast
import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)


class EvidenceType(str, Enum):
    CONTROL_FLOW = "CONTROL_FLOW"
    DATA_FLOW = "DATA_FLOW"
    INTERPROCEDURAL = "INTERPROCEDURAL"
    SPECIALIZED_CONTROL = "SPECIALIZED_CONTROL"


@dataclass
class BusinessEvidenceItem:
    evidence_type: str
    file: str
    function: str
    line: int
    relationship: str
    condition: str = ""
    guarded_operation: str = ""
    source: str = ""
    variable: str = ""
    sink: str = ""
    snippet: str = ""
    confidence: float = 0.85

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.evidence_type,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "relationship": self.relationship,
            "condition": self.condition,
            "guarded_operation": self.guarded_operation,
            "source": self.source,
            "variable": self.variable,
            "sink": self.sink,
            "snippet": self.snippet,
            "confidence": round(self.confidence, 3),
        }


@dataclass
class DeterministicRuleAnalysis:
    rule_id: str
    action_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    condition_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    control_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    control_flow_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    data_flow_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    interprocedural_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    specialized_evidence: list[BusinessEvidenceItem] = field(default_factory=list)
    missing_controls: list[str] = field(default_factory=list)
    negative_evidence: list[str] = field(default_factory=list)
    confidence: float = 0.0
    deterministic_verdict: str = "INSUFFICIENT_EVIDENCE"  # COMPLIANT, VIOLATION, PARTIAL, INSUFFICIENT_EVIDENCE
    matched_file: str = ""
    matched_function: str = ""
    matched_line: int = 0
    matched_snippet: str = ""
    what: str = ""
    why: str = ""
    how: str = ""
    score_boost: float = 0.0

    def all_evidence(self) -> list[BusinessEvidenceItem]:
        return (
            self.action_evidence
            + self.condition_evidence
            + self.control_evidence
            + self.control_flow_evidence
            + self.data_flow_evidence
            + self.interprocedural_evidence
            + self.specialized_evidence
        )


@dataclass
class FunctionASTProfile:
    name: str
    file: str
    line: int
    end_line: int
    args: list[str] = field(default_factory=list)
    calls: list[tuple[str, int, list[str]]] = field(default_factory=list)  # (callee_name, line, arg_names)
    assignments: list[tuple[str, str, int]] = field(default_factory=list)  # (var_name, expr_str, line)
    if_statements: list[dict[str, Any]] = field(default_factory=list)  # [{condition_str, line, guarded_ops}]
    context_managers: list[tuple[str, int]] = field(default_factory=list)  # (mgr_str, line)
    decorators: list[str] = field(default_factory=list)
    snippet: str = ""
    ast_node: Optional[ast.AST] = None


_FILE_AST_CACHE: dict[str, tuple[float, list[FunctionASTProfile]]] = {}


def _node_to_str(node: ast.AST) -> str:
    """Safely format an AST node into unparsed Python code (or fallback repr)."""
    try:
        return ast.unparse(node).strip()
    except Exception:
        return str(node)


class PythonASTExtractor(ast.NodeVisitor):
    """Extracts function-level control flow, data flow, and calls from a Python AST."""

    def __init__(self, rel_path: str, lines: list[str]):
        self.rel_path = rel_path
        self.lines = lines
        self.profiles: list[FunctionASTProfile] = []
        self._current_profile: Optional[FunctionASTProfile] = None

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        prev_profile = self._current_profile
        fn_name = node.name
        start_line = node.lineno
        end_line = getattr(node, "end_lineno", start_line + 15)

        args = [arg.arg for arg in node.args.args]
        decorators = [_node_to_str(dec) for dec in node.decorator_list]

        raw_snippet = "\n".join(self.lines[max(0, start_line - 1): min(len(self.lines), end_line)])

        profile = FunctionASTProfile(
            name=fn_name,
            file=self.rel_path,
            line=start_line,
            end_line=end_line,
            args=args,
            decorators=decorators,
            snippet=raw_snippet[:800],
            ast_node=node,
        )

        self._current_profile = profile
        self.generic_visit(node)
        self.profiles.append(profile)
        self._current_profile = prev_profile

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_With(self, node: ast.With | ast.AsyncWith):
        if self._current_profile:
            for item in node.items:
                mgr_str = _node_to_str(item.context_expr)
                self._current_profile.context_managers.append((mgr_str, node.lineno))
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Assign(self, node: ast.Assign):
        if self._current_profile:
            expr_str = _node_to_str(node.value)
            for target in node.targets:
                var_name = _node_to_str(target)
                self._current_profile.assignments.append((var_name, expr_str, node.lineno))
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        if self._current_profile:
            var_name = _node_to_str(node.target)
            val_str = _node_to_str(node.value)
            self._current_profile.assignments.append((var_name, f"{var_name} += {val_str}", node.lineno))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        if self._current_profile:
            func_str = _node_to_str(node.func)
            arg_strs = [_node_to_str(arg) for arg in node.args] + [f"{kw.arg}={_node_to_str(kw.value)}" for kw in node.keywords if kw.arg]
            self._current_profile.calls.append((func_str, node.lineno, arg_strs))
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        if self._current_profile:
            cond_str = _node_to_str(node.test)
            guarded_ops = []
            for stmt in node.body:
                guarded_ops.append(_node_to_str(stmt))

            self._current_profile.if_statements.append({
                "condition": cond_str,
                "line": node.lineno,
                "guarded_ops": guarded_ops,
                "else_ops": [_node_to_str(s) for s in node.orelse],
            })
        self.generic_visit(node)


class BusinessEvidenceAnalyzer:
    """Deterministic Business Control Evidence Analyzer.
    
    Evaluates Python AST profiles, control-flow structures, data-flow tracks,
    inter-procedural calls, and specialized business rule patterns (REQ-001..005)
    to produce explainable evidence.
    """

    def __init__(self, workspace_dir: Path | None = None):
        self.workspace_dir = (workspace_dir or Path.cwd()).resolve()
        self.profiles: list[FunctionASTProfile] = self._extract_ast_profiles()
        self._fn_map: dict[str, FunctionASTProfile] = {p.name.lower(): p for p in self.profiles}

    def _extract_ast_profiles(self) -> list[FunctionASTProfile]:
        ws_key = str(self.workspace_dir)
        try:
            py_files = list(self.workspace_dir.rglob("*.py")) if self.workspace_dir.exists() else []
            mtime = sum(p.stat().st_mtime for p in py_files) if py_files else 0.0
            cache_key = f"{ws_key}:{len(py_files)}"
        except Exception:
            mtime = 0.0
            cache_key = ws_key

        if cache_key in _FILE_AST_CACHE:
            cached_mtime, cached_profiles = _FILE_AST_CACHE[cache_key]
            if cached_mtime == mtime:
                return cached_profiles

        profiles: list[FunctionASTProfile] = []
        ignore_dirs = {".venv", "node_modules", ".git", "__pycache__", "build", "dist", ".acg_workspaces", ".pytest_cache", "_to_delete"}
        file_count = 0
        max_files = 150

        try:
            for root, dirs, files in os.walk(ws_key):
                dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]
                for file in files:
                    if file_count >= max_files:
                        break
                    if file.endswith(".py"):
                        file_count += 1
                        p = Path(root) / file
                        try:
                            content = p.read_text(encoding="utf-8", errors="ignore")
                            try:
                                rel_path = str(p.relative_to(self.workspace_dir))
                            except ValueError:
                                rel_path = str(p)
                        except Exception:
                            continue

                        try:
                            tree = ast.parse(content, filename=file)
                            lines = content.splitlines()
                            extractor = PythonASTExtractor(rel_path, lines)
                            extractor.visit(tree)
                            profiles.extend(extractor.profiles)
                        except Exception as parse_err:
                            log.debug("AST parse notice for %s: %s", rel_path, parse_err)
                            continue
        except Exception as exc:
            log.warning("AST profile extraction notice: %s", exc)

        _FILE_AST_CACHE[cache_key] = (mtime, profiles)
        return profiles

    # ------------------------------------------------------------------
    # Rule Evaluation Router
    # ------------------------------------------------------------------
    def analyze_rule(self, rule_id: str, requirement_text: str = "", rule_obj: Any = None) -> DeterministicRuleAnalysis:
        analysis = DeterministicRuleAnalysis(rule_id=rule_id)

        # Normalize rule ID format (REQ-001, REQ-002, etc.)
        r_id = (rule_id or "").upper().strip()

        if r_id == "REQ-001" or "cart quantity" in requirement_text.lower() or "inventory" in requirement_text.lower():
            self._analyze_req_001(analysis, requirement_text)
        elif r_id == "REQ-002" or "balance transfer" in requirement_text.lower() or "atomic" in requirement_text.lower():
            self._analyze_req_002(analysis, requirement_text)
        elif r_id == "REQ-003" or "checkout price" in requirement_text.lower() or "authoritative price" in requirement_text.lower():
            self._analyze_req_003(analysis, requirement_text)
        elif r_id == "REQ-004" or "coupon usage" in requirement_text.lower() or "coupon limit" in requirement_text.lower():
            self._analyze_req_004(analysis, requirement_text)
        elif r_id == "REQ-005" or "sufficient funds" in requirement_text.lower() or "funds for authoritative" in requirement_text.lower():
            self._analyze_req_005(analysis, requirement_text)
        else:
            self._analyze_generic_rule(analysis, requirement_text, rule_obj)

        return analysis

    # ------------------------------------------------------------------
    # REQ-001: Cart Quantity and Inventory Rule
    # ------------------------------------------------------------------
    def _analyze_req_001(self, analysis: DeterministicRuleAnalysis, req_text: str):
        """REQ-001: Cart Quantity and Inventory Rule
        Requires positive quantity check & stock/inventory availability check before cart/order update.
        """
        for p in self.profiles:
            s_lower = p.snippet.lower()
            if not any(k in s_lower for k in ["cart", "add_item", "quantity", "stock", "inventory"]):
                continue

            pos_qty_check = False
            stock_check = False
            check_line = 0
            check_cond = ""

            for if_stmt in p.if_statements:
                cond = if_stmt["condition"]
                cond_l = cond.lower()
                if any(k in cond_l for k in ["qty", "quantity"]) and any(op in cond for op in [">", ">=", "<=", "<", "!="]):
                    pos_qty_check = True
                    check_line = if_stmt["line"]
                    check_cond = cond
                if any(k in cond_l for k in ["stock", "inventory", "available"]):
                    stock_check = True
                    check_line = if_stmt["line"]
                    check_cond = f"{check_cond}; {cond}" if check_cond else cond

            has_cart_mutation = any(
                any(k in op.lower() for k in ["cart", "items.append", "add", "item"])
                for if_stmt in p.if_statements for op in if_stmt["guarded_ops"]
            ) or any(any(k in call[0].lower() for k in ["add", "cart", "append"]) for call in p.calls)

            if (pos_qty_check or stock_check) and has_cart_mutation:
                rel = "stock_and_quantity_validated_before_cart_mutation" if (pos_qty_check and stock_check) else "partial_quantity_or_stock_check_before_cart_mutation"
                ev = BusinessEvidenceItem(
                    evidence_type=EvidenceType.SPECIALIZED_CONTROL,
                    file=p.file,
                    function=p.name,
                    line=check_line or p.line,
                    relationship=rel,
                    condition=check_cond,
                    guarded_operation="cart_item_update",
                    snippet=p.snippet[:400],
                    confidence=0.90 if (pos_qty_check and stock_check) else 0.75,
                )
                analysis.specialized_evidence.append(ev)
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = check_line or p.line
                analysis.matched_snippet = p.snippet[:400]

                if pos_qty_check and stock_check:
                    analysis.deterministic_verdict = "COMPLIANT"
                    analysis.what = f"Positive quantity and stock availability checks verified in {p.name}"
                    analysis.why = "Cart quantity and inventory rules satisfied"
                    analysis.how = "Maintain current inventory validation logic"
                    analysis.confidence = 0.90
                    analysis.score_boost = 0.90
                    return
                else:
                    analysis.deterministic_verdict = "PARTIAL"
                    missing = []
                    if not pos_qty_check: missing.append("positive_quantity_check")
                    if not stock_check: missing.append("stock_availability_check")
                    analysis.missing_controls = missing
                    analysis.what = f"Partial inventory check in {p.name} (missing: {', '.join(missing)})"
                    analysis.why = "Incomplete validation before cart mutation"
                    analysis.how = f"Add missing {', '.join(missing)} control"
                    analysis.confidence = 0.70
                    analysis.score_boost = 0.70

        if not analysis.specialized_evidence:
            analysis.deterministic_verdict = "INSUFFICIENT_EVIDENCE"
            analysis.missing_controls = ["positive_quantity_check", "stock_availability_check"]

    # ------------------------------------------------------------------
    # REQ-002: Balance Transfer Integrity Rule
    # ------------------------------------------------------------------
    def _analyze_req_002(self, analysis: DeterministicRuleAnalysis, req_text: str):
        """REQ-002: Balance Transfer Integrity Rule
        Requires sender balance check >= amount, sender debit, recipient credit, and atomic transaction.
        """
        for p in self.profiles:
            s_lower = p.snippet.lower()
            if not any(k in s_lower for k in ["transfer", "balance", "debit", "credit", "sender"]):
                continue

            balance_check = False
            check_line = 0
            check_cond = ""

            for if_stmt in p.if_statements:
                cond = if_stmt["condition"]
                cond_l = cond.lower()
                if any(k in cond_l for k in ["balance", "funds", "amount"]) and any(op in cond for op in [">=", ">", "<=", "<"]):
                    balance_check = True
                    check_line = if_stmt["line"]
                    check_cond = cond

            debit_credit = False
            for var_name, expr_str, l_no in p.assignments:
                if ("balance" in var_name.lower() or "funds" in var_name.lower()) and ("-" in expr_str or "+" in expr_str):
                    debit_credit = True

            has_transaction = any(
                any(k in mgr[0].lower() for k in ["transaction", "atomic", "db.session", "lock"])
                for mgr in p.context_managers
            ) or any(any(k in dec.lower() for k in ["transaction", "atomic"]) for dec in p.decorators)

            if balance_check or debit_credit:
                ev = BusinessEvidenceItem(
                    evidence_type=EvidenceType.CONTROL_FLOW,
                    file=p.file,
                    function=p.name,
                    line=check_line or p.line,
                    relationship="balance_check_guards_transfer" if balance_check else "transfer_mutation_detected",
                    condition=check_cond,
                    guarded_operation="balance_debit_credit" if debit_credit else "transfer_execution",
                    snippet=p.snippet[:400],
                    confidence=0.85 if (balance_check and debit_credit and has_transaction) else 0.70,
                )
                analysis.control_flow_evidence.append(ev)
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = check_line or p.line
                analysis.matched_snippet = p.snippet[:400]

                if balance_check and debit_credit and has_transaction:
                    analysis.deterministic_verdict = "COMPLIANT"
                    analysis.what = f"Atomic balance transfer with sufficient funds check verified in {p.name}"
                    analysis.why = "Balance transfer integrity requirements satisfied"
                    analysis.how = "Maintain atomic transaction controls"
                    analysis.confidence = 0.90
                    analysis.score_boost = 0.90
                    return
                elif balance_check or debit_credit:
                    analysis.deterministic_verdict = "PARTIAL"
                    missing = []
                    if not balance_check: missing.append("sufficient_funds_check")
                    if not has_transaction: missing.append("atomicity")
                    analysis.missing_controls = missing
                    analysis.what = f"Balance transfer logic in {p.name} (missing controls: {', '.join(missing)})"
                    analysis.why = "Transfer operations present but atomicity or funds validation incomplete"
                    analysis.how = "Wrap balance updates in an atomic database transaction"
                    analysis.confidence = 0.70
                    analysis.score_boost = 0.70

        if not analysis.all_evidence():
            analysis.deterministic_verdict = "INSUFFICIENT_EVIDENCE"
            analysis.missing_controls = ["sufficient_funds_check", "atomic_transaction"]

    # ------------------------------------------------------------------
    # REQ-003: Authoritative Checkout Price Rule
    # ------------------------------------------------------------------
    def _analyze_req_003(self, analysis: DeterministicRuleAnalysis, req_text: str):
        """REQ-003: Authoritative Checkout Price Rule
        Requires server-calculated total from authoritative prices/quantities, flowing to order/payment creation.
        Client-supplied price/total must NEVER determine amount charged.
        """
        for p in self.profiles:
            s_lower = p.snippet.lower()
            if not any(k in s_lower for k in ["checkout", "order", "price", "total", "amount", "charge", "payment"]):
                continue

            # Reject pure report downloading/formatting functions
            if any(k in p.name.lower() for k in ["report", "download", "export", "pdf"]):
                continue

            server_calc = False
            server_var = ""
            calc_line = 0

            client_input_trusted = False

            for var_name, expr_str, l_no in p.assignments:
                expr_l = expr_str.lower()
                if any(k in expr_l for k in ["request", "req.", "params", "input", ".get("]) and any(k in var_name.lower() for k in ["total", "price", "amount"]):
                    # Check if client input total flows directly into order/payment call
                    for call_name, c_line, args in p.calls:
                        if any(k in call_name.lower() for k in ["order", "payment", "charge", "pay"]) and any(var_name in a for a in args):
                            client_input_trusted = True
                            ev_neg = BusinessEvidenceItem(
                                evidence_type=EvidenceType.DATA_FLOW,
                                file=p.file,
                                function=p.name,
                                line=l_no,
                                relationship="client_supplied_total_trusted_directly",
                                source=expr_str,
                                variable=var_name,
                                sink=call_name,
                                snippet=p.snippet[:400],
                                confidence=0.90,
                            )
                            analysis.data_flow_evidence.append(ev_neg)
                            analysis.negative_evidence.append("Client-supplied total is directly used for payment/order creation without server-side recalculation")

                if any(k in expr_l for k in ["price", "book.price", "quantity", "price *", "sum(", "calculate_total"]):
                    server_calc = True
                    server_var = var_name
                    calc_line = l_no

            payment_flow = False
            for call_name, c_line, args in p.calls:
                call_l = call_name.lower()
                if any(k in call_l for k in ["pay", "charge", "order", "checkout"]):
                    if server_var and any(server_var in a for a in args):
                        payment_flow = True

            if client_input_trusted and not server_calc:
                analysis.deterministic_verdict = "VIOLATION"
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = p.line
                analysis.matched_snippet = p.snippet[:400]
                analysis.what = f"Client-supplied price/total trusted in {p.name}"
                analysis.why = "Client input bypasses server authoritative pricing calculation"
                analysis.how = "Recalculate order total from authoritative database book prices on server"
                analysis.confidence = 0.90
                analysis.score_boost = 0.90
                return

            if server_calc:
                ev = BusinessEvidenceItem(
                    evidence_type=EvidenceType.DATA_FLOW,
                    file=p.file,
                    function=p.name,
                    line=calc_line or p.line,
                    relationship="server_authoritative_price_calculation",
                    source=server_var,
                    variable=server_var,
                    sink="order_payment_execution" if payment_flow else "calculated_total",
                    snippet=p.snippet[:400],
                    confidence=0.90 if payment_flow else 0.75,
                )
                analysis.data_flow_evidence.append(ev)
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = calc_line or p.line
                analysis.matched_snippet = p.snippet[:400]

                if payment_flow:
                    analysis.deterministic_verdict = "COMPLIANT"
                    analysis.what = f"Server-calculated authoritative price verified in {p.name}"
                    analysis.why = "Authoritative checkout pricing rule satisfied"
                    analysis.how = "Maintain server-side price recalculation"
                    analysis.confidence = 0.90
                    analysis.score_boost = 0.90
                    return
                else:
                    analysis.deterministic_verdict = "PARTIAL"
                    analysis.missing_controls = ["payment_flow_binding"]
                    analysis.what = f"Server price calculated in {p.name} but payment binding requires verification"
                    analysis.why = "Authoritative total calculated but flow to payment sink unverified"
                    analysis.how = "Pass server-derived total to payment processor"
                    analysis.confidence = 0.70
                    analysis.score_boost = 0.70

        if not analysis.all_evidence():
            analysis.deterministic_verdict = "INSUFFICIENT_EVIDENCE"
            analysis.missing_controls = ["server_authoritative_price_calculation"]

    # ------------------------------------------------------------------
    # REQ-004: Coupon Usage Limit Rule
    # ------------------------------------------------------------------
    def _analyze_req_004(self, analysis: DeterministicRuleAnalysis, req_text: str):
        """REQ-004: Coupon Usage Limit Rule
        Requires active check & usage < max_uses check BEFORE coupon application/increment.
        """
        for p in self.profiles:
            s_lower = p.snippet.lower()
            if not any(k in s_lower for k in ["coupon", "discount", "promo", "voucher"]):
                continue

            active_check = False
            usage_check = False
            check_line = 0
            check_cond = ""

            for if_stmt in p.if_statements:
                cond = if_stmt["condition"]
                cond_l = cond.lower()
                if any(k in cond_l for k in ["active", "enabled", "is_valid"]):
                    active_check = True
                    check_line = if_stmt["line"]
                    check_cond = cond
                if any(k in cond_l for k in ["uses", "usage", "count", "limit", "max_uses"]):
                    usage_check = True
                    check_line = if_stmt["line"]
                    check_cond = f"{check_cond}; {cond}" if check_cond else cond

            increment_used = any(
                ("uses" in var.lower() or "usage" in var.lower()) and ("+" in expr or "+=" in expr)
                for var, expr, l in p.assignments
            ) or any("increment" in call[0].lower() for call in p.calls)

            if active_check or usage_check or increment_used:
                ev = BusinessEvidenceItem(
                    evidence_type=EvidenceType.SPECIALIZED_CONTROL,
                    file=p.file,
                    function=p.name,
                    line=check_line or p.line,
                    relationship="coupon_limit_check_guards_application" if (active_check and usage_check) else "coupon_logic_detected",
                    condition=check_cond,
                    guarded_operation="apply_coupon_increment_usage",
                    snippet=p.snippet[:400],
                    confidence=0.90 if (active_check and usage_check and increment_used) else 0.70,
                )
                analysis.specialized_evidence.append(ev)
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = check_line or p.line
                analysis.matched_snippet = p.snippet[:400]

                if active_check and usage_check:
                    analysis.deterministic_verdict = "COMPLIANT"
                    analysis.what = f"Active and usage limit checks verified for coupon in {p.name}"
                    analysis.why = "Coupon usage limit rule satisfied"
                    analysis.how = "Maintain coupon usage limit validation"
                    analysis.confidence = 0.90
                    analysis.score_boost = 0.90
                    return
                else:
                    analysis.deterministic_verdict = "PARTIAL"
                    missing = []
                    if not active_check: missing.append("active_coupon_check")
                    if not usage_check: missing.append("usage_limit_check")
                    analysis.missing_controls = missing
                    analysis.what = f"Coupon logic in {p.name} (missing: {', '.join(missing)})"
                    analysis.why = "Incomplete coupon validation before discount application"
                    analysis.how = f"Add missing {', '.join(missing)} control"
                    analysis.confidence = 0.70
                    analysis.score_boost = 0.70

        if not analysis.specialized_evidence:
            analysis.deterministic_verdict = "INSUFFICIENT_EVIDENCE"
            analysis.missing_controls = ["active_coupon_check", "usage_limit_check"]

    # ------------------------------------------------------------------
    # REQ-005: Sufficient Funds for Authoritative Order Total Rule
    # ------------------------------------------------------------------
    def _analyze_req_005(self, analysis: DeterministicRuleAnalysis, req_text: str):
        """REQ-005: Sufficient Funds for Authoritative Order Total Rule
        Requires user balance >= server authoritative order total before payment/order creation.
        """
        for p in self.profiles:
            s_lower = p.snippet.lower()
            if not any(k in s_lower for k in ["balance", "funds", "order", "total", "pay", "charge"]):
                continue

            funds_check = False
            check_line = 0
            check_cond = ""

            for if_stmt in p.if_statements:
                cond = if_stmt["condition"]
                cond_l = cond.lower()
                if (any(k in cond_l for k in ["balance", "funds", "user"]) and any(k in cond_l for k in ["total", "amount", "price", "order"])) or (any(k in cond_l for k in ["balance", "funds"]) and any(op in cond for op in [">=", ">", "<=", "<", "!="])):
                    funds_check = True
                    check_line = if_stmt["line"]
                    check_cond = cond

            payment_executed = any(
                any(k in call[0].lower() for k in ["pay", "charge", "order", "deduct"])
                for call in p.calls
            )

            if funds_check:
                ev = BusinessEvidenceItem(
                    evidence_type=EvidenceType.CONTROL_FLOW,
                    file=p.file,
                    function=p.name,
                    line=check_line or p.line,
                    relationship="sufficient_funds_guards_authoritative_order_total",
                    condition=check_cond,
                    guarded_operation="payment_order_execution",
                    snippet=p.snippet[:400],
                    confidence=0.90 if payment_executed else 0.75,
                )
                analysis.control_flow_evidence.append(ev)
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = check_line or p.line
                analysis.matched_snippet = p.snippet[:400]

                if payment_executed:
                    analysis.deterministic_verdict = "COMPLIANT"
                    analysis.what = f"Sufficient funds check against authoritative total verified in {p.name}"
                    analysis.why = "Sufficient funds for order total rule satisfied"
                    analysis.how = "Maintain pre-payment funds validation"
                    analysis.confidence = 0.90
                    analysis.score_boost = 0.90
                    return
                else:
                    analysis.deterministic_verdict = "PARTIAL"
                    analysis.missing_controls = ["payment_execution_binding"]
                    analysis.what = f"Funds check detected in {p.name} but payment binding requires verification"
                    analysis.why = "Funds validation present without explicit payment execution link"
                    analysis.how = "Ensure payment execution is guarded by funds check"
                    analysis.confidence = 0.70
                    analysis.score_boost = 0.70

        if not analysis.control_flow_evidence:
            analysis.deterministic_verdict = "INSUFFICIENT_EVIDENCE"
            analysis.missing_controls = ["sufficient_funds_for_authoritative_total_check"]

    # ------------------------------------------------------------------
    # Generic Rule Analysis Fallback
    # ------------------------------------------------------------------
    def _analyze_generic_rule(self, analysis: DeterministicRuleAnalysis, req_text: str, rule_obj: Any):
        req_l = req_text.lower()
        rule_act = getattr(rule_obj, "action", "").lower() if rule_obj else ""
        rule_ctrl = getattr(rule_obj, "control", "").lower() if rule_obj else ""

        for p in self.profiles:
            s_lower = p.snippet.lower() + " " + p.name.lower()
            action_hit = bool(rule_act and rule_act in s_lower) or any(k in s_lower for k in ["process", "execute", "handle", "update"])
            control_hit = bool(rule_ctrl and rule_ctrl in s_lower) or any(k in s_lower for k in ["validate", "check", "verify", "auth", "permission", "limit"])

            if action_hit and control_hit:
                ev = BusinessEvidenceItem(
                    evidence_type=EvidenceType.SPECIALIZED_CONTROL,
                    file=p.file,
                    function=p.name,
                    line=p.line,
                    relationship="action_and_control_matched",
                    snippet=p.snippet[:400],
                    confidence=0.75,
                )
                analysis.specialized_evidence.append(ev)
                analysis.matched_file = p.file
                analysis.matched_function = p.name
                analysis.matched_line = p.line
                analysis.matched_snippet = p.snippet[:400]
                analysis.deterministic_verdict = "PARTIAL"
                analysis.what = f"Action and control matched in {p.name}"
                analysis.why = "Generic rule match"
                analysis.how = "Verify rule controls"
                analysis.confidence = 0.70
                analysis.score_boost = 0.70
                return

        analysis.deterministic_verdict = "INSUFFICIENT_EVIDENCE"
