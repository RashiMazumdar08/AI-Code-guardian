"""
UST layer tests — normalization, tagging, data-flow, and every rung of
the degradation ladder (tree-sitter -> python-ast -> regex -> none).
"""
from __future__ import annotations

import pytest

from guardian.ust import USTBuilder, USTNodeType, parsers
from guardian.ust.fallback import python_ast_ust, regex_ust
from guardian.ust.tagging import resolve_algorithm, resolve_mode

builder = USTBuilder()


PY_SOURCE = '''
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa


@app.route("/refund")
def process_refund(amount, user_input):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    query = "SELECT * FROM refunds WHERE id = " + user_input
    cursor.execute(query)
    return refund_service.refund(amount)


class PaymentProcessor:
    def hash_card(self, pan):
        return hashlib.md5(pan).hexdigest()
'''

JAVA_SOURCE = '''
package com.acme.payments;

import javax.crypto.Cipher;
import java.security.MessageDigest;

public class PaymentService {

    @Transactional
    public byte[] encryptPayment(String amount) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        MessageDigest md = MessageDigest.getInstance("MD5");
        return cipher.doFinal(amount.getBytes());
    }

    public void store(String userInput) {
        statement.executeQuery("SELECT * FROM t WHERE x = " + userInput);
    }
}
'''

JS_SOURCE = '''
const crypto = require('crypto');

app.post('/refund', function handleRefund(req, res) {
  const digest = crypto.createHash('sha1');
  db.query("SELECT * FROM refunds WHERE id = " + req.body.id);
  return res.send(digest);
});
'''

TS_SOURCE = '''
import { Injectable } from '@angular/core';

export class RefundService {
  async processRefund(amount: number, requestBody: any): Promise<void> {
    const hash = crypto.createHash('md5');
    await this.repo.query(`SELECT * FROM r WHERE id = ${requestBody.id}`);
  }
}
'''

RUST_SOURCE = '''
use ring::signature::RsaKeyPair;
use sha2::Sha256;

pub fn encrypt_payment(amount: u64, user_input: String) -> Result<(), Error> {
    let key = RsaKeyPair::from_pkcs8(&bytes)?;
    let digest = Sha256::new();
    let query = format!("SELECT * FROM t WHERE id = {}", user_input);
    conn.execute(&query)?;
    Ok(())
}
'''


def _symbols(ust_file, node_type=None):
    return {n.symbol for n in ust_file.nodes
            if node_type is None or n.type is node_type}


def _crypto_algorithms(ust_file):
    out = set()
    for node in ust_file.nodes:
        for tag in node.crypto_tags:
            if tag.startswith("algorithm:"):
                out.add(tag.split(":", 1)[1])
    return out


# ---------------------------------------------------------------------------
# Per-language normalization
# ---------------------------------------------------------------------------
class TestPythonUST:
    def test_functions_classes_and_imports(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        assert f.language == "python"
        assert not f.parse_error
        assert {fn.name for fn in f.functions()} == {"process_refund", "hash_card"}
        assert "hashlib" in f.imports
        assert any(i.endswith("rsa") for i in f.imports)

    def test_call_symbols_and_arguments(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        calls = _symbols(f, USTNodeType.CALL)
        assert "rsa.generate_private_key" in calls
        assert "cursor.execute" in calls

    def test_enclosing_function_is_tracked(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        execute = next(n for n in f.calls() if n.symbol == "cursor.execute")
        assert execute.enclosing_function == "process_refund"
        assert execute.line > 0

    def test_class_scope_on_methods(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        method = next(n for n in f.functions() if n.name == "hash_card")
        assert method.enclosing_class == "PaymentProcessor"
        assert method.symbol == "PaymentProcessor.hash_card"

    def test_decorator_becomes_annotation(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        annotations = [n for n in f.of_type(USTNodeType.ANNOTATION)]
        assert any("app.route" in a.name for a in annotations)


class TestJavaUST:
    def test_method_and_class_normalization(self):
        f = builder.build_source(JAVA_SOURCE, "PaymentService.java")
        assert f.language == "java"
        assert {fn.name for fn in f.functions()} == {"encryptPayment", "store"}
        method = next(fn for fn in f.functions() if fn.name == "encryptPayment")
        assert method.enclosing_class == "PaymentService"

    def test_dotted_call_symbol_is_rebuilt(self):
        """Java splits calls into object+name; the UST must rejoin them."""
        f = builder.build_source(JAVA_SOURCE, "PaymentService.java")
        assert "Cipher.getInstance" in _symbols(f, USTNodeType.CALL)

    def test_string_argument_is_captured_as_literal(self):
        f = builder.build_source(JAVA_SOURCE, "PaymentService.java")
        cipher = next(n for n in f.calls() if n.symbol == "Cipher.getInstance")
        assert "RSA" in cipher.literals

    def test_annotation_detected(self):
        f = builder.build_source(JAVA_SOURCE, "PaymentService.java")
        assert any(a.name == "Transactional" for a in f.of_type(USTNodeType.ANNOTATION))


class TestJavaScriptUST:
    def test_calls_and_functions(self):
        f = builder.build_source(JS_SOURCE, "server.js")
        assert f.language == "javascript"
        assert "crypto.createHash" in _symbols(f, USTNodeType.CALL)
        assert "handleRefund" in {fn.name for fn in f.functions()}

    def test_typescript_is_supported(self):
        f = builder.build_source(TS_SOURCE, "refund.service.ts")
        assert f.language == "typescript"
        assert "processRefund" in {fn.name for fn in f.functions()}
        assert "@angular/core" in f.imports

    def test_tsx_uses_typescript_normalizer(self):
        f = builder.build_source("export const A = () => <div/>;", "a.tsx")
        assert f.language == "typescript"
        assert not f.parse_error


class TestRustUST:
    def test_functions_and_calls(self):
        f = builder.build_source(RUST_SOURCE, "payments.rs")
        assert f.language == "rust"
        assert "encrypt_payment" in {fn.name for fn in f.functions()}
        assert "RsaKeyPair.from_pkcs8" in _symbols(f, USTNodeType.CALL)

    def test_use_declaration_becomes_import(self):
        f = builder.build_source(RUST_SOURCE, "payments.rs")
        assert any("RsaKeyPair" in i for i in f.imports)

    def test_macro_invocation_is_a_call(self):
        f = builder.build_source(RUST_SOURCE, "payments.rs")
        assert any(n.symbol.startswith("format") for n in f.calls())


# ---------------------------------------------------------------------------
# Cross-language guarantees
# ---------------------------------------------------------------------------
class TestCrossLanguageNormalization:
    @pytest.mark.parametrize("label,source,expected", [
        ("payments.py", PY_SOURCE, "python"),
        ("PaymentService.java", JAVA_SOURCE, "java"),
        ("server.js", JS_SOURCE, "javascript"),
        ("refund.service.ts", TS_SOURCE, "typescript"),
        ("payments.rs", RUST_SOURCE, "rust"),
    ])
    def test_every_language_produces_the_same_node_vocabulary(self, label, source, expected):
        f = builder.build_source(source, label)
        assert f.language == expected
        assert f.functions(), f"no functions normalized for {label}"
        assert f.calls(), f"no calls normalized for {label}"
        for node in f.nodes:
            assert isinstance(node.type, USTNodeType)
            assert node.file == label
            assert node.language == expected
            assert node.node_id

    def test_node_ids_are_stable_across_builds(self):
        a = builder.build_source(PY_SOURCE, "payments.py")
        b = builder.build_source(PY_SOURCE, "payments.py")
        assert [n.node_id for n in a.nodes] == [n.node_id for n in b.nodes]

    def test_function_at_line_lookup(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        execute = next(n for n in f.calls() if n.symbol == "cursor.execute")
        enclosing = f.function_at(execute.line)
        assert enclosing is not None and enclosing.name == "process_refund"


# ---------------------------------------------------------------------------
# Semantic tagging
# ---------------------------------------------------------------------------
class TestCryptoTagging:
    def test_java_cipher_literal_resolves_algorithm(self):
        f = builder.build_source(JAVA_SOURCE, "PaymentService.java")
        assert "RSA" in _crypto_algorithms(f)
        assert "MD5" in _crypto_algorithms(f)

    def test_python_hashlib_and_rsa(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        algorithms = _crypto_algorithms(f)
        assert "RSA" in algorithms
        assert "MD5" in algorithms

    def test_javascript_create_hash(self):
        f = builder.build_source(JS_SOURCE, "server.js")
        assert "SHA-1" in _crypto_algorithms(f)

    def test_rust_crypto(self):
        f = builder.build_source(RUST_SOURCE, "payments.rs")
        algorithms = _crypto_algorithms(f)
        assert "RSA" in algorithms
        assert "SHA-256" in algorithms

    def test_crypto_operation_is_recorded(self):
        f = builder.build_source(JAVA_SOURCE, "PaymentService.java")
        cipher = next(n for n in f.calls() if n.symbol == "Cipher.getInstance")
        assert "operation:encryption" in cipher.crypto_tags

    def test_comment_mentioning_rsa_is_not_a_crypto_usage(self):
        """The whole point of UST over keyword grep: prose is not code."""
        f = builder.build_source("# we should migrate RSA to ML-KEM one day\nx = 1\n",
                                 "notes.py")
        assert not _crypto_algorithms(f)

    def test_unresolved_algorithm_is_flagged_not_guessed(self):
        f = builder.build_source(
            'public class A { void m(String algo) { Cipher.getInstance(algo); } }',
            "A.java")
        cipher = next(n for n in f.calls() if n.symbol == "Cipher.getInstance")
        assert "algorithm:unknown" in cipher.crypto_tags
        assert "algorithm_unresolved" in cipher.crypto_tags

    @pytest.mark.parametrize("text,expected", [
        ("AES/ECB/PKCS5Padding", "AES"),
        ("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSA"),
        ("ML-KEM-768", "ML-KEM"),
        ("Dilithium3", "ML-DSA"),
        ("SHA3-256", "SHA-3"),
        ("secp256r1", "ECC"),
        ("nothing here", ""),
    ])
    def test_algorithm_resolution(self, text, expected):
        assert resolve_algorithm(text) == expected

    def test_mode_resolution(self):
        assert resolve_mode("AES/ECB/PKCS5Padding") == "ECB"
        assert resolve_mode("AES/GCM/NoPadding") == "GCM"


class TestSecurityAndBusinessTagging:
    def test_sql_sink_tagged(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        execute = next(n for n in f.calls() if n.symbol == "cursor.execute")
        assert "sink:sql" in execute.security_tags

    def test_api_endpoint_tagged(self):
        f = builder.build_source(JS_SOURCE, "server.js")
        assert any("api_endpoint" in n.business_tags for n in f.nodes)

    def test_business_domain_vocabulary(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        assert any("refund" in n.business_tags for n in f.nodes)

    def test_authorization_check_tagged(self):
        f = builder.build_source(
            "def approve(x):\n    if not current_user.has_permission('approve'):\n"
            "        raise Error()\n", "a.py")
        assert any("authorization_check" in n.business_tags for n in f.nodes)


class TestDataFlow:
    def test_python_taint_reaches_sql_sink(self):
        f = builder.build_source(PY_SOURCE, "payments.py")
        execute = next(n for n in f.calls() if n.symbol == "cursor.execute")
        assert execute.data_flow.get("tainted") is True
        assert execute.data_flow.get("sink") == "sql"

    def test_typescript_template_literal_taint(self):
        f = builder.build_source(TS_SOURCE, "refund.service.ts")
        query = next(n for n in f.calls() if n.symbol.endswith("repo.query"))
        assert query.data_flow.get("tainted") is True

    def test_rust_format_macro_taint(self):
        f = builder.build_source(RUST_SOURCE, "payments.rs")
        execute = next(n for n in f.calls() if n.symbol == "conn.execute")
        assert execute.data_flow.get("tainted") is True

    def test_safe_parameterised_query_is_not_tainted(self):
        source = (
            "def get(user_input):\n"
            "    cursor.execute('SELECT * FROM t WHERE id = %s', (user_input,))\n")
        f = builder.build_source(source, "safe.py")
        execute = next(n for n in f.calls() if n.symbol == "cursor.execute")
        assert not execute.data_flow.get("tainted")

    def test_sanitised_value_clears_taint(self):
        source = (
            "def get(user_input):\n"
            "    safe = escape(user_input)\n"
            "    cursor.execute('SELECT ' + safe)\n")
        f = builder.build_source(source, "san.py")
        execute = next(n for n in f.calls() if n.symbol == "cursor.execute")
        assert not execute.data_flow.get("tainted")


# ---------------------------------------------------------------------------
# Robustness / degradation ladder
# ---------------------------------------------------------------------------
class TestRobustness:
    def test_unsupported_language_returns_empty_ust_not_error(self):
        f = builder.build_source("SELECT 1;", "query.sql")
        assert f.parser == "none"
        assert f.parse_error == "unsupported language"
        assert f.nodes == []

    def test_malformed_python_still_yields_partial_ust(self):
        """Tree-sitter is error-tolerant; a broken file must not kill a scan."""
        f = builder.build_source(
            "def broken(:\n    cursor.execute('x')\n", "broken.py")
        assert f.parser in ("tree-sitter", "python-ast", "regex")
        assert isinstance(f.nodes, list)

    def test_empty_file(self):
        f = builder.build_source("", "empty.py")
        assert f.nodes == []
        assert not f.parse_error

    def test_binary_garbage_does_not_raise(self):
        f = builder.build_source("\x00\x01\x02\xff garbage", "weird.py")
        assert isinstance(f.nodes, list)

    def test_python_ast_fallback_matches_tree_sitter_shape(self):
        fallback = python_ast_ust(PY_SOURCE, "payments.py")
        assert fallback is not None
        assert fallback.parser == "python-ast"
        assert {fn.name for fn in fallback.functions()} == {"process_refund", "hash_card"}
        assert "cursor.execute" in {n.symbol for n in fallback.calls()}

    def test_python_ast_fallback_reports_syntax_error(self):
        fallback = python_ast_ust("def broken(:\n", "broken.py")
        assert fallback is not None
        assert fallback.parse_error

    def test_regex_fallback_finds_functions_and_calls(self):
        f = regex_ust(JAVA_SOURCE, "PaymentService.java", "java")
        assert f.parser == "regex"
        assert any(fn.name == "encryptPayment" for fn in f.functions())
        assert any(n.symbol.endswith("getInstance") for n in f.calls())

    def test_regex_fallback_is_taggable(self):
        from guardian.ust.tagging import tag_file
        f = tag_file(regex_ust(JAVA_SOURCE, "PaymentService.java", "java"))
        algorithms = _crypto_algorithms(f)
        assert "RSA" in algorithms


class TestRepositoryUST:
    def test_build_repository_mixed_languages(self, tmp_path):
        (tmp_path / "a.py").write_text(PY_SOURCE)
        (tmp_path / "B.java").write_text(JAVA_SOURCE)
        (tmp_path / "c.js").write_text(JS_SOURCE)
        (tmp_path / "d.rs").write_text(RUST_SOURCE)
        (tmp_path / "readme.md").write_text("# not source")

        files = sorted(tmp_path.iterdir())
        ust = builder.build_repository(tmp_path, files)

        assert len(ust) == 4          # markdown has no grammar -> skipped
        assert set(ust.by_language()) == {"python", "java", "javascript", "rust"}
        assert ust.summary()["nodes"] > 0
        assert ust.failed_files() == []

    def test_one_unreadable_file_does_not_break_the_repository_build(self, tmp_path):
        good = tmp_path / "good.py"
        good.write_text("def f():\n    pass\n")
        missing = tmp_path / "missing.py"     # never created
        ust = builder.build_repository(tmp_path, [good, missing])
        assert len(ust) == 2
        assert any(f.parse_error for f in ust)
        assert any(not f.parse_error for f in ust)


class TestParserRegistry:
    def test_extension_mapping(self):
        assert parsers.language_for_path("a/b/c.py") == "python"
        assert parsers.language_for_path("X.java") == "java"
        assert parsers.language_for_path("x.tsx") == "tsx"
        assert parsers.language_for_path("x.unknown") == ""

    def test_tsx_normalizes_to_typescript(self):
        assert parsers.normalizer_language("tsx") == "typescript"

    def test_availability_never_raises(self):
        avail = parsers.availability()
        assert set(avail) == set(parsers.supported_languages())
        assert all(isinstance(v, bool) for v in avail.values())
