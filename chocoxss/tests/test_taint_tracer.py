"""
Tests unitaires — modules/static/taint_tracer.py

Couvre le moteur de traçage de flux de données (le cœur technique de ChocoXSS) :
  - propagation à travers variables, concaténations, template literals
  - blocage par sanitizer efficace
  - piège du sanitizer inefficace dans le mauvais contexte (encodeURIComponent → HTML)
  - fonctions custom inconnues → UNKNOWN plutôt que faux négatif silencieux
  - protection anti-boucle infinie
  - cas réels combinant plusieurs mécanismes
"""

import pytest
from modules.static.js_ast_analyzer import analyze_js
from modules.static.taint_tracer import (
    trace_findings, TaintStatus, _resolve_taint, _SymbolTable,
)


def _trace(code: str):
    """Helper : parse le code, extrait les sinks, les trace, retourne la liste de ConfirmedFinding."""
    result = analyze_js(code)
    sinks = [f for f in result.findings if f.kind == "sink"]
    return trace_findings(sinks, result.ast)


class TestDirectSourceToSink:

    def test_source_directly_in_sink_is_confirmed(self):
        confirmed = _trace('document.write(location.hash);')
        assert len(confirmed) == 1
        assert confirmed[0].confidence == "CONFIRMED"
        assert confirmed[0].taint.source_name == "location.hash"

    def test_clean_literal_is_none(self):
        confirmed = _trace('el.innerHTML = "static text";')
        assert confirmed[0].confidence == "NONE"
        assert confirmed[0].taint.status == TaintStatus.CLEAN


class TestVariablePropagation:

    def test_simple_variable_chain(self):
        code = '''
            var a = location.search;
            el.innerHTML = a;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"
        assert confirmed[0].taint.source_name == "location.search"

    def test_multi_hop_variable_chain(self):
        code = '''
            var a = location.search;
            var b = a;
            var c = b;
            el.innerHTML = c;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_reassignment_uses_latest_value(self):
        code = '''
            var a = "safe";
            a = location.hash;
            el.innerHTML = a;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_unresolved_variable_is_unknown(self):
        # 'x' n'est jamais défini dans ce snippet (paramètre de fonction externe par ex.)
        code = 'function f(x) { el.innerHTML = x; }'
        confirmed = _trace(code)
        assert confirmed[0].confidence == "LIKELY"
        assert confirmed[0].taint.status == TaintStatus.UNKNOWN


class TestConcatenationAndTemplates:

    def test_string_concatenation_left_tainted(self):
        code = '''
            var a = location.search;
            el.innerHTML = a + "_suffix";
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_string_concatenation_right_tainted(self):
        code = '''
            var a = location.search;
            el.innerHTML = "prefix_" + a;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_concatenation_both_clean_is_none(self):
        code = 'el.innerHTML = "a" + "b";'
        confirmed = _trace(code)
        assert confirmed[0].confidence == "NONE"

    def test_template_literal_with_tainted_expression(self):
        code = '''
            var name = location.hash;
            el.innerHTML = `Hello ${name}`;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_template_literal_all_clean(self):
        code = 'el.innerHTML = `Hello world`;'
        confirmed = _trace(code)
        assert confirmed[0].confidence == "NONE"


class TestConditionalExpression:

    def test_ternary_tainted_in_consequent(self):
        code = '''
            var a = location.search;
            el.innerHTML = cond ? a : "safe";
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_ternary_tainted_in_alternate(self):
        code = '''
            var a = location.search;
            el.innerHTML = cond ? "safe" : a;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_ternary_both_clean(self):
        code = 'el.innerHTML = cond ? "a" : "b";'
        confirmed = _trace(code)
        assert confirmed[0].confidence == "NONE"


class TestPassthroughFunctions:

    def test_decode_uri_component_propagates_taint(self):
        code = '''
            var a = location.search;
            var b = decodeURIComponent(a);
            el.innerHTML = b;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_substring_propagates_taint(self):
        code = '''
            var a = location.hash;
            var b = a.substring(1);
            el.innerHTML = b;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"

    def test_chained_passthrough_functions(self):
        code = '''
            var a = location.search;
            var b = decodeURIComponent(a);
            var c = b.trim();
            var d = "prefix_" + c;
            el.innerHTML = d;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"


class TestSanitizerBlocking:

    def test_dompurify_sanitize_blocks_taint_for_html_sink(self):
        code = '''
            var a = location.search;
            var clean = DOMPurify.sanitize(a);
            el.innerHTML = clean;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "SANITIZED"
        assert confirmed[0].taint.sanitizer_name == "DOMPurify.sanitize"
        assert confirmed[0].taint.sanitizer_effective is True

    def test_textcontent_sanitizer_via_assignment(self):
        # textContent est listé comme sanitizer mais c'est une assignation,
        # pas un appel — donc pas concerné par ce test de call-sanitizer.
        # On vérifie juste qu'il n'est jamais lui-même flaggé comme sink.
        code = 'el.textContent = location.search;'
        result = analyze_js(code)
        sinks = [f for f in result.findings if f.kind == "sink"]
        assert len(sinks) == 0

    def test_sanitizer_on_clean_value_stays_clean(self):
        code = '''
            var a = "static";
            var clean = DOMPurify.sanitize(a);
            el.innerHTML = clean;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "NONE"


class TestIneffectiveSanitizerTrap:
    """
    Le cas le plus important à verrouiller : un sanitizer existe et est
    appelé, mais il est inadapté au contexte du sink (encodeURIComponent
    protège un contexte URL, pas un contexte HTML). ChocoXSS doit continuer
    à remonter CONFIRMED, pas se faire tromper par la présence du sanitizer.
    """

    def test_encode_uri_component_does_not_block_html_sink(self):
        code = '''
            var a = location.search;
            var encoded = encodeURIComponent(a);
            el.innerHTML = encoded;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED", \
            "encodeURIComponent ne doit PAS neutraliser un sink HTML"
        assert confirmed[0].taint.sanitizer_name == "encodeURIComponent"
        assert confirmed[0].taint.sanitizer_effective is False

    def test_encode_uri_component_is_noted_even_if_ineffective(self):
        code = '''
            var a = location.hash;
            var encoded = encodeURIComponent(a);
            document.write(encoded);
        '''
        confirmed = _trace(code)
        # Le rapport doit quand même mentionner qu'un sanitizer a été tenté,
        # même s'il ne suffit pas, pour que l'utilisateur comprenne le piège.
        assert confirmed[0].taint.sanitizer_name is not None
        assert confirmed[0].taint.sanitizer_effective is False


class TestUnknownCustomFunctions:

    def test_custom_function_with_tainted_arg_is_likely_not_clean(self):
        code = '''
            var a = location.search;
            var b = myCustomSanitizer(a);
            el.innerHTML = b;
        '''
        confirmed = _trace(code)
        # On ne connaît pas le corps de myCustomSanitizer : ne jamais
        # conclure silencieusement que c'est propre.
        assert confirmed[0].confidence == "LIKELY"
        assert confirmed[0].taint.status == TaintStatus.UNKNOWN

    def test_custom_function_with_clean_arg_stays_clean(self):
        code = '''
            var a = "static";
            var b = myCustomFunction(a);
            el.innerHTML = b;
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "NONE"


class TestNewExpressionAndMethodCalls:

    def test_urlsearchparams_pattern(self):
        code = '''
            var params = new URLSearchParams(location.search);
            var name = params.get("name");
            document.write(name);
        '''
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"
        assert confirmed[0].taint.source_name == "location.search"

    def test_new_expression_with_clean_args(self):
        code = '''
            var params = new URLSearchParams("static=value");
            var name = params.get("name");
            document.write(name);
        '''
        confirmed = _trace(code)
        # 'name' provient d'un objet non taintée — mais params.get() sur un
        # objet inconnu remonte UNKNOWN par prudence (7c dans le tracer),
        # pas un faux CLEAN.
        assert confirmed[0].confidence in ("NONE", "LIKELY")


class TestMultipleSinksIndependentTracing:

    def test_two_sinks_different_confidence_in_same_snippet(self):
        code = '''
            var name = location.search;
            document.getElementById("a").innerHTML = name;

            var safe = DOMPurify.sanitize(name);
            document.getElementById("b").innerHTML = safe;
        '''
        confirmed = _trace(code)
        assert len(confirmed) == 2
        confidences = {c.confidence for c in confirmed}
        assert confidences == {"CONFIRMED", "SANITIZED"}


class TestAntiInfiniteLoop:

    def test_self_referential_assignment_does_not_hang(self):
        # Cas pathologique : a = a (ne devrait jamais arriver en pratique
        # mais ne doit pas boucler indéfiniment)
        code = '''
            var a = a;
            el.innerHTML = a;
        '''
        # Le test réussit simplement s'il se termine (timeout implicite pytest)
        confirmed = _trace(code)
        assert len(confirmed) == 1  # ne doit pas planter ni boucler

    def test_deep_chain_within_max_depth(self):
        # Chaîne de 20 variables — doit rester sous MAX_DEPTH (25)
        lines = ["var v0 = location.search;"]
        for i in range(1, 20):
            lines.append(f"var v{i} = v{i-1};")
        lines.append("el.innerHTML = v19;")
        code = "\n".join(lines)
        confirmed = _trace(code)
        assert confirmed[0].confidence == "CONFIRMED"


class TestSymbolTable:

    def test_captures_variable_declaration(self):
        import esprima
        tree = esprima.parseScript("var x = 42;")
        table = _SymbolTable()
        table.build_from_ast(tree)
        node = table.get("x")
        assert node is not None
        assert node.type == "Literal"
        assert node.value == 42

    def test_captures_reassignment_overwriting_declaration(self):
        import esprima
        tree = esprima.parseScript("var x = 1; x = 2;")
        table = _SymbolTable()
        table.build_from_ast(tree)
        node = table.get("x")
        assert node.value == 2  # la dernière assignation gagne

    def test_unknown_variable_returns_none(self):
        table = _SymbolTable()
        assert table.get("neverDeclared") is None
