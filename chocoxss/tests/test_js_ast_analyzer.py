"""
Tests unitaires — modules/static/js_ast_analyzer.py

Couvre la détection brute de sinks/sources/sanitizers dans l'AST JS :
  - détection par assignation (el.innerHTML = x)
  - détection par appel (eval(x), $(y).html(x))
  - filtrage des faux positifs (setTimeout avec callback safe)
  - gestion des erreurs de parsing
"""

import pytest
from modules.static.js_ast_analyzer import analyze_js, _member_path
import esprima


def _findings_by_kind(result, kind):
    return [f for f in result.findings if f.kind == kind]


class TestMemberPath:

    def test_simple_two_level_path(self):
        tree = esprima.parseScript("location.search;")
        expr = tree.body[0].expression
        assert _member_path(expr) == ("location", "search")

    def test_three_level_path(self):
        tree = esprima.parseScript("document.location.href;")
        expr = tree.body[0].expression
        assert _member_path(expr) == ("document", "location", "href")

    def test_single_identifier_not_a_member_expression(self):
        tree = esprima.parseScript("x;")
        expr = tree.body[0].expression
        assert _member_path(expr) == ("x",)

    def test_computed_member_marked(self):
        tree = esprima.parseScript("obj[key];")
        expr = tree.body[0].expression
        path = _member_path(expr)
        assert "<computed>" in path


class TestSinkDetectionByAssignment:

    def test_innerhtml_assignment_detected(self):
        result = analyze_js('el.innerHTML = x;')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 1
        assert sinks[0].name == "innerHTML"
        assert sinks[0].severity == "CRITICAL"

    def test_outerhtml_assignment_detected(self):
        result = analyze_js('el.outerHTML = x;')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 1
        assert sinks[0].name == "outerHTML"

    def test_textcontent_assignment_not_a_sink(self):
        # textContent est un sanitizer, pas un sink
        result = analyze_js('el.textContent = x;')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 0

    def test_unrelated_assignment_not_detected(self):
        result = analyze_js('el.className = x;')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 0

    def test_assignment_captures_tainted_value_node(self):
        result = analyze_js('el.innerHTML = someVar;')
        sinks = _findings_by_kind(result, "sink")
        assert sinks[0].tainted_value_node is not None
        assert sinks[0].tainted_value_node.type == "Identifier"
        assert sinks[0].tainted_value_node.name == "someVar"


class TestSinkDetectionByCall:

    def test_eval_detected(self):
        result = analyze_js('eval(x);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 1
        assert sinks[0].name == "eval"

    def test_document_write_detected(self):
        result = analyze_js('document.write(x);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 1
        assert sinks[0].name == "document.write"

    def test_jquery_html_detected(self):
        result = analyze_js('$("#x").html(data);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 1
        assert sinks[0].name == "jquery.html"

    def test_settimeout_with_string_is_sink(self):
        result = analyze_js('setTimeout("alert(1)", 100);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 1
        assert sinks[0].name == "setTimeout"

    def test_settimeout_with_function_is_not_sink(self):
        # Le cas sûr classique : callback function, pas de chaîne à évaluer
        result = analyze_js('setTimeout(function() { doStuff(); }, 100);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 0

    def test_settimeout_with_arrow_function_not_sink(self):
        result = analyze_js('setTimeout(() => doStuff(), 100);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 0

    def test_eval_without_arguments_not_flagged(self):
        # eval() sans argument ne peut rien exécuter de dangereux
        result = analyze_js('eval();')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 0


class TestSourceDetection:

    def test_location_search_detected(self):
        result = analyze_js('var x = location.search;')
        sources = _findings_by_kind(result, "source")
        assert any(s.name == "location.search" for s in sources)

    def test_document_cookie_detected(self):
        result = analyze_js('var x = document.cookie;')
        sources = _findings_by_kind(result, "source")
        assert any(s.name == "document.cookie" for s in sources)

    def test_localstorage_getitem_detected(self):
        result = analyze_js('var x = localStorage.getItem("key");')
        sources = _findings_by_kind(result, "source")
        assert any(s.name == "localStorage.getItem" for s in sources)

    def test_no_source_in_clean_code(self):
        result = analyze_js('var x = "static string"; var y = 42;')
        sources = _findings_by_kind(result, "source")
        assert len(sources) == 0


class TestSanitizerDetection:

    def test_dompurify_sanitize_detected(self):
        result = analyze_js('var clean = DOMPurify.sanitize(dirty);')
        sanitizers = _findings_by_kind(result, "sanitizer")
        assert len(sanitizers) == 1
        assert sanitizers[0].name == "DOMPurify.sanitize"

    def test_encode_uri_component_detected(self):
        result = analyze_js('var e = encodeURIComponent(x);')
        sanitizers = _findings_by_kind(result, "sanitizer")
        assert len(sanitizers) == 1
        assert sanitizers[0].name == "encodeURIComponent"

    def test_sanitizer_call_not_also_flagged_as_sink(self):
        # DOMPurify.sanitize ne doit pas apparaître deux fois (sink + sanitizer)
        result = analyze_js('var clean = DOMPurify.sanitize(dirty);')
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 0


class TestParsingRobustness:

    def test_invalid_js_returns_parse_error_not_exception(self):
        result = analyze_js('this is {{{ not valid javascript ][')
        assert len(result.parse_errors) > 0
        assert result.findings == []

    def test_empty_code_no_crash(self):
        result = analyze_js('')
        assert result.findings == []
        assert result.parse_errors == []

    def test_valid_but_unrelated_code_no_findings(self):
        result = analyze_js('function add(a, b) { return a + b; }')
        assert result.findings == []

    def test_line_numbers_are_correct(self):
        code = "var a = 1;\nvar b = 2;\nel.innerHTML = a;"
        result = analyze_js(code)
        sinks = _findings_by_kind(result, "sink")
        assert sinks[0].line == 3


class TestMultipleFindingsInSameSnippet:

    def test_multiple_sinks_all_detected(self):
        code = '''
            eval(a);
            document.write(b);
            el.innerHTML = c;
        '''
        result = analyze_js(code)
        sinks = _findings_by_kind(result, "sink")
        assert len(sinks) == 3
        names = {s.name for s in sinks}
        assert names == {"eval", "document.write", "innerHTML"}

    def test_mixed_sink_source_sanitizer(self):
        code = '''
            var a = location.search;
            var clean = DOMPurify.sanitize(a);
            el.innerHTML = clean;
        '''
        result = analyze_js(code)
        assert len(_findings_by_kind(result, "source")) == 1
        assert len(_findings_by_kind(result, "sanitizer")) == 1
        assert len(_findings_by_kind(result, "sink")) == 1
