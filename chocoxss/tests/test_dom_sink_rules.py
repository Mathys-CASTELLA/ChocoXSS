"""
Tests unitaires — modules/static/dom_sink_rules.py

Couvre l'intégrité du catalogue de règles :
  - cohérence des sinks/sources/sanitizers
  - fonctions de recherche par chemin/suffixe
"""

import pytest
from modules.static.dom_sink_rules import (
    SINKS, SOURCES, SANITIZERS,
    find_sink_by_path, find_sink_by_suffix,
    find_source_by_path, find_source_by_suffix,
    find_sanitizer_by_call, find_sanitizer_by_member_path,
    SinkCategory,
)


class TestCatalogIntegrity:

    def test_all_sinks_have_required_fields(self):
        for sink in SINKS:
            assert sink.name, "sink sans nom"
            assert sink.member_path, f"'{sink.name}' sans member_path"
            assert sink.severity in ("CRITICAL", "HIGH", "MEDIUM"), f"'{sink.name}' sévérité invalide"
            assert sink.description, f"'{sink.name}' sans description"
            assert isinstance(sink.category, SinkCategory)

    def test_all_sources_have_required_fields(self):
        for source in SOURCES:
            assert source.name
            assert source.member_path
            assert source.description

    def test_no_duplicate_sink_names(self):
        names = [s.name for s in SINKS]
        assert len(names) == len(set(names))

    def test_no_duplicate_source_names(self):
        names = [s.name for s in SOURCES]
        assert len(names) == len(set(names))

    def test_sanitizers_have_call_name_or_member_path(self):
        for s in SANITIZERS:
            assert s.call_name or s.member_path, f"'{s.name}' n'a ni call_name ni member_path"


class TestFindSinkByPath:

    def test_exact_match(self):
        result = find_sink_by_path(("innerHTML",))
        assert result is not None
        assert result.name == "innerHTML"

    def test_no_match_returns_none(self):
        assert find_sink_by_path(("notASink",)) is None

    def test_document_write_two_part_path(self):
        result = find_sink_by_path(("document", "write"))
        assert result is not None
        assert result.name == "document.write"


class TestFindSinkBySuffix:

    def test_matches_longer_path_ending_in_sink(self):
        # $("#x").html(...) → chemin complet inclut plus que juste "html"
        result = find_sink_by_suffix(("jquery_wrapper", "html"))
        assert result is not None
        assert result.name == "jquery.html"

    def test_matches_exact_short_path(self):
        result = find_sink_by_suffix(("innerHTML",))
        assert result is not None

    def test_no_false_match_on_unrelated_path(self):
        assert find_sink_by_suffix(("foo", "bar")) is None

    def test_empty_path_returns_none(self):
        assert find_sink_by_suffix(()) is None


class TestFindSourceBySuffix:

    def test_location_search(self):
        result = find_source_by_suffix(("location", "search"))
        assert result is not None
        assert result.name == "location.search"

    def test_nested_path_matches_suffix(self):
        result = find_source_by_suffix(("window", "location", "search"))
        assert result is not None

    def test_no_match(self):
        assert find_source_by_suffix(("not", "a", "source")) is None


class TestFindSanitizerByCall:

    def test_encode_uri_component(self):
        result = find_sanitizer_by_call("encodeURIComponent")
        assert result is not None
        assert result.effective_for == (SinkCategory.URL_INJECTION.value,)

    def test_unknown_call_returns_none(self):
        assert find_sanitizer_by_call("notASanitizer") is None


class TestFindSanitizerByMemberPath:

    def test_dompurify_sanitize(self):
        result = find_sanitizer_by_member_path(("DOMPurify", "sanitize"))
        assert result is not None
        assert "html_injection" in result.effective_for

    def test_textcontent_is_effective_sanitizer_for_html(self):
        result = find_sanitizer_by_member_path(("textContent",))
        assert result is not None
