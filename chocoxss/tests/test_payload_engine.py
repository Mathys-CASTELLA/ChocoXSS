"""
Tests unitaires — modules/active/payload_engine.py

Couvre la génération de payloads et de marqueurs canaris :
  - unicité des marqueurs générés
  - instanciation correcte des templates avec le marqueur
  - couverture des 4 catégories de contexte
"""

import pytest
from modules.active.payload_engine import (
    generate_marker, build_payloads, PayloadContext, PAYLOAD_TEMPLATES,
)


class TestGenerateMarker:

    def test_marker_has_expected_prefix(self):
        marker = generate_marker()
        assert marker.startswith("cxss")

    def test_markers_are_unique_across_calls(self):
        markers = {generate_marker() for _ in range(100)}
        assert len(markers) == 100

    def test_marker_is_reasonably_short(self):
        marker = generate_marker()
        assert len(marker) < 20  # doit tenir dans un payload sans l'alourdir


class TestBuildPayloads:

    def test_marker_embedded_in_every_payload(self):
        marker = "cxsstest123"
        payloads = build_payloads(marker)
        assert len(payloads) > 0
        for payload, context, description in payloads:
            assert marker in payload

    def test_all_context_categories_represented(self):
        payloads = build_payloads("cxsstest123")
        contexts = {ctx for _, ctx, _ in payloads}
        assert contexts == {
            PayloadContext.HTML_BODY,
            PayloadContext.HTML_ATTRIBUTE,
            PayloadContext.JS_STRING,
            PayloadContext.URL_CONTEXT,
        }

    def test_each_payload_has_description(self):
        payloads = build_payloads("cxsstest123")
        for _, _, description in payloads:
            assert description, "chaque payload doit avoir une description explicative"

    def test_different_markers_produce_different_payloads(self):
        p1 = build_payloads("markerAAA")
        p2 = build_payloads("markerBBB")
        assert p1[0][0] != p2[0][0]

    def test_payload_count_matches_template_count(self):
        payloads = build_payloads("cxsstest123")
        assert len(payloads) == len(PAYLOAD_TEMPLATES)


class TestSpecificPayloadContent:

    def test_html_body_contains_script_tag_variant(self):
        payloads = build_payloads("cxssmarker")
        html_body_payloads = [p for p, ctx, _ in payloads if ctx == PayloadContext.HTML_BODY]
        assert any("<script>" in p for p in html_body_payloads)

    def test_html_attribute_contains_quote_breakout(self):
        payloads = build_payloads("cxssmarker")
        attr_payloads = [p for p, ctx, _ in payloads if ctx == PayloadContext.HTML_ATTRIBUTE]
        assert any('"' in p for p in attr_payloads)
        assert any("'" in p for p in attr_payloads)

    def test_url_context_contains_javascript_scheme(self):
        payloads = build_payloads("cxssmarker")
        url_payloads = [p for p, ctx, _ in payloads if ctx == PayloadContext.URL_CONTEXT]
        assert any(p.startswith("javascript:") for p in url_payloads)
