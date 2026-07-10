"""
Tests unitaires — modules/active/bypass_payloads.py

Couvre la génération de variantes de contournement de filtre.
"""

import pytest
from modules.active.bypass_payloads import (
    build_bypass_payloads, BypassTechnique, BYPASS_TEMPLATES,
)
from modules.active.payload_engine import PayloadContext


class TestBuildBypassPayloads:

    def test_marker_embedded_in_every_variant(self):
        marker = "cxsstest123"
        payloads = build_bypass_payloads(marker)
        assert len(payloads) > 0
        for payload, technique, context, description in payloads:
            assert marker in payload

    def test_all_techniques_represented(self):
        payloads = build_bypass_payloads("cxsstest123")
        techniques = {t for _, t, _, _ in payloads}
        assert BypassTechnique.MIXED_CASE in techniques
        assert BypassTechnique.NESTED_TAG in techniques
        assert BypassTechnique.HTML_ENTITY in techniques

    def test_each_variant_has_description(self):
        payloads = build_bypass_payloads("cxsstest123")
        for _, _, _, description in payloads:
            assert description, "chaque variante doit expliquer le filtre naïf ciblé"

    def test_filter_by_context_html_body_only(self):
        payloads = build_bypass_payloads("cxsstest123", context=PayloadContext.HTML_BODY)
        assert len(payloads) > 0
        assert all(ctx == PayloadContext.HTML_BODY for _, _, ctx, _ in payloads)

    def test_filter_by_context_url_only(self):
        payloads = build_bypass_payloads("cxsstest123", context=PayloadContext.URL_CONTEXT)
        assert len(payloads) > 0
        assert all(ctx == PayloadContext.URL_CONTEXT for _, _, ctx, _ in payloads)

    def test_filter_by_unrepresented_context_returns_empty(self):
        # Aucune variante ne cible spécifiquement HTML_ATTRIBUTE dans le catalogue actuel
        payloads = build_bypass_payloads("cxsstest123", context=PayloadContext.HTML_ATTRIBUTE)
        assert payloads == []

    def test_different_markers_produce_different_payloads(self):
        p1 = build_bypass_payloads("markerAAA")
        p2 = build_bypass_payloads("markerBBB")
        assert p1[0][0] != p2[0][0]

    def test_payload_count_matches_template_count_without_filter(self):
        payloads = build_bypass_payloads("cxsstest123")
        assert len(payloads) == len(BYPASS_TEMPLATES)


class TestSpecificBypassContent:

    def test_nested_tag_reconstructs_script_tag_after_naive_strip(self):
        """
        Verrouille le principe même de la technique : après suppression
        de la sous-chaîne '<script>' par un filtre naïf non récursif,
        le texte restant doit former une vraie balise <script> exécutable.
        """
        payloads = build_bypass_payloads("MARKER123", context=PayloadContext.HTML_BODY)
        nested = [p for p, t, _, _ in payloads if t == BypassTechnique.NESTED_TAG]
        assert len(nested) > 0

        for payload in nested:
            simulated_filtered = payload.replace("<script>", "").replace("</script>", "")
            assert "<script>" in simulated_filtered or "<img" in simulated_filtered

    def test_mixed_case_uses_non_lowercase_tag(self):
        payloads = build_bypass_payloads("MARKER123", context=PayloadContext.HTML_BODY)
        mixed = [p for p, t, _, _ in payloads if t == BypassTechnique.MIXED_CASE]
        assert len(mixed) > 0
        assert any(p != p.lower() for p in mixed)

    def test_html_entity_uses_numeric_entities_not_literal_brackets(self):
        payloads = build_bypass_payloads("MARKER123", context=PayloadContext.HTML_BODY)
        entity = [p for p, t, _, _ in payloads if t == BypassTechnique.HTML_ENTITY]
        assert len(entity) > 0
        for payload in entity:
            assert "&#60;" in payload or "&#62;" in payload

    def test_double_url_encoding_uses_percent_25_prefix(self):
        payloads = build_bypass_payloads("MARKER123", context=PayloadContext.HTML_BODY)
        double_enc = [p for p, t, _, _ in payloads if t == BypassTechnique.DOUBLE_URL_ENC]
        assert len(double_enc) > 0
        assert all("%253C" in p for p in double_enc)
