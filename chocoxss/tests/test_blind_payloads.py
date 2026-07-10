"""
Tests unitaires — modules/active/blind_payloads.py

Couvre la soumission de payloads aveugles :
  - génération de payloads de callback avec marqueur unique par point
  - ne classe AUCUN résultat (pas de vérification locale possible par nature)
  - table de corrélation marqueur ↔ point d'injection
  - gestion d'erreur réseau sans bloquer les autres points
"""

import pytest
from unittest.mock import patch, MagicMock

from modules.active.crawler import InjectionPoint
from modules.active.blind_payloads import (
    build_blind_payloads, submit_blind_payloads, BlindScanSummary, BLIND_TEMPLATES,
)


def _make_point(name="message"):
    return InjectionPoint(url="http://x.test/contact", method="POST", param_name=name,
                          param_kind="form_field", other_params={})


class TestBuildBlindPayloads:

    def test_marker_and_callback_embedded_in_every_payload(self):
        payloads = build_blind_payloads("http://collector.test", "cxsstest123")
        assert len(payloads) == len(BLIND_TEMPLATES)
        for payload, technique, description in payloads:
            assert "cxsstest123" in payload
            assert "collector.test" in payload

    def test_callback_trailing_slash_stripped(self):
        payloads = build_blind_payloads("http://collector.test/", "cxsstest")
        # Pas de double slash dans l'URL générée
        assert all("test//?" not in p for p, _, _ in payloads)

    def test_all_techniques_represented(self):
        payloads = build_blind_payloads("http://collector.test", "cxsstest")
        techniques = {t for _, t, _ in payloads}
        assert "script_src" in techniques
        assert "img_beacon" in techniques

    def test_each_payload_has_description(self):
        payloads = build_blind_payloads("http://collector.test", "cxsstest")
        for _, _, description in payloads:
            assert description


class TestSubmitBlindPayloads:

    def test_submits_all_payloads_across_all_points(self):
        points = [_make_point("message"), _make_point("author")]
        mock_session = MagicMock()

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            summary = submit_blind_payloads(points, "http://collector.test", session=mock_session)

        # 5 templates × 2 points = 10 soumissions
        assert len(summary.submissions) == 10

    def test_each_injection_point_gets_own_unique_marker(self):
        points = [_make_point("a"), _make_point("b")]
        mock_session = MagicMock()

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            summary = submit_blind_payloads(points, "http://collector.test", session=mock_session)

        markers_by_param = {}
        for s in summary.submissions:
            markers_by_param.setdefault(s.injection_point.param_name, set()).add(s.marker)

        # Un seul marker par point (partagé entre les 5 techniques de CE point)
        assert all(len(markers) == 1 for markers in markers_by_param.values())
        # Mais des markers DIFFÉRENTS entre points différents (corrélation précise)
        assert markers_by_param["a"] != markers_by_param["b"]

    def test_no_confidence_classification_performed(self):
        """
        Vérrouille le principe structurel : submit_blind_payloads ne doit
        JAMAIS tenter de classer un résultat en RAW/ENCODED/PARTIAL — par
        nature, aucune réponse locale ne peut confirmer un XSS aveugle.
        """
        points = [_make_point()]
        mock_session = MagicMock()

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = ("réponse quelconque", 200, None)
            summary = submit_blind_payloads(points, "http://collector.test", session=mock_session)

        for s in summary.submissions:
            assert not hasattr(s, "confidence")

    def test_network_error_recorded_without_stopping_other_submissions(self):
        points = [_make_point()]
        mock_session = MagicMock()

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = (None, None, "Connection refused")
            summary = submit_blind_payloads(points, "http://collector.test", session=mock_session)

        assert len(summary.submissions) == 5  # tous les templates tentés malgré l'erreur
        assert all(s.error == "Connection refused" for s in summary.submissions)

    def test_empty_injection_points_returns_empty_summary(self):
        summary = submit_blind_payloads([], "http://collector.test")
        assert summary.submissions == []


class TestBlindScanSummaryProperties:

    def test_successful_submissions_excludes_errors(self):
        point = _make_point()
        summary = BlindScanSummary(callback_url="http://c.test")
        from modules.active.blind_payloads import BlindSubmission
        summary.submissions = [
            BlindSubmission(injection_point=point, payload="a", technique="t", marker="m1", description="", error=None),
            BlindSubmission(injection_point=point, payload="b", technique="t", marker="m2", description="", error="failed"),
        ]
        assert len(summary.successful_submissions) == 1

    def test_correlation_table_format(self):
        point = _make_point("email")
        summary = BlindScanSummary(callback_url="http://c.test")
        from modules.active.blind_payloads import BlindSubmission
        summary.submissions = [
            BlindSubmission(injection_point=point, payload="a", technique="t", marker="cxss123", description=""),
        ]
        table = summary.correlation_table()
        assert table == [("cxss123", "email", "http://x.test/contact")]


class TestSubmitBlindPayloadsMaxWorkers:
    """Même principe que scan_all_points/check_stored_xss."""

    def test_default_max_workers_is_one(self):
        import inspect
        sig = inspect.signature(submit_blind_payloads)
        assert sig.parameters["max_workers"].default == 1

    def test_parallel_produces_same_submission_count(self):
        points = [_make_point(f"field{i}") for i in range(3)]
        mock_session = MagicMock()

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            summary_seq = submit_blind_payloads(points, "http://collector.test", session=mock_session, max_workers=1)

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            summary_par = submit_blind_payloads(points, "http://collector.test", session=mock_session, max_workers=3)

        assert len(summary_seq.submissions) == len(summary_par.submissions)

    def test_parallel_each_point_still_gets_unique_marker(self):
        points = [_make_point(f"field{i}") for i in range(3)]
        mock_session = MagicMock()

        with patch("modules.active.blind_payloads._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            summary = submit_blind_payloads(points, "http://collector.test", session=mock_session, max_workers=3)

        markers_by_param = {}
        for s in summary.submissions:
            markers_by_param.setdefault(s.injection_point.param_name, set()).add(s.marker)

        assert all(len(m) == 1 for m in markers_by_param.values())
        all_markers = [next(iter(m)) for m in markers_by_param.values()]
        assert len(set(all_markers)) == 3  # 3 markers distincts, même en parallèle
