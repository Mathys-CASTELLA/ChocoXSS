"""
Tests unitaires — modules/active/stored_checker.py

Couvre la détection de XSS stocké :
  - soumission d'un payload sur un point d'injection distinct de la vérification
  - un seul marqueur partagé pour tout le scan stocké
  - gestion d'erreur sur la soumission (ne bloque pas les autres check_urls)
  - gestion d'erreur sur la vérification (une check_url en panne n'empêche
    pas les autres)
  - retour vide et gracieux sans check_urls (pas d'appel réseau inutile)
"""

import pytest
from unittest.mock import patch, MagicMock
import requests

from modules.active.crawler import InjectionPoint
from modules.active.stored_checker import check_stored_xss, StoredResult, StoredScanSummary
from modules.active.reflection_checker import ReflectionConfidence


def _make_point(method="POST"):
    return InjectionPoint(url="http://x.test/comment", method=method, param_name="message",
                          param_kind="form_field", other_params={"author": "test"})


class TestNoCheckUrlsShortCircuit:

    def test_empty_check_urls_returns_empty_summary_without_network_calls(self):
        with patch("modules.active.stored_checker._send_payload") as mock_send:
            summary = check_stored_xss([_make_point()], check_urls=[])
            mock_send.assert_not_called()
        assert summary.results == []

    def test_no_injection_points_returns_empty_summary(self):
        with patch("modules.active.stored_checker._send_payload") as mock_send:
            summary = check_stored_xss([], check_urls=["http://x.test/blog"])
            mock_send.assert_not_called()
        assert summary.results == []


class TestSubmitThenCheckFlow:

    def test_submits_to_injection_point_and_checks_separate_url(self):
        point = _make_point()
        mock_session = MagicMock()

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = ("Merci pour votre commentaire", 200, None)
            mock_session.get.return_value = MagicMock(
                text="<html><p>test: <script>alert('cxsstest')</script></p></html>",
                status_code=200,
            )

            summary = check_stored_xss(
                [point], check_urls=["http://x.test/blog/post-1"], session=mock_session,
            )

        # Chaque payload doit avoir soumis sur le point ET vérifié sur la check_url
        assert mock_send.call_count == len(summary.results)
        mock_session.get.assert_called()
        # La check_url appelée est bien celle fournie, pas l'URL de soumission
        called_url = mock_session.get.call_args_list[0].args[0]
        assert called_url == "http://x.test/blog/post-1"

    def test_raw_payload_detected_on_check_url(self):
        point = _make_point()
        mock_session = MagicMock()

        def fake_get(url, timeout, verify):
            # Réutilise le vrai marqueur généré — on le récupère via le side_effect
            return MagicMock(text=fake_get.last_payload, status_code=200)

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            def send_side_effect(pt, payload, timeout, session, verify=True):
                fake_get.last_payload = f"<html><body>{payload}</body></html>"
                return ("submitted", 200, None)
            mock_send.side_effect = send_side_effect
            mock_session.get.side_effect = fake_get

            summary = check_stored_xss(
                [point], check_urls=["http://x.test/blog"], session=mock_session,
            )

        raw_results = [r for r in summary.results if r.confidence == ReflectionConfidence.REFLECTED_RAW]
        assert len(raw_results) > 0

    def test_multiple_check_urls_all_tested_per_payload(self):
        point = _make_point()
        mock_session = MagicMock()

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

            summary = check_stored_xss(
                [point],
                check_urls=["http://x.test/blog/a", "http://x.test/blog/b"],
                session=mock_session,
            )

        # 10 payloads (payload_engine) × 2 check_urls = 20 résultats
        assert len(summary.results) == 20
        checked_urls = {r.check_url for r in summary.results}
        assert checked_urls == {"http://x.test/blog/a", "http://x.test/blog/b"}


class TestSharedMarkerAcrossScan:

    def test_single_marker_used_for_entire_stored_scan(self):
        point = _make_point()
        mock_session = MagicMock()

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

            summary = check_stored_xss(
                [point], check_urls=["http://x.test/blog"], session=mock_session,
            )

        # Tous les payloads soumis doivent contenir le même marker
        submitted_payloads = [call.args[1] for call in mock_send.call_args_list]
        assert all(summary.marker in p for p in submitted_payloads)


class TestErrorHandling:

    def test_submit_error_produces_request_error_for_all_check_urls(self):
        point = _make_point()
        mock_session = MagicMock()

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = (None, None, "Connection refused")

            summary = check_stored_xss(
                [point],
                check_urls=["http://x.test/blog/a", "http://x.test/blog/b"],
                session=mock_session,
            )

        assert all(r.confidence == ReflectionConfidence.REQUEST_ERROR for r in summary.results)
        assert all(r.error is not None for r in summary.results)
        # Pas d'appel de vérification si la soumission a échoué
        mock_session.get.assert_not_called()

    def test_check_url_error_does_not_block_other_check_urls(self):
        point = _make_point()
        mock_session = MagicMock()

        def fake_get(url, timeout, verify):
            if "broken" in url:
                raise requests.exceptions.ConnectionError("refused")
            return MagicMock(text="<html>clean</html>", status_code=200)

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            mock_session.get.side_effect = fake_get

            summary = check_stored_xss(
                [point],
                check_urls=["http://x.test/broken", "http://x.test/working"],
                session=mock_session,
            )

        broken_results = [r for r in summary.results if r.check_url == "http://x.test/broken"]
        working_results = [r for r in summary.results if r.check_url == "http://x.test/working"]
        assert all(r.confidence == ReflectionConfidence.REQUEST_ERROR for r in broken_results)
        assert all(r.confidence != ReflectionConfidence.REQUEST_ERROR for r in working_results)


class TestSummaryProperties:

    def test_stored_findings_excludes_not_reflected_and_errors(self):
        point = _make_point()
        summary = StoredScanSummary(target_url="http://x.test", check_urls=["http://x.test/blog"], marker="m")
        summary.results = [
            StoredResult(injection_point=point, payload="a", context=None, description="",
                        check_url="u", confidence=ReflectionConfidence.REFLECTED_RAW),
            StoredResult(injection_point=point, payload="b", context=None, description="",
                        check_url="u", confidence=ReflectionConfidence.NOT_REFLECTED),
            StoredResult(injection_point=point, payload="c", context=None, description="",
                        check_url="u", confidence=ReflectionConfidence.REQUEST_ERROR),
        ]
        assert len(summary.stored_findings) == 1

    def test_raw_findings_only_reflected_raw(self):
        point = _make_point()
        summary = StoredScanSummary(target_url="http://x.test", check_urls=["http://x.test/blog"], marker="m")
        summary.results = [
            StoredResult(injection_point=point, payload="a", context=None, description="",
                        check_url="u", confidence=ReflectionConfidence.REFLECTED_RAW),
            StoredResult(injection_point=point, payload="b", context=None, description="",
                        check_url="u", confidence=ReflectionConfidence.REFLECTED_ENCODED),
        ]
        assert len(summary.raw_findings) == 1


class TestCheckStoredXssMaxWorkers:
    """Même principe que scan_all_points : max_workers=1 par défaut, comportement identique en parallèle."""

    def test_default_max_workers_is_one(self):
        import inspect
        sig = inspect.signature(check_stored_xss)
        assert sig.parameters["max_workers"].default == 1

    def test_parallel_produces_same_result_count(self):
        points = [_make_point() for _ in range(3)]
        mock_session = MagicMock()

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

            summary_seq = check_stored_xss(
                points, check_urls=["http://x.test/blog"], session=mock_session, max_workers=1,
            )

        with patch("modules.active.stored_checker._send_payload") as mock_send:
            mock_send.return_value = ("ok", 200, None)
            mock_session2 = MagicMock()
            mock_session2.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)
            summary_par = check_stored_xss(
                points, check_urls=["http://x.test/blog"], session=mock_session2, max_workers=3,
            )

        assert len(summary_seq.results) == len(summary_par.results)
