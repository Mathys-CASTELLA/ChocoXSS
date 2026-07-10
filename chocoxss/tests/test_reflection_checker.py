"""
Tests unitaires — modules/active/reflection_checker.py

Couvre la logique de classification de réflexion (le cœur du mode actif) :
  - distinction REFLECTED_RAW / REFLECTED_ENCODED / REFLECTED_PARTIAL / NOT_REFLECTED
  - non-régression sur le piège "marker seul != payload complet"
  - non-régression sur le faux positif javascript: hors contexte href/src
  - pipeline complet avec requêtes HTTP mockées
"""

import pytest
from unittest.mock import MagicMock, patch
from modules.active.crawler import InjectionPoint
from modules.active.payload_engine import PayloadContext
from modules.active.reflection_checker import (
    _classify_reflection, _send_payload, scan_injection_point, scan_all_points,
    _classify_bypass_reflection, ReflectionConfidence,
)


class TestClassifyReflectionBasics:

    def test_not_reflected_when_marker_absent(self):
        conf, snippet = _classify_reflection(
            '<script>x</script>', 'cxss123', '<html>no marker here</html>', PayloadContext.HTML_BODY
        )
        assert conf == ReflectionConfidence.NOT_REFLECTED

    def test_raw_reflection_when_payload_appears_verbatim(self):
        payload = '<script>/*cxss123*/</script>'
        body = f'<html><body>{payload}</body></html>'
        conf, snippet = _classify_reflection(payload, 'cxss123', body, PayloadContext.HTML_BODY)
        assert conf == ReflectionConfidence.REFLECTED_RAW

    def test_encoded_reflection_when_html_escaped(self):
        payload = '<script>/*cxss123*/</script>'
        body = '<html><body>&lt;script&gt;/*cxss123*/&lt;/script&gt;</body></html>'
        conf, snippet = _classify_reflection(payload, 'cxss123', body, PayloadContext.HTML_BODY)
        assert conf == ReflectionConfidence.REFLECTED_ENCODED


class TestMarkerVsPayloadDistinctionRegression:
    """
    Verrouille le bug conceptuel identifié dès la conception : chercher
    uniquement le marker dans la réponse ne suffit pas, car un payload
    encodé contient toujours le marker en clair. Il faut vérifier le
    PAYLOAD COMPLET pour distinguer raw d'encoded.
    """

    def test_marker_alone_present_but_payload_encoded_is_not_raw(self):
        payload = '<img src=x onerror="/*cxss999*/">'
        # Le payload est encodé, mais "cxss999" reste lisible dans le texte encodé
        body = '<html>&lt;img src=x onerror=&quot;/*cxss999*/&quot;&gt;</html>'
        conf, _ = _classify_reflection(payload, 'cxss999', body, PayloadContext.HTML_BODY)
        assert conf != ReflectionConfidence.REFLECTED_RAW
        assert conf == ReflectionConfidence.REFLECTED_ENCODED

    def test_partial_filter_detected_when_dangerous_chars_remain(self):
        # Le serveur a supprimé <script> mais laissé le marker et d'autres chars
        payload = '<script>/*cxss777*/</script>'
        body = '<html><body>"quoted" /*cxss777*/ <b>bold</b></body></html>'
        conf, _ = _classify_reflection(payload, 'cxss777', body, PayloadContext.HTML_BODY)
        assert conf == ReflectionConfidence.REFLECTED_PARTIAL


class TestJavascriptUrlContextRegression:
    """
    Verrouille le bug découvert lors du test contre le serveur local :
    un payload "javascript:..." reflété dans du TEXTE BRUT (pas dans un
    attribut href/src réel) n'est pas exploitable, même s'il apparaît
    tel quel dans la réponse. Doit être requalifié REFLECTED_ENCODED
    plutôt que REFLECTED_RAW pour ne pas produire de faux positif.
    """

    def test_javascript_payload_in_plain_text_is_not_raw(self):
        payload = 'javascript:/*cxss555*/'
        body = f'<html><body>Resultats pour : {payload}</body></html>'
        conf, _ = _classify_reflection(payload, 'cxss555', body, PayloadContext.URL_CONTEXT)
        assert conf != ReflectionConfidence.REFLECTED_RAW, \
            "javascript: en texte brut hors attribut ne doit pas être classé RAW"

    def test_javascript_payload_inside_href_attribute_is_raw(self):
        payload = 'javascript:/*cxss555*/'
        body = f'<html><body><a href="{payload}">click</a></body></html>'
        conf, _ = _classify_reflection(payload, 'cxss555', body, PayloadContext.URL_CONTEXT)
        assert conf == ReflectionConfidence.REFLECTED_RAW

    def test_javascript_payload_inside_src_attribute_is_raw(self):
        payload = 'javascript:/*cxss555*/'
        body = f"<html><body><img src='{payload}'></body></html>"
        conf, _ = _classify_reflection(payload, 'cxss555', body, PayloadContext.URL_CONTEXT)
        assert conf == ReflectionConfidence.REFLECTED_RAW

    def test_non_url_context_payloads_unaffected_by_this_rule(self):
        # La règle spéciale ne doit s'appliquer qu'au contexte URL_CONTEXT
        payload = '<script>/*cxss555*/</script>'
        body = f'<html><body>{payload}</body></html>'
        conf, _ = _classify_reflection(payload, 'cxss555', body, PayloadContext.HTML_BODY)
        assert conf == ReflectionConfidence.REFLECTED_RAW


class TestSendPayload:

    def test_get_request_uses_session_get(self):
        point = InjectionPoint(url="http://x.com/search", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="response body", status_code=200)

        body, status, error = _send_payload(point, "<payload>", 10, mock_session)

        mock_session.get.assert_called_once()
        assert body == "response body"
        assert status == 200
        assert error is None

    def test_post_request_uses_session_post(self):
        point = InjectionPoint(url="http://x.com/comment", method="POST",
                               param_name="message", param_kind="form_field", other_params={})
        mock_session = MagicMock()
        mock_session.post.return_value = MagicMock(text="ok", status_code=200)

        body, status, error = _send_payload(point, "<payload>", 10, mock_session)

        mock_session.post.assert_called_once()
        assert body == "ok"

    def test_network_error_returns_error_tuple(self):
        import requests
        point = InjectionPoint(url="http://x.com/x", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout("timed out")

        body, status, error = _send_payload(point, "<payload>", 10, mock_session)
        assert body is None
        assert status is None
        assert "timed out" in error

    def test_payload_injected_into_correct_param(self):
        point = InjectionPoint(url="http://x.com/search", method="GET",
                               param_name="q", param_kind="url_query",
                               other_params={"page": "2"})
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="ok", status_code=200)

        _send_payload(point, "PAYLOAD_HERE", 10, mock_session)

        call_kwargs = mock_session.get.call_args.kwargs
        assert call_kwargs["params"]["q"] == "PAYLOAD_HERE"
        assert call_kwargs["params"]["page"] == "2"  # autres params préservés


class TestScanInjectionPoint:

    def test_returns_one_result_per_payload_template(self):
        from modules.active.payload_engine import PAYLOAD_TEMPLATES
        point = InjectionPoint(url="http://x.com/search", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="clean page, no reflection", status_code=200)

        results = scan_injection_point(point, "cxsstest", timeout=5, session=mock_session)
        assert len(results) == len(PAYLOAD_TEMPLATES)
        assert all(r.confidence == ReflectionConfidence.NOT_REFLECTED for r in results)

    def test_detects_raw_reflection_end_to_end(self):
        point = InjectionPoint(url="http://x.com/search", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()

        def fake_get(url, params, timeout, verify=True):
            # Simule un serveur vulnérable qui reflète tout sans échapper
            injected = params.get("q", "")
            return MagicMock(text=f"<html>{injected}</html>", status_code=200)

        mock_session.get.side_effect = fake_get

        results = scan_injection_point(point, "cxsstest", timeout=5, session=mock_session)
        raw_results = [r for r in results if r.confidence == ReflectionConfidence.REFLECTED_RAW]
        assert len(raw_results) > 0


class TestScanAllPoints:

    def test_uses_single_shared_marker_across_all_points(self):
        points = [
            InjectionPoint(url="http://x.com/a", method="GET", param_name="p1",
                           param_kind="url_query", other_params={}),
            InjectionPoint(url="http://x.com/b", method="GET", param_name="p2",
                           param_kind="url_query", other_params={}),
        ]
        import modules.active.reflection_checker as rc
        original_scan = rc.scan_injection_point
        markers_seen = []

        def spy_scan(point, marker, timeout=10, delay=0.0, session=None, verify=True, bypass_on_partial=False, refresh_csrf=False):
            markers_seen.append(marker)
            return []

        rc.scan_injection_point = spy_scan
        try:
            rc.scan_all_points(points, "http://x.com", timeout=5)
        finally:
            rc.scan_injection_point = original_scan

        assert len(set(markers_seen)) == 1, "le marker doit être identique pour tous les points d'un même scan"

    def test_summary_counts_injection_points_tested(self):
        points = [
            InjectionPoint(url="http://x.com/a", method="GET", param_name="p1",
                           param_kind="url_query", other_params={}),
        ]
        import modules.active.reflection_checker as rc
        original_scan = rc.scan_injection_point
        rc.scan_injection_point = lambda *a, **k: []
        try:
            summary = rc.scan_all_points(points, "http://x.com", timeout=5)
        finally:
            rc.scan_injection_point = original_scan

        assert summary.injection_points_tested == 1


class TestClassifyBypassReflection:
    """
    Verrouille le bug identifié en conditions réelles (serveur avec filtre
    naïf non récursif sur <script>) : contrairement à _classify_reflection,
    _classify_bypass_reflection ne compare pas le payload ENVOYÉ au texte
    de la réponse — elle cherche un pattern dangereux RECONSTITUÉ, car
    certaines techniques (nested_tag) transforment délibérément le payload
    à travers le filtre plutôt que de le faire passer intact.
    """

    def test_marker_absent_is_not_reflected(self):
        conf, _ = _classify_bypass_reflection("cxss123", "<html>rien ici</html>")
        assert conf == ReflectionConfidence.NOT_REFLECTED

    def test_reconstructed_script_tag_after_naive_filter_is_raw(self):
        # Simule exactement le cas réel : <scr<script>ipt>alert('m')</scr</script>ipt>
        # après un .replace("<script>","").replace("</script>","") non récursif
        # devient <script>alert('m')</script> — DIFFÉRENT du payload envoyé,
        # mais bien exécutable.
        body = "<html><body><input value=\"<script>alert('cxss123')</script>\"></body></html>"
        conf, snippet = _classify_bypass_reflection("cxss123", body)
        assert conf == ReflectionConfidence.REFLECTED_RAW
        assert "cxss123" in snippet

    def test_event_handler_pattern_detected_as_raw(self):
        body = '<html><img src=x onerror="alert(\'cxss123\')"></html>'
        conf, _ = _classify_bypass_reflection("cxss123", body)
        assert conf == ReflectionConfidence.REFLECTED_RAW

    def test_javascript_uri_pattern_detected_as_raw(self):
        body = "<html><a href=\"javascript:alert('cxss123')\">x</a></html>"
        conf, _ = _classify_bypass_reflection("cxss123", body)
        assert conf == ReflectionConfidence.REFLECTED_RAW

    def test_marker_present_but_no_dangerous_pattern_is_partial(self):
        # Le filtre a bien neutralisé la variante — le marker survit dans
        # du texte inoffensif, sans balise/attribut exécutable reconstitué.
        body = "<html><body>filtered: cxss123 nothing dangerous here</body></html>"
        conf, _ = _classify_bypass_reflection("cxss123", body)
        assert conf == ReflectionConfidence.REFLECTED_PARTIAL

    def test_case_insensitive_script_tag_detected(self):
        body = "<html><ScRiPt>alert('cxss123')</ScRiPt></html>"
        conf, _ = _classify_bypass_reflection("cxss123", body)
        assert conf == ReflectionConfidence.REFLECTED_RAW


class TestBypassOnPartialIntegration:
    """
    Vérifie que scan_injection_point ne déclenche le retry bypass QUE
    lorsque bypass_on_partial=True ET qu'un résultat standard revient
    REFLECTED_PARTIAL — pas de surcoût de requêtes sur les autres cas.
    """

    def test_bypass_not_triggered_by_default(self):
        point = InjectionPoint(url="http://x.test/search", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()
        # Simule un filtrage partiel (payload standard filtré)
        mock_session.get.return_value = MagicMock(text="<html>filtered</html>", status_code=200)

        with patch("modules.active.reflection_checker._retry_with_bypasses") as mock_retry:
            scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, bypass_on_partial=False)
            mock_retry.assert_not_called()

    def test_bypass_triggered_only_on_partial_results(self):
        point = InjectionPoint(url="http://x.test/search", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()
        # Toutes les requêtes reviennent "clean" (NOT_REFLECTED) — pas de
        # marker dans la réponse, donc jamais PARTIAL, donc pas de retry.
        mock_session.get.return_value = MagicMock(text="<html>clean, no marker</html>", status_code=200)

        with patch("modules.active.reflection_checker._retry_with_bypasses") as mock_retry:
            scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, bypass_on_partial=True)
            mock_retry.assert_not_called()

    def test_bypass_results_tagged_with_technique(self):
        point = InjectionPoint(url="http://x.test/search", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
        mock_session = MagicMock()

        def fake_get(url, params, timeout, verify=True):
            marker = "cxsstest"
            payload = params.get("q", "")
            # Simule le filtre naïf : supprime <script>/</script> une fois
            filtered = payload.replace("<script>", "").replace("</script>", "")
            return MagicMock(text=f"<html>{filtered}</html>", status_code=200)

        mock_session.get.side_effect = fake_get

        results = scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, bypass_on_partial=True)

        bypass_results = [r for r in results if r.bypass_technique is not None]
        assert len(bypass_results) > 0
        for r in bypass_results:
            assert r.original_payload is not None


class TestRefreshCsrfIntegration:
    """
    Vérifie l'intégration du rafraîchissement CSRF dans scan_injection_point :
    déclenché une fois avant la boucle de payloads, uniquement pour les
    points POST, uniquement si refresh_csrf=True.
    """

    def _make_csrf_point(self, method="POST"):
        return InjectionPoint(
            url="http://x.test/submit", method=method, param_name="message",
            param_kind="form_field",
            other_params={"csrf_token": "stale-token"},
            page_url="http://x.test/form",
        )

    def test_refresh_not_called_by_default(self):
        point = self._make_csrf_point()
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

        with patch("modules.active.reflection_checker.refresh_csrf_field") as mock_refresh:
            scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, refresh_csrf=False)
            mock_refresh.assert_not_called()

    def test_refresh_called_once_when_enabled_on_post(self):
        point = self._make_csrf_point(method="POST")
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

        with patch("modules.active.reflection_checker.refresh_csrf_field") as mock_refresh:
            mock_refresh.return_value = {"csrf_token": "fresh-token"}
            scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, refresh_csrf=True)
            mock_refresh.assert_called_once()  # une fois, pas une fois par payload

    def test_refresh_not_called_on_get_points(self):
        point = self._make_csrf_point(method="GET")
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

        with patch("modules.active.reflection_checker.refresh_csrf_field") as mock_refresh:
            scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, refresh_csrf=True)
            mock_refresh.assert_not_called()

    def test_fresh_params_used_for_all_payload_submissions(self):
        point = self._make_csrf_point()
        mock_session = MagicMock()
        sent_tokens = []

        def fake_get_or_post(url, params=None, data=None, timeout=None, verify=None):
            payload_data = data if data is not None else params
            if payload_data and "csrf_token" in payload_data:
                sent_tokens.append(payload_data["csrf_token"])
            return MagicMock(text="<html>clean</html>", status_code=200)

        mock_session.post.side_effect = fake_get_or_post
        mock_session.get.side_effect = fake_get_or_post

        with patch("modules.active.reflection_checker.refresh_csrf_field") as mock_refresh:
            mock_refresh.return_value = {"csrf_token": "fresh-token"}
            scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, refresh_csrf=True)

        # Tous les payloads POST doivent utiliser le token rafraîchi, pas l'original périmé
        assert len(sent_tokens) > 0
        assert all(t == "fresh-token" for t in sent_tokens)

    def test_falls_back_to_original_params_when_refresh_fails(self):
        point = self._make_csrf_point()
        mock_session = MagicMock()
        mock_session.post.return_value = MagicMock(text="<html>clean</html>", status_code=200)

        with patch("modules.active.reflection_checker.refresh_csrf_field") as mock_refresh:
            mock_refresh.return_value = None  # échec du rafraîchissement
            # Ne doit pas lever d'exception — retombe sur le point d'origine
            results = scan_injection_point(point, "cxsstest", timeout=5, session=mock_session, refresh_csrf=True)
            assert len(results) > 0


class TestScanAllPointsMaxWorkers:
    """
    Verrouille la parallélisation (point 7) : max_workers=1 préserve le
    comportement séquentiel historique exact, max_workers>1 produit les
    MÊMES résultats mais en parallèle — testé contre un vrai serveur
    Flask threadé pour prouver un vrai gain de temps mesurable.
    """

    def test_default_max_workers_is_one(self):
        import inspect
        sig = inspect.signature(scan_all_points)
        assert sig.parameters["max_workers"].default == 1

    def test_max_workers_one_tests_all_points_correctly(self):
        points = [
            InjectionPoint(url=f"http://x.test/p{i}", method="GET", param_name="q",
                           param_kind="url_query", other_params={})
            for i in range(3)
        ]
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

        summary = scan_all_points(points, "http://x.test", timeout=5, session=mock_session, max_workers=1)

        assert summary.injection_points_tested == 3
        # 10 payloads standards × 3 points
        assert len(summary.results) == 30

    def test_max_workers_greater_than_one_same_result_count(self):
        points = [
            InjectionPoint(url=f"http://x.test/p{i}", method="GET", param_name="q",
                           param_kind="url_query", other_params={})
            for i in range(3)
        ]
        mock_session = MagicMock()
        mock_session.get.return_value = MagicMock(text="<html>clean</html>", status_code=200)

        summary = scan_all_points(points, "http://x.test", timeout=5, session=mock_session, max_workers=3)

        assert summary.injection_points_tested == 3
        assert len(summary.results) == 30

    def test_real_server_parallel_faster_than_sequential(self):
        """
        Preuve mesurable contre un vrai serveur HTTP local threadé : le
        même scan doit être significativement plus rapide en parallèle.
        """
        import threading
        import http.server
        import time as time_module

        request_delay = 0.1

        class SlowHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                time_module.sleep(request_delay)
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>clean</body></html>")

            def log_message(self, format, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            points = [
                InjectionPoint(url=f"http://127.0.0.1:{port}/p{i}", method="GET",
                               param_name="q", param_kind="url_query", other_params={})
                for i in range(4)
            ]

            start = time_module.time()
            summary_seq = scan_all_points(points, "http://x.test", timeout=5, max_workers=1)
            elapsed_seq = time_module.time() - start

            start = time_module.time()
            summary_par = scan_all_points(points, "http://x.test", timeout=5, max_workers=4)
            elapsed_par = time_module.time() - start

            assert len(summary_seq.results) == len(summary_par.results)
            assert elapsed_par < elapsed_seq / 2, (
                f"attendu un gain net : séquentiel={elapsed_seq:.2f}s, parallèle={elapsed_par:.2f}s"
            )
        finally:
            server.shutdown()
            server.server_close()
