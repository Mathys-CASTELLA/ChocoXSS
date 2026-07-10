"""
Tests unitaires — modules/active/dom_verifier.py

Couvre la vérification DOM XSS en conditions réelles (vrai navigateur,
vraie navigation réseau — pas de rejeu local comme headless_verifier.py) :
  - construction d'URL de test selon le vecteur (fragment / query)
  - détection d'exécution réelle sur une page vulnérable
  - absence de faux positif sur une page qui échappe correctement
  - le vecteur url_fragment n'est JAMAIS transmis au serveur (propriété
    fondamentale du DOM XSS pur)

Utilise un vrai serveur HTTP local (thread en arrière-plan) plutôt qu'un
process externe, pour éviter toute dépendance à l'environnement du
sandbox — et un vrai Chromium headless (comportement réel à valider,
pas juste de la logique Python).
"""

import threading
import http.server
import socket
import pytest
from pathlib import Path

from modules.active.dom_verifier import (
    verify_dom_xss, verify_dom_xss_multi, _build_test_url, ExecutionConfidence,
    _session_cookies_to_playwright, _capture_dom_screenshot,
)


# ─── Serveur de test local (thread) ───────────────────────────────────────────

_REQUESTS_RECEIVED = []


class _DomTestHandler(http.server.BaseHTTPRequestHandler):
    """
    Sert plusieurs pages :
      /vulnerable  : innerHTML alimenté par location.hash — vrai DOM XSS
      /safe        : textContent alimenté par location.hash — safe
      /query-vuln  : innerHTML alimenté par un paramètre de query 'name'
      /protected   : comme /vulnerable, mais exige un cookie de session
                     valide (401 sinon) — pour tester l'import de cookies
                     depuis la session requests vers le contexte Playwright.
    Enregistre chaque requête reçue dans _REQUESTS_RECEIVED, pour vérifier
    que le fragment d'URL n'atteint JAMAIS le serveur (propriété du DOM XSS).
    """

    def do_GET(self):
        _REQUESTS_RECEIVED.append(self.path)

        if self.path.startswith("/protected"):
            cookie_header = self.headers.get("Cookie", "")
            if "session_id=valid-token" not in cookie_header:
                self.send_response(401)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body>401 non autorise</body></html>")
                return
            body = b'''<html><body><div id="g"></div><script>
                document.getElementById("g").innerHTML =
                    decodeURIComponent(location.hash.substring(1));
            </script></body></html>'''
        elif self.path.startswith("/vulnerable"):
            body = b'''<html><body><div id="g"></div><script>
                document.getElementById("g").innerHTML =
                    decodeURIComponent(location.hash.substring(1));
            </script></body></html>'''
        elif self.path.startswith("/safe"):
            body = b'''<html><body><div id="g"></div><script>
                document.getElementById("g").textContent =
                    decodeURIComponent(location.hash.substring(1));
            </script></body></html>'''
        elif self.path.startswith("/query-vuln"):
            body = b'''<html><body><div id="g"></div><script>
                var params = new URLSearchParams(location.search);
                document.getElementById("g").innerHTML = params.get("chocoxss") || "";
            </script></body></html>'''
        else:
            body = b'<html><body>404</body></html>'

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # silence les logs par défaut


@pytest.fixture(scope="module")
def dom_test_server():
    """Démarre un serveur HTTP local sur un port libre, pour toute la durée du module."""
    server = http.server.HTTPServer(("127.0.0.1", 0), _DomTestHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def clear_requests_log():
    _REQUESTS_RECEIVED.clear()
    yield


# ─── Tests unitaires purs (pas de navigateur) ─────────────────────────────────

class TestBuildTestUrl:

    def test_fragment_vector_appends_hash(self):
        url = _build_test_url("http://x.test/page", "<script>alert(1)</script>", "url_fragment", "chocoxss")
        assert url == "http://x.test/page#<script>alert(1)</script>"

    def test_query_vector_adds_param(self):
        url = _build_test_url("http://x.test/page", "<script>x</script>", "query_param", "chocoxss")
        assert "chocoxss=" in url
        assert url.startswith("http://x.test/page?")

    def test_query_vector_preserves_existing_params(self):
        url = _build_test_url("http://x.test/page?existing=1", "payload", "query_param", "chocoxss")
        assert "existing=1" in url
        assert "chocoxss=payload" in url

    def test_unknown_vector_raises(self):
        with pytest.raises(ValueError):
            _build_test_url("http://x.test/", "x", "not_a_real_vector", "chocoxss")


# ─── Tests d'intégration avec vrai navigateur + vrai serveur ──────────────────

class TestVerifyDomXssRealBrowser:

    def test_vulnerable_page_confirms_execution_via_fragment(self, dom_test_server):
        summary = verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment",),
        )
        assert len(summary.confirmed) > 0

    def test_safe_page_no_false_positive(self, dom_test_server):
        summary = verify_dom_xss(
            f"{dom_test_server}/safe", timeout_ms=3000, vectors=("url_fragment",),
        )
        assert len(summary.confirmed) == 0

    def test_fragment_never_reaches_server(self, dom_test_server):
        """
        Verrouille la propriété fondamentale du DOM XSS pur : le payload
        placé dans le fragment d'URL ne doit JAMAIS apparaître dans les
        requêtes reçues par le serveur — c'est justement pour ça qu'un
        scan actif classique (basé sur requests) ne peut pas le détecter.
        """
        verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment",),
        )
        # Le serveur ne voit que "/vulnerable", jamais le payload après le '#'
        assert all("script" not in path.lower() for path in _REQUESTS_RECEIVED)
        assert all("alert" not in path.lower() for path in _REQUESTS_RECEIVED)

    def test_query_vector_reaches_server_unlike_fragment(self, dom_test_server):
        """Contraste : contrairement au fragment, le paramètre de query EST transmis."""
        verify_dom_xss(
            f"{dom_test_server}/query-vuln", timeout_ms=3000, vectors=("query_param",),
        )
        assert any("chocoxss=" in path for path in _REQUESTS_RECEIVED)

    def test_query_param_vulnerable_page_confirms_execution(self, dom_test_server):
        summary = verify_dom_xss(
            f"{dom_test_server}/query-vuln", timeout_ms=3000, vectors=("query_param",),
        )
        assert len(summary.confirmed) > 0

    def test_both_vectors_produce_double_the_results(self, dom_test_server):
        summary_one = verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment",),
        )
        summary_both = verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment", "query_param"),
        )
        assert len(summary_both.results) == 2 * len(summary_one.results)

    def test_invalid_target_returns_verification_error_not_crash(self):
        summary = verify_dom_xss(
            "http://127.0.0.1:1/nowhere", timeout_ms=2000, vectors=("url_fragment",),
        )
        assert len(summary.results) > 0
        assert all(r.execution == ExecutionConfidence.VERIFICATION_ERROR for r in summary.results)


# ─── Tests de conversion de cookies (logique pure) ────────────────────────────

class TestSessionCookiesToPlaywright:

    def test_none_session_returns_empty_list(self):
        assert _session_cookies_to_playwright(None, "http://x.test/") == []

    def test_empty_session_returns_empty_list(self):
        import requests
        session = requests.Session()
        assert _session_cookies_to_playwright(session, "http://x.test/") == []

    def test_converts_cookie_to_playwright_format(self):
        import requests
        session = requests.Session()
        session.cookies.set("session_id", "abc123", domain="x.test", path="/")

        cookies = _session_cookies_to_playwright(session, "http://x.test/")

        assert len(cookies) == 1
        assert cookies[0]["name"] == "session_id"
        assert cookies[0]["value"] == "abc123"
        assert cookies[0]["domain"] == "x.test"
        assert cookies[0]["path"] == "/"

    def test_multiple_cookies_all_converted(self):
        import requests
        session = requests.Session()
        session.cookies.set("a", "1", domain="x.test", path="/")
        session.cookies.set("b", "2", domain="x.test", path="/")

        cookies = _session_cookies_to_playwright(session, "http://x.test/")
        assert len(cookies) == 2
        names = {c["name"] for c in cookies}
        assert names == {"a", "b"}

    def test_cookie_without_domain_falls_back_to_target_hostname(self):
        import requests
        session = requests.Session()
        # Un cookie fixé programmatiquement sans domaine explicite
        session.cookies.set("token", "xyz", domain="", path="/")

        cookies = _session_cookies_to_playwright(session, "http://127.0.0.1:8779/page")
        # Le domaine par défaut doit être celui de l'URL cible
        assert any(c["name"] == "token" and c["domain"] == "127.0.0.1" for c in cookies)


# ─── Tests d'intégration : authentification réelle sur cible DOM XSS ──────────

class TestVerifyDomXssWithAuthentication:
    """
    Verrouille le bug corrigé : sans session, une page DOM XSS protégée
    par cookie était testée déconnectée (0 confirmation, sans erreur
    explicite). Avec la session, ses cookies sont importés dans le
    contexte Playwright et la navigation réelle voit la vraie page.
    """

    def test_protected_page_without_session_finds_nothing(self, dom_test_server):
        summary = verify_dom_xss(
            f"{dom_test_server}/protected", timeout_ms=3000, vectors=("url_fragment",),
            session=None,
        )
        assert len(summary.confirmed) == 0

    def test_protected_page_with_valid_session_confirms_execution(self, dom_test_server):
        import requests
        from urllib.parse import urlparse

        session = requests.Session()
        host = urlparse(dom_test_server).hostname
        session.cookies.set("session_id", "valid-token-abc", domain=host, path="/")

        summary = verify_dom_xss(
            f"{dom_test_server}/protected", timeout_ms=3000, vectors=("url_fragment",),
            session=session,
        )
        assert len(summary.confirmed) > 0

    def test_protected_page_with_invalid_cookie_still_finds_nothing(self, dom_test_server):
        import requests
        from urllib.parse import urlparse

        session = requests.Session()
        host = urlparse(dom_test_server).hostname
        session.cookies.set("session_id", "wrong-token", domain=host, path="/")

        summary = verify_dom_xss(
            f"{dom_test_server}/protected", timeout_ms=3000, vectors=("url_fragment",),
            session=session,
        )
        assert len(summary.confirmed) == 0


# ─── Tests : vérification sur plusieurs pages (verify_dom_xss_multi) ──────────

class TestVerifyDomXssMulti:
    """
    Verrouille le fix du trou --dom-xss + --crawl-depth : avant, --dom-xss
    ne testait jamais que l'URL de départ, jamais les pages découvertes
    par un crawl récursif. verify_dom_xss_multi comble ça en testant
    plusieurs pages avec un seul navigateur partagé.
    """

    def test_empty_url_list_returns_empty_summary(self):
        summary = verify_dom_xss_multi([])
        assert summary.results == []
        assert summary.confirmed == []

    def test_tests_all_provided_urls(self, dom_test_server):
        urls = [f"{dom_test_server}/vulnerable", f"{dom_test_server}/safe"]
        summary = verify_dom_xss_multi(urls, timeout_ms=3000, vectors=("url_fragment",))

        # 10 payloads × 2 pages = 20 résultats au total
        assert len(summary.results) == 20

    def test_finds_confirmations_only_on_vulnerable_pages(self, dom_test_server):
        urls = [f"{dom_test_server}/vulnerable", f"{dom_test_server}/safe"]
        summary = verify_dom_xss_multi(urls, timeout_ms=3000, vectors=("url_fragment",))

        assert len(summary.confirmed) > 0
        assert all("/safe" not in r.tested_url for r in summary.confirmed)
        assert all("/vulnerable" in r.tested_url for r in summary.confirmed)

    def test_single_url_behaves_like_verify_dom_xss(self, dom_test_server):
        single = verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment",),
        )
        multi = verify_dom_xss_multi(
            [f"{dom_test_server}/vulnerable"], timeout_ms=3000, vectors=("url_fragment",),
        )
        assert len(single.results) == len(multi.results)
        assert len(single.confirmed) == len(multi.confirmed)

    def test_target_url_field_set_to_first_url(self, dom_test_server):
        urls = [f"{dom_test_server}/vulnerable", f"{dom_test_server}/safe"]
        summary = verify_dom_xss_multi(urls, timeout_ms=3000, vectors=("url_fragment",))
        assert summary.target_url == urls[0]

    def test_authentication_cookies_apply_across_all_pages(self, dom_test_server):
        import requests
        from urllib.parse import urlparse

        session = requests.Session()
        host = urlparse(dom_test_server).hostname
        session.cookies.set("session_id", "valid-token-abc", domain=host, path="/")

        urls = [f"{dom_test_server}/protected", f"{dom_test_server}/vulnerable"]
        summary = verify_dom_xss_multi(
            urls, timeout_ms=3000, vectors=("url_fragment",), session=session,
        )

        confirmed_urls = {r.tested_url.split("#")[0] for r in summary.confirmed}
        assert f"{dom_test_server}/protected" in confirmed_urls
        assert f"{dom_test_server}/vulnerable" in confirmed_urls


# ─── Tests : capture d'écran sur exécution confirmée (point 6) ────────────────

class TestDomScreenshotCapture:
    """
    Même principe que côté headless_verifier.py, appliqué à la navigation
    réelle : capture uniquement sur EXECUTED_CONFIRMED, jamais par défaut,
    échec de capture toléré sans planter la vérification.
    """

    def test_no_screenshot_by_default(self, dom_test_server):
        summary = verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment",),
        )
        assert len(summary.confirmed) > 0
        assert all(r.screenshot_path is None for r in summary.confirmed)

    def test_screenshot_created_when_dir_provided(self, dom_test_server, tmp_path):
        summary = verify_dom_xss(
            f"{dom_test_server}/vulnerable", timeout_ms=3000, vectors=("url_fragment",),
            screenshot_dir=str(tmp_path),
        )
        assert len(summary.confirmed) > 0
        for r in summary.confirmed:
            assert r.screenshot_path is not None
            assert Path(r.screenshot_path).exists()
            assert Path(r.screenshot_path).stat().st_size > 0

    def test_no_screenshot_on_safe_page(self, dom_test_server, tmp_path):
        summary = verify_dom_xss(
            f"{dom_test_server}/safe", timeout_ms=3000, vectors=("url_fragment",),
            screenshot_dir=str(tmp_path),
        )
        assert len(summary.confirmed) == 0
        assert all(r.screenshot_path is None for r in summary.results)

    def test_screenshot_dir_propagates_through_multi(self, dom_test_server, tmp_path):
        urls = [f"{dom_test_server}/vulnerable", f"{dom_test_server}/safe"]
        summary = verify_dom_xss_multi(
            urls, timeout_ms=3000, vectors=("url_fragment",), screenshot_dir=str(tmp_path),
        )
        assert len(summary.confirmed) > 0
        for r in summary.confirmed:
            assert r.screenshot_path is not None
            assert Path(r.screenshot_path).exists()

    def test_capture_dom_screenshot_failure_returns_none(self):
        class FakePage:
            def screenshot(self, path):
                raise RuntimeError("simulated failure")

        result = _capture_dom_screenshot(FakePage(), "/tmp/wont_matter", "http://x.test/page#payload")
        assert result is None
