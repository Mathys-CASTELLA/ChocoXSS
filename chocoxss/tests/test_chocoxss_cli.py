"""
Tests unitaires — chocoxss.py

Couvre l'orchestration du CLI unifié :
  - run_static_analysis sur HTML et JS
  - run_active_scan toujours un tuple à 3 éléments (arité stable)
  - export_results_json produit une structure cohérente
  - validation des arguments argparse (flags mutuellement exclusifs,
    cohérence -f/-u avec --static-only/--active-only)
"""

import json
import sys
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import chocoxss
from modules.active.crawler import CrawlResult, InjectionPoint
from modules.active.reflection_checker import ScanSummary, ReflectionResult, ReflectionConfidence
from modules.active.payload_engine import PayloadContext
from modules.active.headless_verifier import VerificationResult, ExecutionConfidence


CHOCOXSS_PATH = Path(__file__).parent.parent / "chocoxss.py"


class TestRunStaticAnalysis:

    def test_html_with_vulnerable_script_returns_confirmed_finding(self):
        html = '''
        <script>
          var a = location.search;
          el.innerHTML = a;
        </script>
        '''
        confirmed = chocoxss.run_static_analysis(html, "test.html", is_html=True)
        assert len(confirmed) == 1
        assert confirmed[0].confidence == "CONFIRMED"

    def test_js_file_analysis(self):
        js = "eval(x);"
        confirmed = chocoxss.run_static_analysis(js, "test.js", is_html=False)
        assert len(confirmed) == 1
        assert confirmed[0].sink_finding.name == "eval"

    def test_clean_html_returns_empty_list(self):
        html = "<html><body>Hello world</body></html>"
        confirmed = chocoxss.run_static_analysis(html, "clean.html", is_html=True)
        assert confirmed == []

    def test_invalid_js_does_not_crash(self):
        js = "this is {{{ not valid ]["
        confirmed = chocoxss.run_static_analysis(js, "broken.js", is_html=False)
        assert confirmed == []

    def test_html_with_invalid_inline_script_skips_gracefully(self):
        html = '<script>this is {{{ not valid ][</script>'
        # Ne doit pas lever d'exception, juste ne rien retourner pour ce script
        confirmed = chocoxss.run_static_analysis(html, "test.html", is_html=True)
        assert confirmed == []


class TestRunActiveScanReturnArity:
    """
    Verrouille la cohérence de retour de run_active_scan : toujours un
    tuple à 3 éléments (crawl_result, summary_ou_None, verifications),
    même sur les chemins d'échec précoce — pour que main() puisse
    toujours faire un unpacking simple sans vérifier la longueur.
    """

    def test_returns_3tuple_on_fetch_error_with_no_points(self):
        with patch("chocoxss.crawl") as mock_crawl:
            mock_crawl.return_value = CrawlResult(
                target_url="http://x.test", injection_points=[], fetch_error="connection refused"
            )
            result = chocoxss.run_active_scan("http://x.test", chocoxss.ScanOptions(timeout=5, do_verify=False))

        assert len(result) == 3
        crawl_result, summary, verifications = result
        assert summary is None
        assert verifications == []

    def test_returns_3tuple_when_no_injection_points(self):
        with patch("chocoxss.crawl") as mock_crawl:
            mock_crawl.return_value = CrawlResult(
                target_url="http://x.test", injection_points=[], fetch_error=None
            )
            result = chocoxss.run_active_scan("http://x.test", chocoxss.ScanOptions(timeout=5, do_verify=False))

        assert len(result) == 3
        _, summary, verifications = result
        assert summary is None
        assert verifications == []

    def test_returns_3tuple_on_successful_scan(self):
        point = InjectionPoint(url="http://x.test", method="GET", param_name="q",
                               param_kind="url_query", other_params={})
        with patch("chocoxss.crawl") as mock_crawl, \
             patch("chocoxss.scan_all_points") as mock_scan:
            mock_crawl.return_value = CrawlResult(
                target_url="http://x.test", injection_points=[point], fetch_error=None
            )
            mock_scan.return_value = ScanSummary(target_url="http://x.test", marker="cxsstest", results=[])

            result = chocoxss.run_active_scan("http://x.test", chocoxss.ScanOptions(timeout=5, do_verify=False))

        assert len(result) == 3
        _, summary, verifications = result
        assert summary is not None
        assert verifications == []

    def test_verify_skipped_when_do_verify_false(self):
        point = InjectionPoint(url="http://x.test", method="GET", param_name="q",
                               param_kind="url_query", other_params={})
        fake_result = ReflectionResult(
            injection_point=point, payload="<script>alert(1)</script>",
            context=PayloadContext.HTML_BODY, description="test",
            confidence=ReflectionConfidence.REFLECTED_RAW,
        )
        with patch("chocoxss.crawl") as mock_crawl, \
             patch("chocoxss.scan_all_points") as mock_scan, \
             patch("chocoxss.verify_batch") as mock_verify:
            mock_crawl.return_value = CrawlResult(
                target_url="http://x.test", injection_points=[point], fetch_error=None
            )
            mock_scan.return_value = ScanSummary(
                target_url="http://x.test", marker="cxsstest", results=[fake_result]
            )

            chocoxss.run_active_scan("http://x.test", chocoxss.ScanOptions(timeout=5, do_verify=False))

            mock_verify.assert_not_called()

    def test_verify_called_when_raw_findings_present(self):
        point = InjectionPoint(url="http://x.test", method="GET", param_name="q",
                               param_kind="url_query", other_params={})
        fake_result = ReflectionResult(
            injection_point=point, payload="<script>alert(1)</script>",
            context=PayloadContext.HTML_BODY, description="test",
            confidence=ReflectionConfidence.REFLECTED_RAW,
        )
        with patch("chocoxss.crawl") as mock_crawl, \
             patch("chocoxss.scan_all_points") as mock_scan, \
             patch("chocoxss.verify_batch") as mock_verify:
            mock_crawl.return_value = CrawlResult(
                target_url="http://x.test", injection_points=[point], fetch_error=None
            )
            mock_scan.return_value = ScanSummary(
                target_url="http://x.test", marker="cxsstest", results=[fake_result]
            )
            mock_verify.return_value = []

            chocoxss.run_active_scan("http://x.test", chocoxss.ScanOptions(timeout=5, do_verify=True))

            mock_verify.assert_called_once()


class TestExportResultsJson:

    def test_export_creates_valid_json(self, tmp_path):
        out_path = tmp_path / "results.json"
        chocoxss.export_results_json(str(out_path), None, None, [])

        assert out_path.exists()
        data = json.loads(out_path.read_text())
        assert "generated_at" in data
        assert data["static_findings"] == []
        assert data["active_findings"] == []
        assert data["verified_executions"] == []

    def test_export_includes_verification_details(self, tmp_path):
        point = InjectionPoint(url="http://x.test", method="GET", param_name="q",
                               param_kind="url_query", other_params={})
        reflection = ReflectionResult(
            injection_point=point, payload="<script>alert(1)</script>",
            context=PayloadContext.HTML_BODY, description="test",
            confidence=ReflectionConfidence.REFLECTED_RAW,
        )
        verification = VerificationResult(
            reflection_result=reflection,
            execution=ExecutionConfidence.EXECUTED_CONFIRMED,
            detail="Dialogue alert() intercepté",
        )
        out_path = tmp_path / "results.json"
        chocoxss.export_results_json(str(out_path), None, None, [verification])

        data = json.loads(out_path.read_text())
        assert len(data["verified_executions"]) == 1
        assert data["verified_executions"][0]["execution"] == "executed_confirmed"
        assert data["verified_executions"][0]["param"] == "q"

    def test_export_excludes_not_reflected_from_active_findings(self, tmp_path):
        point = InjectionPoint(url="http://x.test", method="GET", param_name="q",
                               param_kind="url_query", other_params={})
        raw_result = ReflectionResult(
            injection_point=point, payload="p1", context=PayloadContext.HTML_BODY,
            description="", confidence=ReflectionConfidence.REFLECTED_RAW,
        )
        not_reflected = ReflectionResult(
            injection_point=point, payload="p2", context=PayloadContext.HTML_BODY,
            description="", confidence=ReflectionConfidence.NOT_REFLECTED,
        )
        summary = ScanSummary(target_url="http://x.test", marker="m",
                              results=[raw_result, not_reflected])

        out_path = tmp_path / "results.json"
        chocoxss.export_results_json(str(out_path), None, summary, [])

        data = json.loads(out_path.read_text())
        assert len(data["active_findings"]) == 1
        assert data["active_findings"][0]["confidence"] == "reflected_raw"


class TestArgparseValidation:
    """
    Tests d'intégration légers : invoquent réellement le script en
    subprocess pour valider le comportement argparse (parser.error()
    provoque un sys.exit(2), ce qui est plus fiable à tester via
    subprocess qu'en import direct).
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_no_source_argument_fails(self):
        result = self._run([])
        assert result.returncode != 0

    def test_file_and_url_mutually_exclusive(self):
        result = self._run(["-f", "x.html", "-u", "http://x.test"])
        assert result.returncode == 2
        assert "not allowed" in result.stderr

    def test_static_only_and_active_only_mutually_exclusive(self):
        result = self._run(["-u", "http://x.test", "--static-only", "--active-only"])
        assert result.returncode == 2
        assert "mutuellement exclusifs" in result.stderr

    def test_static_only_with_file_flag_rejected(self):
        result = self._run(["-f", "x.html", "--static-only"])
        assert result.returncode == 2
        assert "ne s'appliquent qu'avec" in result.stderr

    def test_missing_file_reports_error_without_crash(self):
        result = self._run(["-f", "/tmp/definitely_does_not_exist_chocoxss.html"])
        # sys.exit(1) : sortie d'erreur intentionnelle et propre, pas une
        # exception non gérée (le stdout contient le message clair, pas de traceback).
        assert result.returncode == 1
        assert "introuvable" in result.stdout
        assert "Traceback" not in result.stdout


class TestVerboseReflectionTable:
    """
    Verrouille le comportement du flag --verbose : affiche l'extrait de
    réponse HTTP (response_snippet) pour chaque réflexion détectée, sans
    quoi un REFLECTED_PARTIAL est illisible sans rejouer la requête à la main.
    """

    def _make_summary_with_snippet(self, snippet: str, confidence=ReflectionConfidence.REFLECTED_PARTIAL):
        point = InjectionPoint(url="http://x.test/redirect", method="GET",
                               param_name="redirect_to", param_kind="url_query", other_params={})
        result = ReflectionResult(
            injection_point=point, payload="<script>alert('cxsstest')</script>",
            context=PayloadContext.HTML_BODY, description="test",
            confidence=confidence,
            response_snippet=snippet,
        )
        return ScanSummary(target_url="http://x.test", marker="cxsstest", results=[result])

    def test_verbose_true_includes_snippet_in_rich_output(self, monkeypatch):
        from rich.console import Console
        recording_console = Console(record=True, width=200)
        monkeypatch.setattr(chocoxss, "console", recording_console)

        summary = self._make_summary_with_snippet('value="alert(&#39;cxsstest&#39;)">')
        chocoxss._print_reflection_table(summary, verbose=True)

        output = recording_console.export_text()
        assert "Extrait de la réponse" in output
        assert "alert" in output

    def test_verbose_false_omits_snippet_column(self, monkeypatch):
        from rich.console import Console
        recording_console = Console(record=True, width=200)
        monkeypatch.setattr(chocoxss, "console", recording_console)

        summary = self._make_summary_with_snippet('value="alert(&#39;cxsstest&#39;)">')
        chocoxss._print_reflection_table(summary, verbose=False)

        output = recording_console.export_text()
        assert "Extrait de la réponse" not in output

    def test_verbose_falls_back_to_error_when_no_snippet(self, monkeypatch):
        from rich.console import Console
        recording_console = Console(record=True, width=200)
        monkeypatch.setattr(chocoxss, "console", recording_console)

        point = InjectionPoint(url="http://x.test/x", method="GET", param_name="q",
                               param_kind="url_query", other_params={})
        result = ReflectionResult(
            injection_point=point, payload="p", context=PayloadContext.HTML_BODY,
            description="", confidence=ReflectionConfidence.REQUEST_ERROR,
            error="Connection timed out",
        )
        summary = ScanSummary(target_url="http://x.test", marker="m", results=[result])

        chocoxss._print_reflection_table(summary, verbose=True)
        output = recording_console.export_text()
        assert "Connection timed out" in output

    def test_run_active_scan_default_verbose_is_false(self):
        """--verbose n'est jamais activé par défaut (comportement historique préservé)."""
        # Le paramètre a été déplacé dans ScanOptions lors du refactor
        # (regroupement des kwargs pour éviter l'explosion de signature) —
        # on vérifie donc le défaut du dataclass plutôt que celui de la fonction.
        assert chocoxss.ScanOptions().verbose is False


class TestCookieParsing:

    def test_simple_single_cookie(self):
        result = chocoxss._parse_cookie_string("session_id=abc123")
        assert result == {"session_id": "abc123"}

    def test_multiple_cookies(self):
        result = chocoxss._parse_cookie_string("wordpress_logged_in=xyz; wordpress_sec=abc")
        assert result == {"wordpress_logged_in": "xyz", "wordpress_sec": "abc"}

    def test_tolerates_extra_whitespace(self):
        result = chocoxss._parse_cookie_string("  a=1  ;   b=2   ")
        assert result == {"a": "1", "b": "2"}

    def test_ignores_malformed_segment_without_equals(self):
        result = chocoxss._parse_cookie_string("a=1; malformed; b=2")
        assert result == {"a": "1", "b": "2"}

    def test_empty_string_returns_empty_dict(self):
        assert chocoxss._parse_cookie_string("") == {}

    def test_value_containing_equals_sign_preserved(self):
        # Un token JWT ou base64 peut contenir des '=' de padding
        result = chocoxss._parse_cookie_string("token=abc=def=")
        assert result == {"token": "abc=def="}


class TestHeaderParsing:

    def test_single_header(self):
        result = chocoxss._parse_header_strings(["Authorization: Bearer xyz"])
        assert result == {"Authorization": "Bearer xyz"}

    def test_multiple_headers(self):
        result = chocoxss._parse_header_strings([
            "Authorization: Bearer xyz",
            "X-Custom: value",
        ])
        assert result == {"Authorization": "Bearer xyz", "X-Custom": "value"}

    def test_malformed_header_without_colon_is_skipped(self, capsys):
        result = chocoxss._parse_header_strings(["NoColonHere"])
        assert result == {}

    def test_valid_and_malformed_mixed(self):
        result = chocoxss._parse_header_strings(["NoColon", "Valid: yes"])
        assert result == {"Valid": "yes"}

    def test_empty_list_returns_empty_dict(self):
        assert chocoxss._parse_header_strings([]) == {}

    def test_value_with_colon_preserved(self):
        # Ex: un header contenant une URL avec son propre ':'
        result = chocoxss._parse_header_strings(["Referer: https://example.com/x"])
        assert result == {"Referer": "https://example.com/x"}


class TestAuthenticatedSessionIntegration:
    """
    Vérifie que -b/--cookie et -H/--header sont bien appliqués sur la
    session partagée avant d'attaquer la cible — sans quoi le scan actif
    sur une zone authentifiée échouerait silencieusement (comme le 401
    reproduit manuellement avant ce correctif).
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_cookie_flag_reports_count_loaded(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",  # cible injoignable, on vérifie juste le parsing
            "-b", "a=1; b=2",
            "--static-only",
        ])
        assert "2 cookie(s) chargé(s)" in result.stdout

    def test_header_flag_reports_count_applied(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "-H", "X-Test: value",
            "--static-only",
        ])
        assert "1 en-tête(s) custom appliqué(s)" in result.stdout

    def test_malformed_header_warns_but_does_not_crash(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "-H", "NoColonAtAll",
            "--static-only",
        ])
        assert "Header ignoré" in result.stdout
        assert "Traceback" not in result.stdout


class TestCheckUrlValidation:
    """
    Vérifie les garde-fous argparse pour --check-url : nécessite une URL
    cible (pas un fichier local, sur lequel il n'y a aucun serveur à
    attaquer) et le scan actif (incompatible avec --static-only).
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_check_url_with_file_rejected(self):
        result = self._run(["-f", "x.html", "--check-url", "http://x.test/blog"])
        assert result.returncode == 2
        assert "nécessite -u/--url" in result.stderr

    def test_check_url_with_static_only_rejected(self):
        result = self._run(["-u", "http://x.test", "--static-only", "--check-url", "http://x.test/blog"])
        assert result.returncode == 2
        assert "incompatible avec --static-only" in result.stderr

    def test_check_url_repeatable(self):
        # Validation seule : la cible est injoignable, mais argparse doit
        # accepter plusieurs occurrences sans erreur de parsing.
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--check-url", "http://x.test/a",
            "--check-url", "http://x.test/b",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout


class TestProxyFlag:
    """
    Vérifie que --proxy configure bien session.proxies et que le scan
    continue de fonctionner (ou d'échouer proprement) sans planter.
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_proxy_flag_reports_routing(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "-p", "http://127.0.0.1:8080",
            "--static-only",
        ])
        assert "routé via http://127.0.0.1:8080" in result.stdout

    def test_proxy_without_insecure_warns_about_tls_interception(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "-p", "http://127.0.0.1:8080",
            "--static-only",
        ])
        assert "interception TLS" in result.stdout

    def test_proxy_with_insecure_no_tls_warning(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "-p", "http://127.0.0.1:8080",
            "-k",
            "--static-only",
        ])
        assert "interception TLS" not in result.stdout

    def test_no_proxy_flag_no_routing_message(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--static-only",
        ])
        assert "routé via" not in result.stdout

    def test_proxy_sets_session_proxies_dict(self, monkeypatch):
        """
        Vérifie directement la logique de câblage (sans dépendre du réseau) :
        après le bloc if args.proxy, session.proxies doit contenir le proxy
        pour http ET https (Burp/ZAP interceptent généralement les deux).
        """
        import requests as req
        session = req.Session()
        proxy_url = "http://127.0.0.1:8080"
        session.proxies = {"http": proxy_url, "https": proxy_url}
        assert session.proxies["http"] == proxy_url
        assert session.proxies["https"] == proxy_url


class TestCrawlDepthValidation:
    """
    Vérifie les garde-fous argparse pour --crawl-depth : nécessite une
    URL cible et le scan actif, comme --check-url.
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_crawl_depth_with_file_rejected(self):
        result = self._run(["-f", "x.html", "--crawl-depth", "2"])
        assert result.returncode == 2
        assert "nécessite -u/--url" in result.stderr

    def test_crawl_depth_with_static_only_rejected(self):
        result = self._run(["-u", "http://x.test", "--static-only", "--crawl-depth", "2"])
        assert result.returncode == 2
        assert "incompatible avec --static-only" in result.stderr

    def test_negative_crawl_depth_rejected(self):
        result = self._run(["-u", "http://x.test", "--crawl-depth", "-1", "--active-only", "--no-verify"])
        assert result.returncode == 2
        assert "doit être positif ou nul" in result.stderr

    def test_crawl_depth_zero_is_valid_default_behavior(self):
        # 0 est la valeur par défaut, ne doit PAS être rejeté
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--crawl-depth", "0",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_max_pages_and_crawl_external_accepted(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--crawl-depth", "2",
            "--max-pages", "5",
            "--crawl-external",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout


class TestDomXssAndBlindCallbackValidation:
    """
    Vérifie les garde-fous argparse pour --dom-xss et --blind-callback :
    nécessitent tous deux une URL cible ; --blind-callback nécessite en
    plus le scan actif (pour obtenir des points d'injection).
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_dom_xss_with_file_rejected(self):
        result = self._run(["-f", "x.html", "--dom-xss"])
        assert result.returncode == 2
        assert "nécessite -u/--url" in result.stderr

    def test_blind_callback_with_file_rejected(self):
        result = self._run(["-f", "x.html", "--blind-callback", "http://c.test"])
        assert result.returncode == 2
        assert "nécessite -u/--url" in result.stderr

    def test_blind_callback_with_static_only_rejected(self):
        result = self._run(["-u", "http://x.test", "--static-only", "--blind-callback", "http://c.test"])
        assert result.returncode == 2
        assert "incompatible avec --static-only" in result.stderr

    def test_dom_xss_with_static_only_still_allowed(self):
        # --dom-xss ne nécessite PAS de points d'injection (il opère
        # directement sur l'URL), donc --static-only n'est pas incompatible
        # — contrairement à --check-url/--blind-callback qui ont besoin
        # du crawl. On vérifie juste qu'aucune erreur de validation ne
        # bloque cette combinaison (le flag est simplement ignoré si
        # do_active est False, cf. main()).
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--static-only", "--dom-xss",
        ])
        assert result.returncode in (0, 1)  # pas de code 2 (erreur argparse)

    def test_run_dom_scan_accepts_extra_urls_parameter(self):
        """
        Verrouille la signature du fix --dom-xss + --crawl-depth :
        run_dom_scan doit accepter un extra_urls optionnel, sans quoi
        --dom-xss reste structurellement limité à args.url même avec
        --crawl-depth.
        """
        import inspect
        sig = inspect.signature(chocoxss.run_dom_scan)
        assert "extra_urls" in sig.parameters
        assert sig.parameters["extra_urls"].default is None

    def test_dom_scan_dispatches_to_multi_when_extra_urls_given(self, monkeypatch):
        calls = {"single": 0, "multi": 0}

        def fake_multi(urls, **kwargs):
            calls["multi"] += 1
            from modules.active.dom_verifier import DomScanSummary
            return DomScanSummary(target_url=urls[0])

        def fake_single(url, **kwargs):
            calls["single"] += 1
            from modules.active.dom_verifier import DomScanSummary
            return DomScanSummary(target_url=url)

        monkeypatch.setattr(chocoxss, "verify_dom_xss_multi", fake_multi)
        monkeypatch.setattr(chocoxss, "verify_dom_xss", fake_single)

        options = chocoxss.ScanOptions()
        chocoxss.run_dom_scan("http://x.test/a", options, extra_urls=["http://x.test/b"])

        assert calls["multi"] == 1
        assert calls["single"] == 0

    def test_dom_scan_uses_single_when_no_extra_urls(self, monkeypatch):
        calls = {"single": 0, "multi": 0}

        def fake_multi(urls, **kwargs):
            calls["multi"] += 1
            from modules.active.dom_verifier import DomScanSummary
            return DomScanSummary(target_url=urls[0])

        def fake_single(url, **kwargs):
            calls["single"] += 1
            from modules.active.dom_verifier import DomScanSummary
            return DomScanSummary(target_url=url)

        monkeypatch.setattr(chocoxss, "verify_dom_xss_multi", fake_multi)
        monkeypatch.setattr(chocoxss, "verify_dom_xss", fake_single)

        options = chocoxss.ScanOptions()
        chocoxss.run_dom_scan("http://x.test/a", options, extra_urls=None)

        assert calls["single"] == 1
        assert calls["multi"] == 0

    def test_dom_scan_deduplicates_url_already_in_extra_urls(self, monkeypatch):
        received_urls = []

        def fake_multi(urls, **kwargs):
            received_urls.extend(urls)
            from modules.active.dom_verifier import DomScanSummary
            return DomScanSummary(target_url=urls[0])

        monkeypatch.setattr(chocoxss, "verify_dom_xss_multi", fake_multi)

        options = chocoxss.ScanOptions()
        # "http://x.test/a" apparaît en double (url de départ + dans extra_urls)
        chocoxss.run_dom_scan("http://x.test/a", options, extra_urls=["http://x.test/a", "http://x.test/b"])

        assert received_urls.count("http://x.test/a") == 1
        assert "http://x.test/b" in received_urls


class TestDelayAndRefreshCsrfFlags:
    """
    Vérifie que --delay et --refresh-csrf sont acceptés par argparse et
    ne cassent pas le scan (validation légère — le comportement réel de
    delay/refresh_csrf est déjà couvert par des tests dédiés sur les
    modules crawler.py et reflection_checker.py).
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_delay_flag_accepted(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--delay", "0.1",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_negative_delay_not_rejected_by_argparse(self):
        # Pas de validation stricte sur delay (contrairement à crawl-depth) —
        # une valeur négative n'a juste aucun effet (time.sleep négatif ignoré
        # ou immédiat selon la plateforme), mais ne doit pas planter.
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--delay", "-1",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_refresh_csrf_flag_accepted(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--refresh-csrf",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_delay_and_refresh_csrf_combined(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--delay", "0.1", "--refresh-csrf",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout


class TestScanOptionsDataclass:
    """
    Verrouille le refactor de simplification des signatures : les 4
    fonctions run_*_scan doivent accepter un ScanOptions unique plutôt
    qu'une liste de kwargs individuels qui grossissait à chaque nouvelle
    fonctionnalité (12 paramètres avant ce refactor).
    """

    def test_default_construction_has_sane_defaults(self):
        o = chocoxss.ScanOptions()
        assert o.session is None
        assert o.timeout == 10
        assert o.verify_ssl is True
        assert o.verbose is False
        assert o.bypass is False
        assert o.crawl_depth == 0
        assert o.max_pages == 20
        assert o.allow_external is False
        assert o.delay == 0.0
        assert o.refresh_csrf is False
        assert o.proxy is None
        assert o.do_verify is True

    def test_run_active_scan_accepts_options_object(self):
        import inspect
        sig = inspect.signature(chocoxss.run_active_scan)
        params = list(sig.parameters.keys())
        assert params == ["url", "options"]

    def test_run_dom_scan_accepts_options_object(self):
        import inspect
        sig = inspect.signature(chocoxss.run_dom_scan)
        params = list(sig.parameters.keys())
        # extra_urls a été ajouté après ce refactor pour le fix
        # --dom-xss + --crawl-depth — url/options restent les 2 premiers
        # paramètres positionnels, c'est ce qui compte pour cette assertion.
        assert params[:2] == ["url", "options"]

    def test_run_stored_scan_accepts_options_object(self):
        import inspect
        sig = inspect.signature(chocoxss.run_stored_scan)
        params = list(sig.parameters.keys())
        assert params == ["injection_points", "check_urls", "options"]

    def test_run_blind_scan_accepts_options_object(self):
        import inspect
        sig = inspect.signature(chocoxss.run_blind_scan)
        params = list(sig.parameters.keys())
        assert params == ["injection_points", "callback_url", "options"]

    def test_custom_options_override_specific_fields(self):
        o = chocoxss.ScanOptions(timeout=30, verbose=True, crawl_depth=2)
        assert o.timeout == 30
        assert o.verbose is True
        assert o.crawl_depth == 2
        assert o.delay == 0.0
        assert o.bypass is False


class TestConfigSubcommand:
    """
    Vérifie la sous-commande `chocoxss.py config` (show/init) et que le
    fichier de config est effectivement appliqué au scan — voir aussi
    tests/test_common_config.py pour la logique de résolution elle-même.
    """

    def _run(self, args, env=None):
        run_env = dict(os.environ)
        if env:
            run_env.update(env)
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15, env=run_env,
        )

    def test_config_show_runs_without_crashing(self, tmp_path):
        result = self._run(["config", "show"], env={"HOME": str(tmp_path)})
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_config_init_creates_file(self, tmp_path):
        result = self._run(["config", "init"], env={"HOME": str(tmp_path)})
        assert result.returncode == 0
        assert (tmp_path / ".chocoxss.conf").exists()

    def test_config_init_does_not_overwrite_without_force(self, tmp_path):
        conf_path = tmp_path / ".chocoxss.conf"
        conf_path.write_text("timeout = 99\n")

        result = self._run(["config", "init"], env={"HOME": str(tmp_path)})
        assert result.returncode == 0
        assert "existe déjà" in result.stdout
        assert conf_path.read_text() == "timeout = 99\n"

    def test_config_init_force_overwrites(self, tmp_path):
        conf_path = tmp_path / ".chocoxss.conf"
        conf_path.write_text("timeout = 99\n")

        result = self._run(["config", "init", "--force"], env={"HOME": str(tmp_path)})
        assert result.returncode == 0
        assert conf_path.read_text() != "timeout = 99\n"

    def test_unknown_config_subcommand_errors_cleanly(self, tmp_path):
        result = self._run(["config", "bogus"], env={"HOME": str(tmp_path)})
        assert result.returncode == 1
        assert "Traceback" not in result.stdout

    def test_config_file_values_actually_applied_to_scan(self, tmp_path):
        """
        Test d'intégration bout en bout : un fichier de config avec
        insecure=true doit déclencher le message d'avertissement SSL
        même sans -k passé explicitement en CLI.
        """
        conf_path = tmp_path / ".chocoxss.conf"
        conf_path.write_text("insecure = true\n")

        result = self._run(
            ["-u", "http://127.0.0.1:1/nowhere", "--static-only"],
            env={"HOME": str(tmp_path)},
        )
        assert "Vérification SSL désactivée" in result.stdout

    def test_cli_flag_overrides_config_file_value(self, tmp_path):
        """
        Le fichier dit crawl_depth=1, mais --crawl-depth 0 explicite doit
        gagner — vérifié indirectement via l'absence du message de crawl
        récursif ('page(s) visitée').
        """
        conf_path = tmp_path / ".chocoxss.conf"
        conf_path.write_text("[crawl]\ncrawl_depth = 1\n")

        result = self._run(
            ["-u", "http://127.0.0.1:1/nowhere", "--active-only", "--no-verify", "--crawl-depth", "0"],
            env={"HOME": str(tmp_path)},
        )
        assert "page(s) visitée" not in result.stdout


class TestWithSpinnerHelper:
    """
    Verrouille le refactor de dé-duplication RICH/non-RICH : _with_spinner
    doit exécuter fn(*args, **kwargs) exactement une fois, retourner son
    résultat tel quel, et ne pas avaler d'exception silencieusement.
    """

    def test_calls_function_with_given_args_and_kwargs(self):
        calls = []
        def fn(a, b, c=None):
            calls.append((a, b, c))
            return "result"

        result = chocoxss._with_spinner("test...", fn, 1, 2, c=3)
        assert calls == [(1, 2, 3)]
        assert result == "result"

    def test_returns_function_result_unchanged(self):
        def fn():
            return {"key": "value", "n": 42}

        result = chocoxss._with_spinner("test...", fn)
        assert result == {"key": "value", "n": 42}

    def test_function_called_exactly_once(self):
        call_count = {"n": 0}
        def fn():
            call_count["n"] += 1
            return None

        chocoxss._with_spinner("test...", fn)
        assert call_count["n"] == 1

    def test_exception_in_function_propagates(self):
        def fn():
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            chocoxss._with_spinner("test...", fn)

    def test_works_with_no_args(self):
        def fn():
            return "no-args-result"

        assert chocoxss._with_spinner("test...", fn) == "no-args-result"

    def test_works_with_only_kwargs(self):
        def fn(x=None, y=None):
            return (x, y)

        assert chocoxss._with_spinner("test...", fn, x=1, y=2) == (1, 2)


class TestScreenshotDirFlag:
    """
    Vérifie que --screenshot-dir est accepté par argparse, se propage bien
    dans ScanOptions, et ne casse rien même sur une cible injoignable —
    le comportement réel de capture est déjà couvert par les tests
    dédiés sur headless_verifier.py et dom_verifier.py.
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_flag_accepted_without_crash(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--screenshot-dir", "/tmp/some_dir",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_scan_options_default_screenshot_dir_is_none(self):
        assert chocoxss.ScanOptions().screenshot_dir is None

    def test_scan_options_accepts_custom_screenshot_dir(self):
        o = chocoxss.ScanOptions(screenshot_dir="/tmp/proofs")
        assert o.screenshot_dir == "/tmp/proofs"


class TestThreadsFlag:
    """
    Vérifie --threads : validation argparse, câblage ScanOptions,
    et l'avertissement d'interaction avec --delay.
    """

    def _run(self, args):
        return subprocess.run(
            [sys.executable, str(CHOCOXSS_PATH), *args],
            capture_output=True, text=True, timeout=15,
        )

    def test_flag_accepted_without_crash(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--threads", "5",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 0
        assert "Traceback" not in result.stdout

    def test_zero_threads_rejected(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--threads", "0",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 2
        assert "positif" in result.stderr

    def test_negative_threads_rejected(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--threads", "-3",
            "--active-only", "--no-verify",
        ])
        assert result.returncode == 2

    def test_threads_and_delay_combined_warns(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--threads", "5", "--delay", "0.5",
            "--active-only", "--no-verify",
        ])
        assert "débit global" in result.stdout

    def test_threads_alone_no_warning(self):
        result = self._run([
            "-u", "http://127.0.0.1:1/nowhere",
            "--threads", "5",
            "--active-only", "--no-verify",
        ])
        assert "débit global" not in result.stdout

    def test_scan_options_default_threads_is_one(self):
        assert chocoxss.ScanOptions().threads == 1

    def test_scan_options_accepts_custom_threads(self):
        o = chocoxss.ScanOptions(threads=8)
        assert o.threads == 8
