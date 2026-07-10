"""
Tests unitaires — modules/active/headless_verifier.py

Couvre la vérification d'exécution réelle en navigateur :
  - fast-path : les résultats non-REFLECTED_RAW ne déclenchent jamais
    de navigateur (économie de temps, comportement attendu documenté)
  - exécution confirmée via interception de dialogue alert()
  - non-exécution correctement détectée quand le contexte d'injection
    supposé par le payload ne correspond pas à la réalité
  - gestion des erreurs réseau lors du re-fetch HTTP

Ces tests utilisent un VRAI navigateur Playwright (comportement fiable
à valider, pas juste une logique Python) mais mockent la couche HTTP
(_send_payload) pour ne pas dépendre d'un serveur vivant — on contrôle
ainsi précisément le corps de réponse simulé sans latence réseau.
"""

import pytest
from unittest.mock import patch
from pathlib import Path
from modules.active.crawler import InjectionPoint
from modules.active.payload_engine import PayloadContext
from modules.active.reflection_checker import ReflectionResult, ReflectionConfidence
from modules.active.headless_verifier import (
    verify_execution, verify_batch, ExecutionConfidence, _generate_exec_token, _capture_screenshot,
)


def _make_point():
    return InjectionPoint(url="http://x.test/search", method="GET",
                          param_name="q", param_kind="url_query", other_params={})


def _make_result(payload: str, confidence: ReflectionConfidence, context=PayloadContext.HTML_BODY):
    return ReflectionResult(
        injection_point=_make_point(),
        payload=payload,
        context=context,
        description="test payload",
        confidence=confidence,
    )


class TestGenerateExecToken:

    def test_token_has_expected_prefix(self):
        assert _generate_exec_token().startswith("chocoxss_")

    def test_tokens_are_unique(self):
        tokens = {_generate_exec_token() for _ in range(50)}
        assert len(tokens) == 50


class TestFastPathSkipsBrowser:
    """
    Les résultats qui ne sont pas REFLECTED_RAW ne peuvent physiquement pas
    s'exécuter (le payload n'apparaît même pas tel quel dans la réponse),
    donc le vérificateur ne doit jamais lancer de navigateur pour eux —
    c'est une garantie de performance importante pour un scan avec
    beaucoup de résultats ENCODED/PARTIAL/NOT_REFLECTED.
    """

    @pytest.mark.parametrize("confidence", [
        ReflectionConfidence.REFLECTED_ENCODED,
        ReflectionConfidence.REFLECTED_PARTIAL,
        ReflectionConfidence.NOT_REFLECTED,
        ReflectionConfidence.REQUEST_ERROR,
    ])
    def test_non_raw_confidence_never_touches_browser(self, confidence):
        result = _make_result("<script>alert('x')</script>", confidence)
        with patch("modules.active.headless_verifier._send_payload") as mock_send:
            verification = verify_execution(result)
            mock_send.assert_not_called()
        assert verification.execution == ExecutionConfidence.NOT_EXECUTED


class TestRealBrowserExecution:
    """
    Tests d'intégration avec un vrai navigateur Chromium headless.
    La couche HTTP est mockée pour contrôler précisément le corps de
    réponse simulé, mais le rendu/l'exécution JS est 100% réel.
    """

    def test_script_tag_in_body_is_confirmed_executed(self):
        marker = "chocoxsstest001"
        payload = f"<script>alert('{marker}')</script>"
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = f"<html><body>{payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000)

        assert verification.execution == ExecutionConfidence.EXECUTED_CONFIRMED
        assert "alert" in verification.detail.lower()

    def test_img_onerror_is_confirmed_executed(self):
        marker = "chocoxsstest002"
        payload = f"<img src=x onerror=\"alert('{marker}')\">"
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = f"<html><body>{payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000)

        assert verification.execution == ExecutionConfidence.EXECUTED_CONFIRMED

    def test_attribute_breakout_without_real_attribute_context_not_executed(self):
        # Le payload SUPPOSE être injecté dans un attribut existant, mais
        # ici il est simplement collé en texte brut sans balise porteuse —
        # il ne doit PAS s'exécuter, ce qui est le comportement réel attendu.
        marker = "chocoxsstest003"
        payload = f'" onmouseover="alert(\'{marker}\')" x="'
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_ATTRIBUTE)
        fake_body = f"<html><body>Resultat: {payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000)

        assert verification.execution == ExecutionConfidence.NOT_EXECUTED

    def test_clean_text_never_executes(self):
        result = _make_result("static text", ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = "<html><body>static text</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000)

        assert verification.execution == ExecutionConfidence.NOT_EXECUTED

    def test_svg_onload_is_confirmed_executed(self):
        marker = "chocoxsstest004"
        payload = f"<svg onload=\"alert('{marker}')\">"
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = f"<html><body>{payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000)

        assert verification.execution == ExecutionConfidence.EXECUTED_CONFIRMED


class TestHttpErrorHandling:

    def test_refetch_error_returns_verification_error(self):
        result = _make_result("<script>alert(1)</script>", ReflectionConfidence.REFLECTED_RAW)

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(None, None, "Connection refused")):
            verification = verify_execution(result)

        assert verification.execution == ExecutionConfidence.VERIFICATION_ERROR
        assert verification.error == "Connection refused"


class TestVerifyBatch:

    def test_processes_multiple_results_with_shared_browser(self):
        marker1, marker2 = "chocoxssbatch01", "chocoxssbatch02"
        results = [
            _make_result(f"<script>alert('{marker1}')</script>", ReflectionConfidence.REFLECTED_RAW),
            _make_result(f"<script>alert('{marker2}')</script>", ReflectionConfidence.REFLECTED_RAW),
        ]

        def fake_send(point, payload, timeout, session, verify=True):
            return f"<html><body>{payload}</body></html>", 200, None

        with patch("modules.active.headless_verifier._send_payload", side_effect=fake_send):
            verifications = verify_batch(results, timeout_ms=3000)

        assert len(verifications) == 2
        assert all(v.execution == ExecutionConfidence.EXECUTED_CONFIRMED for v in verifications)

    def test_empty_list_returns_empty(self):
        assert verify_batch([]) == []

    def test_mixed_confidences_only_raw_reaches_browser(self):
        results = [
            _make_result("x", ReflectionConfidence.NOT_REFLECTED),
            _make_result("<script>alert('chocoxssbatch03')</script>", ReflectionConfidence.REFLECTED_RAW),
        ]

        call_count = {"n": 0}
        def fake_send(point, payload, timeout, session, verify=True):
            call_count["n"] += 1
            return f"<html><body>{payload}</body></html>", 200, None

        with patch("modules.active.headless_verifier._send_payload", side_effect=fake_send):
            verifications = verify_batch(results, timeout_ms=3000)

        assert len(verifications) == 2
        assert call_count["n"] == 1, "seul le résultat REFLECTED_RAW doit déclencher un re-fetch HTTP"
        assert verifications[0].execution == ExecutionConfidence.NOT_EXECUTED
        assert verifications[1].execution == ExecutionConfidence.EXECUTED_CONFIRMED


class TestScreenshotCapture:
    """
    Verrouille la capture d'écran sur exécution confirmée (point 6) :
      - jamais de capture sur NOT_EXECUTED/VERIFICATION_ERROR (rien à montrer)
      - jamais de capture par défaut (screenshot_dir=None)
      - fichier PNG réellement créé sur EXECUTED_CONFIRMED avec screenshot_dir
      - un échec de capture ne fait jamais planter toute la vérification
    """

    def test_no_screenshot_by_default(self, tmp_path):
        marker = "chocoxsstest001"
        payload = f"<script>alert('{marker}')</script>"
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = f"<html><body>{payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000)

        assert verification.execution == ExecutionConfidence.EXECUTED_CONFIRMED
        assert verification.screenshot_path is None

    def test_screenshot_created_when_dir_provided(self, tmp_path):
        marker = "chocoxsstest002"
        payload = f"<script>alert('{marker}')</script>"
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = f"<html><body>{payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000, screenshot_dir=str(tmp_path))

        assert verification.screenshot_path is not None
        assert Path(verification.screenshot_path).exists()
        assert Path(verification.screenshot_path).stat().st_size > 0

    def test_no_screenshot_on_not_executed(self, tmp_path):
        result = _make_result("static text", ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = "<html><body>static text</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000, screenshot_dir=str(tmp_path))

        assert verification.execution == ExecutionConfidence.NOT_EXECUTED
        assert verification.screenshot_path is None

    def test_no_screenshot_on_verification_error(self, tmp_path):
        result = _make_result("<script>alert(1)</script>", ReflectionConfidence.REFLECTED_RAW)

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(None, None, "Connection refused")):
            verification = verify_execution(result, screenshot_dir=str(tmp_path))

        assert verification.execution == ExecutionConfidence.VERIFICATION_ERROR
        assert verification.screenshot_path is None

    def test_screenshot_filename_contains_param_name(self, tmp_path):
        marker = "chocoxsstest003"
        payload = f"<script>alert('{marker}')</script>"
        result = _make_result(payload, ReflectionConfidence.REFLECTED_RAW, PayloadContext.HTML_BODY)
        fake_body = f"<html><body>{payload}</body></html>"

        with patch("modules.active.headless_verifier._send_payload",
                  return_value=(fake_body, 200, None)):
            verification = verify_execution(result, timeout_ms=3000, screenshot_dir=str(tmp_path))

        assert "q" in Path(verification.screenshot_path).name

    def test_capture_screenshot_failure_returns_none_not_exception(self):
        """
        Un objet page invalide (échec de capture simulé) ne doit jamais
        lever d'exception — juste retourner None silencieusement, pour
        ne pas faire échouer toute la vérification à cause d'un problème
        de disque/permissions sur le screenshot seul.
        """
        class FakePage:
            def screenshot(self, path):
                raise RuntimeError("simulated failure")

        result = _capture_screenshot(FakePage(), "/tmp/wont_matter", "param", "token123")
        assert result is None

    def test_verify_batch_propagates_screenshot_dir(self, tmp_path):
        marker1 = "chocoxssbatch10"
        results = [
            _make_result(f"<script>alert('{marker1}')</script>", ReflectionConfidence.REFLECTED_RAW),
        ]

        def fake_send(point, payload, timeout, session, verify=True):
            return f"<html><body>{payload}</body></html>", 200, None

        with patch("modules.active.headless_verifier._send_payload", side_effect=fake_send):
            verifications = verify_batch(results, timeout_ms=3000, screenshot_dir=str(tmp_path))

        assert verifications[0].screenshot_path is not None
        assert Path(verifications[0].screenshot_path).exists()
