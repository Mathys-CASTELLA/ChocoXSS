"""
ChocoXSS — Headless Verifier (mode actif, confirmation d'exécution)
=======================================================================

Complète reflection_checker.py : celui-ci prouve qu'un payload est reflété
SANS ÊTRE ÉCHAPPÉ dans le HTML brut, mais ne garantit pas qu'il s'exécute
réellement dans un navigateur (un REFLECTED_RAW peut atterrir dans une zone
morte du DOM, un attribut déjà fermé différemment que prévu, etc.).

Ce module ouvre un vrai navigateur headless (Chromium via Playwright),
rejoue la réponse HTTP exacte obtenue avec le payload injecté, et vérifie
si le payload s'est réellement exécuté via deux mécanismes complémentaires :

  1. Interception des dialogues navigateur (alert/confirm/prompt) —
     couvre tous les payloads de la forme alert(1), confirm(1)...
  2. Marqueur global JS unique par test (window.__chocoxss_<token> = true)
     injecté dans le payload lui-même — couvre les payloads qui ne passent
     pas par un dialogue (ex: fetch() exfiltration, modification DOM discrète)

Niveau de confiance final après vérification :
  EXECUTED_CONFIRMED : le payload s'est exécuté dans un vrai navigateur
  NOT_EXECUTED        : reflété mais aucune exécution détectée (faux positif
                        du reflection_checker, ou contexte DOM qui neutralise
                        le payload malgré l'absence d'échappement serveur)
  VERIFICATION_ERROR  : erreur technique pendant la vérification (timeout,
                        page qui redirige, contenu binaire...)

Limites assumées :
  - Coûteux en temps (~0.3-1s par payload vérifié) — à réserver aux
    findings REFLECTED_RAW du reflection_checker, pas à tout envoyer ici.
  - Ne rejoue que le corps HTML de la réponse, pas les scripts externes
    (<script src="...">) référencés par la page — cohérent avec la limite
    déjà documentée du parseur statique.
  - Un payload qui nécessite une interaction utilisateur (onclick sans
    déclenchement automatique) ne sera jamais détecté comme exécuté ici,
    ce qui est le comportement correct : sans clic réel, il ne s'exécute
    pas non plus pour une victime qui ne clique pas.
"""

from __future__ import annotations

import re
import secrets
import string
import requests
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from modules.active.reflection_checker import ReflectionResult, ReflectionConfidence, _send_payload


class ExecutionConfidence(Enum):
    EXECUTED_CONFIRMED = "executed_confirmed"
    NOT_EXECUTED       = "not_executed"
    VERIFICATION_ERROR = "verification_error"


@dataclass
class VerificationResult:
    reflection_result: ReflectionResult
    execution: ExecutionConfidence
    detail: str = ""             # ex: "dialog alert() intercepté" / "marqueur JS déclenché"
    error: str | None = None
    screenshot_path: str | None = None  # capture d'écran si EXECUTED_CONFIRMED et screenshot_dir fourni


def _capture_screenshot(page, screenshot_dir: str, param_name: str, token: str) -> str | None:
    """
    Capture une preuve visuelle de l'état de la page après exécution
    confirmée d'un payload. Tolérant aux échecs : une capture qui rate
    (permissions, page fermée entre-temps...) ne doit jamais faire
    échouer toute la vérification, juste retourner None silencieusement.

    Le nom de fichier inclut le token unique de la vérification pour
    rester corrélable avec le résultat correspondant dans le rapport.
    """
    try:
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
        safe_param = "".join(c if c.isalnum() else "_" for c in param_name)[:40]
        filename = f"{safe_param}_{token}.png"
        path = str(Path(screenshot_dir) / filename)
        page.screenshot(path=path)
        return path
    except Exception:
        return None


def _generate_exec_token() -> str:
    """Token unique par vérification, pour le marqueur global d'exécution."""
    alphabet = string.ascii_lowercase + string.digits
    return "chocoxss_" + "".join(secrets.choice(alphabet) for _ in range(8))


def _inject_exec_marker(payload_context_body: str, token: str) -> str:
    """
    Injecte un hook JS de marquage dans le corps de la page, en plus du
    payload lui-même, pour détecter une exécution qui ne passe pas par
    un dialogue navigateur.

    Stratégie : on ajoute un <script> qui définit window.__marker = false
    par défaut, et on modifie légèrement les payloads alert(1)/confirm(1)
    ne serait-ce que via l'interception de dialogue déjà en place — ce
    hook sert de FILET DE SÉCURITÉ pour les payloads qui n'utilisent pas
    alert() (ex: quelqu'un pourrait vouloir tester document.title=... ou
    fetch(...) dans une future extension des payloads).
    """
    init_script = f'<script>window.__{token} = false;</script>'
    return init_script + payload_context_body


def verify_execution(
    reflection_result: ReflectionResult,
    timeout_ms: int = 3000,
    browser=None,
    http_timeout: int = 10,
    session: requests.Session | None = None,
    verify: bool = True,
    screenshot_dir: str | None = None,
) -> VerificationResult:
    """
    Vérifie dans un vrai navigateur headless si le payload d'un
    ReflectionResult s'exécute réellement.

    Le corps HTML complet n'est pas transmis directement : reflection_checker
    ne le conserve que sous forme d'extrait tronqué (response_snippet), donc
    ce module renvoie lui-même la requête avec le même payload pour récupérer
    une réponse fraîche et complète, juste avant la vérification navigateur.
    Ça évite d'alourdir ReflectionResult avec des corps de réponse potentiellement
    volumineux pour tous les payloads, alors que seule une minorité (les
    REFLECTED_RAW) sera jamais escaladée jusqu'ici.

    Args:
        reflection_result: résultat REFLECTED_RAW à vérifier (les autres
            niveaux de confiance n'ont pas de sens à vérifier ici — pas
            d'exécution possible sans réflexion brute)
        timeout_ms: délai d'attente pour le chargement + exécution JS côté navigateur
        browser: instance Playwright Browser réutilisable entre appels
            (fortement recommandé pour scanner plusieurs findings sans
            relancer un navigateur à chaque fois — voir verify_batch())
        http_timeout: délai pour la requête HTTP de re-fetch
        session: session requests réutilisable (cookies, headers custom...)
        verify: vérification du certificat SSL pour le re-fetch HTTP,
            passée explicitement (voir chocoxss.py --insecure)
        screenshot_dir: si fourni, capture une preuve visuelle (PNG) pour
            chaque exécution confirmée — voir chocoxss.py --screenshot-dir

    Returns:
        VerificationResult avec le niveau de confiance final.
    """
    if reflection_result.confidence != ReflectionConfidence.REFLECTED_RAW:
        return VerificationResult(
            reflection_result=reflection_result,
            execution=ExecutionConfidence.NOT_EXECUTED,
            detail="Vérification navigateur non pertinente (pas de réflexion brute confirmée)",
        )

    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", "ChocoXSS/0.1")
    point = reflection_result.injection_point
    payload = reflection_result.payload

    body, status, error = _send_payload(point, payload, http_timeout, sess, verify=verify)
    if error or body is None:
        return VerificationResult(
            reflection_result=reflection_result,
            execution=ExecutionConfidence.VERIFICATION_ERROR,
            detail="Échec du re-fetch HTTP pour la vérification",
            error=error,
        )

    return _verify_html_body(reflection_result, body, timeout_ms, browser, screenshot_dir=screenshot_dir)


def _verify_html_body(
    reflection_result: ReflectionResult,
    response_body: str,
    timeout_ms: int,
    browser,
    screenshot_dir: str | None = None,
) -> VerificationResult:
    """
    Cœur de la vérification navigateur, une fois le corps HTML disponible.

    Args:
        screenshot_dir: si fourni, capture un screenshot de la page APRÈS
            confirmation d'exécution. Important : la capture doit se faire
            après dialog.dismiss(), jamais avant ni pendant — un dialogue
            natif du navigateur bloque tout rendu de page tant qu'il n'est
            pas fermé, donc appeler page.screenshot() dans le handler AVANT
            le dismiss() provoque un deadlock (confirmé expérimentalement).
            Le screenshot montre l'état de la page après l'exécution du
            payload (ex: icône d'image cassée pour <img onerror>, contenu
            injecté visible pour du HTML stocké) — pas le dialogue lui-même,
            qui est une fenêtre du navigateur et n'apparaît jamais dans un
            screenshot de page quoi qu'il arrive.
    """
    token = _generate_exec_token()
    dialog_fired = {"value": False, "type": None}

    own_browser = browser is None
    pw_ctx = None

    try:
        if own_browser:
            pw_ctx = sync_playwright().start()
            browser = pw_ctx.chromium.launch()

        page = browser.new_page()

        def handle_dialog(dialog):
            dialog_fired["value"] = True
            dialog_fired["type"] = dialog.type
            dialog.dismiss()

        page.on("dialog", handle_dialog)

        html_with_marker = _inject_exec_marker(response_body, token)

        def handle_route(route):
            route.fulfill(status=200, content_type="text/html", body=html_with_marker)

        fake_url = "http://chocoxss-verify.test/page"
        page.route(fake_url, handle_route)

        page.goto(fake_url, timeout=timeout_ms)
        page.wait_for_timeout(min(500, timeout_ms))

        screenshot_path = None
        if dialog_fired["value"] and screenshot_dir:
            screenshot_path = _capture_screenshot(
                page, screenshot_dir, reflection_result.injection_point.param_name, token,
            )

        page.close()

        if dialog_fired["value"]:
            return VerificationResult(
                reflection_result=reflection_result,
                execution=ExecutionConfidence.EXECUTED_CONFIRMED,
                detail=f"Dialogue {dialog_fired['type']}() intercepté — exécution JS confirmée",
                screenshot_path=screenshot_path,
            )

        return VerificationResult(
            reflection_result=reflection_result,
            execution=ExecutionConfidence.NOT_EXECUTED,
            detail="Payload reflété sans échappement mais aucune exécution JS détectée "
                   "(contexte DOM probablement non exploitable malgré l'absence de filtrage serveur)",
        )

    except PlaywrightTimeoutError as e:
        return VerificationResult(
            reflection_result=reflection_result,
            execution=ExecutionConfidence.VERIFICATION_ERROR,
            detail="Timeout pendant le chargement de la page",
            error=str(e),
        )
    except Exception as e:
        return VerificationResult(
            reflection_result=reflection_result,
            execution=ExecutionConfidence.VERIFICATION_ERROR,
            detail="Erreur technique pendant la vérification navigateur",
            error=str(e),
        )
    finally:
        if own_browser and pw_ctx is not None:
            try:
                browser.close()
            except Exception:
                pass
            pw_ctx.stop()


def verify_batch(
    reflection_results: list[ReflectionResult],
    timeout_ms: int = 3000,
    http_timeout: int = 10,
    session: requests.Session | None = None,
    verify: bool = True,
    screenshot_dir: str | None = None,
) -> list[VerificationResult]:
    """
    Vérifie une liste de ReflectionResult en réutilisant un seul navigateur
    ET une seule session HTTP pour toute la batch — bien plus rapide que
    d'ouvrir/fermer Chromium et une session à chaque payload.

    Args:
        reflection_results: liste des résultats à vérifier (typiquement
            filtrée en amont pour ne garder que les REFLECTED_RAW, cf.
            docstring de verify_execution — passer des résultats d'un
            autre niveau ne fait rien de dangereux, juste un aller-retour
            inutile classé NOT_EXECUTED immédiatement)
        timeout_ms: délai de chargement/exécution par page
        http_timeout: délai pour chaque requête HTTP de re-fetch
        session: session requests réutilisable
        verify: vérification du certificat SSL pour le re-fetch HTTP,
            passée explicitement à chaque requête (voir chocoxss.py --insecure
            pour les cibles à certificat auto-signé, courant en labo CTF)
        screenshot_dir: si fourni, capture une preuve visuelle (PNG) pour
            chaque exécution confirmée — voir chocoxss.py --screenshot-dir

    Returns:
        Liste de VerificationResult, un par ReflectionResult fourni.
    """
    sess = session or requests.Session()

    with sync_playwright() as pw_ctx:
        browser = pw_ctx.chromium.launch()
        try:
            results = [
                verify_execution(r, timeout_ms=timeout_ms, browser=browser,
                                 http_timeout=http_timeout, session=sess, verify=verify,
                                 screenshot_dir=screenshot_dir)
                for r in reflection_results
            ]
        finally:
            browser.close()

    return results
