"""
ChocoXSS — Vérification DOM XSS en conditions réelles
=========================================================

Complète l'analyse statique (modules/static/) ET headless_verifier.py.

L'analyse statique détecte qu'une source DOM (location.hash, location.search...)
atteint un sink dangereux (innerHTML, eval...) dans le CODE SOURCE de la page.
Mais elle ne confirme jamais que ça s'exécute vraiment — le JS peut être
minifié différemment en prod, chargé dynamiquement, ou le sink peut être
neutralisé par un mécanisme non visible dans l'AST (ex: un intercepteur
global ajouté par un autre script).

headless_verifier.py, de son côté, ne navigue JAMAIS vers la vraie cible :
il REJOUE localement le corps HTML déjà récupéré par requests (via
page.route). C'est parfait pour confirmer un XSS réfléchi/stocké (le
payload est passé par le serveur, donc requests l'a déjà vu), mais ÇA
RATE COMPLÈTEMENT le XSS DOM pur : un payload placé dans le FRAGMENT
d'URL (#...) n'est JAMAIS envoyé au serveur — aucune requête HTTP ne le
transporte, donc requests ne le voit jamais, donc reflection_checker ne
peut structurellement pas le détecter.

Ce module comble ce trou : il ouvre un VRAI navigateur et navigue
RÉELLEMENT vers l'URL cible, avec le payload injecté dans :
  1. Le fragment d'URL (#payload)   — jamais transmis au serveur, le
                                       vecteur DOM XSS le plus classique
  2. Un paramètre de query ajouté   — pour le cas où le JS client lit
                                       location.search sans que le
                                       serveur ne le reflète jamais dans
                                       sa réponse (SPA, JS pur côté client)

Contrairement à headless_verifier.py, ce module fait de VRAIES requêtes
réseau vers la cible — il respecte donc --proxy et --insecure comme le
reste du pipeline requests, mais via la configuration de contexte
navigateur Playwright plutôt que via une session requests. Il importe
aussi les COOKIES de la session requests partagée (voir --cookie/-b) dans
le contexte Playwright avant de naviguer : sans ça, tester une page DOM
XSS derrière une authentification échouerait silencieusement — le
navigateur atterrirait sur un écran de login, jamais sur la page réelle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

import requests
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

from modules.active.payload_engine import generate_marker, build_payloads
from modules.active.headless_verifier import ExecutionConfidence


def _session_cookies_to_playwright(session: requests.Session | None, target_url: str) -> list[dict]:
    """
    Convertit les cookies d'une requests.Session vers le format attendu
    par Playwright's context.add_cookies() — sans ça, une session
    authentifiée passée via --cookie/-b n'a aucun effet sur la navigation
    réelle de dom_verifier.py, qui utilise un contexte navigateur
    entièrement séparé de la session requests du reste du pipeline.

    Args:
        session: session requests dont on veut réutiliser les cookies
            (peut être None — retourne alors une liste vide)
        target_url: URL cible, utilisée comme domaine par défaut pour les
            cookies qui n'en portent pas explicitement un (rare mais
            possible selon comment ils ont été fixés programmatiquement)

    Returns:
        Liste de cookies au format Playwright (name/value/domain/path/secure).
    """
    if session is None or not session.cookies:
        return []

    default_domain = urlparse(target_url).hostname or ""
    playwright_cookies = []

    for cookie in session.cookies:
        domain = cookie.domain or default_domain
        if not domain:
            continue  # Playwright exige un domaine, on ne peut rien inférer
        playwright_cookies.append({
            "name": cookie.name,
            "value": cookie.value,
            "domain": domain,
            "path": cookie.path or "/",
            "secure": bool(cookie.secure),
        })

    return playwright_cookies


@dataclass
class DomVerificationResult:
    target_url: str
    tested_url: str           # URL réellement visitée (avec le payload injecté)
    vector: str                # "url_fragment" | "query_param"
    payload: str
    context: str                # valeur de PayloadContext (ex: "html_body")
    execution: ExecutionConfidence
    detail: str = ""
    error: str | None = None
    screenshot_path: str | None = None  # capture d'écran si EXECUTED_CONFIRMED et screenshot_dir fourni


@dataclass
class DomScanSummary:
    target_url: str
    results: list[DomVerificationResult] = field(default_factory=list)

    @property
    def confirmed(self) -> list[DomVerificationResult]:
        return [r for r in self.results if r.execution == ExecutionConfidence.EXECUTED_CONFIRMED]


def _build_test_url(target_url: str, payload: str, vector: str, query_param_name: str) -> str:
    """Construit l'URL de test avec le payload injecté selon le vecteur choisi."""
    parsed = urlparse(target_url)

    if vector == "url_fragment":
        # Le fragment n'est jamais URL-encodé par le navigateur pour la
        # navigation interne — on l'injecte tel quel après le '#'.
        return urlunparse(parsed._replace(fragment=payload))

    if vector == "query_param":
        existing = parse_qs(parsed.query, keep_blank_values=True)
        existing[query_param_name] = [payload]
        new_query = urlencode(existing, doseq=True)
        return urlunparse(parsed._replace(query=new_query))

    raise ValueError(f"Vecteur inconnu : {vector}")


def _navigate_and_check(
    url: str,
    timeout_ms: int,
    browser,
    proxy: str | None,
    ignore_https_errors: bool,
    cookies: list[dict] | None = None,
    screenshot_dir: str | None = None,
) -> tuple[ExecutionConfidence, str, str | None, str | None]:
    """
    Navigue réellement vers `url` dans un nouveau contexte navigateur et
    détecte l'exécution via interception de dialogue (alert/confirm/prompt),
    comme headless_verifier.py mais sur une vraie connexion réseau.

    Args:
        cookies: cookies au format Playwright à injecter dans le contexte
            AVANT la navigation — voir _session_cookies_to_playwright().
            Sans ça, une session authentifiée (--cookie/-b) n'a aucun
            effet ici : le contexte Playwright est entièrement séparé de
            la session requests utilisée par le reste du pipeline.
        screenshot_dir: si fourni, capture une preuve visuelle (PNG) après
            confirmation d'exécution. Capturée APRÈS dialog.dismiss(),
            jamais avant — un dialogue natif bloque tout rendu de page
            tant qu'il n'est pas fermé (deadlock confirmé expérimentalement
            en appelant page.screenshot() depuis le handler avant dismiss()).

    Returns:
        (execution, detail, error, screenshot_path)
    """
    context_kwargs = {"ignore_https_errors": ignore_https_errors}
    if proxy:
        context_kwargs["proxy"] = {"server": proxy}

    context = browser.new_context(**context_kwargs)

    if cookies:
        try:
            context.add_cookies(cookies)
        except Exception:
            # Un cookie malformé (domaine incompatible avec la cible,
            # format inattendu...) ne doit pas faire échouer toute la
            # vérification — on navigue simplement sans authentification.
            pass

    dialog_fired = {"value": False, "type": None}

    try:
        page = context.new_page()

        def handle_dialog(dialog):
            dialog_fired["value"] = True
            dialog_fired["type"] = dialog.type
            dialog.dismiss()

        page.on("dialog", handle_dialog)

        page.goto(url, timeout=timeout_ms, wait_until="load")
        page.wait_for_timeout(min(500, timeout_ms))

        if dialog_fired["value"]:
            screenshot_path = None
            if screenshot_dir:
                screenshot_path = _capture_dom_screenshot(page, screenshot_dir, url)
            return (
                ExecutionConfidence.EXECUTED_CONFIRMED,
                f"Dialogue {dialog_fired['type']}() intercepté lors de la navigation réelle",
                None,
                screenshot_path,
            )
        return ExecutionConfidence.NOT_EXECUTED, "Aucune exécution détectée sur la vraie cible", None, None

    except PlaywrightTimeoutError as e:
        return ExecutionConfidence.VERIFICATION_ERROR, "Timeout lors de la navigation", str(e), None
    except Exception as e:
        return ExecutionConfidence.VERIFICATION_ERROR, "Erreur technique lors de la navigation", str(e), None
    finally:
        context.close()


def _capture_dom_screenshot(page, screenshot_dir: str, tested_url: str) -> str | None:
    """
    Capture une preuve visuelle après exécution confirmée en navigation
    réelle. Tolérant aux échecs — voir headless_verifier._capture_screenshot
    pour le même principe.
    """
    try:
        Path(screenshot_dir).mkdir(parents=True, exist_ok=True)
        import secrets as _secrets
        import string as _string
        token = "".join(_secrets.choice(_string.ascii_lowercase + _string.digits) for _ in range(8))
        parsed = urlparse(tested_url)
        safe_path = "".join(c if c.isalnum() else "_" for c in parsed.path)[:40] or "root"
        filename = f"dom_{safe_path}_{token}.png"
        path = str(Path(screenshot_dir) / filename)
        page.screenshot(path=path)
        return path
    except Exception:
        return None


def verify_dom_xss(
    target_url: str,
    timeout_ms: int = 5000,
    vectors: tuple[str, ...] = ("url_fragment", "query_param"),
    query_param_name: str = "chocoxss",
    proxy: str | None = None,
    ignore_https_errors: bool = False,
    browser=None,
    session: requests.Session | None = None,
    screenshot_dir: str | None = None,
) -> DomScanSummary:
    """
    Teste le XSS DOM en conditions réelles : navigue un vrai navigateur
    vers la vraie cible avec chaque payload standard injecté dans le
    fragment d'URL et/ou un paramètre de query ajouté.

    Args:
        target_url: URL de la cible (sans payload — il sera ajouté ici)
        timeout_ms: délai de navigation + exécution par test
        vectors: vecteurs à tester — "url_fragment" (jamais transmis au
            serveur, LE vecteur DOM XSS classique) et/ou "query_param"
            (pour un JS client qui lit location.search sans jamais faire
            réémettre la valeur par le serveur)
        query_param_name: nom du paramètre de query ajouté pour le
            vecteur "query_param" (évite d'écraser un paramètre existant
            de l'URL cible)
        proxy: URL de proxy à appliquer au contexte navigateur (voir
            chocoxss.py --proxy) — contrairement à headless_verifier.py,
            ce module fait de VRAIES requêtes réseau vers la cible
        ignore_https_errors: équivalent --insecure pour la navigation
            réelle (certificat auto-signé)
        browser: instance Playwright Browser réutilisable entre appels
        session: session requests dont les cookies sont importés dans le
            contexte Playwright avant chaque navigation — indispensable
            pour tester une page DOM XSS derrière une authentification
            (--cookie/-b). Sans ça, la navigation réelle se fait
            déconnectée et peut atterrir sur un écran de login au lieu
            de la vraie page, sans erreur explicite pour le signaler.
        screenshot_dir: si fourni, capture une preuve visuelle (PNG) pour
            chaque exécution confirmée — voir chocoxss.py --screenshot-dir

    Returns:
        DomScanSummary avec un DomVerificationResult par (payload × vecteur).
    """
    summary = DomScanSummary(target_url=target_url)
    marker = generate_marker()
    payloads = build_payloads(marker)
    cookies = _session_cookies_to_playwright(session, target_url)

    own_browser = browser is None
    pw_ctx = None

    try:
        if own_browser:
            pw_ctx = sync_playwright().start()
            browser = pw_ctx.chromium.launch()

        for payload, context, description in payloads:
            for vector in vectors:
                try:
                    tested_url = _build_test_url(target_url, payload, vector, query_param_name)
                except ValueError as e:
                    summary.results.append(DomVerificationResult(
                        target_url=target_url, tested_url=target_url, vector=vector,
                        payload=payload, context=context.value,
                        execution=ExecutionConfidence.VERIFICATION_ERROR,
                        error=str(e),
                    ))
                    continue

                execution, detail, error, screenshot_path = _navigate_and_check(
                    tested_url, timeout_ms, browser, proxy, ignore_https_errors, cookies=cookies,
                    screenshot_dir=screenshot_dir,
                )
                summary.results.append(DomVerificationResult(
                    target_url=target_url, tested_url=tested_url, vector=vector,
                    payload=payload, context=context.value,
                    execution=execution, detail=detail, error=error,
                    screenshot_path=screenshot_path,
                ))
    finally:
        if own_browser and pw_ctx is not None:
            try:
                browser.close()
            except Exception:
                pass
            pw_ctx.stop()

    return summary


def verify_dom_xss_multi(
    target_urls: list[str],
    timeout_ms: int = 5000,
    vectors: tuple[str, ...] = ("url_fragment", "query_param"),
    query_param_name: str = "chocoxss",
    proxy: str | None = None,
    ignore_https_errors: bool = False,
    session: requests.Session | None = None,
    screenshot_dir: str | None = None,
) -> DomScanSummary:
    """
    Teste le XSS DOM en conditions réelles sur PLUSIEURS pages, en
    réutilisant un seul navigateur pour toutes plutôt que d'en relancer
    un par page — même principe que verify_batch() côté headless_verifier.

    Comble le trou laissé par verify_dom_xss() seul : --dom-xss ne
    testait jusqu'ici que l'URL de départ, jamais les pages découvertes
    par un crawl récursif (--crawl-depth). Une cible avec du DOM XSS sur
    une page profonde du site n'était donc jamais atteinte, même avec
    --crawl-depth 3 — le scan actif classique couvre bien toutes les
    pages du crawl, mais --dom-xss restait limité à args.url.

    Args:
        target_urls: liste des URLs à tester (typiquement les pages
            visitées par un crawl récursif — voir crawler.RecursiveCrawlResult.pages_visited)
        (autres args : identiques à verify_dom_xss())

    Returns:
        DomScanSummary unique fusionnant les résultats de toutes les
        pages testées — chaque DomVerificationResult garde son propre
        target_url/tested_url pour distinguer d'où vient chaque finding.
    """
    merged = DomScanSummary(target_url=target_urls[0] if target_urls else "")

    if not target_urls:
        return merged

    with sync_playwright() as pw_ctx:
        browser = pw_ctx.chromium.launch()
        try:
            for url in target_urls:
                page_summary = verify_dom_xss(
                    url, timeout_ms=timeout_ms, vectors=vectors,
                    query_param_name=query_param_name, proxy=proxy,
                    ignore_https_errors=ignore_https_errors, browser=browser,
                    session=session, screenshot_dir=screenshot_dir,
                )
                merged.results.extend(page_summary.results)
        finally:
            browser.close()

    return merged
