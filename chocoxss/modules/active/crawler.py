"""
ChocoXSS — Crawler (mode actif)
==================================

Découvre les points d'injection potentiels sur une URL donnée :
  1. Paramètres de la query string de l'URL elle-même
  2. Formulaires (<form>) présents dans la page — champs input/textarea/select

Chaque point d'injection est représenté par un InjectionPoint, indépendant
de la manière dont il sera testé ensuite (c'est payload_engine.py et
reflection_checker.py qui s'en chargent).

Deux modes :
  - crawl()           : une seule page (comportement historique, par défaut)
  - crawl_recursive()  : suit les liens <a href> découverts jusqu'à une
                         profondeur/nombre de pages donné, pour couvrir
                         une surface plus large qu'un point d'entrée unique
                         (ex: tout un site WordPress plutôt que juste
                         wp-login.php) — voir chocoxss.py --crawl-depth.

Limites assumées pour la V1 :
  - Pas de rendu JavaScript : un formulaire généré dynamiquement en JS
    après chargement de la page ne sera pas détecté (nécessiterait Playwright).
  - crawl_recursive() ne suit que les liens <a href> présents dans le HTML
    statique — pas de clic sur des boutons JS, pas de découverte via
    sitemap.xml ou robots.txt (à ajouter si besoin).
  - Restreint au même domaine par défaut (safety) — voir allow_external.
  - Les champs "hidden" sont inclus par défaut car ils sont parfois
    reflétés sans validation côté serveur (CSRF tokens exclus par heuristique).
"""

from __future__ import annotations

import requests
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup


# Noms de champs qu'on exclut par défaut car quasi-jamais exploitables
# et source de bruit inutile (tokens anti-CSRF, etc.)
SKIP_FIELD_NAMES = {"csrf_token", "csrf", "_token", "authenticity_token", "__requestverificationtoken"}

DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "ChocoXSS/0.1 (+authorized security testing)"


@dataclass
class InjectionPoint:
    """Un point d'entrée testable : un paramètre GET ou un champ de formulaire."""
    url: str                    # URL cible de la requête (action du form ou URL de base)
    method: str                 # "GET" ou "POST"
    param_name: str             # nom du paramètre à injecter
    param_kind: str             # "url_query" | "form_field"
    other_params: dict          # autres paramètres à envoyer tels quels (valeurs par défaut)
    field_type: str = "text"    # type HTML du champ (text, hidden, textarea...)
    source_snippet: str = ""    # extrait HTML/URL d'origine, pour le rapport
    page_url: str = ""          # URL de la PAGE où le champ a été trouvé (peut différer de
                                 # `url` si l'action du form pointe ailleurs) — nécessaire
                                 # pour rafraîchir un token CSRF avant soumission, voir
                                 # crawler.refresh_csrf_field() et chocoxss.py --refresh-csrf


@dataclass
class CrawlResult:
    target_url: str
    injection_points: list[InjectionPoint] = field(default_factory=list)
    forms_found: int = 0
    fetch_error: str | None = None
    status_code: int | None = None


def _extract_url_params(url: str) -> list[InjectionPoint]:
    """Extrait les paramètres de la query string de l'URL cible elle-même."""
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return []

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    points = []
    for name in params:
        other = {k: v[0] for k, v in params.items() if k != name}
        points.append(InjectionPoint(
            url=base_url,
            method="GET",
            param_name=name,
            param_kind="url_query",
            other_params=other,
            source_snippet=f"?{name}={params[name][0]}",
        ))
    return points


def _extract_form_points(html: str, base_url: str) -> tuple[list[InjectionPoint], int]:
    """Extrait tous les champs testables de tous les formulaires de la page."""
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    points = []

    for form in forms:
        action = form.get("action", "").strip()
        method = form.get("method", "get").strip().upper()
        if method not in ("GET", "POST"):
            method = "GET"

        form_url = urljoin(base_url, action) if action else base_url

        # Collecter tous les champs avec leur valeur par défaut
        fields = {}
        field_types = {}
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            field_type = inp.get("type", "text").lower() if inp.name == "input" else inp.name
            if field_type in ("submit", "button", "reset", "image", "file"):
                continue
            value = inp.get("value", "")
            fields[name] = value
            field_types[name] = field_type

        # Un InjectionPoint par champ testable (on exclut les tokens CSRF connus)
        for name, field_type in field_types.items():
            if name.lower() in SKIP_FIELD_NAMES:
                continue
            other = {k: v for k, v in fields.items() if k != name}
            points.append(InjectionPoint(
                url=form_url,
                method=method,
                param_name=name,
                param_kind="form_field",
                other_params=other,
                field_type=field_type,
                source_snippet=f'<form action="{action}" method="{method.lower()}"> champ "{name}"',
                page_url=base_url,
            ))

    return points, len(forms)


def crawl(
    url: str,
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
    verify: bool = True,
) -> CrawlResult:
    """
    Récupère une URL et en extrait tous les points d'injection découvrables
    (paramètres de la query string + champs de formulaires).

    Args:
        url: URL cible à analyser
        timeout: délai max en secondes pour la requête HTTP
        session: session requests réutilisable (cookies, headers custom...)
        verify: vérification du certificat SSL. Passé explicitement à
            chaque requête plutôt que de compter sur l'attribut
            session.verify, qui n'est pas toujours respecté selon les
            versions de requests/urllib3 — voir chocoxss.py --insecure.

    Returns:
        CrawlResult avec la liste des InjectionPoint trouvés.
    """
    result = CrawlResult(target_url=url)

    # 1. Params de l'URL elle-même — ne nécessite pas de requête HTTP
    result.injection_points.extend(_extract_url_params(url))

    # 2. Récupérer la page pour en extraire les formulaires
    sess = session or requests.Session()
    # setdefault (pas =) : si l'appelant a déjà fixé un User-Agent custom
    # sur la session partagée (--header côté chocoxss.py), on le respecte.
    sess.headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    try:
        resp = sess.get(
            url,
            timeout=timeout,
            verify=verify,
        )
        result.status_code = resp.status_code
    except requests.exceptions.RequestException as e:
        result.fetch_error = str(e)
        return result

    form_points, n_forms = _extract_form_points(resp.text, url)
    result.injection_points.extend(form_points)
    result.forms_found = n_forms

    return result


# ═══════════════════════════════════════════════════════════════════════════
# Crawl récursif — suit les liens pour couvrir plusieurs pages
# ═══════════════════════════════════════════════════════════════════════════

# Extensions de fichiers non-HTML à ne pas suivre (images, styles, scripts,
# archives...) — évite de télécharger inutilement des binaires en cherchant
# des formulaires dedans.
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".js", ".mjs",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".webm",
    ".woff", ".woff2", ".ttf", ".eot",
    ".xml", ".json",
}


@dataclass
class RecursiveCrawlResult:
    start_url: str
    injection_points: list[InjectionPoint] = field(default_factory=list)
    pages_visited: list[str] = field(default_factory=list)
    pages_skipped_external: list[str] = field(default_factory=list)
    fetch_errors: dict[str, str] = field(default_factory=dict)
    forms_found_total: int = 0
    max_pages_reached: bool = False


def _normalize_url(url: str) -> str:
    """
    Normalise une URL pour la déduplication : retire le fragment (#...)
    et la barre oblique finale redondante, pour éviter de revisiter
    /page et /page/ ou /page#section comme deux URLs différentes.
    """
    parsed = urlparse(url)
    path = parsed.path.rstrip("/") or "/"
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def _extract_links(html: str, base_url: str) -> list[str]:
    """Extrait tous les liens <a href> absolus d'une page, HTML/navigables uniquement."""
    soup = BeautifulSoup(html, "html.parser")
    links = []

    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue

        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)

        if parsed.scheme not in ("http", "https"):
            continue

        # Ignorer les fichiers non-HTML évidents (par extension)
        path_lower = parsed.path.lower()
        if any(path_lower.endswith(ext) for ext in _SKIP_EXTENSIONS):
            continue

        links.append(absolute)

    return links


def crawl_recursive(
    start_url: str,
    max_depth: int = 1,
    max_pages: int = 20,
    allow_external: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
    session: requests.Session | None = None,
    verify: bool = True,
) -> RecursiveCrawlResult:
    """
    Crawl récursif en largeur (BFS) : part de start_url, suit les liens
    <a href> découverts jusqu'à max_depth sauts, et agrège les points
    d'injection de toutes les pages visitées.

    Args:
        start_url: URL de départ
        max_depth: nombre de sauts de liens à suivre (0 = équivalent à
            crawl() simple, 1 = start_url + pages qu'elle lie directement...)
        max_pages: plafond dur du nombre total de pages visitées, quelle
            que soit la profondeur — garde-fou contre un crawl qui explose
            sur un site avec énormément de liens internes
        allow_external: si False (défaut), ne suit que les liens vers le
            même domaine que start_url — évite de partir crawler tout
            le web par accident depuis un lien externe
        timeout: délai HTTP par page
        session: session requests réutilisable (cookies, headers custom)
        verify: vérification du certificat SSL, passée explicitement à
            chaque requête (voir chocoxss.py --insecure)

    Returns:
        RecursiveCrawlResult avec les points d'injection agrégés et la
        liste des pages effectivement visitées (pour le rapport).
    """
    result = RecursiveCrawlResult(start_url=start_url)

    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", DEFAULT_USER_AGENT)

    start_domain = urlparse(start_url).netloc
    visited: set[str] = set()
    # File BFS : (url, profondeur_actuelle)
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])

    while queue:
        if len(visited) >= max_pages:
            result.max_pages_reached = True
            break

        url, depth = queue.popleft()
        normalized = _normalize_url(url)

        if normalized in visited:
            continue
        visited.add(normalized)

        # Points d'injection depuis la query string, sans requête HTTP
        result.injection_points.extend(_extract_url_params(url))

        try:
            resp = sess.get(url, timeout=timeout, verify=verify)
        except requests.exceptions.RequestException as e:
            result.fetch_errors[url] = str(e)
            continue

        result.pages_visited.append(url)

        content_type = resp.headers.get("Content-Type", "")
        if "html" not in content_type and content_type:
            # Réponse non-HTML (JSON d'API, binaire...) : pas de formulaire
            # à en extraire, mais la page compte comme visitée.
            continue

        form_points, n_forms = _extract_form_points(resp.text, url)
        result.injection_points.extend(form_points)
        result.forms_found_total += n_forms

        # Poursuivre le crawl si on n'a pas atteint la profondeur max
        if depth >= max_depth:
            continue

        for link in _extract_links(resp.text, url):
            link_domain = urlparse(link).netloc
            if not allow_external and link_domain != start_domain:
                if link not in result.pages_skipped_external:
                    result.pages_skipped_external.append(link)
                continue
            if _normalize_url(link) not in visited:
                queue.append((link, depth + 1))

    return result


# ═══════════════════════════════════════════════════════════════════════════
# Rafraîchissement de token CSRF
# ═══════════════════════════════════════════════════════════════════════════

def refresh_csrf_field(
    point: InjectionPoint,
    session: requests.Session,
    timeout: int = DEFAULT_TIMEOUT,
    verify: bool = True,
) -> dict | None:
    """
    Re-fetch la page d'origine du formulaire (point.page_url) et cherche
    une valeur fraîche pour tout champ CSRF connu présent dans
    point.other_params, pour remplacer une valeur devenue périmée.

    Problème résolu : un token CSRF capturé lors du crawl initial peut être
    régénéré à chaque GET par le serveur (comportement courant — WordPress
    nonces, Django CSRF, Rails authenticity_token...). Réutiliser tel quel
    ce token pour plusieurs soumissions successives peut faire échouer les
    payloads suivants avec un 403/redirect, alors que le point d'injection
    est peut-être bien vulnérable — c'est un faux négatif silencieux.

    Limite assumée : rafraîchit une fois par appel, pas par soumission
    individuelle — couvre le cas courant d'un token périmé par le temps
    écoulé pendant le scan, PAS le cas plus rare d'un token à usage unique
    strict (qui nécessiterait un rafraîchissement avant CHAQUE payload,
    bien plus coûteux en requêtes) — voir chocoxss.py --refresh-csrf.

    Args:
        point: point d'injection dont on veut rafraîchir les champs CSRF
        session: session requests (doit conserver les cookies de session
            entre la page du formulaire et la soumission — c'est le cas
            normal avec une requests.Session() réutilisée)
        timeout: délai de la requête de rafraîchissement
        verify: vérification SSL, passée explicitement (voir --insecure)

    Returns:
        Un nouveau dict other_params avec les champs CSRF connus mis à
        jour, ou None si rien à rafraîchir (pas de champ CSRF détecté,
        pas de page_url connue, ou échec de la requête — dans ce cas
        l'appelant doit retomber sur les other_params d'origine plutôt
        que de bloquer le scan).
    """
    csrf_keys = [k for k in point.other_params if k.lower() in SKIP_FIELD_NAMES]
    if not csrf_keys or not point.page_url:
        return None

    try:
        resp = session.get(point.page_url, timeout=timeout, verify=verify)
    except requests.exceptions.RequestException:
        return None

    soup = BeautifulSoup(resp.text, "html.parser")
    fresh_values = {}
    for inp in soup.find_all("input"):
        name = inp.get("name")
        if name and name in csrf_keys:
            fresh_values[name] = inp.get("value", "")

    if not fresh_values:
        return None

    updated = dict(point.other_params)
    updated.update(fresh_values)
    return updated
