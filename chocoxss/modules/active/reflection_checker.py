"""
ChocoXSS — Reflection Checker (mode actif)
=============================================

Envoie les payloads générés par payload_engine.py sur chaque InjectionPoint
découvert par crawler.py, puis analyse la réponse HTTP pour déterminer si
le payload est réfléchi de façon exploitable.

Logique de détection (le point technique important) :
  Chercher uniquement le marqueur canari dans la réponse NE SUFFIT PAS,
  car un payload encodé par le serveur contient toujours le marqueur en
  clair (ex: &lt;script&gt;/*cxss123*/&lt;/script&gt; contient "cxss123").
  Il faut donc vérifier si le PAYLOAD COMPLET, avec ses caractères spéciaux
  (<, >, ", ') apparaît tel quel dans la réponse — c'est ça qui prouve que
  le serveur n'a pas échappé la sortie.

Niveaux de confiance :
  REFLECTED_RAW      : le payload complet apparaît sans aucun encodage
                        → très probablement exploitable
  REFLECTED_ENCODED   : le marqueur apparaît mais le payload a été encodé
                        (&lt;, &quot;...) → probablement safe
  REFLECTED_PARTIAL   : le marqueur apparaît mais pas le payload complet
                        (filtrage partiel : certains caractères supprimés)
                        → à vérifier manuellement, comportement ambigu
  NOT_REFLECTED       : ni le marqueur ni le payload n'apparaissent
                        → probablement filtré/rejeté ou point non exploitable

Limites assumées pour la V1 :
  - Pas de rendu JS : on ne confirme jamais qu'un payload s'EXÉCUTE
    réellement, seulement qu'il est réfléchi de façon non échappée dans
    le HTML brut renvoyé. Un payload REFLECTED_RAW dans du texte qui finit
    dans un attribut déjà fermé, par exemple, pourrait ne pas s'exécuter
    en pratique — la vérification finale doit se faire dans un navigateur.
  - Ne gère pas nativement les CSRF tokens dynamiques par requête (un champ
    hidden re-généré à chaque GET empêcherait le POST suivant) — à améliorer
    en V1.5 si besoin en récupérant un token frais avant chaque injection.
"""

from __future__ import annotations

import time
import re
import html as html_module
import requests
from dataclasses import dataclass, field, replace
from enum import Enum

from modules.active.crawler import InjectionPoint, refresh_csrf_field
from modules.common.concurrency import run_concurrent
from modules.active.payload_engine import generate_marker, build_payloads, PayloadContext


class ReflectionConfidence(Enum):
    REFLECTED_RAW     = "reflected_raw"
    REFLECTED_ENCODED = "reflected_encoded"
    REFLECTED_PARTIAL = "reflected_partial"
    NOT_REFLECTED     = "not_reflected"
    REQUEST_ERROR     = "request_error"


@dataclass
class ReflectionResult:
    injection_point: InjectionPoint
    payload: str
    context: PayloadContext
    description: str
    confidence: ReflectionConfidence
    response_status: int | None = None
    error: str | None = None
    response_snippet: str = ""   # extrait de la réponse autour de la réflexion, pour le rapport
    bypass_technique: str | None = None  # non-None si ce résultat vient d'une variante de contournement
    original_payload: str | None = None  # payload standard qui a déclenché ce retry (si bypass_technique)


@dataclass
class ScanSummary:
    target_url: str
    marker: str
    results: list[ReflectionResult] = field(default_factory=list)
    injection_points_tested: int = 0

    @property
    def vulnerable_results(self) -> list[ReflectionResult]:
        return [r for r in self.results if r.confidence == ReflectionConfidence.REFLECTED_RAW]

    @property
    def suspicious_results(self) -> list[ReflectionResult]:
        return [r for r in self.results if r.confidence == ReflectionConfidence.REFLECTED_PARTIAL]


def _send_payload(
    point: InjectionPoint, payload: str, timeout: int, session: requests.Session, verify: bool = True,
) -> tuple[str | None, int | None, str | None]:
    """
    Envoie une requête HTTP avec le payload injecté dans le bon paramètre.

    Args:
        verify: vérification du certificat SSL, passée explicitement
            (voir crawl() pour l'explication du pourquoi).

    Returns:
        (corps_de_la_réponse, status_code, erreur)
    """
    params = dict(point.other_params)
    params[point.param_name] = payload

    try:
        if point.method == "GET":
            resp = session.get(point.url, params=params, timeout=timeout, verify=verify)
        else:
            resp = session.post(point.url, data=params, timeout=timeout, verify=verify)
        return resp.text, resp.status_code, None
    except requests.exceptions.RequestException as e:
        return None, None, str(e)


def _classify_reflection(payload: str, marker: str, body: str, context: PayloadContext) -> tuple[ReflectionConfidence, str]:
    """
    Détermine le niveau de confiance de la réflexion dans le corps de réponse.

    Méthode : plutôt que de chercher "des caractères dangereux à proximité"
    (fragile — la page elle-même contient toujours des < > " dans son propre
    balisage, ce qui produisait des faux REFLECTED_PARTIAL), on compare le
    payload à deux versions du corps de réponse :

      1. Le corps brut          → si le payload y est identique  → RAW
      2. Le corps HTML-décodé   → si le payload y réapparaît     → ENCODED
         (peu importe que le serveur utilise &#39; ou &#x27; ou &apos;,
         html.unescape() gère toutes les formes d'entités standard)
      3. Ni l'un ni l'autre     → PARTIAL (des caractères ont été réellement
         supprimés/modifiés, pas juste échappés — filtrage actif à contourner)

    Cas particulier URL_CONTEXT : un payload "javascript:..." n'est dangereux
    que s'il atterrit RÉELLEMENT dans un attribut href/src. S'il est reflété
    en texte brut sans caractère HTML à échapper, il est inoffensif même si
    techniquement "brut" — on le requalifie donc en ENCODED (= sans risque ici).

    Returns:
        (confidence, extrait_de_contexte)
    """
    if marker not in body:
        return ReflectionConfidence.NOT_REFLECTED, ""

    idx = body.find(marker)
    start = max(0, idx - 40)
    end = min(len(body), idx + len(marker) + 40)
    snippet = body[start:end].replace("\n", " ").strip()

    if payload in body:
        if context == PayloadContext.URL_CONTEXT:
            attr_context = any(
                attr in body[max(0, idx - 60):idx].lower()
                for attr in ('href="', "href='", 'src="', "src='")
            )
            if not attr_context:
                return ReflectionConfidence.REFLECTED_ENCODED, snippet  # inoffensif ici
        return ReflectionConfidence.REFLECTED_RAW, snippet

    # Le payload brut n'apparaît pas tel quel : vérifier si un décodage
    # d'entités HTML le fait réapparaître intact (= safe, juste échappé).
    if payload in html_module.unescape(body):
        return ReflectionConfidence.REFLECTED_ENCODED, snippet

    # Ni brut ni récupérable par décodage d'entités : le serveur a réellement
    # modifié/supprimé une partie du payload (filtrage actif).
    return ReflectionConfidence.REFLECTED_PARTIAL, snippet


# Patterns "dangereux reconstitués" pour la classification des variantes
# de contournement. Contrairement à _classify_reflection (qui compare le
# payload ENVOYÉ au texte brut de la réponse), certaines techniques comme
# nested_tag transforment délibérément le payload à travers le filtre :
# <scr<script>ipt>X</scr</script>ipt>  →  filtre supprime "<script>" une fois
#                                       →  <script>X</script> (reconstitué !)
# Le payload reçu ne matchera donc JAMAIS littéralement — il faut chercher
# si un pattern exécutable a été RECONSTITUÉ dans la réponse, peu importe
# sa ressemblance avec le payload d'origine.
_DANGEROUS_PATTERN_TEMPLATES = [
    r'<script[^>]*>[^<]*{marker}[^<]*</script>',        # balise script reconstituée
    r'on\w+\s*=\s*["\']?[^"\'>]*{marker}',                # attribut événement (onerror, onload...)
    r'javascript\s*:[^>\s]*{marker}',                     # URI javascript: reconstituée
    r'<(?:img|svg|iframe|body|input)[^>]*{marker}',       # balise porteuse d'événement
]


def _classify_bypass_reflection(marker: str, body: str) -> tuple[ReflectionConfidence, str]:
    """
    Classification spécifique aux variantes de contournement (bypass_payloads.py).

    Ne compare PAS le payload envoyé au texte de la réponse (il a été
    délibérément conçu pour être transformé par le filtre) — cherche plutôt
    si un pattern dangereux exécutable a été RECONSTITUÉ dans la réponse
    brute, peu importe sa forme finale.

    Returns:
        (confidence, extrait_de_contexte)
    """
    if marker not in body:
        return ReflectionConfidence.NOT_REFLECTED, ""

    idx = body.find(marker)
    start = max(0, idx - 40)
    end = min(len(body), idx + len(marker) + 40)
    snippet = body[start:end].replace("\n", " ").strip()

    escaped_marker = re.escape(marker)
    for template in _DANGEROUS_PATTERN_TEMPLATES:
        pattern = re.compile(template.format(marker=escaped_marker), re.IGNORECASE | re.DOTALL)
        if pattern.search(body):
            return ReflectionConfidence.REFLECTED_RAW, snippet

    # Le marqueur est présent mais aucun pattern exécutable reconstitué :
    # le contournement a échoué, le filtre tient bon sur cette variante.
    return ReflectionConfidence.REFLECTED_PARTIAL, snippet


def scan_injection_point(
    point: InjectionPoint,
    marker: str,
    timeout: int = 10,
    delay: float = 0.0,
    session: requests.Session | None = None,
    verify: bool = True,
    bypass_on_partial: bool = False,
    refresh_csrf: bool = False,
) -> list[ReflectionResult]:
    """
    Teste tous les payloads (toutes catégories confondues) sur un seul
    InjectionPoint et retourne un ReflectionResult par payload testé.

    Args:
        bypass_on_partial: si True, chaque payload standard qui revient
            REFLECTED_PARTIAL (preuve d'un filtrage actif) déclenche
            automatiquement un retry avec les variantes de contournement
            de bypass_payloads.py ciblant le même contexte — voir
            chocoxss.py --bypass. Désactivé par défaut pour ne pas
            multiplier le nombre de requêtes sur un scan standard.
        refresh_csrf: si True et que le point est un formulaire POST avec
            un champ CSRF connu, rafraîchit ce champ UNE FOIS avant de
            tester tous les payloads du point (pas à chaque soumission —
            voir crawler.refresh_csrf_field() pour la limite assumée sur
            les tokens à usage unique strict) — voir chocoxss.py --refresh-csrf.
    """
    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", "ChocoXSS/0.1")
    payloads = build_payloads(marker)
    results = []

    if refresh_csrf and point.method == "POST":
        fresh_params = refresh_csrf_field(point, sess, timeout=timeout, verify=verify)
        if fresh_params is not None:
            point = replace(point, other_params=fresh_params)

    for payload, context, description in payloads:
        if delay:
            time.sleep(delay)

        body, status, error = _send_payload(point, payload, timeout, sess, verify=verify)

        if error:
            results.append(ReflectionResult(
                injection_point=point, payload=payload, context=context,
                description=description, confidence=ReflectionConfidence.REQUEST_ERROR,
                error=error,
            ))
            continue

        confidence, snippet = _classify_reflection(payload, marker, body, context)
        results.append(ReflectionResult(
            injection_point=point, payload=payload, context=context,
            description=description, confidence=confidence,
            response_status=status, response_snippet=snippet,
        ))

        if bypass_on_partial and confidence == ReflectionConfidence.REFLECTED_PARTIAL:
            results.extend(_retry_with_bypasses(
                point, marker, context, payload, timeout, delay, sess, verify,
            ))

    return results


def _retry_with_bypasses(
    point: InjectionPoint,
    marker: str,
    context: PayloadContext,
    original_payload: str,
    timeout: int,
    delay: float,
    session: requests.Session,
    verify: bool,
) -> list[ReflectionResult]:
    """
    Relance les variantes de contournement (bypass_payloads.py) ciblant
    le même contexte que le payload standard qui a révélé un filtrage
    actif (REFLECTED_PARTIAL).
    """
    from modules.active.bypass_payloads import build_bypass_payloads

    results = []
    bypass_variants = build_bypass_payloads(marker, context=context)

    for payload, technique, ctx, description in bypass_variants:
        if delay:
            time.sleep(delay)

        body, status, error = _send_payload(point, payload, timeout, session, verify=verify)

        if error:
            results.append(ReflectionResult(
                injection_point=point, payload=payload, context=ctx,
                description=description, confidence=ReflectionConfidence.REQUEST_ERROR,
                error=error, bypass_technique=technique.value, original_payload=original_payload,
            ))
            continue

        confidence, snippet = _classify_bypass_reflection(marker, body)
        results.append(ReflectionResult(
            injection_point=point, payload=payload, context=ctx,
            description=description, confidence=confidence,
            response_status=status, response_snippet=snippet,
            bypass_technique=technique.value, original_payload=original_payload,
        ))

    return results


def scan_all_points(
    injection_points: list[InjectionPoint],
    target_url: str,
    timeout: int = 10,
    delay: float = 0.0,
    session: requests.Session | None = None,
    verify: bool = True,
    bypass_on_partial: bool = False,
    refresh_csrf: bool = False,
    max_workers: int = 1,
) -> ScanSummary:
    """
    Point d'entrée principal du mode actif : teste tous les points
    d'injection découverts par le crawler avec un marqueur unique
    partagé pour l'ensemble du scan (permet de dédupliquer/corréler
    facilement dans le rapport final).

    Args:
        session: session requests réutilisable.
        verify: vérification du certificat SSL, passée explicitement à
            chaque requête (pas seulement via session.verify, qui n'est
            pas fiable selon les versions de requests/urllib3) — voir
            chocoxss.py --insecure pour les cibles à certificat
            auto-signé (courant en labo CTF).
        bypass_on_partial: relance automatiquement des variantes de
            contournement sur tout résultat REFLECTED_PARTIAL — voir
            chocoxss.py --bypass.
        refresh_csrf: rafraîchit le token CSRF d'un point POST avant de
            tester ses payloads — voir chocoxss.py --refresh-csrf.
        max_workers: 1 (défaut) = un point d'injection à la fois, comme
            avant ce paramètre. > 1 = teste plusieurs points en parallèle
            via un pool de threads — voir chocoxss.py --threads. La
            granularité de parallélisation est le POINT D'INJECTION, pas
            le payload individuel : chaque point garde sa boucle de
            payloads séquentielle en interne (le --delay reste donc
            significatif PAR POINT), seuls les points tournent en
            parallèle entre eux.
    """
    marker = generate_marker()
    summary = ScanSummary(target_url=target_url, marker=marker)
    sess = session or requests.Session()

    tasks = [
        (lambda p=point: scan_injection_point(
            p, marker, timeout=timeout, delay=delay, session=sess,
            verify=verify, bypass_on_partial=bypass_on_partial, refresh_csrf=refresh_csrf,
        ))
        for point in injection_points
    ]
    all_results = run_concurrent(tasks, max_workers=max_workers)

    for results in all_results:
        summary.results.extend(results)
    summary.injection_points_tested = len(injection_points)

    return summary
