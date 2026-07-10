"""
ChocoXSS — Détection de XSS stocké (mode actif)
===================================================

Complète reflection_checker.py, qui ne teste que le XSS réfléchi immédiat
(payload envoyé et cherché dans la RÉPONSE DE LA MÊME REQUÊTE). Beaucoup
de XSS réels sont stockés : le payload est soumis sur une page (formulaire
de commentaire, champ de profil...) et ne réapparaît que plus tard, sur
une page différente — après modération, sur la page de profil public,
dans un flux d'activité, etc.

Principe :
  1. Soumettre chaque payload sur un InjectionPoint (comme reflection_checker)
  2. Au lieu de chercher le marqueur dans la réponse immédiate, aller
     charger une ou plusieurs "check_urls" fournies par l'utilisateur
     (l'endroit où il pense que la valeur stockée va ressortir)
  3. Réutiliser la même classification que le réfléchi (_classify_reflection)
     pour déterminer si le payload stocké est RAW/ENCODED/PARTIAL

Ce module ne devine PAS automatiquement où une valeur stockée va
réapparaître — il faut le préciser via --check-url. C'est un choix
délibéré : deviner à l'aveugle produirait trop de faux négatifs (il
faudrait crawler tout le site) pour un gain incertain. L'utilisateur
sait généralement où chercher (page de profil, page du commentaire...).

Limites assumées :
  - Pas de détection automatique de modération/délai (un commentaire
    WordPress modéré n'apparaîtra pas immédiatement — relancer le check
    plus tard avec les mêmes check_urls si besoin)
  - Chaque payload soumis crée une entrée réelle côté serveur (commentaire,
    entrée de profil...) — à utiliser avec discernement sur une cible de
    test, pas question de spammer une vraie page de commentaires publique
  - Un seul marqueur partagé pour tout le scan stocké, comme pour le réfléchi
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from modules.active.crawler import InjectionPoint
from modules.active.payload_engine import generate_marker, build_payloads, PayloadContext
from modules.active.reflection_checker import (
    _send_payload, _classify_reflection, ReflectionConfidence,
)
from modules.common.concurrency import run_concurrent


@dataclass
class StoredResult:
    """Résultat de vérification d'un payload stocké sur une check_url donnée."""
    injection_point: InjectionPoint
    payload: str
    context: PayloadContext
    description: str
    check_url: str
    confidence: ReflectionConfidence   # même échelle que le réfléchi (RAW/ENCODED/PARTIAL/NOT_REFLECTED)
    submit_status: int | None = None    # code HTTP de la soumission
    check_status: int | None = None     # code HTTP de la vérification sur check_url
    response_snippet: str = ""
    error: str | None = None


@dataclass
class StoredScanSummary:
    target_url: str
    check_urls: list[str]
    marker: str
    results: list[StoredResult] = field(default_factory=list)

    @property
    def stored_findings(self) -> list[StoredResult]:
        """Résultats où le payload stocké a été retrouvé, quel que soit le niveau de confiance."""
        return [r for r in self.results if r.confidence != ReflectionConfidence.NOT_REFLECTED
                and r.confidence != ReflectionConfidence.REQUEST_ERROR]

    @property
    def raw_findings(self) -> list[StoredResult]:
        return [r for r in self.results if r.confidence == ReflectionConfidence.REFLECTED_RAW]


def check_stored_xss(
    injection_points: list[InjectionPoint],
    check_urls: list[str],
    timeout: int = 10,
    delay: float = 0.0,
    session: requests.Session | None = None,
    verify: bool = True,
    max_workers: int = 1,
) -> StoredScanSummary:
    """
    Soumet un payload par InjectionPoint puis vérifie sa présence sur
    chacune des check_urls fournies.

    Args:
        injection_points: points d'injection découverts par le crawler
            (typiquement des champs de formulaire POST — commentaire,
            profil... — mais fonctionne aussi sur des paramètres GET)
        check_urls: URLs à consulter après soumission pour chercher le
            payload stocké (page de profil, page du commentaire publié...)
        timeout: délai HTTP pour chaque requête (soumission + vérification)
        delay: pause entre chaque soumission (utile si la cible a un
            rate-limit ou pour laisser le temps à une modération asynchrone)
        session: session requests réutilisable (cookies, headers custom —
            le XSS stocké nécessite très souvent une session authentifiée)
        verify: vérification du certificat SSL, passée explicitement à
            chaque requête (voir chocoxss.py --insecure)
        max_workers: 1 (défaut) = un point d'injection à la fois. > 1 =
            teste plusieurs points en parallèle via un pool de threads —
            voir chocoxss.py --threads. Chaque point garde sa boucle
            payload×check_url séquentielle en interne.

    Returns:
        StoredScanSummary avec un StoredResult par (payload × check_url).
    """
    sess = session or requests.Session()
    sess.headers.setdefault("User-Agent", "ChocoXSS/0.1")

    marker = generate_marker()
    summary = StoredScanSummary(
        target_url=injection_points[0].url if injection_points else "",
        check_urls=check_urls,
        marker=marker,
    )

    if not injection_points or not check_urls:
        return summary

    payloads = build_payloads(marker)

    tasks = [
        (lambda p=point: _check_stored_xss_for_point(
            p, marker, payloads, check_urls, timeout, delay, sess, verify,
        ))
        for point in injection_points
    ]
    all_results = run_concurrent(tasks, max_workers=max_workers)

    for results in all_results:
        summary.results.extend(results)

    return summary


def _check_stored_xss_for_point(
    point: InjectionPoint,
    marker: str,
    payloads: list[tuple[str, PayloadContext, str]],
    check_urls: list[str],
    timeout: int,
    delay: float,
    sess: requests.Session,
    verify: bool,
) -> list[StoredResult]:
    """
    Soumet tous les payloads sur UN point d'injection puis vérifie chaque
    check_url — c'est cette fonction qui tourne en parallèle entre points
    quand max_workers > 1 dans check_stored_xss(). Extraite pour garder
    la boucle payload×check_url exactement identique au comportement
    séquentiel historique, que ce soit appelée en série ou en parallèle.
    """
    results: list[StoredResult] = []

    for payload, context, description in payloads:
        if delay:
            time.sleep(delay)

        # 1. Soumission du payload sur le point d'injection
        _, submit_status, submit_error = _send_payload(point, payload, timeout, sess, verify=verify)

        if submit_error:
            for check_url in check_urls:
                results.append(StoredResult(
                    injection_point=point, payload=payload, context=context,
                    description=description, check_url=check_url,
                    confidence=ReflectionConfidence.REQUEST_ERROR,
                    error=f"Échec de soumission : {submit_error}",
                ))
            continue

        # 2. Vérification sur chaque check_url
        for check_url in check_urls:
            try:
                resp = sess.get(check_url, timeout=timeout, verify=verify)
                confidence, snippet = _classify_reflection(payload, marker, resp.text, context)
                results.append(StoredResult(
                    injection_point=point, payload=payload, context=context,
                    description=description, check_url=check_url,
                    confidence=confidence, submit_status=submit_status,
                    check_status=resp.status_code, response_snippet=snippet,
                ))
            except requests.exceptions.RequestException as e:
                results.append(StoredResult(
                    injection_point=point, payload=payload, context=context,
                    description=description, check_url=check_url,
                    confidence=ReflectionConfidence.REQUEST_ERROR,
                    submit_status=submit_status,
                    error=f"Échec de vérification sur {check_url} : {e}",
                ))

    return results
