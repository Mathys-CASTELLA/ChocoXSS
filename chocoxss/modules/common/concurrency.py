"""
ChocoXSS — Parallélisation optionnelle des scans
====================================================

Helper partagé par reflection_checker.py, stored_checker.py et
blind_payloads.py pour exécuter une liste de tâches indépendantes en
série (comportement historique, max_workers=1) ou en parallèle via un
ThreadPoolExecutor (max_workers > 1) — voir chocoxss.py --threads.

Pourquoi des threads et pas des processus ou de l'async :
  - Les tâches sont I/O-bound (attente réseau), pas CPU-bound — le GIL
    Python n'est donc pas un frein réel ici, ThreadPoolExecutor est le
    choix le plus simple et le moins intrusif sur le reste du code.
  - requests.Session est communément utilisée depuis plusieurs threads
    en pratique (urllib3 gère le verrouillage de son pool de connexions
    en interne), même si ce n'est pas une garantie officielle de la
    librairie requests — comportement stable et largement éprouvé.

Pourquoi PAS de parallélisation de Playwright (headless_verifier.py,
dom_verifier.py) :
  - L'API synchrone de Playwright n'est pas conçue pour être pilotée
    depuis plusieurs threads simultanément (elle encapsule une boucle
    d'événements interne prévue pour un seul thread pilote). Paralléliser
    la navigation nécessiterait l'API asynchrone de Playwright — un
    changement bien plus large, hors scope ici. Le vrai goulot
    d'étranglement d'un scan typique reste de toute façon le grand
    nombre de requêtes HTTP séquentielles (reflection/stored/blind), pas
    la poignée de vérifications navigateur qui les suivent.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Callable, TypeVar

T = TypeVar("T")


def run_concurrent(tasks: list[Callable[[], T]], max_workers: int = 1) -> list[T]:
    """
    Exécute une liste de callables sans argument.

    Args:
        tasks: liste de fonctions à appeler (typiquement des closures
            capturant leurs propres arguments via une valeur par défaut,
            pour éviter le piège classique de late-binding des lambdas
            dans une boucle — voir les appelants pour l'idiome utilisé)
        max_workers: 1 (défaut) = exécution séquentielle stricte, résultat
            et timing identiques au comportement historique d'avant ce
            module. > 1 = parallélisation via ThreadPoolExecutor.

    Returns:
        Liste des résultats, dans le MÊME ORDRE que `tasks` — même en
        mode parallèle (executor.map préserve l'ordre d'entrée, pas
        l'ordre de complétion), pour que le rapport final reste lisible
        et reproductible indépendamment du nombre de threads utilisés.
    """
    if max_workers <= 1:
        return [task() for task in tasks]

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(lambda t: t(), tasks))
