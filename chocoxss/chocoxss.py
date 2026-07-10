#!/usr/bin/env python3
"""
ChocoXSS — Point d'entrée CLI unifié
=======================================

Combine les trois étages du scanner en une seule commande :
  1. Analyse statique   — extraction HTML/JS + détection de sinks/sources
                           + traçage source→sink (taint tracing)
  2. Scan actif          — découverte de points d'injection + envoi de
                           payloads + classification de la réflexion
  3. Vérification        — confirmation d'exécution réelle en navigateur
                           headless (uniquement sur les REFLECTED_RAW)

Comportement selon l'entrée :
  - Fichier local (.html/.js)  → analyse statique uniquement
                                  (pas de serveur à attaquer)
  - URL                        → analyse statique du HTML récupéré
                                  + scan actif (crawl + injection + vérif)
                                  par défaut

Usage :
    chocoxss.py -f page.html
    chocoxss.py -f script.js
    chocoxss.py -u http://cible.test/search?q=test
    chocoxss.py -u http://cible.test/page --static-only
    chocoxss.py -u http://cible.test/page --active-only
    chocoxss.py -u http://cible.test/page --no-verify
    chocoxss.py -u http://cible.test/page --export-json resultats.json
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

import requests
import urllib3

from modules.static.html_parser import extract_from_html
from modules.static.js_ast_analyzer import analyze_js
from modules.static.taint_tracer import trace_findings

from modules.active.crawler import crawl, crawl_recursive
from modules.active.reflection_checker import scan_all_points, ReflectionConfidence
from modules.active.headless_verifier import verify_batch, ExecutionConfidence
from modules.active.stored_checker import check_stored_xss
from modules.active.blind_payloads import submit_blind_payloads
from modules.active.dom_verifier import verify_dom_xss, verify_dom_xss_multi
from modules.common.config import (
    apply_to_parser, cmd_config_show, cmd_config_init,
)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


BANNER = r"""
   ___ _                  _  __ ____ ____
  / __| |_  ___  __ ___  \ \/ // ___/ ___|
 | (__| ' \/ _ \/ _/ _ \  \  / \___ \___ \
  \___|_||_\___/\__\___/  /_\  |___/|___/
"""

CONFIDENCE_ORDER = {"CONFIRMED": 0, "LIKELY": 1, "SANITIZED": 2, "NONE": 3}
CONFIDENCE_COLOR = {"CONFIRMED": "red", "LIKELY": "yellow", "SANITIZED": "green", "NONE": "dim"}

REFLECTION_COLOR = {
    "reflected_raw": "red",
    "reflected_partial": "yellow",
    "reflected_encoded": "green",
    "not_reflected": "dim",
    "request_error": "dim red",
}

EXECUTION_COLOR = {
    "executed_confirmed": "bold red",
    "not_executed": "yellow",
    "verification_error": "dim red",
}


def _print(msg="", style=None):
    if RICH:
        console.print(msg, style=style)
    else:
        import re
        print(re.sub(r"\[/?[a-z_ ]*\]", "", str(msg)))


def print_banner():
    if RICH:
        console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        console.print("[dim]Scanner de vulnérabilités XSS — statique + actif + vérification navigateur[/dim]\n")
    else:
        print(BANNER)


# ─── Authentification (cookies / headers custom) ──────────────────────────────

def _parse_cookie_string(raw: str) -> dict[str, str]:
    """
    Parse une chaîne de cookies au format navigateur/curl :
    "nom1=valeur1; nom2=valeur2" → {"nom1": "valeur1", "nom2": "valeur2"}

    Tolère les espaces superflus et ignore silencieusement les segments
    mal formés (sans '=') plutôt que de faire planter tout le scan pour
    une virgule oubliée en copiant depuis les devtools du navigateur.
    """
    cookies = {}
    for part in raw.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        cookies[name.strip()] = value.strip()
    return cookies


def _parse_header_strings(raw_headers: list[str]) -> dict[str, str]:
    """
    Parse une liste de headers au format "Nom: Valeur" (un par occurrence
    de -H/--header) en dict prêt pour session.headers.update().

    Un header mal formé (sans ':') est ignoré avec un avertissement plutôt
    que de faire planter le scan.
    """
    headers = {}
    for raw in raw_headers:
        if ":" not in raw:
            _print(f"[yellow][!] Header ignoré (format attendu \"Nom: Valeur\") : {raw}[/yellow]")
            continue
        name, _, value = raw.partition(":")
        headers[name.strip()] = value.strip()
    return headers


# ─── Étage 1 : analyse statique ───────────────────────────────────────────────

def run_static_analysis(content: str, filename: str, is_html: bool):
    """
    Lance l'analyse statique complète (extraction + AST + taint tracing)
    sur du contenu HTML ou JS, et affiche les résultats.

    Returns:
        Liste de ConfirmedFinding (pour un résumé global en fin de scan).
    """
    _print(f"\n[bold]── Analyse statique : {filename} ──[/bold]\n")

    all_confirmed = []

    if is_html:
        extraction = extract_from_html(content, filename)
        _print(f"[dim]{len(extraction.scripts)} fragments JS extraits, "
              f"{len(extraction.external_scripts)} scripts externes ignorés, "
              f"{extraction.forms_found} formulaire(s) détecté(s)[/dim]")

        for script in extraction.scripts:
            if script.kind == "external_script":
                continue
            result = analyze_js(script.code, filename=filename)
            if result.parse_errors:
                for err in result.parse_errors:
                    _print(f"[yellow][!] {err}[/yellow]")
                continue
            sinks = [f for f in result.findings if f.kind == "sink"]
            confirmed = trace_findings(sinks, result.ast)
            for c in confirmed:
                c.sink_finding.file = f"{filename} [{script.kind}]"
            all_confirmed.extend(confirmed)
    else:
        result = analyze_js(content, filename=filename)
        if result.parse_errors:
            for err in result.parse_errors:
                _print(f"[red][!] {err}[/red]")
            return []
        sinks = [f for f in result.findings if f.kind == "sink"]
        all_confirmed = trace_findings(sinks, result.ast)

    _print_static_table(all_confirmed)
    return all_confirmed


def _print_static_table(confirmed: list):
    if not confirmed:
        _print("[green]Aucun sink dangereux détecté.[/green]")
        return

    if RICH:
        t = Table(box=box.ROUNDED)
        t.add_column("Confiance", style="bold")
        t.add_column("Sink")
        t.add_column("Ligne", justify="right")
        t.add_column("Source")
        t.add_column("Sanitizer")
        t.add_column("Code")

        for c in sorted(confirmed, key=lambda x: CONFIDENCE_ORDER.get(x.confidence, 9)):
            color = CONFIDENCE_COLOR.get(c.confidence, "white")
            sanit = c.taint.sanitizer_name or "—"
            if c.taint.sanitizer_name and not c.taint.sanitizer_effective:
                sanit += " [red](inefficace ici !)[/red]"
            t.add_row(
                f"[{color}]{c.confidence}[/{color}]",
                c.sink_finding.name,
                str(c.sink_finding.line),
                c.taint.source_name or "—",
                sanit,
                c.sink_finding.code_snippet[:60],
            )
        console.print(t)
    else:
        for c in sorted(confirmed, key=lambda x: CONFIDENCE_ORDER.get(x.confidence, 9)):
            print(f"  [{c.confidence:10}] L{c.sink_finding.line} {c.sink_finding.name:15} "
                  f"source={c.taint.source_name} sanitizer={c.taint.sanitizer_name}")


# ─── Étage 2 : scan actif ──────────────────────────────────────────────────────

@dataclass
class ScanOptions:
    """
    Regroupe toutes les options transversales du scan actif.

    Remplace la liste croissante de kwargs individuels que run_active_scan()
    et consorts accumulaient à chaque nouvelle fonctionnalité (12 paramètres
    avant ce refactor) — chaque nouveau flag CLI n'a plus besoin d'être
    répercuté dans 4 signatures de fonction différentes, juste ajouté ici
    une fois.

    session: None par défaut — les fonctions qui en ont besoin créent une
        requests.Session() à la volée si absente (comportement identique
        à avant, juste centralisé).
    """
    session: requests.Session | None = None
    timeout: int = 10
    verify_ssl: bool = True
    verbose: bool = False
    bypass: bool = False
    crawl_depth: int = 0
    max_pages: int = 20
    allow_external: bool = False
    delay: float = 0.0
    refresh_csrf: bool = False
    proxy: str | None = None
    do_verify: bool = True
    screenshot_dir: str | None = None
    threads: int = 1


def _with_spinner(description: str, fn, *args, **kwargs):
    """
    Exécute fn(*args, **kwargs) en affichant un spinner Rich pendant
    l'appel si disponible, ou juste le message brut sinon.

    Élimine la duplication qui s'était accumulée à chaque nouvel étage
    de scan : le même appel (scan_all_points, check_stored_xss,
    verify_dom_xss, verify_batch...) était écrit deux fois avec des
    arguments identiques — une fois dans le bloc `if RICH:` avec le
    spinner, une fois dans le `else:` sans. Chaque nouveau paramètre
    ajouté à l'un des deux appels devait être répliqué manuellement dans
    l'autre, ce qui a déjà causé des oublis pendant le développement.

    Args:
        description: message affiché pendant l'exécution (avec ou sans spinner)
        fn: fonction à appeler
        *args, **kwargs: transmis tels quels à fn

    Returns:
        Le résultat de fn(*args, **kwargs).
    """
    if RICH:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task(description, total=None)
            result = fn(*args, **kwargs)
            progress.update(task, completed=True)
        return result
    else:
        print(description)
        return fn(*args, **kwargs)


def run_active_scan(url: str, options: ScanOptions):
    """
    Lance le crawl + l'injection de payloads + (optionnellement) la
    vérification navigateur, avec affichage de progression.

    Returns:
        (crawl_result, summary_ou_None, verifications) — toujours un tuple
        à 3 éléments pour un unpacking simple côté appelant, même en cas
        d'échec précoce (fetch impossible, aucun point d'injection...).
    """
    o = options
    _print(f"\n[bold]── Scan actif : {url} ──[/bold]\n")

    if o.crawl_depth > 0:
        result = crawl_recursive(url, max_depth=o.crawl_depth, max_pages=o.max_pages,
                                 allow_external=o.allow_external, timeout=o.timeout,
                                 session=o.session, verify=o.verify_ssl)
        _print(f"[dim]{len(result.pages_visited)} page(s) visitée(s) "
              f"(profondeur max {o.crawl_depth}), {result.forms_found_total} formulaire(s) au total[/dim]")
        if result.pages_skipped_external:
            _print(f"[dim]{len(result.pages_skipped_external)} lien(s) externe(s) ignoré(s) "
                  f"(--crawl-external pour les suivre)[/dim]")
        if result.max_pages_reached:
            _print(f"[yellow][!] Limite de {o.max_pages} pages atteinte — le site a "
                  f"potentiellement plus de pages non explorées.[/yellow]")
        for failed_url, err in result.fetch_errors.items():
            _print(f"[dim red][!] Échec sur {failed_url} : {err}[/dim red]")

        if not result.injection_points:
            _print("[yellow]Aucun point d'injection à tester sur les pages visitées.[/yellow]")
            return result, None, []
    else:
        result = crawl(url, timeout=o.timeout, session=o.session, verify=o.verify_ssl)
        if result.fetch_error:
            _print(f"[red][!] Erreur de récupération de la page : {result.fetch_error}[/red]")
            if not result.injection_points:
                return result, None, []
            _print("[yellow][!] Poursuite avec les seuls paramètres de l'URL.[/yellow]")

        n_points = len(result.injection_points)
        _print(f"[dim]{n_points} point(s) d'injection découvert(s) "
              f"({result.forms_found} formulaire(s) sur la page)[/dim]")

        if n_points == 0:
            _print("[yellow]Aucun point d'injection à tester (pas de paramètre GET, pas de formulaire).[/yellow]")
            return result, None, []

    n_points = len(result.injection_points)

    summary = _with_spinner(
        f"Envoi des payloads sur {n_points} point(s)...",
        scan_all_points, result.injection_points, url,
        timeout=o.timeout, session=o.session, verify=o.verify_ssl,
        bypass_on_partial=o.bypass, delay=o.delay, refresh_csrf=o.refresh_csrf,
        max_workers=o.threads,
    )

    _print_reflection_table(summary, verbose=o.verbose)

    verifications = []
    if o.do_verify:
        raw_findings = [r for r in summary.results if r.confidence == ReflectionConfidence.REFLECTED_RAW]
        if raw_findings:
            _print(f"\n[dim]Vérification navigateur de {len(raw_findings)} résultat(s) REFLECTED_RAW...[/dim]")
            verifications = _with_spinner(
                "Lancement du navigateur headless...",
                verify_batch, raw_findings,
                timeout_ms=3000, http_timeout=o.timeout, session=o.session, verify=o.verify_ssl,
                screenshot_dir=o.screenshot_dir,
            )
            _print_verification_table(verifications)
        else:
            _print("[dim]Aucun résultat REFLECTED_RAW à vérifier dans un navigateur.[/dim]")

    return result, summary, verifications


def _print_reflection_table(summary, verbose: bool = False):
    if not summary.results:
        return

    interesting = [r for r in summary.results if r.confidence != ReflectionConfidence.NOT_REFLECTED]
    if not interesting:
        _print("[green]Aucune réflexion détectée sur les points testés.[/green]")
        return

    has_bypass = any(r.bypass_technique for r in interesting)

    if RICH:
        t = Table(title=f"Réflexions détectées ({len(interesting)}/{len(summary.results)} tests)", box=box.ROUNDED)
        t.add_column("Confiance", style="bold")
        t.add_column("Param")
        t.add_column("Contexte")
        if has_bypass:
            t.add_column("Technique")
        t.add_column("Payload")
        if verbose:
            t.add_column("Extrait de la réponse")

        order = {"reflected_raw": 0, "reflected_partial": 1, "reflected_encoded": 2, "request_error": 3}
        for r in sorted(interesting, key=lambda x: order.get(x.confidence.value, 9)):
            color = REFLECTION_COLOR.get(r.confidence.value, "white")
            row = [
                f"[{color}]{r.confidence.value}[/{color}]",
                r.injection_point.param_name,
                r.context.value,
            ]
            if has_bypass:
                row.append(f"[magenta]{r.bypass_technique}[/magenta]" if r.bypass_technique else "—")
            row.append(r.payload[:50])
            if verbose:
                snippet = r.response_snippet or r.error or "—"
                row.append(snippet[:80])
            t.add_row(*row)
        console.print(t)

        bypass_raw = [r for r in interesting if r.bypass_technique and r.confidence == ReflectionConfidence.REFLECTED_RAW]
        if bypass_raw:
            console.print(
                f"\n[bold red]⚠ {len(bypass_raw)} contournement(s) de filtre réussi(s) "
                f"— un payload standard était filtré mais une variante est passée en brut.[/bold red]"
            )
    else:
        for r in interesting:
            line = f"  [{r.confidence.value:20}] {r.injection_point.param_name:15} {r.payload[:50]}"
            if r.bypass_technique:
                line += f" (bypass: {r.bypass_technique})"
            if verbose:
                snippet = r.response_snippet or r.error or "—"
                line += f"\n        └─ {snippet[:100]}"
            print(line)


def _print_verification_table(verifications):
    if not verifications:
        return

    has_screenshot = any(v.screenshot_path for v in verifications)

    if RICH:
        t = Table(title="Vérification navigateur (exécution réelle)", box=box.ROUNDED)
        t.add_column("Exécution", style="bold")
        t.add_column("Param")
        t.add_column("Contexte")
        t.add_column("Détail")
        if has_screenshot:
            t.add_column("Capture")

        order = {"executed_confirmed": 0, "verification_error": 1, "not_executed": 2}
        for v in sorted(verifications, key=lambda x: order.get(x.execution.value, 9)):
            color = EXECUTION_COLOR.get(v.execution.value, "white")
            row = [
                f"[{color}]{v.execution.value}[/{color}]",
                v.reflection_result.injection_point.param_name,
                v.reflection_result.context.value,
                v.detail[:60],
            ]
            if has_screenshot:
                row.append(v.screenshot_path or "—")
            t.add_row(*row)
        console.print(t)
    else:
        for v in verifications:
            line = f"  [{v.execution.value:20}] {v.detail[:60]}"
            if v.screenshot_path:
                line += f"\n        📷 {v.screenshot_path}"
            print(line)


# ─── Étage complémentaire : XSS stocké ─────────────────────────────────────────

def run_stored_scan(injection_points, check_urls: list[str], options: ScanOptions):
    """
    Soumet les payloads sur chaque point d'injection découvert puis
    vérifie leur présence sur les check_urls fournies par l'utilisateur.

    Contrairement au scan actif classique (reflection_checker), le XSS
    stocké nécessite de préciser où chercher — voir --check-url. Sans
    check_urls, cette étape est simplement sautée (pas d'appel réseau
    inutile, pas de comportement par défaut surprenant).

    Returns:
        StoredScanSummary ou None si aucune check_url fournie.
    """
    if not check_urls:
        return None

    o = options
    _print(f"\n[bold]── Recherche de XSS stocké ({len(check_urls)} URL(s) à vérifier) ──[/bold]\n")

    summary = _with_spinner(
        "Soumission des payloads et vérification...",
        check_stored_xss, injection_points, check_urls,
        timeout=o.timeout, session=o.session, verify=o.verify_ssl, delay=o.delay,
        max_workers=o.threads,
    )

    _print_stored_table(summary, verbose=o.verbose)
    return summary


def _print_stored_table(summary, verbose: bool = False):
    if summary is None or not summary.results:
        return

    interesting = summary.stored_findings
    if not interesting:
        _print("[green]Aucun payload stocké retrouvé sur les URL vérifiées.[/green]")
        return

    if RICH:
        t = Table(title=f"XSS stocké détecté ({len(interesting)}/{len(summary.results)} tests)", box=box.ROUNDED)
        t.add_column("Confiance", style="bold")
        t.add_column("Param")
        t.add_column("Check URL")
        t.add_column("Payload")
        if verbose:
            t.add_column("Extrait de la réponse")

        order = {"reflected_raw": 0, "reflected_partial": 1, "reflected_encoded": 2, "request_error": 3}
        for r in sorted(interesting, key=lambda x: order.get(x.confidence.value, 9)):
            color = REFLECTION_COLOR.get(r.confidence.value, "white")
            row = [
                f"[{color}]{r.confidence.value}[/{color}]",
                r.injection_point.param_name,
                r.check_url[:40],
                r.payload[:40],
            ]
            if verbose:
                snippet = r.response_snippet or r.error or "—"
                row.append(snippet[:80])
            t.add_row(*row)
        console.print(t)
    else:
        for r in interesting:
            print(f"  [{r.confidence.value:20}] {r.injection_point.param_name:15} "
                  f"{r.check_url} {r.payload[:40]}")


# ─── Étage complémentaire : XSS DOM en conditions réelles ──────────────────────

def run_dom_scan(url: str, options: ScanOptions, extra_urls: list[str] | None = None):
    """
    Navigue réellement vers la cible avec chaque payload injecté dans le
    fragment d'URL et un paramètre de query — seul moyen de détecter un
    XSS DOM pur, jamais transmis au serveur donc invisible pour le
    scan actif classique (reflection_checker.py).

    Contrairement au reste du pipeline, fait de VRAIES requêtes réseau
    vers la cible (pas de rejeu local) — respecte donc --proxy/--insecure
    via la configuration du contexte navigateur Playwright.

    Le paramètre timeout n'est pas utilisé ici (verify_dom_xss a son
    propre timeout_ms fixe pour la navigation) — conservé sur ScanOptions
    pour cohérence avec les autres étages, pas pour un usage direct.

    Args:
        extra_urls: pages supplémentaires à tester en plus de `url` —
            typiquement result.pages_visited d'un crawl récursif
            (--crawl-depth > 0). Sans ça, --dom-xss se limitait à
            l'URL de départ même si --crawl-depth avait découvert
            d'autres pages potentiellement vulnérables au DOM XSS.
    """
    o = options
    all_urls = [url] + [u for u in (extra_urls or []) if u != url]

    if len(all_urls) > 1:
        _print(f"\n[bold]── Vérification DOM XSS en conditions réelles ({len(all_urls)} page(s)) ──[/bold]\n")
    else:
        _print(f"\n[bold]── Vérification DOM XSS en conditions réelles : {url} ──[/bold]\n")
    _print("[dim]Navigation réelle vers la cible avec chaque payload dans le "
          "fragment d'URL et un paramètre de query — plus lent que le reste "
          "du scan (nouvelle page par payload).[/dim]")

    if o.session is not None and len(o.session.cookies) > 0:
        _print(f"[dim]{len(o.session.cookies)} cookie(s) de session importé(s) "
              f"dans le navigateur pour cette vérification.[/dim]")

    if len(all_urls) > 1:
        summary = _with_spinner(
            f"Navigation sur {len(all_urls)} page(s), payload par payload...",
            verify_dom_xss_multi, all_urls,
            timeout_ms=5000, proxy=o.proxy, ignore_https_errors=not o.verify_ssl, session=o.session,
            screenshot_dir=o.screenshot_dir,
        )
    else:
        summary = _with_spinner(
            "Navigation payload par payload...",
            verify_dom_xss, url,
            timeout_ms=5000, proxy=o.proxy, ignore_https_errors=not o.verify_ssl, session=o.session,
            screenshot_dir=o.screenshot_dir,
        )

    _print_dom_table(summary)
    return summary


def _print_dom_table(summary):
    if not summary.results:
        return

    interesting = [r for r in summary.results if r.execution != ExecutionConfidence.NOT_EXECUTED]
    if not interesting:
        _print("[green]Aucun XSS DOM confirmé sur les vecteurs testés.[/green]")
        return

    has_screenshot = any(r.screenshot_path for r in interesting)

    if RICH:
        t = Table(title=f"XSS DOM confirmé en conditions réelles ({len(summary.confirmed)}/{len(summary.results)} tests)", box=box.ROUNDED)
        t.add_column("Exécution", style="bold")
        t.add_column("Vecteur")
        t.add_column("Payload")
        t.add_column("Détail")
        if has_screenshot:
            t.add_column("Capture")

        order = {"executed_confirmed": 0, "verification_error": 1}
        for r in sorted(interesting, key=lambda x: order.get(x.execution.value, 9)):
            color = EXECUTION_COLOR.get(r.execution.value, "white")
            row = [
                f"[{color}]{r.execution.value}[/{color}]",
                r.vector,
                r.payload[:50],
                r.detail[:50],
            ]
            if has_screenshot:
                row.append(r.screenshot_path or "—")
            t.add_row(*row)
        console.print(t)

        if summary.confirmed:
            console.print(
                f"\n[bold red]⚠ {len(summary.confirmed)} XSS DOM confirmé(s) par navigation "
                f"réelle — invisible pour le scan actif classique.[/bold red]"
            )
    else:
        for r in interesting:
            line = f"  [{r.execution.value:20}] {r.vector:15} {r.payload[:50]}"
            if r.screenshot_path:
                line += f"\n        📷 {r.screenshot_path}"
            print(line)


# ─── Étage complémentaire : XSS aveugle (blind / out-of-band) ──────────────────

def run_blind_scan(injection_points, callback_url: str, options: ScanOptions):
    """
    Soumet des payloads de callback sur chaque point d'injection découvert.
    Ne confirme RIEN localement — c'est le rôle du collecteur externe de
    l'utilisateur, potentiellement bien après la fin du scan. Affiche une
    table de corrélation (marqueur ↔ point d'injection) pour recouper
    manuellement les hits reçus côté collecteur.
    """
    o = options
    _print(f"\n[bold]── Soumission XSS aveugle vers {callback_url} ──[/bold]\n")
    _print("[dim]Ces payloads ne sont PAS vérifiés par ChocoXSS — surveillez votre "
          "collecteur externe et recoupez les hits avec la table ci-dessous.[/dim]")

    summary = submit_blind_payloads(injection_points, callback_url, timeout=o.timeout,
                                    session=o.session, verify=o.verify_ssl, delay=o.delay,
                                    max_workers=o.threads)
    _print_blind_table(summary)
    return summary


def _print_blind_table(summary):
    correlation = summary.correlation_table()
    if not correlation:
        _print("[yellow]Aucune soumission aveugle effectuée.[/yellow]")
        return

    n_errors = len(summary.submissions) - len(summary.successful_submissions)

    if RICH:
        t = Table(title=f"Corrélation XSS aveugle ({len(correlation)} soumission(s) réussie(s))", box=box.ROUNDED)
        t.add_column("Marqueur", style="bold cyan")
        t.add_column("Paramètre")
        t.add_column("URL de soumission")

        for marker, param_name, url in correlation:
            t.add_row(marker, param_name, url[:50])
        console.print(t)

        console.print(
            f"\n[dim]Recherchez ces marqueurs dans les logs de votre collecteur "
            f"({summary.callback_url}) — l'exécution peut survenir bien après "
            f"la fin de ce scan (modération, consultation différée...).[/dim]"
        )
        if n_errors:
            _print(f"[yellow][!] {n_errors} soumission(s) ont échoué (voir erreurs réseau).[/yellow]")
    else:
        for marker, param_name, url in correlation:
            print(f"  {marker}  {param_name:15} {url[:50]}")


# ─── Export JSON ──────────────────────────────────────────────────────────────

def export_results_json(path: str, static_findings, active_summary, verifications, stored_summary=None, dom_summary=None, blind_summary=None):
    payload = {
        "generated_at": datetime.now().isoformat(),
        "static_findings": [
            {
                "sink": c.sink_finding.name,
                "line": c.sink_finding.line,
                "file": c.sink_finding.file,
                "confidence": c.confidence,
                "source": c.taint.source_name,
                "sanitizer": c.taint.sanitizer_name,
                "sanitizer_effective": c.taint.sanitizer_effective,
                "code": c.sink_finding.code_snippet,
            }
            for c in (static_findings or [])
        ],
        "active_findings": [
            {
                "param": r.injection_point.param_name,
                "method": r.injection_point.method,
                "url": r.injection_point.url,
                "context": r.context.value,
                "confidence": r.confidence.value,
                "payload": r.payload,
            }
            for r in (active_summary.results if active_summary else [])
            if r.confidence != ReflectionConfidence.NOT_REFLECTED
        ],
        "verified_executions": [
            {
                "param": v.reflection_result.injection_point.param_name,
                "payload": v.reflection_result.payload,
                "execution": v.execution.value,
                "detail": v.detail,
                "screenshot_path": v.screenshot_path,
            }
            for v in verifications
        ],
        "stored_findings": [
            {
                "param": r.injection_point.param_name,
                "method": r.injection_point.method,
                "submit_url": r.injection_point.url,
                "check_url": r.check_url,
                "context": r.context.value,
                "confidence": r.confidence.value,
                "payload": r.payload,
            }
            for r in (stored_summary.results if stored_summary else [])
            if r.confidence not in (ReflectionConfidence.NOT_REFLECTED, ReflectionConfidence.REQUEST_ERROR)
        ],
        "dom_findings": [
            {
                "tested_url": r.tested_url,
                "vector": r.vector,
                "payload": r.payload,
                "execution": r.execution.value,
                "detail": r.detail,
                "screenshot_path": r.screenshot_path,
            }
            for r in (dom_summary.results if dom_summary else [])
            if r.execution == ExecutionConfidence.EXECUTED_CONFIRMED
        ],
        "blind_submissions": [
            {
                "marker": marker,
                "param": param_name,
                "submit_url": url,
                "callback_url": blind_summary.callback_url if blind_summary else "",
            }
            for marker, param_name, url in (blind_summary.correlation_table() if blind_summary else [])
        ],
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    _print(f"\n[green][+] Résultats exportés : {path}[/green]")


# ─── Résumé final ──────────────────────────────────────────────────────────────

def print_summary(static_findings, active_summary, verifications, elapsed: float, stored_summary=None, dom_summary=None, blind_summary=None):
    n_static_confirmed = sum(1 for c in (static_findings or []) if c.confidence == "CONFIRMED")
    n_static_likely = sum(1 for c in (static_findings or []) if c.confidence == "LIKELY")

    n_active_raw = sum(1 for r in (active_summary.results if active_summary else [])
                       if r.confidence == ReflectionConfidence.REFLECTED_RAW)

    n_executed = sum(1 for v in verifications if v.execution == ExecutionConfidence.EXECUTED_CONFIRMED)

    n_stored_raw = sum(1 for r in (stored_summary.results if stored_summary else [])
                       if r.confidence == ReflectionConfidence.REFLECTED_RAW)

    n_dom_confirmed = len(dom_summary.confirmed) if dom_summary else 0
    n_blind_sent = len(blind_summary.successful_submissions) if blind_summary else 0

    if RICH:
        lines = []
        if static_findings is not None:
            lines.append(f"Analyse statique : [red]{n_static_confirmed} confirmée(s)[/red], "
                        f"[yellow]{n_static_likely} probable(s)[/yellow]")
        if active_summary is not None:
            lines.append(f"Scan actif       : [red]{n_active_raw} réflexion(s) brute(s)[/red]")
        if verifications:
            lines.append(f"Vérification     : [bold red]{n_executed} exécution(s) confirmée(s)[/bold red] "
                        f"en navigateur réel")
        if stored_summary is not None:
            lines.append(f"XSS stocké       : [bold red]{n_stored_raw} payload(s) brut(s) retrouvé(s)[/bold red]")
        if dom_summary is not None:
            lines.append(f"XSS DOM réel     : [bold red]{n_dom_confirmed} exécution(s) confirmée(s)[/bold red] "
                        f"par navigation vers la vraie cible")
        if blind_summary is not None:
            lines.append(f"XSS aveugle      : [cyan]{n_blind_sent} payload(s) soumis[/cyan] "
                        f"— à corréler avec votre collecteur")

        console.print(Panel(
            "\n".join(lines) + f"\n\n[dim]Terminé en {elapsed:.1f}s[/dim]",
            title="[bold]Résumé[/bold]",
            border_style="cyan",
        ))
    else:
        print(f"\n=== Résumé (en {elapsed:.1f}s) ===")
        if static_findings is not None:
            print(f"  Statique : {n_static_confirmed} confirmée(s), {n_static_likely} probable(s)")
        if active_summary is not None:
            print(f"  Actif    : {n_active_raw} réflexion(s) brute(s)")
        if verifications:
            print(f"  Vérifié  : {n_executed} exécution(s) confirmée(s)")
        if stored_summary is not None:
            print(f"  Stocké   : {n_stored_raw} payload(s) brut(s) retrouvé(s)")
        if dom_summary is not None:
            print(f"  DOM réel : {n_dom_confirmed} exécution(s) confirmée(s)")
        if blind_summary is not None:
            print(f"  Aveugle  : {n_blind_sent} payload(s) soumis")


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    # ── Sous-commande `config` ────────────────────────────────────────────────
    # Traitée avant le parser principal pour ne pas exiger -f/-u.
    if len(sys.argv) >= 2 and sys.argv[1] == "config":
        sub = sys.argv[2] if len(sys.argv) >= 3 else "show"
        force = "--force" in sys.argv

        if sub in ("show", "s"):
            cmd_config_show()
        elif sub in ("init", "i"):
            cmd_config_init(force=force)
        else:
            print("Sous-commande config inconnue.\n"
                  "  chocoxss.py config show          — afficher la config active\n"
                  "  chocoxss.py config init          — créer ~/.chocoxss.conf\n"
                  "  chocoxss.py config init --force  — écraser ~/.chocoxss.conf")
            sys.exit(1)
        sys.exit(0)

    parser = argparse.ArgumentParser(
        prog="chocoxss",
        description="ChocoXSS — Scanner de vulnérabilités XSS (statique + actif + vérification navigateur)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  chocoxss.py -f page.html
  chocoxss.py -f script.js
  chocoxss.py -u http://cible.test/search?q=test
  chocoxss.py -u http://cible.test/search?q=test --verbose
  chocoxss.py -u https://10.10.10.1/ --insecure
  chocoxss.py -u https://cible.test/profile -b "wordpress_logged_in=xyz; wordpress_sec=abc"
  chocoxss.py -u https://cible.test/api -H "Authorization: Bearer xxx"
  chocoxss.py -u https://cible.test/comment --check-url https://cible.test/blog/post-1
  chocoxss.py -u https://cible.test/page -p http://127.0.0.1:8080 --insecure
  chocoxss.py -u https://cible.test/page --bypass
  chocoxss.py -u https://cible.test/ --crawl-depth 2 --max-pages 30
  chocoxss.py -u https://cible.test/dom --dom-xss
  chocoxss.py -u https://cible.test/contact --blind-callback https://votre-collecteur.test
  chocoxss.py -u https://cible.test/page --delay 0.5
  chocoxss.py -u https://cible.test/comment --refresh-csrf
  chocoxss.py -u https://cible.test/page --screenshot-dir ./preuves
  chocoxss.py -u https://cible.test/ --crawl-depth 2 --threads 5
  chocoxss.py config init
  chocoxss.py config show
  chocoxss.py -u http://cible.test/page --static-only
  chocoxss.py -u http://cible.test/page --active-only
  chocoxss.py -u http://cible.test/page --no-verify
  chocoxss.py -u http://cible.test/page --export-json resultats.json
        """,
    )

    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-f", "--file", help="Fichier local à analyser (.html ou .js) — analyse statique uniquement")
    source.add_argument("-u", "--url", help="URL cible — analyse statique du HTML récupéré + scan actif")

    parser.add_argument("--static-only", action="store_true",
                        help="Sur une URL : n'exécuter que l'analyse statique (pas de scan actif)")
    parser.add_argument("--active-only", action="store_true",
                        help="Sur une URL : n'exécuter que le scan actif (pas d'analyse statique du HTML)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Désactiver la vérification navigateur headless (plus rapide, moins fiable)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Afficher l'extrait de réponse HTTP autour du marqueur pour chaque "
                             "réflexion détectée (utile pour comprendre un REFLECTED_PARTIAL "
                             "sans avoir à rejouer la requête à la main)")
    parser.add_argument("-k", "--insecure", action="store_true",
                        help="Désactiver la vérification du certificat SSL (cibles à certificat "
                             "auto-signé, courant en labo CTF/HTB — équivalent à curl -k)")
    parser.add_argument("-b", "--cookie", metavar="\"nom=valeur; nom2=valeur2\"",
                        help="Cookies à envoyer avec chaque requête, pour scanner une zone "
                             "authentifiée (profil admin, éditeur de widgets...). Connectez-vous "
                             "dans un navigateur, copiez le header Cookie depuis les outils "
                             "développeur, et collez-le tel quel ici (équivalent à curl -b).")
    parser.add_argument("-H", "--header", metavar="\"Nom: Valeur\"", action="append", default=[],
                        help="En-tête HTTP additionnel, répétable (ex: -H \"Authorization: "
                             "Bearer xxx\"). Équivalent à curl -H.")
    parser.add_argument("-p", "--proxy", metavar="URL",
                        help="Faire transiter toutes les requêtes HTTP(S) par un proxy "
                             "(ex: -p http://127.0.0.1:8080 pour Burp Suite ou ZAP) — permet "
                             "d'inspecter et rejouer manuellement chaque requête envoyée par "
                             "ChocoXSS. Pensez à ajouter --insecure si le proxy fait de "
                             "l'interception TLS avec son propre certificat (comme Burp par défaut).")
    parser.add_argument("--check-url", metavar="URL", action="append", default=[],
                        help="Recherche de XSS STOCKÉ : après avoir envoyé les payloads sur "
                             "les points d'injection découverts, vérifie leur présence sur "
                             "cette URL (répétable). Ex: la page de profil public où un champ "
                             "de bio soumis va réapparaître, ou la page d'un commentaire publié.")
    parser.add_argument("--bypass", action="store_true",
                        help="Relancer automatiquement des variantes de contournement de "
                             "filtre (casse mixte, tag imbriqué, entités HTML, double encodage "
                             "URL...) sur tout résultat REFLECTED_PARTIAL — preuve qu'un "
                             "filtrage actif existe, potentiellement contournable. Multiplie "
                             "les requêtes uniquement sur les points où un filtre a été détecté.")
    parser.add_argument("--crawl-depth", type=int, default=0, metavar="N",
                        help="Suivre les liens <a href> de la page jusqu'à N sauts, pour "
                             "couvrir plusieurs pages plutôt qu'un seul point d'entrée "
                             "(ex: tout un site plutôt que juste la page de connexion). "
                             "0 (défaut) = une seule page, comportement historique.")
    parser.add_argument("--max-pages", type=int, default=20, metavar="N",
                        help="Plafond de pages visitées en mode --crawl-depth (défaut : 20) "
                             "— garde-fou contre un crawl qui explose sur un gros site.")
    parser.add_argument("--crawl-external", action="store_true",
                        help="Autoriser --crawl-depth à suivre des liens en dehors du domaine "
                             "de départ (désactivé par défaut, par sécurité).")
    parser.add_argument("--dom-xss", action="store_true",
                        help="Vérifier le XSS DOM en conditions réelles : navigue un vrai "
                             "navigateur vers la vraie cible avec chaque payload dans le "
                             "fragment d'URL (#...) et un paramètre de query — seul moyen de "
                             "détecter un XSS qui ne quitte jamais le navigateur (invisible "
                             "pour le scan actif classique, qui repose sur les réponses HTTP).")
    parser.add_argument("--blind-callback", metavar="URL",
                        help="Recherche de XSS AVEUGLE : soumet des payloads de callback "
                             "(script src, fetch...) sur chaque point d'injection découvert, "
                             "pointant vers votre propre collecteur (Burp Collaborator, "
                             "Interactsh, serveur de logs custom). ChocoXSS ne confirme rien "
                             "lui-même — surveillez votre collecteur, potentiellement bien "
                             "après la fin du scan (modération, consultation différée...).")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout des requêtes HTTP en secondes (défaut : 10)")
    parser.add_argument("--delay", type=float, default=0.0, metavar="SEC",
                        help="Pause entre chaque requête de payload, en secondes (défaut : 0). "
                             "Utile contre un WAF/rate-limit qui bloquerait une rafale de "
                             "requêtes — en pentest réel avec une fenêtre de test limitée, "
                             "un blocage IP peut coûter plus cher qu'un scan un peu plus lent.")
    parser.add_argument("-t", "--threads", type=int, default=1, metavar="N",
                        help="Tester plusieurs points d'injection en parallèle (défaut : 1, "
                             "séquentiel). Accélère nettement un scan avec beaucoup de points "
                             "(--crawl-depth notamment). Chaque point garde sa boucle de "
                             "payloads séquentielle en interne, donc --delay reste "
                             "significatif PAR POINT — mais combiner --threads élevé avec "
                             "--delay augmente quand même le débit global de requêtes vers la "
                             "cible, ce qui peut aller à l'encontre du rate-limiting recherché "
                             "par --delay. Ne s'applique pas à --dom-xss (Playwright n'est pas "
                             "parallélisable de façon fiable depuis plusieurs threads).")
    parser.add_argument("--refresh-csrf", action="store_true",
                        help="Rafraîchir le token CSRF d'un formulaire POST avant de tester "
                             "ses payloads, en re-chargeant la page d'origine (une fois par "
                             "point, pas par soumission). Utile contre les cibles qui "
                             "régénèrent leur token à chaque chargement de page (WordPress "
                             "nonces, Django CSRF...), sans quoi les soumissions échouent "
                             "silencieusement avec un token périmé — faux négatif potentiel.")
    parser.add_argument("--screenshot-dir", metavar="DIR",
                        help="Capturer une preuve visuelle (PNG) pour chaque exécution XSS "
                             "confirmée (réfléchi/stocké vérifié en navigateur, DOM en "
                             "conditions réelles) — utile pour un rapport de pentest. La "
                             "capture montre l'état de la page APRÈS le payload, pas le "
                             "dialogue alert() lui-même (fenêtre native du navigateur, jamais "
                             "visible dans un screenshot de page).")
    parser.add_argument("--export-json", metavar="FICHIER",
                        help="Exporter tous les résultats dans un fichier JSON")

    # ── Charger ~/.chocoxss.conf comme defaults — les flags CLI gardent priorité ──
    _cfg_path = apply_to_parser(parser, verbose=False)

    args = parser.parse_args()

    if args.static_only and args.active_only:
        parser.error("--static-only et --active-only sont mutuellement exclusifs")
    if args.file and (args.static_only or args.active_only):
        parser.error("--static-only/--active-only ne s'appliquent qu'avec -u/--url")
    if args.check_url and args.file:
        parser.error("--check-url nécessite -u/--url (pas de scan actif possible sur un fichier local)")
    if args.check_url and args.static_only:
        parser.error("--check-url nécessite le scan actif — incompatible avec --static-only")
    if args.crawl_depth > 0 and args.file:
        parser.error("--crawl-depth nécessite -u/--url (pas de crawl possible sur un fichier local)")
    if args.crawl_depth > 0 and args.static_only:
        parser.error("--crawl-depth nécessite le scan actif — incompatible avec --static-only")
    if args.crawl_depth < 0:
        parser.error("--crawl-depth doit être positif ou nul")
    if args.dom_xss and args.file:
        parser.error("--dom-xss nécessite -u/--url (pas de navigateur à pointer sur un fichier local)")
    if args.blind_callback and args.file:
        parser.error("--blind-callback nécessite -u/--url (pas de points d'injection sur un fichier local)")
    if args.blind_callback and args.static_only:
        parser.error("--blind-callback nécessite le scan actif — incompatible avec --static-only")
    if args.threads < 1:
        parser.error("--threads doit être un entier positif (1 minimum)")

    print_banner()
    if _cfg_path:
        _print(f"[dim][config] {_cfg_path}[/dim]")
    if args.threads > 1 and args.delay > 0:
        _print(f"[yellow][!] --threads {args.threads} combiné à --delay {args.delay}s : le délai "
              f"reste respecté PAR POINT testé, mais le débit global de requêtes vers la "
              f"cible augmente quand même avec plusieurs threads en parallèle.[/yellow]")
    start = time.time()

    static_findings = None
    active_summary = None
    verifications = []
    stored_summary = None
    dom_summary = None
    blind_summary = None

    # Session HTTP partagée pour tout le scan. La vérification SSL est
    # passée explicitement à chaque requête (verify_ssl) plutôt que via
    # l'attribut session.verify seul, qui s'est avéré ne pas être respecté
    # de façon fiable selon les versions de requests/urllib3.
    session = requests.Session()
    session.headers.setdefault("User-Agent", "ChocoXSS/0.1")
    verify_ssl = not args.insecure
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        _print("[yellow][!] Vérification SSL désactivée (--insecure) — "
              "à réserver aux cibles de confiance (labo CTF, certificat auto-signé).[/yellow]\n")

    if args.cookie:
        cookies = _parse_cookie_string(args.cookie)
        session.cookies.update(cookies)
        _print(f"[dim][*] {len(cookies)} cookie(s) chargé(s) — scan en session authentifiée.[/dim]")

    if args.header:
        headers = _parse_header_strings(args.header)
        session.headers.update(headers)
        _print(f"[dim][*] {len(headers)} en-tête(s) custom appliqué(s).[/dim]")

    if args.proxy:
        session.proxies = {"http": args.proxy, "https": args.proxy}
        _print(f"[dim][*] Trafic HTTP(S) routé via {args.proxy}[/dim]")
        if verify_ssl:
            _print("[yellow][!] Proxy actif sans --insecure : si c'est Burp/ZAP avec "
                  "interception TLS, les requêtes HTTPS échoueront sauf à installer "
                  "son certificat, ou à relancer avec -k.[/yellow]")

    if args.file:
        path = Path(args.file)
        if not path.exists():
            _print(f"[red][!] Fichier introuvable : {args.file}[/red]")
            sys.exit(1)
        content = path.read_text(encoding="utf-8", errors="replace")
        is_html = path.suffix.lower() in (".html", ".htm")
        static_findings = run_static_analysis(content, str(path), is_html)

    else:  # args.url
        do_static = not args.active_only
        do_active = not args.static_only

        if do_static:
            try:
                resp = session.get(args.url, timeout=args.timeout, verify=verify_ssl)
                static_findings = run_static_analysis(resp.text, args.url, is_html=True)
            except requests.exceptions.RequestException as e:
                _print(f"[red][!] Impossible de récupérer {args.url} pour l'analyse statique : {e}[/red]")
                if not do_active:
                    sys.exit(1)

        if do_active:
            options = ScanOptions(
                session=session, timeout=args.timeout, verify_ssl=verify_ssl,
                verbose=args.verbose, bypass=args.bypass, crawl_depth=args.crawl_depth,
                max_pages=args.max_pages, allow_external=args.crawl_external,
                delay=args.delay, refresh_csrf=args.refresh_csrf, proxy=args.proxy,
                do_verify=not args.no_verify, screenshot_dir=args.screenshot_dir,
                threads=args.threads,
            )

            crawl_result, active_summary, verifications = run_active_scan(args.url, options)

            if args.check_url:
                injection_points = crawl_result.injection_points if crawl_result else []
                if not injection_points:
                    _print("[yellow][!] --check-url ignoré : aucun point d'injection découvert.[/yellow]")
                else:
                    stored_summary = run_stored_scan(injection_points, args.check_url, options)

            if args.dom_xss:
                # Si un crawl récursif (--crawl-depth) a découvert d'autres
                # pages, on les teste aussi pour le DOM XSS — sans ça,
                # --dom-xss restait limité à args.url même sur un site
                # exploré en profondeur.
                extra_urls = getattr(crawl_result, "pages_visited", None) if crawl_result else None
                dom_summary = run_dom_scan(args.url, options, extra_urls=extra_urls)

            if args.blind_callback:
                injection_points = crawl_result.injection_points if crawl_result else []
                if not injection_points:
                    _print("[yellow][!] --blind-callback ignoré : aucun point d'injection découvert.[/yellow]")
                else:
                    blind_summary = run_blind_scan(injection_points, args.blind_callback, options)

    elapsed = time.time() - start
    print_summary(static_findings, active_summary, verifications, elapsed,
                  stored_summary=stored_summary, dom_summary=dom_summary, blind_summary=blind_summary)

    if args.export_json:
        export_results_json(args.export_json, static_findings, active_summary, verifications,
                            stored_summary=stored_summary, dom_summary=dom_summary, blind_summary=blind_summary)


if __name__ == "__main__":
    main()
