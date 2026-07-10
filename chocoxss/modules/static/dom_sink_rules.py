"""
XSStress — Base de règles DOM Sinks/Sources/Sanitizers
=========================================================

Référence centrale utilisée par js_ast_analyzer.py et taint_tracer.py
pour identifier :
  - les SINKS   : points où une donnée non fiable peut causer une exécution de code
  - les SOURCES : points d'entrée de données potentiellement contrôlées par un attaquant
  - les SANITIZERS : fonctions/patterns qui neutralisent le caractère dangereux d'une donnée

Organisé par catégorie DOM XSS classique (cf. OWASP DOM-based XSS Prevention Cheat Sheet) :
  - HTML sinks       : injection dans le DOM en tant que balisage
  - JS execution sinks : exécution de code arbitraire
  - URL sinks        : injection dans un attribut src/href/action
  - jQuery sinks     : équivalents jQuery des sinks natifs
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum


class SinkCategory(Enum):
    HTML_INJECTION = "html_injection"     # innerHTML, document.write...
    CODE_EXECUTION = "code_execution"     # eval, Function, setTimeout(string)
    URL_INJECTION  = "url_injection"      # location.href, .src, .action
    JQUERY         = "jquery"             # $().html(), $().append()...
    STORAGE        = "storage"            # localStorage utilisé comme sink indirect


@dataclass
class SinkRule:
    name: str                  # identifiant technique (ex: "innerHTML")
    category: SinkCategory
    member_path: tuple[str, ...]  # chemin de propriétés à matcher, ex: ("innerHTML",) ou ("document", "write")
    severity: str               # CRITICAL / HIGH / MEDIUM
    description: str
    owasp_ref: str = ""


@dataclass
class SourceRule:
    name: str
    member_path: tuple[str, ...]
    description: str


@dataclass
class SanitizerRule:
    name: str
    # Soit un nom de fonction appelée : encodeURIComponent(x)
    # Soit un chemin de méthode : DOMPurify.sanitize(x)
    call_name: str | None = None
    member_path: tuple[str, ...] | None = None
    description: str = ""
    # Certains sanitizers sont partiels (encodeURIComponent ne protège pas
    # contre un contexte HTML brut, par ex.) — on le note pour ne pas
    # sur-neutraliser le taint dans un contexte incompatible.
    effective_for: tuple[str, ...] = ()  # catégories de sink pour lesquelles il est réellement efficace


# ═══════════════════════════════════════════════════════════════════════════
# SINKS — points d'exécution/injection dangereux
# ═══════════════════════════════════════════════════════════════════════════

SINKS: list[SinkRule] = [
    # ── HTML injection (le plus courant) ──────────────────────────────────────
    SinkRule("innerHTML", SinkCategory.HTML_INJECTION, ("innerHTML",),
             "CRITICAL", "Injection HTML directe via innerHTML — exécute tout script/event handler inséré",
             "https://owasp.org/www-community/attacks/DOM_Based_XSS"),
    SinkRule("outerHTML", SinkCategory.HTML_INJECTION, ("outerHTML",),
             "CRITICAL", "Remplace l'élément entier — même risque que innerHTML"),
    SinkRule("insertAdjacentHTML", SinkCategory.HTML_INJECTION, ("insertAdjacentHTML",),
             "CRITICAL", "Insertion HTML positionnelle — exécute le contenu inséré"),
    SinkRule("document.write", SinkCategory.HTML_INJECTION, ("document", "write"),
             "CRITICAL", "Écrit du HTML brut dans le flux du document"),
    SinkRule("document.writeln", SinkCategory.HTML_INJECTION, ("document", "writeln"),
             "CRITICAL", "Variante de document.write"),

    # ── Exécution de code arbitraire ───────────────────────────────────────────
    SinkRule("eval", SinkCategory.CODE_EXECUTION, ("eval",),
             "CRITICAL", "Exécute une chaîne comme code JavaScript"),
    SinkRule("Function", SinkCategory.CODE_EXECUTION, ("Function",),
             "CRITICAL", "Constructeur Function — équivalent à eval pour du code dynamique"),
    SinkRule("setTimeout", SinkCategory.CODE_EXECUTION, ("setTimeout",),
             "HIGH", "setTimeout(string, ...) exécute la chaîne comme code — setTimeout(fn, ...) est sûr"),
    SinkRule("setInterval", SinkCategory.CODE_EXECUTION, ("setInterval",),
             "HIGH", "setInterval(string, ...) exécute la chaîne comme code"),
    SinkRule("execScript", SinkCategory.CODE_EXECUTION, ("execScript",),
             "CRITICAL", "Ancien équivalent IE de eval"),

    # ── Injection d'URL (moins direct mais exploitable via javascript:) ───────
    SinkRule("location.href", SinkCategory.URL_INJECTION, ("location", "href"),
             "HIGH", "Une valeur 'javascript:...' assignée exécute du code"),
    SinkRule("location.assign", SinkCategory.URL_INJECTION, ("location", "assign"),
             "HIGH", "Idem location.href via méthode"),
    SinkRule("location.replace", SinkCategory.URL_INJECTION, ("location", "replace"),
             "HIGH", "Idem location.href via méthode"),
    SinkRule("script.src", SinkCategory.URL_INJECTION, ("src",),
             "HIGH", "Charge et exécute un script depuis une URL contrôlée"),
    SinkRule("iframe.src", SinkCategory.URL_INJECTION, ("src",),
             "MEDIUM", "Peut charger du contenu contrôlé par l'attaquant (moins direct)"),

    # ── jQuery (toujours largement utilisé en prod) ────────────────────────────
    SinkRule("jquery.html", SinkCategory.JQUERY, ("html",),
             "CRITICAL", "$(x).html(data) — équivalent jQuery de innerHTML"),
    SinkRule("jquery.append", SinkCategory.JQUERY, ("append",),
             "HIGH", "$(x).append(data) — insère et exécute du HTML"),
    SinkRule("jquery.prepend", SinkCategory.JQUERY, ("prepend",),
             "HIGH", "$(x).prepend(data) — insère et exécute du HTML"),
    SinkRule("jquery.after", SinkCategory.JQUERY, ("after",),
             "MEDIUM", "$(x).after(data) — insère du HTML adjacent"),
    SinkRule("jquery.before", SinkCategory.JQUERY, ("before",),
             "MEDIUM", "$(x).before(data) — insère du HTML adjacent"),
    SinkRule("jquery.globalEval", SinkCategory.JQUERY, ("globalEval",),
             "CRITICAL", "$.globalEval(data) — équivalent eval de jQuery"),
]


# ═══════════════════════════════════════════════════════════════════════════
# SOURCES — données potentiellement contrôlées par l'attaquant
# ═══════════════════════════════════════════════════════════════════════════

SOURCES: list[SourceRule] = [
    SourceRule("location.href", ("location", "href"),
               "URL complète — contrôlable via lien/redirection"),
    SourceRule("location.search", ("location", "search"),
               "Query string — le vecteur XSS DOM le plus courant"),
    SourceRule("location.hash", ("location", "hash"),
               "Fragment d'URL — jamais envoyé au serveur, souvent oublié côté validation"),
    SourceRule("location.pathname", ("location", "pathname"),
               "Chemin d'URL — peut contenir du payload si reflété sans encodage"),
    SourceRule("document.URL", ("document", "URL"),
               "Équivalent string de location.href"),
    SourceRule("document.documentURI", ("document", "documentURI"),
               "Équivalent document.URL"),
    SourceRule("document.referrer", ("document", "referrer"),
               "Header Referer — falsifiable par l'attaquant qui contrôle le lien source"),
    SourceRule("window.name", ("window", "name"),
               "Persiste entre navigations — vecteur classique de XSS cross-page"),
    SourceRule("postMessage", ("data",),
               "Paramètre 'data' d'un event listener 'message' — dangereux sans vérif d'origine"),
    SourceRule("localStorage.getItem", ("localStorage", "getItem"),
               "Peut être empoisonné par un XSS précédent ou une autre origine partagée"),
    SourceRule("sessionStorage.getItem", ("sessionStorage", "getItem"),
               "Idem localStorage, portée à l'onglet"),
    SourceRule("document.cookie", ("document", "cookie"),
               "Peut contenir des données injectées côté serveur ou par un autre script"),
]


# ═══════════════════════════════════════════════════════════════════════════
# SANITIZERS — fonctions qui neutralisent le taint (avec efficacité contextuelle)
# ═══════════════════════════════════════════════════════════════════════════

SANITIZERS: list[SanitizerRule] = [
    SanitizerRule(
        "encodeURIComponent", call_name="encodeURIComponent",
        description="Encode pour un contexte URL — INEFFICACE si réinjecté dans du HTML brut",
        effective_for=(SinkCategory.URL_INJECTION.value,),
    ),
    SanitizerRule(
        "encodeURI", call_name="encodeURI",
        description="Encode une URL complète — mêmes limites que encodeURIComponent",
        effective_for=(SinkCategory.URL_INJECTION.value,),
    ),
    SanitizerRule(
        "DOMPurify.sanitize", member_path=("DOMPurify", "sanitize"),
        description="Sanitizer HTML dédié — efficace pour tous les sinks HTML",
        effective_for=(SinkCategory.HTML_INJECTION.value, SinkCategory.JQUERY.value),
    ),
    SanitizerRule(
        "textContent", member_path=("textContent",),
        description="Assignation à textContent au lieu de innerHTML — échappe automatiquement",
        effective_for=(SinkCategory.HTML_INJECTION.value,),
    ),
    SanitizerRule(
        "escapeHtml", call_name="escapeHtml",
        description="Fonction custom courante — efficacité non garantie, à vérifier manuellement",
        effective_for=(),  # on ne peut pas garantir l'efficacité d'une fonction custom
    ),
    SanitizerRule(
        "sanitizeHtml", call_name="sanitizeHtml",
        description="Fonction custom courante (lib 'sanitize-html' côté Node) — efficace si utilisée correctement",
        effective_for=(SinkCategory.HTML_INJECTION.value,),
    ),
    SanitizerRule(
        "JSON.stringify", member_path=("JSON", "stringify"),
        description="Neutralise le contexte JS (échappe guillemets) mais pas le contexte HTML",
        effective_for=(SinkCategory.CODE_EXECUTION.value,),
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
# Accès rapide
# ═══════════════════════════════════════════════════════════════════════════

def find_sink_by_path(path: tuple[str, ...]) -> SinkRule | None:
    """Cherche un sink dont le member_path correspond exactement au chemin donné."""
    for sink in SINKS:
        if sink.member_path == path:
            return sink
    return None


def find_sink_by_suffix(path: tuple[str, ...]) -> SinkRule | None:
    """
    Cherche un sink dont le member_path est un suffixe du chemin donné.
    Utile pour matcher `$("#x").html(...)` où le chemin complet est
    plus long que juste ("html",).
    """
    for sink in SINKS:
        n = len(sink.member_path)
        if len(path) >= n and path[-n:] == sink.member_path:
            return sink
    return None


def find_source_by_path(path: tuple[str, ...]) -> SourceRule | None:
    for source in SOURCES:
        if source.member_path == path:
            return source
    return None


def find_source_by_suffix(path: tuple[str, ...]) -> SourceRule | None:
    for source in SOURCES:
        n = len(source.member_path)
        if len(path) >= n and path[-n:] == source.member_path:
            return source
    return None


def find_sanitizer_by_call(call_name: str) -> SanitizerRule | None:
    for s in SANITIZERS:
        if s.call_name == call_name:
            return s
    return None


def find_sanitizer_by_member_path(path: tuple[str, ...]) -> SanitizerRule | None:
    for s in SANITIZERS:
        if s.member_path and path[-len(s.member_path):] == s.member_path:
            return s
    return None


# Noms de sinks/sources sous forme de sets pour des checks O(1) rapides
SINK_LEAF_NAMES   = {sink.member_path[-1] for sink in SINKS}
SOURCE_LEAF_NAMES = {source.member_path[-1] for source in SOURCES}
SANITIZER_CALL_NAMES = {s.call_name for s in SANITIZERS if s.call_name}
