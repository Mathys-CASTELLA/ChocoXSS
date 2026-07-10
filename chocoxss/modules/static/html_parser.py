"""
XSStress — Parser HTML
=========================

Extrait d'un document HTML tout ce qui peut contenir ou exécuter du
JavaScript, pour analyse ultérieure par js_ast_analyzer.py :

  1. Scripts inline           <script>...</script>
  2. Scripts externes         <script src="..."> (référencés, pas suivis en V1)
  3. Attributs event handler  onclick, onerror, onload, etc.
  4. URIs javascript:          href="javascript:...", src="javascript:..."

Chaque extrait garde une trace de sa position dans le document source
(ligne approximative, élément parent, attribut) pour un rapport utile.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from bs4 import BeautifulSoup, Tag


# Liste des attributs "on*" reconnus par le DOM — on filtre sur ce préfixe
# plutôt qu'une liste exhaustive, HTML5 permettant des handlers sur presque
# tout élément (onclick, onerror, onload, onmouseover, onfocus...).
EVENT_HANDLER_PREFIX = "on"

# Attributs pouvant contenir une URI (donc potentiellement "javascript:")
URI_ATTRIBUTES = ("href", "src", "action", "formaction", "data")


@dataclass
class ExtractedScript:
    """Un fragment de JavaScript extrait du HTML, prêt pour analyze_js()."""
    kind: str                 # "inline_script" | "event_handler" | "javascript_uri" | "external_script"
    code: str                 # code JS à analyser (vide pour external_script)
    tag_name: str              # ex: "script", "img", "a"
    attribute: str | None      # ex: "onclick", "href" — None pour <script> inline
    approx_line: int           # ligne approximative dans le document HTML source
    context_snippet: str       # extrait HTML autour de l'élément (pour le rapport)
    external_src: str | None = None  # URL si kind == "external_script"


@dataclass
class HtmlExtractionResult:
    scripts: list[ExtractedScript] = field(default_factory=list)
    forms_found: int = 0
    external_scripts: list[str] = field(default_factory=list)
    parse_warnings: list[str] = field(default_factory=list)


def _approx_line(soup_or_tag, html_source: str) -> int:
    """
    BeautifulSoup (parser html.parser/lxml) ne conserve pas nativement les
    numéros de ligne pour tous les parsers. On utilise sourceline si présent
    (lxml le fournit), sinon fallback à une recherche approximative de la
    représentation du tag dans le texte source.
    """
    line = getattr(soup_or_tag, "sourceline", None)
    if line:
        return line
    return 0  # inconnu — le rapport affichera "?"


def extract_from_html(html: str, filename: str = "<inline>") -> HtmlExtractionResult:
    """
    Parse un document HTML et extrait tous les points d'injection JS possibles.

    Args:
        html: contenu HTML brut
        filename: nom du fichier source (pour le rapport)

    Returns:
        HtmlExtractionResult listant tous les ExtractedScript trouvés.
    """
    result = HtmlExtractionResult()

    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception as e:
        result.parse_warnings.append(f"{filename}: erreur de parsing HTML — {e}")
        return result

    # ── 1. Scripts <script>...</script> et <script src="..."> ──────────────────
    for script_tag in soup.find_all("script"):
        src = script_tag.get("src")
        if src:
            result.external_scripts.append(src)
            result.scripts.append(ExtractedScript(
                kind="external_script",
                code="",
                tag_name="script",
                attribute="src",
                approx_line=_approx_line(script_tag, html),
                context_snippet=str(script_tag)[:120],
                external_src=src,
            ))
            continue

        # Ignorer les scripts de type non-JS (JSON, templates Handlebars/Vue...)
        script_type = (script_tag.get("type") or "").lower()
        if script_type and script_type not in (
            "text/javascript", "application/javascript", "module", ""
        ):
            continue

        code = script_tag.string
        if code and code.strip():
            result.scripts.append(ExtractedScript(
                kind="inline_script",
                code=str(code),
                tag_name="script",
                attribute=None,
                approx_line=_approx_line(script_tag, html),
                context_snippet="<script> inline",
            ))

    # ── 2. Attributs event handler on* sur tous les éléments ────────────────────
    for tag in soup.find_all(True):
        if not isinstance(tag, Tag):
            continue
        for attr, value in tag.attrs.items():
            if not attr.lower().startswith(EVENT_HANDLER_PREFIX):
                continue
            if not isinstance(value, str) or not value.strip():
                continue
            result.scripts.append(ExtractedScript(
                kind="event_handler",
                code=value,
                tag_name=tag.name,
                attribute=attr,
                approx_line=_approx_line(tag, html),
                context_snippet=f'<{tag.name} {attr}="{value[:60]}">',
            ))

    # ── 3. URIs javascript: dans href/src/action/formaction ────────────────────
    for tag in soup.find_all(True):
        if not isinstance(tag, Tag):
            continue
        for attr in URI_ATTRIBUTES:
            value = tag.get(attr)
            if not isinstance(value, str):
                continue
            stripped = value.strip()
            if stripped.lower().startswith("javascript:"):
                js_code = stripped[len("javascript:"):]
                result.scripts.append(ExtractedScript(
                    kind="javascript_uri",
                    code=js_code,
                    tag_name=tag.name,
                    attribute=attr,
                    approx_line=_approx_line(tag, html),
                    context_snippet=f'<{tag.name} {attr}="{stripped[:60]}">',
                ))

    # ── Stats complémentaires pour le rapport ───────────────────────────────────
    result.forms_found = len(soup.find_all("form"))

    return result


def extract_from_html_file(path: str) -> HtmlExtractionResult:
    """Lit et extrait depuis un fichier .html sur disque."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        html = f.read()
    return extract_from_html(html, filename=path)
