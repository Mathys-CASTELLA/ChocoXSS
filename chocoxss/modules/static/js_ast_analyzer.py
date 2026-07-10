"""
XSStress — Analyseur AST JavaScript
=====================================

Parse du code JS avec esprima et détecte, au niveau syntaxique brut,
les occurrences de sinks et sources dangereux définis dans dom_sink_rules.py.

Ce module NE fait PAS de taint tracing (traçage source→sink à travers les
variables) — c'est le rôle de taint_tracer.py. Ici on identifie seulement
les "points d'intérêt" bruts : chaque sink et chaque source rencontrés
dans l'AST, avec leur position et un extrait de code.

Deux formes de sink sont gérées :
  1. Assignation à une propriété : `el.innerHTML = x`  → AssignmentExpression
  2. Appel de méthode/fonction    : `eval(x)`, `$(y).html(x)` → CallExpression

Erreurs de parsing (JS invalide, syntaxe ES6+ non supportée par esprima)
sont capturées et renvoyées comme findings de type "parse_error" plutôt
que de faire planter le scan.
"""

from __future__ import annotations

import esprima
from dataclasses import dataclass, field
from typing import Any

from modules.static.dom_sink_rules import (
    find_sink_by_suffix,
    find_source_by_suffix,
    find_sanitizer_by_call,
    find_sanitizer_by_member_path,
    SinkRule,
    SourceRule,
    SanitizerRule,
)


# ─── Types de résultat ────────────────────────────────────────────────────────

@dataclass
class RawFinding:
    """Une occurrence brute de sink ou source détectée dans l'AST (avant taint tracing)."""
    kind: str                    # "sink" | "source" | "sanitizer" | "parse_error"
    name: str                    # nom de la règle matchée (ex: "innerHTML")
    line: int
    column: int
    code_snippet: str            # extrait de code reconstruit depuis l'AST
    node_type: str                # type de nœud ESTree ("AssignmentExpression", "CallExpression"...)
    severity: str = "INFO"
    description: str = ""
    file: str = ""
    # Le nœud AST brut de l'argument/valeur assignée, pour le taint tracer
    tainted_value_node: Any = field(default=None, repr=False)
    # Pour les sinks par assignation : le nœud identifiant assigné (variable locale du sink)
    assignment_target_node: Any = field(default=None, repr=False)


@dataclass
class AnalysisResult:
    findings: list[RawFinding] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    ast: Any = field(default=None, repr=False)  # arbre pour réutilisation par le taint tracer


# ─── Helpers de parcours de MemberExpression ──────────────────────────────────

def _member_path(node) -> tuple[str, ...]:
    """
    Reconstruit le chemin de propriétés d'une chaîne de MemberExpression.
    Ex: document.location.href → ("document", "location", "href")
    S'arrête si un membre est calculé dynamiquement (obj[x]) car le nom
    n'est pas statiquement connu.
    """
    parts = []
    current = node
    while current is not None:
        if current.type == "MemberExpression":
            if current.computed:
                # Propriété calculée dynamiquement (ex: obj[varName]) — on ne peut
                # pas résoudre le nom statiquement, on marque et on s'arrête.
                parts.insert(0, "<computed>")
                current = current.object
                continue
            if current.property.type == "Identifier":
                parts.insert(0, current.property.name)
            current = current.object
        elif current.type == "Identifier":
            parts.insert(0, current.name)
            current = None
        elif current.type == "ThisExpression":
            parts.insert(0, "this")
            current = None
        else:
            # CallExpression, Literal, etc. — on arrête la remontée ici
            current = None
    return tuple(parts)


def _snippet_from_node(node, source_lines: list[str], max_len: int = 120) -> str:
    """Reconstruit un extrait de code lisible depuis loc.start/end du nœud."""
    try:
        start_line = node.loc.start.line - 1
        end_line   = node.loc.end.line - 1
        if start_line == end_line:
            line = source_lines[start_line]
            snippet = line[node.loc.start.column:node.loc.end.column]
        else:
            snippet = source_lines[start_line][node.loc.start.column:]
        snippet = snippet.strip()
        return snippet[:max_len] + ("…" if len(snippet) > max_len else "")
    except (IndexError, AttributeError):
        return "<extrait indisponible>"


# ─── Visiteur AST principal ────────────────────────────────────────────────────

class _SinkSourceVisitor:
    """
    Parcourt récursivement l'AST et collecte les findings bruts.
    Pas de framework de visiteur externe utilisé — esprima ne fournit pas
    de walker intégré pratique, donc parcours manuel générique par attributs.
    """

    def __init__(self, source_lines: list[str], filename: str):
        self.source_lines = source_lines
        self.filename = filename
        self.findings: list[RawFinding] = []

    def visit(self, node, parent=None):
        if node is None or not hasattr(node, "type"):
            return

        node_type = node.type

        if node_type == "AssignmentExpression":
            self._check_assignment_sink(node)
        elif node_type == "CallExpression":
            self._check_call_sink_or_sanitizer(node)
            self._check_call_source(node)
        elif node_type == "MemberExpression":
            self._check_member_source(node)

        # Parcours récursif générique : on visite tous les attributs enfants
        # qui sont soit des nœuds AST, soit des listes de nœuds.
        for attr_name in self._child_attrs(node):
            child = getattr(node, attr_name, None)
            if child is None:
                continue
            if isinstance(child, list):
                for item in child:
                    self.visit(item, node)
            elif hasattr(child, "type"):
                self.visit(child, node)

    @staticmethod
    def _child_attrs(node) -> list[str]:
        """Retourne les noms d'attributs du nœud susceptibles de contenir des sous-nœuds."""
        # esprima expose les nœuds comme des objets avec __dict__ ; on filtre
        # les clés internes non pertinentes (type, loc, range).
        skip = {"type", "loc", "range"}
        return [k for k in vars(node).keys() if k not in skip]

    # ── Détection sink par assignation : el.innerHTML = x ──────────────────────

    def _check_assignment_sink(self, node):
        if node.left.type != "MemberExpression":
            return

        path = _member_path(node.left)
        if not path:
            return

        sink = find_sink_by_suffix(path)
        if sink is None:
            return

        self.findings.append(RawFinding(
            kind="sink",
            name=sink.name,
            line=node.loc.start.line,
            column=node.loc.start.column,
            code_snippet=_snippet_from_node(node, self.source_lines),
            node_type="AssignmentExpression",
            severity=sink.severity,
            description=sink.description,
            file=self.filename,
            tainted_value_node=node.right,
            assignment_target_node=node.left,
        ))

    # ── Détection sink/sanitizer par appel : eval(x), $(y).html(x) ──────────────

    def _check_call_sink_or_sanitizer(self, node):
        callee = node.callee

        # Cas 1 : appel direct — eval(x), Function(x)
        if callee.type == "Identifier":
            call_name = callee.name

            sanitizer = find_sanitizer_by_call(call_name)
            if sanitizer:
                self.findings.append(RawFinding(
                    kind="sanitizer",
                    name=sanitizer.name,
                    line=node.loc.start.line,
                    column=node.loc.start.column,
                    code_snippet=_snippet_from_node(node, self.source_lines),
                    node_type="CallExpression",
                    description=sanitizer.description,
                    file=self.filename,
                    tainted_value_node=node.arguments[0] if node.arguments else None,
                ))
                return

            sink = find_sink_by_suffix((call_name,))
            if sink and node.arguments:
                # setTimeout/setInterval ne sont dangereux que si le 1er argument
                # est une chaîne littérale ou une concaténation — pas une fonction.
                first_arg = node.arguments[0]
                if call_name in ("setTimeout", "setInterval") and first_arg.type not in (
                    "Literal", "BinaryExpression", "TemplateLiteral", "Identifier"
                ):
                    return
                self.findings.append(RawFinding(
                    kind="sink",
                    name=sink.name,
                    line=node.loc.start.line,
                    column=node.loc.start.column,
                    code_snippet=_snippet_from_node(node, self.source_lines),
                    node_type="CallExpression",
                    severity=sink.severity,
                    description=sink.description,
                    file=self.filename,
                    tainted_value_node=first_arg,
                ))
            return

        # Cas 2 : appel de méthode — obj.method(x), $(y).html(x), DOMPurify.sanitize(x)
        if callee.type == "MemberExpression":
            path = _member_path(callee)
            if not path:
                return

            sanitizer = find_sanitizer_by_member_path(path)
            if sanitizer:
                self.findings.append(RawFinding(
                    kind="sanitizer",
                    name=sanitizer.name,
                    line=node.loc.start.line,
                    column=node.loc.start.column,
                    code_snippet=_snippet_from_node(node, self.source_lines),
                    node_type="CallExpression",
                    description=sanitizer.description,
                    file=self.filename,
                    tainted_value_node=node.arguments[0] if node.arguments else None,
                ))
                return

            sink = find_sink_by_suffix(path)
            if sink and node.arguments:
                self.findings.append(RawFinding(
                    kind="sink",
                    name=sink.name,
                    line=node.loc.start.line,
                    column=node.loc.start.column,
                    code_snippet=_snippet_from_node(node, self.source_lines),
                    node_type="CallExpression",
                    severity=sink.severity,
                    description=sink.description,
                    file=self.filename,
                    tainted_value_node=node.arguments[0],
                ))

    # ── Détection source par appel : localStorage.getItem(...) ─────────────────

    def _check_call_source(self, node):
        callee = node.callee
        if callee.type != "MemberExpression":
            return
        path = _member_path(callee)
        if not path:
            return
        source = find_source_by_suffix(path)
        if source:
            self.findings.append(RawFinding(
                kind="source",
                name=source.name,
                line=node.loc.start.line,
                column=node.loc.start.column,
                code_snippet=_snippet_from_node(node, self.source_lines),
                node_type="CallExpression",
                description=source.description,
                file=self.filename,
            ))

    # ── Détection source par accès membre : location.search, document.cookie ───

    def _check_member_source(self, node):
        path = _member_path(node)
        if not path:
            return
        source = find_source_by_suffix(path)
        if source is None:
            return

        # Éviter les doublons : si ce MemberExpression est le callee d'un
        # CallExpression déjà traité par _check_call_source, on skip.
        # (heuristique simple : une source par accès de type propriété pure,
        #  pas de vérif d'unicité stricte pour garder le code lisible)
        self.findings.append(RawFinding(
            kind="source",
            name=source.name,
            line=node.loc.start.line,
            column=node.loc.start.column,
            code_snippet=_snippet_from_node(node, self.source_lines),
            node_type="MemberExpression",
            description=source.description,
            file=self.filename,
        ))


# ─── API publique ─────────────────────────────────────────────────────────────

def analyze_js(code: str, filename: str = "<inline>") -> AnalysisResult:
    """
    Parse et analyse un extrait de code JavaScript.

    Args:
        code: le code source JS à analyser
        filename: nom du fichier d'origine (pour le rapport)

    Returns:
        AnalysisResult avec les findings bruts (sinks/sources/sanitizers)
        et l'AST complet (réutilisable par le taint tracer).
    """
    result = AnalysisResult()
    source_lines = code.split("\n")

    try:
        tree = esprima.parseScript(code, options={"loc": True, "range": True, "tolerant": True})
    except Exception:
        try:
            # Certains snippets (modules, import/export) nécessitent parseModule
            tree = esprima.parseModule(code, options={"loc": True, "range": True, "tolerant": True})
        except Exception as e:
            result.parse_errors.append(f"{filename}: échec du parsing JS — {e}")
            return result

    result.ast = tree

    visitor = _SinkSourceVisitor(source_lines, filename)
    visitor.visit(tree)
    result.findings = visitor.findings

    return result


def analyze_js_file(path: str) -> AnalysisResult:
    """Lit et analyse un fichier .js sur disque."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        code = f.read()
    return analyze_js(code, filename=path)
