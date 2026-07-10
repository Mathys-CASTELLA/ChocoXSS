"""
ChocoXSS — Taint Tracer
=========================

Établit le lien de causalité réel entre une SOURCE (donnée contrôlable
par l'attaquant) et un SINK (point d'exécution dangereux), en traçant
le flux de données à travers les variables intermédiaires de l'AST.

C'est ce qui distingue ChocoXSS d'un grep glorifié : js_ast_analyzer.py
détecte les sinks/sources de façon indépendante ; ce module prouve
(ou infirme) que la valeur qui arrive dans un sink provient réellement
d'une source, malgré les réassignations, concaténations, et appels de
fonctions intermédiaires.

Exemple concret tracé correctement :

    var a = location.search;        // a ← SOURCE
    var b = decodeURIComponent(a);  // b ← a (passthrough, pas un sanitizer HTML)
    var c = "prefix_" + b;          // c ← b (concaténation)
    el.innerHTML = c;               // SINK ← c  =>  CONFIRMED, chaîne : c ← b ← a ← location.search

Et un cas correctement neutralisé :

    var a = location.search;
    var clean = DOMPurify.sanitize(a);  // clean : sanitizer HTML efficace
    el.innerHTML = clean;                // SINK ← clean  =>  SAFE (taint bloqué)

Limites connues de la V1 (documentées, pas cachées) :
  - Portée (scope) simplifiée : la table de symboles est quasi-globale,
    pas de vraie résolution de scope par fonction/bloc. Un shadowing de
    variable (même nom réutilisé dans une fonction imbriquée) peut donner
    un faux résultat. Acceptable pour du code applicatif typique, pas pour
    du code fortement modulaire à variables très génériques (x, y, tmp).
  - Pas de suivi inter-fichiers : chaque fichier JS est tracé indépendamment.
  - Pas de suivi à travers des appels de fonctions custom définies par
    l'utilisateur (on regarde uniquement DANS les arguments passés, pas
    ce qui se passe DANS le corps d'une fonction custom appelée).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from modules.static.dom_sink_rules import (
    find_source_by_suffix,
    find_sanitizer_by_call,
    find_sanitizer_by_member_path,
    SinkCategory,
)
from modules.static.js_ast_analyzer import RawFinding, _member_path


# ─── Fonctions "passthrough" connues ──────────────────────────────────────────
# Ces fonctions transforment une valeur mais ne neutralisent PAS un contexte
# HTML (contrairement aux sanitizers). Le taint doit continuer à se propager
# à travers elles. Liste non exhaustive, mais couvre les cas les plus courants.
KNOWN_PASSTHROUGH_CALLS = {
    "decodeURIComponent", "decodeURI", "unescape",
    "String", "toString", "trim", "toLowerCase", "toUpperCase",
    "substring", "substr", "slice", "concat", "replace", "split",
    "parseInt", "parseFloat",
}


class TaintStatus(Enum):
    TAINTED   = "tainted"     # provient d'une source, aucun sanitizer efficace rencontré
    SANITIZED = "sanitized"   # provient d'une source MAIS un sanitizer efficace l'a neutralisée
    CLEAN     = "clean"       # ne provient d'aucune source identifiable
    UNKNOWN   = "unknown"     # impossible à déterminer (ex: paramètre de fonction externe)


@dataclass
class TaintLink:
    """Un maillon de la chaîne de propagation source → ... → sink."""
    description: str      # ex: "b = decodeURIComponent(a)"
    line: int


@dataclass
class TaintResult:
    status: TaintStatus
    source_name: str | None = None       # ex: "location.search"
    chain: list[TaintLink] = field(default_factory=list)  # dans l'ordre source → sink
    sanitizer_name: str | None = None    # si SANITIZED, quel sanitizer a bloqué le taint
    sanitizer_effective: bool = True     # False si le sanitizer existe mais est inadapté au contexte


@dataclass
class ConfirmedFinding:
    """Un sink dont la donnée d'entrée a été tracée jusqu'à (ou pas) une source."""
    sink_finding: RawFinding
    taint: TaintResult

    @property
    def confidence(self) -> str:
        """
        CONFIRMED  : source tracée avec certitude jusqu'au sink, aucun sanitizer efficace
        LIKELY     : source tracée mais via une fonction custom non analysée (UNKNOWN sur un maillon)
        SANITIZED  : source tracée mais un sanitizer efficace bloque le chemin
        NONE       : aucune source identifiée en amont du sink
        """
        if self.taint.status == TaintStatus.TAINTED:
            return "CONFIRMED"
        if self.taint.status == TaintStatus.UNKNOWN:
            return "LIKELY"
        if self.taint.status == TaintStatus.SANITIZED:
            return "SANITIZED"
        return "NONE"


# ─── Table de symboles ─────────────────────────────────────────────────────────

class _SymbolTable:
    """
    Table quasi-globale variable → dernier nœud d'expression qui lui a été assigné.

    Limite assumée (cf. docstring module) : pas de vraie gestion de scope.
    Pour la V1, une variable réassignée écrase simplement l'entrée précédente,
    ce qui correspond au comportement JS le plus courant dans du code non
    fortement modulaire (le cas typique d'un bout de JS applicatif vulnérable).
    """

    def __init__(self):
        self._table: dict[str, Any] = {}

    def set(self, name: str, node: Any):
        self._table[name] = node

    def get(self, name: str) -> Any | None:
        return self._table.get(name)

    def build_from_ast(self, ast_root):
        """Parcourt tout l'AST et peuple la table avec chaque assignation rencontrée."""
        self._walk(ast_root)

    def _walk(self, node):
        if node is None or not hasattr(node, "type"):
            return

        if node.type == "VariableDeclarator" and node.id.type == "Identifier" and node.init is not None:
            self.set(node.id.name, node.init)

        elif node.type == "AssignmentExpression" and node.left.type == "Identifier" and node.operator == "=":
            self.set(node.left.name, node.right)

        for attr_name in [k for k in vars(node).keys() if k not in ("type", "loc", "range")]:
            child = getattr(node, attr_name, None)
            if isinstance(child, list):
                for item in child:
                    self._walk(item)
            elif hasattr(child, "type"):
                self._walk(child)


# ─── Résolution récursive du taint ────────────────────────────────────────────

def _resolve_taint(
    node: Any,
    symbols: _SymbolTable,
    sink_category: str,
    chain: list[TaintLink] | None = None,
    depth: int = 0,
    _visited: set[int] | None = None,
) -> TaintResult:
    """
    Détermine récursivement si `node` remonte à une source, et si un
    sanitizer efficace bloque le chemin en cours de route.

    Args:
        node: nœud AST à analyser (la valeur assignée à un sink, ou un
              sous-composant lors de la récursion)
        symbols: table de symboles pré-construite pour ce fichier
        sink_category: catégorie du sink cible (pour juger l'efficacité
              contextuelle d'un sanitizer rencontré)
        chain: accumulateur de la chaîne de propagation (ordre source→sink
              reconstruit à l'envers puis inversé à la fin)
        depth: protection anti-boucle infinie (variables auto-référentes)
        _visited: ids Python des nœuds déjà visités dans CETTE résolution,
              pour éviter les cycles (ex: a = f(a) mal formé)
    """
    if chain is None:
        chain = []
    if _visited is None:
        _visited = set()

    MAX_DEPTH = 25
    if node is None or depth > MAX_DEPTH:
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

    node_id = id(node)
    if node_id in _visited:
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))
    _visited.add(node_id)

    node_type = node.type

    # ── Cas 1 : accès direct à une source (location.search, document.cookie...) ──
    if node_type == "MemberExpression":
        path = _member_path(node)
        source = find_source_by_suffix(path) if path else None
        if source:
            return TaintResult(
                status=TaintStatus.TAINTED,
                source_name=source.name,
                chain=list(reversed(chain)),
            )
        # MemberExpression qui n'est pas une source connue : creuser dans l'objet
        # (ex: params.get(...) où params vient d'une source — géré au niveau CallExpression)
        return _resolve_taint(node.object, symbols, sink_category, chain, depth + 1, _visited)

    # ── Cas 2 : littéral (string, number...) — jamais taintée ─────────────────
    if node_type == "Literal":
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

    # ── Cas 3 : identifiant — résoudre via la table de symboles ────────────────
    if node_type == "Identifier":
        definition = symbols.get(node.name)
        if definition is None:
            # Variable non résolue : paramètre de fonction, import, ou variable
            # globale externe — on ne peut pas savoir, mais on ne l'ignore pas
            # silencieusement pour autant : on remonte UNKNOWN pour ne pas
            # masquer un faux négatif potentiel.
            return TaintResult(status=TaintStatus.UNKNOWN, chain=list(reversed(chain)))
        new_chain = chain + [TaintLink(description=f"{node.name} ← <déclaration ligne {getattr(definition.loc, 'start', None) and definition.loc.start.line}>", line=getattr(definition.loc, "start", None) and definition.loc.start.line or 0)]
        return _resolve_taint(definition, symbols, sink_category, new_chain, depth + 1, _visited)

    # ── Cas 4 : concaténation binaire ("prefix_" + x) ──────────────────────────
    if node_type == "BinaryExpression" and node.operator == "+":
        left_result  = _resolve_taint(node.left,  symbols, sink_category, chain, depth + 1, _visited)
        if left_result.status == TaintStatus.TAINTED:
            return left_result
        right_result = _resolve_taint(node.right, symbols, sink_category, chain, depth + 1, _visited)
        if right_result.status == TaintStatus.TAINTED:
            return right_result
        # Si l'un des deux est UNKNOWN et l'autre CLEAN, le résultat global
        # reste incertain plutôt que faussement CLEAN.
        if TaintStatus.UNKNOWN in (left_result.status, right_result.status):
            return TaintResult(status=TaintStatus.UNKNOWN, chain=list(reversed(chain)))
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

    # ── Cas 5 : template literal (`Hello ${x}`) ────────────────────────────────
    if node_type == "TemplateLiteral":
        for expr in node.expressions:
            r = _resolve_taint(expr, symbols, sink_category, chain, depth + 1, _visited)
            if r.status in (TaintStatus.TAINTED, TaintStatus.UNKNOWN):
                return r
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

    # ── Cas 6 : expression conditionnelle (ternaire) ───────────────────────────
    if node_type == "ConditionalExpression":
        cons = _resolve_taint(node.consequent, symbols, sink_category, chain, depth + 1, _visited)
        if cons.status in (TaintStatus.TAINTED, TaintStatus.UNKNOWN):
            return cons
        return _resolve_taint(node.alternate, symbols, sink_category, chain, depth + 1, _visited)

    # ── Cas 7 : appel de fonction ────────────────────────────────────────────────
    if node_type == "CallExpression":
        callee = node.callee

        # 7a. Sanitizer connu → bloque (ou pas, selon l'efficacité contextuelle)
        sanitizer = None
        if callee.type == "Identifier":
            sanitizer = find_sanitizer_by_call(callee.name)
        elif callee.type == "MemberExpression":
            path = _member_path(callee)
            sanitizer = find_sanitizer_by_member_path(path) if path else None

        if sanitizer:
            # On trace quand même si l'argument était taintée à la base,
            # pour savoir si le sanitizer a une vraie utilité ici ou non.
            arg_result = TaintResult(status=TaintStatus.CLEAN)
            if node.arguments:
                arg_result = _resolve_taint(node.arguments[0], symbols, sink_category, chain, depth + 1, _visited)

            if arg_result.status != TaintStatus.TAINTED:
                # Rien à sanitizer, ou déjà clean/inconnu
                return arg_result

            effective = (not sanitizer.effective_for) or (sink_category in sanitizer.effective_for)
            if effective:
                return TaintResult(
                    status=TaintStatus.SANITIZED,
                    source_name=arg_result.source_name,
                    chain=arg_result.chain,
                    sanitizer_name=sanitizer.name,
                    sanitizer_effective=True,
                )
            else:
                # Sanitizer présent mais inadapté au contexte du sink → reste TAINTED,
                # c'est un piège classique (ex: encodeURIComponent avant un innerHTML)
                return TaintResult(
                    status=TaintStatus.TAINTED,
                    source_name=arg_result.source_name,
                    chain=arg_result.chain,
                    sanitizer_name=sanitizer.name,
                    sanitizer_effective=False,
                )

        # 7b. Fonction passthrough connue → creuser dans la bonne source de taint.
        # Deux cas distincts :
        #   - appel de fonction libre  : decodeURIComponent(a)  → le taint vient de l'ARGUMENT
        #   - appel de méthode d'objet : a.substring(1)         → le taint vient de l'OBJET,
        #     l'argument (1) n'est qu'un paramètre de la méthode, pas la donnée transformée.
        call_name = callee.name if callee.type == "Identifier" else (
            callee.property.name if callee.type == "MemberExpression" and callee.property.type == "Identifier" else None
        )
        if call_name in KNOWN_PASSTHROUGH_CALLS:
            if callee.type == "MemberExpression":
                # Méthode : obj.method(args) → creuser dans l'objet, pas les arguments
                return _resolve_taint(callee.object, symbols, sink_category, chain, depth + 1, _visited)
            if node.arguments:
                # Fonction libre : f(x) → creuser dans le premier argument
                return _resolve_taint(node.arguments[0], symbols, sink_category, chain, depth + 1, _visited)
            return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

        # 7c. Méthode sur un objet potentiellement taintée : params.get("x")
        #     où params = new URLSearchParams(location.search)
        if callee.type == "MemberExpression":
            obj_result = _resolve_taint(callee.object, symbols, sink_category, chain, depth + 1, _visited)
            if obj_result.status in (TaintStatus.TAINTED, TaintStatus.UNKNOWN):
                return obj_result

        # 7d. Fonction custom inconnue : on ne connaît pas son corps.
        # On regarde si l'un des arguments est taintée — si oui, on ne peut
        # pas garantir que la fonction neutralise le taint, donc UNKNOWN
        # plutôt qu'un faux CLEAN silencieux.
        for arg in node.arguments:
            arg_result = _resolve_taint(arg, symbols, sink_category, chain, depth + 1, _visited)
            if arg_result.status == TaintStatus.TAINTED:
                return TaintResult(status=TaintStatus.UNKNOWN, chain=arg_result.chain)
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

    # ── Cas 8 : new Expression (ex: new URLSearchParams(location.search)) ──────
    if node_type == "NewExpression":
        for arg in node.arguments:
            r = _resolve_taint(arg, symbols, sink_category, chain, depth + 1, _visited)
            if r.status in (TaintStatus.TAINTED, TaintStatus.UNKNOWN):
                return r
        return TaintResult(status=TaintStatus.CLEAN, chain=list(reversed(chain)))

    # ── Cas par défaut : type de nœud non géré explicitement ────────────────────
    # On préfère UNKNOWN à CLEAN pour ne pas masquer silencieusement un taint
    # qu'on n'a pas su analyser (ex: SequenceExpression, ArrayExpression complexe).
    return TaintResult(status=TaintStatus.UNKNOWN, chain=list(reversed(chain)))


# ─── API publique ─────────────────────────────────────────────────────────────

def trace_findings(sink_findings: list[RawFinding], ast_root: Any) -> list[ConfirmedFinding]:
    """
    Pour chaque sink détecté par js_ast_analyzer, trace sa valeur d'entrée
    jusqu'à une source potentielle.

    Args:
        sink_findings: findings de kind == "sink" issus de analyze_js()
        ast_root: l'AST complet du même fichier (pour construire la table de symboles)

    Returns:
        Liste de ConfirmedFinding, un par sink, avec son statut de confiance.
    """
    symbols = _SymbolTable()
    symbols.build_from_ast(ast_root)

    results = []
    for finding in sink_findings:
        if finding.kind != "sink":
            continue

        sink_category = _infer_sink_category(finding.name)

        if finding.tainted_value_node is None:
            taint = TaintResult(status=TaintStatus.UNKNOWN)
        else:
            taint = _resolve_taint(finding.tainted_value_node, symbols, sink_category)

        results.append(ConfirmedFinding(sink_finding=finding, taint=taint))

    return results


def _infer_sink_category(sink_name: str) -> str:
    """Retrouve la catégorie du sink à partir de son nom, pour juger l'efficacité des sanitizers."""
    from modules.static.dom_sink_rules import SINKS
    for sink in SINKS:
        if sink.name == sink_name:
            return sink.category.value
    return ""
