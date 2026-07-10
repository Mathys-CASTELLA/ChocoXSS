#!/usr/bin/env python3
"""
ChocoXSS — Démo CLI (analyse statique avec taint tracing)
============================================================

Usage :
    python demo_scan.py fichier.html
    python demo_scan.py fichier.js
    echo '<script>eval(x)</script>' | python demo_scan.py -
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.static.html_parser import extract_from_html
from modules.static.js_ast_analyzer import analyze_js
from modules.static.taint_tracer import trace_findings

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
    console = Console()
except ImportError:
    RICH = False


CONFIDENCE_ORDER = {"CONFIRMED": 0, "LIKELY": 1, "SANITIZED": 2, "NONE": 3}
CONFIDENCE_COLOR = {"CONFIRMED": "red", "LIKELY": "yellow", "SANITIZED": "green", "NONE": "dim"}


def scan_html(html: str, filename: str):
    extraction = extract_from_html(html, filename)
    all_confirmed = []
    all_sources = []
    all_sanitizers = []

    for script in extraction.scripts:
        if script.kind == "external_script":
            continue
        result = analyze_js(script.code, filename=filename)
        sinks = [f for f in result.findings if f.kind == "sink"]
        confirmed = trace_findings(sinks, result.ast)
        for c in confirmed:
            c.sink_finding.file = f"{filename} [{script.kind}]"
        all_confirmed.extend(confirmed)
        all_sources.extend([f for f in result.findings if f.kind == "source"])
        all_sanitizers.extend([f for f in result.findings if f.kind == "sanitizer"])

    return all_confirmed, all_sources, all_sanitizers, extraction


def scan_js(code: str, filename: str):
    result = analyze_js(code, filename=filename)
    sinks = [f for f in result.findings if f.kind == "sink"]
    confirmed = trace_findings(sinks, result.ast)
    sources = [f for f in result.findings if f.kind == "source"]
    sanitizers = [f for f in result.findings if f.kind == "sanitizer"]
    return confirmed, sources, sanitizers, None


def print_results(confirmed, sources, sanitizers, extraction=None):
    if RICH:
        console.print(Panel.fit(
            "[bold cyan]ChocoXSS[/bold cyan] — [yellow]Analyse statique avec taint tracing[/yellow]"
        ))

        if extraction:
            console.print(f"[dim]{len(extraction.scripts)} fragments JS extraits, "
                          f"{len(extraction.external_scripts)} scripts externes ignorés, "
                          f"{extraction.forms_found} formulaire(s) détecté(s)[/dim]\n")

        if confirmed:
            t = Table(title=f"🎯 Sinks analysés ({len(confirmed)})", box=box.ROUNDED)
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
                    c.sink_finding.code_snippet,
                )
            console.print(t)
        else:
            console.print("[green]Aucun sink détecté.[/green]")

        if sanitizers:
            console.print(f"\n[bold green]🛡  Sanitizers rencontrés ({len(sanitizers)})[/bold green]")
            for f in sanitizers:
                console.print(f"  [dim]L{f.line}[/dim] {f.name} — {f.description}")

        n_confirmed = sum(1 for c in confirmed if c.confidence == "CONFIRMED")
        n_likely    = sum(1 for c in confirmed if c.confidence == "LIKELY")
        n_sanitized = sum(1 for c in confirmed if c.confidence == "SANITIZED")

        console.print(
            f"\n[bold]Résumé :[/bold] "
            f"[red]{n_confirmed} confirmée(s)[/red] · "
            f"[yellow]{n_likely} probable(s)[/yellow] · "
            f"[green]{n_sanitized} neutralisée(s)[/green]"
        )

    else:
        print(f"\n=== ChocoXSS — Analyse statique ===\n")
        for c in sorted(confirmed, key=lambda x: CONFIDENCE_ORDER.get(x.confidence, 9)):
            print(f"  [{c.confidence:10}] L{c.sink_finding.line} {c.sink_finding.name:15} "
                  f"source={c.taint.source_name} sanitizer={c.taint.sanitizer_name}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python demo_scan.py <fichier.html|fichier.js|->")
        sys.exit(1)

    arg = sys.argv[1]

    if arg == "-":
        content = sys.stdin.read()
        filename = "<stdin>"
        is_html = "<" in content and ">" in content
    else:
        path = Path(arg)
        if not path.exists():
            print(f"[!] Fichier introuvable : {arg}")
            sys.exit(1)
        content = path.read_text(encoding="utf-8", errors="replace")
        filename = str(path)
        is_html = path.suffix.lower() in (".html", ".htm")

    if is_html:
        confirmed, sources, sanitizers, extraction = scan_html(content, filename)
    else:
        confirmed, sources, sanitizers, extraction = scan_js(content, filename)

    print_results(confirmed, sources, sanitizers, extraction)


if __name__ == "__main__":
    main()
