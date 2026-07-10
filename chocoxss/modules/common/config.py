"""
ChocoXSS — Gestion du fichier de configuration
==================================================

Lit ~/.chocoxss.conf (format TOML) et applique les valeurs comme
defaults argparse — les arguments CLI ont toujours la priorité.
Même principe que ~/.chocoscan.conf sur ChocoScan.

Fichier de config exemple : ~/.chocoxss.conf
─────────────────────────────────────────────
  # Options par défaut de ChocoXSS
  # Toutes les valeurs ici sont surchargées par les arguments CLI.

  insecure     = false
  timeout      = 15
  delay        = 0.3
  refresh_csrf = true
  proxy        = "http://127.0.0.1:8080"

  [crawl]
  crawl_depth    = 1
  max_pages      = 30
  crawl_external = false

  [scan]
  bypass    = false
  verbose   = true
  no_verify = false
─────────────────────────────────────────────

Priorité de résolution (la plus haute gagne) :
  1. Argument CLI explicite        (--timeout 20)
  2. Variable d'environnement      (CHOCOXSS_TIMEOUT=20)
  3. Fichier ~/.chocoxss.conf
  4. Défaut argparse

Les identifiants sensibles (cookie, header) ne sont volontairement PAS
gérés par ce module — un cookie de session change trop souvent d'une
cible à l'autre pour justifier de le stocker en clair dans un fichier
de config persistant. Passez-les toujours en CLI (-b/-H) ou via variable
d'environnement au cas par cas.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path
from typing import Any


CONFIG_SEARCH_PATHS: list[Path] = [
    Path.home() / ".chocoxss.conf",
    Path.home() / ".config" / "chocoxss" / "config.toml",
    Path(".chocoxss.conf"),
]

CONFIG_ENV_VAR = "CHOCOXSS_CONFIG"

# clé_toml → (type Python, valeur_défaut, section_toml ou None pour racine)
CONFIGURABLE_KEYS: dict[str, tuple[type, Any, str | None]] = {
    "insecure":       (bool,  False,   None),
    "timeout":        (int,   10,      None),
    "delay":          (float, 0.0,     None),
    "threads":        (int,   1,       None),
    "refresh_csrf":   (bool,  False,   None),
    "proxy":          (str,   "",      None),
    "screenshot_dir": (str,   "",      None),
    "verbose":        (bool,  False,   "scan"),
    "bypass":         (bool,  False,   "scan"),
    "no_verify":      (bool,  False,   "scan"),
    "crawl_depth":    (int,   0,       "crawl"),
    "max_pages":      (int,   20,      "crawl"),
    "crawl_external": (bool,  False,   "crawl"),
}


def find_config_file() -> Path | None:
    env_path = os.environ.get(CONFIG_ENV_VAR)
    if env_path:
        p = Path(env_path).expanduser()
        if p.exists():
            return p
        _warn(f"${CONFIG_ENV_VAR}={env_path} introuvable, ignoré.")

    for p in CONFIG_SEARCH_PATHS:
        if p.expanduser().exists():
            return p.expanduser()

    return None


def _warn(msg: str):
    try:
        from rich.console import Console
        Console(stderr=True).print(f"[yellow dim][config] {msg}[/yellow dim]")
    except ImportError:
        print(f"[config] {msg}", file=sys.stderr)


def _info(msg: str):
    try:
        from rich.console import Console
        Console(stderr=True).print(f"[dim][config] {msg}[/dim]")
    except ImportError:
        pass


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Charge et valide le fichier de config. Retourne {} si absent/invalide."""
    path = config_path or find_config_file()
    if path is None:
        return {}

    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        _warn(f"Erreur de syntaxe dans {path} : {e}")
        return {}
    except OSError as e:
        _warn(f"Impossible de lire {path} : {e}")
        return {}

    return _flatten_and_validate(raw, path)


def _flatten_and_validate(raw: dict, path: Path) -> dict[str, Any]:
    flat: dict[str, Any] = {}
    unknown: list[str] = []

    for key, value in raw.items():
        if isinstance(value, dict):
            for subkey, subval in value.items():
                _process_key(subkey, subval, flat, unknown)
        else:
            _process_key(key, value, flat, unknown)

    if unknown:
        _warn(f"{path.name} : clés inconnues ignorées : {', '.join(unknown)}")

    return flat


def _process_key(key: str, value: Any, flat: dict, unknown: list):
    if key not in CONFIGURABLE_KEYS:
        unknown.append(key)
        return

    expected_type, _, _ = CONFIGURABLE_KEYS[key]
    try:
        if expected_type == bool:
            if not isinstance(value, bool):
                raise TypeError(f"attendu bool, reçu {type(value).__name__}")
            flat[key] = value
        elif expected_type == float:
            flat[key] = float(value)
        elif expected_type == int:
            flat[key] = int(value)
        elif expected_type == str:
            flat[key] = str(value)
        else:
            flat[key] = value
    except (TypeError, ValueError) as e:
        _warn(f"Clé '{key}' : valeur invalide ({e}), ignorée.")


def load_env_overrides() -> dict[str, Any]:
    """Lit les variables d'environnement CHOCOXSS_* (priorité sur le fichier)."""
    overrides: dict[str, Any] = {}
    prefix = "CHOCOXSS_"

    for env_key, env_val in os.environ.items():
        if not env_key.startswith(prefix) or env_key == CONFIG_ENV_VAR:
            continue
        config_key = env_key[len(prefix):].lower()
        if config_key not in CONFIGURABLE_KEYS:
            continue

        expected_type, _, _ = CONFIGURABLE_KEYS[config_key]
        try:
            if expected_type == bool:
                overrides[config_key] = env_val.strip().lower() in ("1", "true", "yes", "on")
            elif expected_type == float:
                overrides[config_key] = float(env_val)
            elif expected_type == int:
                overrides[config_key] = int(env_val)
            else:
                overrides[config_key] = env_val
        except (ValueError, TypeError):
            _warn(f"${env_key} : valeur invalide '{env_val}', ignorée.")

    return overrides


def apply_to_parser(parser, config_path: Path | None = None, verbose: bool = True) -> Path | None:
    """
    Charge la config et l'applique sur le parser via set_defaults().
    Les valeurs CLI ont toujours la priorité (comportement naturel de
    set_defaults : il ne remplace que les défauts, pas les valeurs
    explicitement passées par l'utilisateur).
    """
    path = config_path or find_config_file()

    file_cfg = load_config(path)
    env_cfg = load_env_overrides()
    merged = {**file_cfg, **env_cfg}

    # Une valeur str vide dans le TOML ne doit pas écraser le défaut None
    # de argparse (concerne les chemins/URL optionnels : proxy, screenshot_dir)
    for optional_str_key in ("proxy", "screenshot_dir"):
        if merged.get(optional_str_key) == "":
            merged.pop(optional_str_key)

    if not merged:
        return path

    parser.set_defaults(**merged)

    if verbose and path:
        _info(f"Config chargée : {path}")

    return path


def cmd_config_show(config_path: Path | None = None):
    """Affiche la config active (fichier + env) avec leur source."""
    path = config_path or find_config_file()
    file_cfg = load_config(path)
    env_cfg = load_env_overrides()

    try:
        from rich.console import Console
        from rich.table import Table
        from rich import box as rbox

        c = Console()
        t = Table(
            title=f"Config active — {path or 'aucun fichier trouvé'}",
            box=rbox.ROUNDED,
            show_header=True,
        )
        t.add_column("Clé", style="cyan", min_width=16)
        t.add_column("Valeur", style="bold", min_width=10)
        t.add_column("Source", style="dim", min_width=14)

        for key in sorted(CONFIGURABLE_KEYS):
            _, default, _ = CONFIGURABLE_KEYS[key]
            if key in env_cfg:
                val, source = env_cfg[key], f"$CHOCOXSS_{key.upper()}"
            elif key in file_cfg:
                val, source = file_cfg[key], path.name if path else "fichier"
            else:
                val, source = default, "défaut"
            val_str = str(val) if val not in (None, "") else "—"
            t.add_row(key, val_str, source)

        c.print(t)
        if not path:
            c.print("\n[dim]Aucun fichier de config trouvé. Créez [bold]~/.chocoxss.conf[/bold] "
                    "avec [bold]chocoxss.py config init[/bold].[/dim]")
    except ImportError:
        print(f"\nConfig active — {path or 'aucun fichier'}")
        print(f"{'Clé':<18} {'Valeur':<12} Source")
        print("-" * 50)
        for key in sorted(CONFIGURABLE_KEYS):
            _, default, _ = CONFIGURABLE_KEYS[key]
            if key in env_cfg:
                val, source = env_cfg[key], "env"
            elif key in file_cfg:
                val, source = file_cfg[key], "fichier"
            else:
                val, source = default, "défaut"
            print(f"  {key:<16} {str(val):<12} {source}")


def cmd_config_init(target: Path | None = None, force: bool = False):
    """Crée (ou écrase si force=True) ~/.chocoxss.conf avec toutes les options commentées."""
    dest = target or Path.home() / ".chocoxss.conf"

    if dest.exists() and not force:
        try:
            from rich.console import Console
            Console().print(f"[yellow][!] {dest} existe déjà. Utilisez --force pour écraser.[/yellow]")
        except ImportError:
            print(f"[!] {dest} existe déjà.")
        return

    content = _generate_default_config()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content, encoding="utf-8")

    try:
        from rich.console import Console
        Console().print(f"[green][+] Config créée : {dest}[/green]")
        Console().print("[dim]Éditez le fichier pour personnaliser vos préférences.[/dim]")
    except ImportError:
        print(f"[+] Config créée : {dest}")


def _generate_default_config() -> str:
    from datetime import datetime
    now = datetime.now().strftime("%Y-%m-%d")

    return f"""# ChocoXSS — Fichier de configuration personnelle
# Généré le {now}
# Emplacement : ~/.chocoxss.conf
#
# Toutes les valeurs ici sont des DÉFAUTS — surchargées par les arguments
# CLI (ex: --timeout 20 écrase timeout ci-dessous).
#
# Variables d'environnement : CHOCOXSS_<CLÉ_MAJUSCULE>
#   ex: export CHOCOXSS_DELAY=0.5
#
# Les cookies/headers (-b/-H) ne sont volontairement pas gérables ici —
# trop spécifiques à chaque cible pour un fichier de config persistant.

# ─── Réseau ──────────────────────────────────────────────────────────────────

# Désactiver la vérification du certificat SSL (labo CTF, certificat auto-signé)
insecure = false

# Timeout des requêtes HTTP, en secondes
timeout = 10

# Pause entre chaque requête de payload, en secondes (0 = pas de pause)
delay = 0.0

# Nombre de points d'injection testés en parallèle (1 = séquentiel)
threads = 1

# Rafraîchir le token CSRF d'un formulaire avant de le tester
refresh_csrf = false

# Proxy pour toutes les requêtes HTTP(S) — laisser vide pour désactiver
# proxy = "http://127.0.0.1:8080"

# Dossier de capture d'écran pour chaque exécution XSS confirmée — laisser
# vide pour désactiver (pas de screenshot par défaut)
# screenshot_dir = "~/chocoxss_screenshots"

# ─── Crawl ───────────────────────────────────────────────────────────────────

[crawl]
# Suivre les liens de la page jusqu'à N sauts (0 = une seule page)
crawl_depth = 0

# Plafond de pages visitées en mode crawl_depth
max_pages = 20

# Autoriser le crawl à sortir du domaine de départ
crawl_external = false

# ─── Scan ────────────────────────────────────────────────────────────────────

[scan]
# Afficher l'extrait de réponse HTTP pour chaque réflexion détectée
verbose = false

# Relancer des variantes de contournement de filtre sur REFLECTED_PARTIAL
bypass = false

# Désactiver la vérification navigateur headless (plus rapide, moins fiable)
no_verify = false
"""
