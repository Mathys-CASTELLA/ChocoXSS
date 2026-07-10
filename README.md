<div align="center">

```
   ___ _                  _  __ ____ ____
  / __| |_  ___  __ ___  \ \/ // ___/ ___|
 | (__| ' \/ _ \/ _/ _ \  \  / \___ \___ \
  \___|_||_\___/\__\___/  /_\  |___/|___/
```

**Scanner de vulnérabilités XSS — statique, réfléchi, stocké, DOM et aveugle**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://www.python.org/)

*Développé par **Mathys CASTELLA** (Kinder-Bueno) — Projet portfolio pentest, complément de [ChocoScan](https://github.com/<votre-user>/chocoscan)*

</div>

---

## Présentation

ChocoXSS est un scanner de vulnérabilités **Cross-Site Scripting (XSS)** qui couvre les quatre familles de XSS plutôt qu'une seule :

| Type de XSS | Comment ChocoXSS le trouve |
|---|---|
| **Réfléchi** | Envoie des payloads contextuels, classe la réflexion (brute/encodée/filtrée), confirme l'exécution dans un vrai navigateur |
| **Stocké** | Soumet un payload sur un point d'injection, vérifie sa présence sur une autre URL (page de profil, article publié...) |
| **DOM-based** | Navigue réellement vers la cible avec le payload dans le fragment d'URL (`#...`) — le seul moyen de tester ce qui ne quitte jamais le navigateur |
| **Aveugle (out-of-band)** | Soumet des payloads de callback vers un collecteur externe, pour les cas où l'exécution a lieu ailleurs, plus tard (panneau d'admin, modération...) |

L'objectif : au lieu de balancer une liste de payloads et d'espérer, ChocoXSS explique **pourquoi** une vulnérabilité existe (quelle source, quel chemin, quel sanitizer manquant ou inefficace) et **confirme** qu'elle est réellement exploitable avant de la remonter — jusqu'à en capturer une preuve visuelle.

---

## Fonctionnalités

### Analyse statique avec taint tracing
- Parse le HTML (`<script>` inline, attributs `on*`, URIs `javascript:`) et le JS (AST via `esprima`)
- Catalogue de **19 sinks**, **12 sources**, **7 sanitizers** avec leur **efficacité contextuelle**
- **Vrai traçage de flux de données** à travers réassignations, concaténations, template literals, fonctions passthrough (`decodeURIComponent`, `.substring()`...)
- Détecte le piège du **sanitizer mal choisi** : `encodeURIComponent()` avant un `innerHTML` neutralise un contexte URL, pas un contexte HTML
- 4 niveaux de confiance : `CONFIRMED` / `LIKELY` / `SANITIZED` / `NONE`

### XSS réfléchi
- **Crawler** simple ou **récursif** (`--crawl-depth`, suit les liens `<a href>` jusqu'à N sauts, restreint au domaine de départ par défaut)
- 10 payloads contextuels avec **marqueur canari unique par scan**
- Classification robuste par décodage d'entités HTML : `REFLECTED_RAW` / `ENCODED` / `PARTIAL` / `NOT_REFLECTED`
- **Contournement de filtre** (`--bypass`) : 12 variantes (casse mixte, tag imbriqué, entités numériques, double encodage URL...) déclenchées automatiquement sur un `PARTIAL`, classées par pattern reconstitué plutôt que par correspondance littérale

### Vérification par navigateur headless
- Rejoue la réponse HTTP exacte dans un vrai **Chromium headless** (Playwright), confirme l'exécution via interception de dialogue
- Distingue "reflété sans échappement" de "réellement exploitable" — un payload peut passer brut sans jamais s'exécuter si son contexte d'injection supposé ne correspond pas à la réalité

### XSS stocké
- `--check-url` : soumet sur un point d'injection, vérifie sur une (ou plusieurs) URL différente

### XSS DOM en conditions réelles
- `--dom-xss` : navigue un **vrai navigateur vers la vraie cible**, payload dans le fragment d'URL (jamais transmis au serveur) et un paramètre de query
- Combiné à `--crawl-depth`, teste toutes les pages découvertes, pas seulement l'URL de départ
- Importe automatiquement les cookies de session (`-b`) dans le contexte Playwright

### XSS aveugle (out-of-band)
- `--blind-callback` : soumet des payloads de callback (script src, fetch, onerror...) vers un collecteur externe (Burp Collaborator, Interactsh...)
- Table de corrélation marqueur ↔ point d'injection pour recouper les hits reçus, potentiellement bien après la fin du scan

### Session, réseau et rate-limiting
- `-b`/`-H` : cookies et headers custom pour scanner une zone authentifiée
- `-k`/`--insecure` : certificats auto-signés (labo CTF)
- `-p`/`--proxy` : router le trafic via Burp/ZAP
- `--refresh-csrf` : rafraîchit un token CSRF régénéré côté serveur avant de tester un point POST
- `--delay` / `-t`/`--threads` : throttling ou parallélisation (plusieurs points d'injection testés simultanément)

### Preuves et rapport
- `--screenshot-dir` : capture PNG pour chaque exécution confirmée (réfléchie, stockée ou DOM)
- `--export-json` : export structuré de tous les résultats
- `--verbose` : extrait de réponse HTTP affiché pour chaque réflexion

### Fichier de configuration
- `~/.chocoxss.conf` (TOML) pour ne pas retaper les mêmes flags à chaque scan — priorité `CLI > $CHOCOXSS_* > fichier > défaut`

---

## Installation

**Prérequis :** Python 3.11+, pip

```bash
git clone https://github.com/<votre-user>/chocoxss.git
cd chocoxss

pip install -r requirements.txt
python -m playwright install chromium   # navigateur headless, une seule fois
```

**Dépendances :**

| Paquet | Usage |
|--------|-------|
| `esprima` | Parsing JavaScript en AST (ESTree) |
| `beautifulsoup4` | Parsing HTML |
| `requests` | Requêtes HTTP pour le mode actif |
| `playwright` | Navigateur headless (vérification + XSS DOM réel) |
| `rich` | Interface terminal (tableaux, couleurs, spinners) |

---

## Guide d'utilisation

### Analyse statique d'un fichier local

```bash
chocoxss.py -f page.html
chocoxss.py -f script.js
```

### Scan complet sur une URL

```bash
chocoxss.py -u http://cible.test/search?q=test
```

Enchaîne par défaut : analyse statique du HTML récupéré → scan actif (réfléchi + contournement si demandé) → vérification navigateur.

### Isoler un étage

```bash
chocoxss.py -u http://cible.test/page --static-only
chocoxss.py -u http://cible.test/page --active-only
chocoxss.py -u http://cible.test/page --no-verify        # actif sans navigateur, plus rapide
```

### Couvrir plusieurs pages

```bash
chocoxss.py -u https://cible.test/ --crawl-depth 2 --max-pages 30
chocoxss.py -u https://cible.test/ --crawl-depth 2 --crawl-external   # sortir du domaine
```

### Session authentifiée

```bash
chocoxss.py -u https://cible.test/profile -b "session_id=xyz; other=abc"
chocoxss.py -u https://cible.test/api -H "Authorization: Bearer xxx"
```

### Contournement de filtre

```bash
chocoxss.py -u https://cible.test/page --bypass
```

### XSS stocké

```bash
chocoxss.py -u https://cible.test/comment --check-url https://cible.test/blog/post-1
```

### XSS DOM en conditions réelles

```bash
chocoxss.py -u https://cible.test/page --dom-xss
chocoxss.py -u https://cible.test/dashboard -b "session_id=xyz" --dom-xss
chocoxss.py -u https://cible.test/ --crawl-depth 2 --dom-xss   # sur tout le site découvert
```

### XSS aveugle

```bash
chocoxss.py -u https://cible.test/contact --blind-callback https://votre-collecteur.test
```

### Cible à certificat auto-signé / proxy

```bash
chocoxss.py -u https://10.10.10.1/ --insecure
chocoxss.py -u https://cible.test/page -p http://127.0.0.1:8080 --insecure
```

### Rate-limiting et parallélisation

```bash
chocoxss.py -u https://cible.test/page --delay 0.5             # ralentir (WAF)
chocoxss.py -u https://cible.test/ --crawl-depth 2 --threads 5  # accélérer (plusieurs points)
```

### Token CSRF régénéré

```bash
chocoxss.py -u https://cible.test/comment --refresh-csrf
```

### Preuves visuelles et export

```bash
chocoxss.py -u https://cible.test/page --screenshot-dir ./preuves
chocoxss.py -u https://cible.test/page --export-json resultats.json
chocoxss.py -u https://cible.test/page --verbose
```

### Fichier de configuration

```bash
chocoxss.py config init      # créer ~/.chocoxss.conf
chocoxss.py config show      # afficher la config active (fichier + env + défauts)
chocoxss.py config init --force
```

```toml
insecure     = true
timeout      = 15
delay        = 0.3
threads      = 3
refresh_csrf = true

[crawl]
crawl_depth = 1
max_pages   = 30

[scan]
verbose = true
```

---

## Comprendre les niveaux de confiance

### Analyse statique

| Niveau | Signification |
|--------|----------------|
| `CONFIRMED` | Source tracée avec certitude jusqu'au sink, aucun sanitizer efficace |
| `LIKELY` | Le taint passe par une fonction custom non analysée — traité comme suspect plutôt qu'ignoré |
| `SANITIZED` | Sanitizer efficace confirmé sur ce chemin précis |
| `NONE` | Aucune source identifiée en amont du sink |

### Scan actif (réfléchi et stocké)

| Niveau | Signification |
|--------|----------------|
| `REFLECTED_RAW` | Le payload complet apparaît sans encodage — potentiellement exploitable |
| `REFLECTED_ENCODED` | Le payload est reflété mais entité-encodé — safe |
| `REFLECTED_PARTIAL` | Filtrage actif détecté (certains caractères réellement supprimés) — cible de `--bypass` |
| `NOT_REFLECTED` | Le marqueur n'apparaît pas dans la réponse |

### Vérification navigateur (réfléchi/stocké et DOM)

| Niveau | Signification |
|--------|----------------|
| `EXECUTED_CONFIRMED` | Le payload s'est réellement exécuté dans Chromium |
| `NOT_EXECUTED` | Reflété brut mais le contexte réel ne permet pas l'exécution |
| `VERIFICATION_ERROR` | Erreur technique pendant la vérification (timeout, re-fetch échoué) |

### XSS aveugle

Aucune classification automatique — par nature, l'exécution a lieu hors du cycle de vie du scan. ChocoXSS fournit une table de corrélation (marqueur unique par point d'injection) à recouper manuellement avec les logs du collecteur.

---

## Architecture du projet

```
chocoxss/
├── chocoxss.py                        # Point d'entrée CLI unifié
├── demo_scan.py                       # Démo historique (analyse statique seule)
│
├── modules/
│   ├── static/
│   │   ├── dom_sink_rules.py          # Catalogue sinks / sources / sanitizers
│   │   ├── html_parser.py             # Extraction JS depuis un document HTML
│   │   ├── js_ast_analyzer.py         # Détection brute de sinks/sources (AST esprima)
│   │   └── taint_tracer.py            # Traçage de flux source → sink
│   │
│   ├── active/
│   │   ├── crawler.py                 # Découverte de points d'injection (simple + récursif)
│   │   ├── payload_engine.py          # Génération de payloads contextuels
│   │   ├── bypass_payloads.py         # Variantes de contournement de filtre
│   │   ├── reflection_checker.py      # Envoi et classification de la réflexion
│   │   ├── stored_checker.py          # Détection de XSS stocké
│   │   ├── blind_payloads.py          # XSS aveugle (callback out-of-band)
│   │   ├── headless_verifier.py       # Confirmation d'exécution (rejeu local)
│   │   └── dom_verifier.py            # Confirmation d'exécution DOM (navigation réelle)
│   │
│   └── common/
│       ├── config.py                  # Fichier ~/.chocoxss.conf (TOML)
│       └── concurrency.py             # Parallélisation optionnelle (--threads)
│
├── tests/                             # Suite pytest (387 tests)
├── requirements.txt
└── requirements-dev.txt
```

---

## Développement et tests

```bash
pip install -r requirements-dev.txt
python -m playwright install chromium   # requis pour les tests du navigateur headless

pytest                                   # suite complète (387 tests)
pytest tests/test_taint_tracer.py -v    # un module spécifique
pytest -k "sanitizer"                    # tests correspondant à un mot-clé
```

La suite couvre des pièges découverts pendant le développement, verrouillés par des tests de non-régression :

- **Sanitizer inadapté au contexte** : `encodeURIComponent()` avant un `innerHTML` ne doit jamais neutraliser le taint
- **Faux positif `javascript:`** : reflété en texte brut (hors attribut `href`/`src`), il n'est pas exploitable malgré une réflexion "brute" au sens littéral
- **Bug `.substring()`** : une fonction passthrough appelée en méthode (`a.substring(1)`) tire son taint de l'objet, pas de l'argument
- **Bypass `nested_tag`** : un filtre naïf non récursif reconstitue une vraie balise `<script>` — nécessite une classification par pattern, pas par correspondance littérale au payload envoyé
- **Cookies non transmis à Playwright** : le contexte navigateur de `--dom-xss` est isolé de la session `requests` — sans import explicite des cookies, une page DOM XSS authentifiée échoue silencieusement
- **Token CSRF périmé** : capturé au crawl initial, un token peut expirer avant que le point ne soit testé — `--refresh-csrf` le rafraîchit une fois par point

---

## Exemple concret

Code JS analysé :
```javascript
var params = new URLSearchParams(location.search);
var name = params.get("name");
var encoded = encodeURIComponent(name);
document.getElementById("greeting").innerHTML = encoded;
```

Résultat ChocoXSS :
```
CONFIRMED  innerHTML  L4  source=location.search  sanitizer=encodeURIComponent (inefficace ici !)
```

Un scanner naïf verrait `encodeURIComponent()` et conclurait "c'est échappé, donc safe". ChocoXSS sait que ce sanitizer protège un contexte URL, pas un contexte HTML, et continue de remonter la vulnérabilité.

---

## Avertissement légal

ChocoXSS est conçu pour être utilisé **uniquement sur des systèmes pour lesquels vous disposez d'une autorisation explicite** : machines personnelles, laboratoires CTF (HackTheBox, TryHackMe, RootMe), ou dans le cadre d'une mission de pentest avec contrat signé.

Toute utilisation sur des systèmes tiers sans autorisation est illégale et contraire à l'éthique. L'auteur décline toute responsabilité en cas d'utilisation malveillante.

---

<div align="center">

*Développé par **Mathys CASTELLA** (Kinder-Bueno) — étudiant en cybersécurité*

</div>
