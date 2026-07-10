# ChocoXSS — Installation

```bash
pip install -r requirements.txt

# Playwright a besoin d'un navigateur téléchargé séparément (une seule fois) :
python -m playwright install chromium
```

## Lancer les tests

```bash
pip install -r requirements-dev.txt
python -m playwright install chromium   # requis pour tests/test_headless_verifier.py
pytest -v
```

## Utilisation — point d'entrée unifié `chocoxss.py`

```bash
# Analyse statique d'un fichier local (HTML ou JS)
python chocoxss.py -f page.html
python chocoxss.py -f script.js

# Scan complet sur une URL : statique + actif + vérification navigateur
python chocoxss.py -u http://cible.test/search?q=test

# N'exécuter qu'un étage
python chocoxss.py -u http://cible.test/page --static-only
python chocoxss.py -u http://cible.test/page --active-only

# Scan actif rapide sans vérification navigateur (plus rapide, moins fiable)
python chocoxss.py -u http://cible.test/page --no-verify

# Afficher l'extrait de réponse HTTP autour du marqueur pour chaque
# réflexion — indispensable pour comprendre un REFLECTED_PARTIAL sans
# avoir à rejouer la requête à la main
python chocoxss.py -u http://cible.test/page --verbose

# Cible à certificat auto-signé (labo CTF, HTB...)
python chocoxss.py -u https://cible.test/page --insecure

# Scanner une zone authentifiée : connectez-vous dans un navigateur,
# copiez le header Cookie depuis les outils développeur (F12 > Network),
# et passez-le tel quel avec -b
python chocoxss.py -u https://cible.test/profile -b "wordpress_logged_in=xyz; wordpress_sec=abc"

# En-tête HTTP additionnel, répétable (ex: token d'API)
python chocoxss.py -u https://cible.test/api -H "Authorization: Bearer xxx"

# Recherche de XSS STOCKÉ : soumet les payloads sur les points d'injection
# découverts, puis vérifie leur présence sur la ou les URL fournies
# (répétable) — utile pour un commentaire dont le contenu ressort sur
# une autre page, un champ de profil affiché ailleurs, etc.
python chocoxss.py -u https://cible.test/comment --check-url https://cible.test/blog/post-1

# Contournement de filtre : si un payload standard revient REFLECTED_PARTIAL
# (preuve qu'un filtrage actif existe), relance automatiquement des
# variantes ciblées (casse mixte, tag imbriqué, entités HTML, double
# encodage URL...) sur ce même point pour tenter de le contourner.
python chocoxss.py -u https://cible.test/page --bypass

# Crawl récursif : suit les liens <a href> de la page jusqu'à N sauts,
# pour couvrir tout un site plutôt qu'un seul point d'entrée (ex: partir
# de la page d'accueil et découvrir automatiquement les formulaires de
# contact, commentaire, recherche... sur les pages liées).
python chocoxss.py -u https://cible.test/ --crawl-depth 2 --max-pages 30

# Autoriser le crawl récursif à sortir du domaine de départ (off par défaut)
python chocoxss.py -u https://cible.test/ --crawl-depth 2 --crawl-external

# XSS DOM en conditions réelles : navigue un vrai navigateur vers la vraie
# cible avec chaque payload dans le fragment d'URL (#...) et un paramètre
# de query — seul moyen de détecter un XSS qui ne quitte jamais le
# navigateur (invisible pour le scan actif classique basé sur les
# réponses HTTP, puisque le fragment n'est jamais transmis au serveur).
# Les cookies passés via -b sont automatiquement importés dans le
# navigateur, pour tester une page DOM XSS derrière une authentification.
python chocoxss.py -u https://cible.test/page --dom-xss
python chocoxss.py -u https://cible.test/dashboard -b "session_id=xyz" --dom-xss

# --dom-xss teste aussi les pages découvertes par --crawl-depth, pas
# seulement l'URL de départ — combiner les deux couvre le DOM XSS sur
# tout un site plutôt qu'un seul point d'entrée.
python chocoxss.py -u https://cible.test/ --crawl-depth 2 --dom-xss

# XSS aveugle (blind / out-of-band) : soumet des payloads de callback
# (script src, fetch...) sur chaque point d'injection découvert, pointant
# vers votre propre collecteur (Burp Collaborator, Interactsh, serveur de
# logs custom). ChocoXSS ne confirme rien lui-même — surveillez le
# collecteur, potentiellement bien après la fin du scan.
python chocoxss.py -u https://cible.test/contact --blind-callback https://votre-collecteur.test

# Ralentir le scan pour éviter un blocage WAF/rate-limit — en pentest réel
# avec une fenêtre de test limitée, un blocage IP coûte plus cher qu'un
# scan un peu plus lent.
python chocoxss.py -u https://cible.test/page --delay 0.5

# Rafraîchir le token CSRF d'un formulaire avant de le tester — utile
# contre les cibles qui régénèrent leur token à chaque chargement de page
# (WordPress nonces, Django CSRF...), sans quoi les soumissions échouent
# silencieusement avec un token périmé.
python chocoxss.py -u https://cible.test/comment --refresh-csrf

# Capturer une preuve visuelle (PNG) pour chaque exécution XSS confirmée
# (réfléchi/stocké vérifié en navigateur, DOM en conditions réelles) —
# utile pour un rapport de pentest. La capture montre l'état de la page
# APRÈS le payload, pas le dialogue alert() lui-même (fenêtre native du
# navigateur, jamais visible dans un screenshot de page).
python chocoxss.py -u https://cible.test/page --screenshot-dir ./preuves
python chocoxss.py -u https://cible.test/page --dom-xss --screenshot-dir ./preuves

# Tester plusieurs points d'injection en parallèle (défaut : 1, séquentiel)
# — accélère nettement un scan avec beaucoup de points (--crawl-depth
# notamment). Ne s'applique pas à --dom-xss (Playwright n'est pas
# parallélisable de façon fiable depuis plusieurs threads).
python chocoxss.py -u https://cible.test/ --crawl-depth 2 --threads 5

# Router le trafic HTTP(S) via Burp Suite ou ZAP pour inspecter/rejouer
# manuellement chaque requête. Ajoutez --insecure si le proxy fait de
# l'interception TLS avec son propre certificat (comportement par défaut
# de Burp), sauf à avoir installé son certificat comme root de confiance.
python chocoxss.py -u https://cible.test/page -p http://127.0.0.1:8080 --insecure

# Exporter tous les résultats en JSON
python chocoxss.py -u http://cible.test/page --export-json resultats.json

# Ajuster le timeout des requêtes HTTP (défaut : 10s)
python chocoxss.py -u http://cible.test/page --timeout 20
```

Sur un **fichier local**, seule l'analyse statique est possible (pas de serveur à attaquer).
Sur une **URL**, les trois étages s'enchaînent par défaut :

1. Analyse statique du HTML récupéré (extraction JS + taint tracing)
2. Scan actif (découverte de points d'injection + envoi de payloads)
3. Vérification navigateur des résultats `REFLECTED_RAW` (Playwright headless)

## Fichier de configuration

Pour ne plus retaper les mêmes flags à chaque scan :

```bash
# Créer ~/.chocoxss.conf avec toutes les options commentées
python chocoxss.py config init

# Afficher la config active (fichier + variables env + défauts)
python chocoxss.py config show

# Écraser un fichier existant
python chocoxss.py config init --force
```

Exemple de `~/.chocoxss.conf` :

```toml
insecure     = true
timeout      = 15
delay        = 0.3
refresh_csrf = true

[crawl]
crawl_depth = 1
max_pages   = 30

[scan]
verbose = true
```

Priorité de résolution : `CLI explicite > $CHOCOXSS_* > ~/.chocoxss.conf > défaut`.
Les cookies/headers (`-b`/`-H`) ne sont volontairement pas gérables via ce
fichier — trop spécifiques à chaque cible pour un fichier de config
persistant, à passer en CLI au cas par cas.

## Modules

| Module | Rôle |
|---|---|
| `chocoxss.py` | Point d'entrée CLI unifié — orchestre les 3 étages |
| `modules/common/config.py` | Fichier de config `~/.chocoxss.conf` (TOML) |
| `modules/common/concurrency.py` | Parallélisation optionnelle des scans (`--threads`) |
| `modules/static/dom_sink_rules.py` | Catalogue de sinks/sources/sanitizers XSS DOM |
| `modules/static/js_ast_analyzer.py` | Détection brute de sinks/sources dans l'AST JS (esprima) |
| `modules/static/html_parser.py` | Extraction du JS depuis un document HTML |
| `modules/static/taint_tracer.py` | Traçage source→sink à travers les variables (data-flow analysis) |
| `modules/active/crawler.py` | Découverte de points d'injection (params URL + formulaires) |
| `modules/active/payload_engine.py` | Génération de payloads XSS contextuels avec marqueur canari |
| `modules/active/reflection_checker.py` | Envoi des payloads et classification de la réflexion (RAW/ENCODED/PARTIAL) |
| `modules/active/headless_verifier.py` | Confirmation d'exécution réelle via navigateur headless (Playwright) |
| `modules/active/stored_checker.py` | Détection de XSS stocké — soumission + vérification sur une URL séparée |
| `modules/active/bypass_payloads.py` | Variantes de contournement de filtre, déclenchées sur REFLECTED_PARTIAL |
| `modules/active/dom_verifier.py` | XSS DOM en conditions réelles — navigation vers la vraie cible (fragment/query) |
| `modules/active/blind_payloads.py` | XSS aveugle — soumission de payloads de callback vers un collecteur externe |

## Pipeline complet mode actif (utilisation programmatique)

```python
from modules.active.crawler import crawl
from modules.active.reflection_checker import scan_all_points, ReflectionConfidence
from modules.active.headless_verifier import verify_batch, ExecutionConfidence

# 1. Découvrir les points d'injection
result = crawl("http://cible.test/search?q=test")

# 2. Envoyer les payloads et classifier la réflexion
summary = scan_all_points(result.injection_points, result.target_url)

# 3. Ne vérifier dans un vrai navigateur que les REFLECTED_RAW (économie de temps)
raw_findings = [r for r in summary.results if r.confidence == ReflectionConfidence.REFLECTED_RAW]
verifications = verify_batch(raw_findings)

# 4. Les vraies vulnérabilités confirmées
confirmed = [v for v in verifications if v.execution == ExecutionConfidence.EXECUTED_CONFIRMED]
for v in confirmed:
    print(f"XSS confirmé : {v.reflection_result.injection_point.param_name} — {v.reflection_result.payload}")
```

