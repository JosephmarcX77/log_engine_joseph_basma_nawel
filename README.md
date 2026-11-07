# Engine de traitement et d'analyse de flux de logs sécurisé

Projet final ING3 — Python avancé. Moteur d'analyse de logs de sécurité écrit en
**Python standard** (aucune dépendance pour le moteur) : ingestion paresseuse par
générateurs, pipeline fonctionnel (`filter` / `map` / `lambda`), routage par
`match-case`, agrégation en une seule passe (`set`, `frozenset`, `defaultdict`),
détection de force brute, moteur de règles dynamique (`*args` / `**kwargs`) et
audit d'introspection (`globals()` / `locals()`).

**Mémoire constante** : aucun fichier n'est jamais chargé en entier ; la mémoire pic
reste quasi identique entre 10 000 et 2 000 000 de lignes (voir [Benchmark](#benchmark)).

---

## Sommaire

1. [Prérequis](#prérequis)
2. [Installation](#installation)
3. [Utilisation](#utilisation)
4. [Tests et qualité](#tests-et-qualité)
5. [Architecture](#architecture)
6. [Format des logs et jeux de données](#format-des-logs-et-jeux-de-données)
7. [Choix techniques](#choix-techniques)
8. [Benchmark](#benchmark)
9. [Correspondance barème → code](#correspondance-barème--code)
10. [Répartition du travail (trinôme)](#répartition-du-travail-trinôme)

---

## Prérequis

- **Python 3.10 ou plus** (obligatoire pour `match-case`) — développé et testé en 3.11.4.
- Git.

## Installation

```bash
git clone <url-du-dépôt> log_engine
cd log_engine
python -m venv .venv
```

Activation de l'environnement virtuel :

| Système | Commande |
|---|---|
| Linux / macOS | `source .venv/bin/activate` |
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Windows (cmd) | `.venv\Scripts\activate.bat` |
| Windows (Git Bash) | `source .venv/Scripts/activate` |

Puis :

```bash
pip install -r requirements.txt
```

`requirements.txt` est généré par `pip freeze` depuis le venv du projet. Les
dépendances ne servent qu'aux **tests** (`pytest`), à la **qualité** (`flake8`,
`mypy`) et au **rapport** (`jupyter`, `nbformat`, `nbconvert`, `matplotlib`) :
le moteur (`engine/`) n'utilise que la bibliothèque standard. Seule retouche
après `pip freeze` : le paquet propre à Windows `pywinpty` (dépendance de
Jupyter) porte le marqueur d'environnement `; os_name == "nt"`, pour que
l'installation fonctionne aussi sous Linux / macOS.

> **Windows : chemins longs.** JupyterLab installe des fichiers très profonds. Si
> le projet est cloné dans un dossier au chemin déjà long, `pip install` peut
> échouer avec `OSError: [Errno 2] No such file or directory` (limite de 260
> caractères). Cloner dans un chemin court (ex. `C:\dev\log_engine`) ou activer
> la prise en charge des chemins longs de Windows.

## Utilisation

Toutes les commandes passent par le point d'entrée unique `main.py`
(`python main.py --help`, `python main.py <commande> --help`).

| Commande | Rôle |
|---|---|
| `python main.py generate [--files N --lines N --seed S]` | génère `data/samples/*.log`, `data/blacklist.txt`, `ground_truth.json` |
| `python main.py generate --big` | génère `data/big/big_01.log` (2 000 000 lignes, non versionné) |
| `python main.py run [--input data/samples --blacklist data/blacklist.txt --threshold 5 --window 60 --output output/]` | pipeline complet + rapport |
| `python main.py audit [mêmes options]` | pipeline + audit d'introspection `globals()` / `locals()` |
| `python main.py benchmark --input data/big [--sizes 10000 100000 1000000]` | mémoire pic (`tracemalloc`) et débit |

Options utiles de `run` / `audit` : `--critical-limit`, `--critical-period`,
`--error-ratio`, `--min-events`, `--escalation-window`, `--min-level ERROR`
(filtre supplémentaire), `--strict` (validation niveau/IP dans le parseur plutôt
que dans les lambdas), `-v` (logs DEBUG), `--debug` (trace complète des erreurs).

Code de sortie : **0** si tout s'est bien passé, **1** en cas d'erreur fatale
(message lisible sur `stderr`, jamais de traceback brut) :

```text
$ python main.py run --input dossier/inexistant
Erreur : Source de logs inaccessible 'dossier/inexistant' : chemin introuvable
$ echo $?
1
```

### `generate`

```text
$ python main.py generate
Fichiers générés dans data/samples :
  - server_01.log    2026-11-05       10 000 lignes
  - server_02.log    2026-11-06       10 000 lignes
  - server_03.log    2026-11-07       10 000 lignes
Lignes totales        : 30 000
  vides attendues     : 186
  rejets attendus     : 428
  valides attendues   : 29 386
Séquences d'attaque   : 73 (54 complètes, 19 interrompues)
Rafales CRITICAL      : 3
Escalades injectées   : 6
IP attendues en alerte (seuil 5, fenêtre 60 s) : 51
  - 103.118.4.114    12 échecs
  ...
IP interrompues (aucune alerte attendue) : 14
Vérité terrain : data/samples/ground_truth.json
```

### `run` (extrait)

```text
========================================================================================
  LOG ENGINE v1.0.0 — rapport d'analyse de sécurité
========================================================================================
Sources     : 3 fichier(s) [server_01.log, server_02.log, server_03.log]
Période     : 2026-11-05T00:00:04  ->  2026-11-07T22:31:20
Durée       : 1.60 s (18 741 lignes/s)
Paramètres  : seuil=5 échecs, fenêtre=60 s, CRITICAL max=10/5 min

[1] INGESTION
  Lignes lues ................     30 000
  Lignes vides (filter None) .        186
  Erreurs de parsing .........        236   (fields: 112, json: 124)
  Écartées par les lambdas ...        192   (niveau_invalide: 72, ip_invalide: 72, horodatage_nul: 48)
  Total rejetées .............        428
  Enregistrements valides ....     29 386

[2] RÉPARTITION PAR NIVEAU
  INFO         23 338   79.4 %  ########################
  WARNING       3 502   11.9 %  ####
  ERROR         2 323    7.9 %  ##
  CRITICAL        223    0.8 %

[3] TOP 10 UTILISATEURS
   1. user_017        4 268
   2. user_047        2 607
   3. user_016        1 855
  ...

[4] ENSEMBLES D'IP  (active = IP ayant généré ERROR/CRITICAL)
  active | blacklist    270  union : périmètre de surveillance
  active & blacklist     10  blacklistées ACTIVES -> ALERTE
      151.221.29.33, 151.43.44.53, 222.240.158.193, 222.75.52.97
      31.89.164.75, 45.142.59.13, 5.127.228.225, 89.130.72.208
      91.189.93.62, 91.197.205.57
  active - blacklist    255  inconnues -> à investiguer
  blacklist - active      5  blacklistées dormantes
      116.98.61.177, 196.25.153.254, 41.100.71.93, 41.4.93.141
      58.244.77.217
  active ^ blacklist    260  statut incohérent (diff. sym.)

[5] FORCE BRUTE (>= 5 échecs consécutifs en 60 s) : 51 alerte(s)
  IP               échecs  début                fin        durée  cible     blacklist
  5.147.166.158         8  2026-11-05T06:50:56  06:51:13     17s  root      -
  45.97.239.254        12  2026-11-05T07:51:19  07:51:44     25s  test      -
  5.127.228.225         9  2026-11-05T08:47:07  08:47:24     17s  admin     OUI
  ...
  Séquences interrompues par login_success : 21 | IP au cycle complet sans attaque (else) : 214

[6] RÈGLES DE SÉCURITÉ : 80 alerte(s)
  rule_blacklisted_ip_active       10 alerte(s)
  rule_brute_force                 51 alerte(s)
  rule_critical_burst              3 alerte(s)
  rule_suspicious_user             5 alerte(s)
  rule_privilege_escalation        9 alerte(s)
  rule_critical_over_20            2 alerte(s)
========================================================================================
Rapport JSON : output/report_20261107_164731.json
Signature    : HMAC-SHA256 3aa6d95c0fc6cfd2...
```

Le rapport JSON complet (`output/report_<horodatage>.json`) est **signé en
HMAC-SHA256** ; le secret est lu dans la variable d'environnement
`LOG_ENGINE_SECRET` (valeur de démonstration par défaut). Le détail de chaque
ligne rejetée est journalisé dans `output/engine_<horodatage>.log` sans jamais
interrompre le pipeline.

### `audit` (extrait)

```text
AUDIT D'INTROSPECTION (globals() / locals())
--- caller_locals : 15 variable(s), 2 575 o, 1 masquée(s)
variable                   type               taille (o)  aperçu
aggregator                 StreamAggregator           56  <engine.analytics.StreamAggregator object at ...
blacklist                  frozenset                 728  frozenset({'116.98.61.177', '151.221.29.33', ...
signing_secret             str                        67  ***MASQUÉ***
...
--- audit_locals : 6 variable(s) ...
--- globals : 44 variable(s) ...
Audit JSON   : output/audit_20261107_164738.json
```

### `benchmark`

Voir la section [Benchmark](#benchmark).

### Rapport (notebook)

`notebooks/rapport.ipynb` (exécuté, avec sorties) et son export
`notebooks/rapport.html`. Pour le régénérer :

```bash
jupyter nbconvert --to notebook --execute --inplace notebooks/rapport.ipynb
jupyter nbconvert --to html notebooks/rapport.ipynb
```

L'exécution complète prend ~10 minutes (benchmark sur 1 million de lignes sous
`tracemalloc`). L'export PDF (`--to pdf`) nécessite une installation LaTeX, absente
de l'environnement : l'export HTML est fourni à la place.

## Tests et qualité

```bash
pytest              # 127 tests
flake8              # PEP 8, lignes de 88 caractères max (config : setup.cfg)
mypy engine         # typage strict (mypy engine tests main.py : 0 erreur ;
                    #  scripts/generate_logs.py est vérifié via main.py)
```

Les tests (`tests/`, fixtures dans `conftest.py` avec `tmp_path`) couvrent
notamment : générateurs paresseux (`inspect.isgenerator`, consommation partielle),
`yield from` sur plusieurs fichiers dont un manquant, parsing des 3 formats et de
chaque type de corruption, immutabilité des tuples et du `frozenset`, chaque
branche du `match-case` (et l'absence de `if` dans le routage, vérifiée par
`ast`), opérations d'ensembles, `defaultdict` sans `KeyError`, détection de force
brute (avec / sans `break`, branche `else`), **conformité exacte à
`ground_truth.json`** (sur les échantillons et sur un jeu généré avec une autre
graine), équivalence détection en flux / détection globale,
`apply_security_rules` avec un nombre variable de règles et de kwargs, règle qui
plante, audit qui masque les secrets, CLI de bout en bout et codes de sortie.

## Architecture

```text
log_engine/
├── main.py                 # point d'entrée CLI unique (generate / run / audit / benchmark)
├── requirements.txt        # pip freeze
├── setup.cfg               # configuration flake8 / mypy / pytest
├── scripts/
│   └── generate_logs.py    # générateur de jeux de données déterministes
├── data/
│   ├── blacklist.txt       # 15 IP blacklistées
│   ├── samples/            # 3 x 10 000 lignes + ground_truth.json (versionnés)
│   └── big/                # 2 000 000 lignes (non versionné, --big)
├── engine/
│   ├── config.py           # constantes et seuils par défaut
│   ├── exceptions.py       # LogEngineError, LogSourceError, LogParseError, RuleError, ...
│   ├── models.py           # LogRecord (TypedDict), ConnectionMeta (tuple), Alert, ...
│   ├── ingestion.py        # MODULE 1 : yield / yield from
│   ├── parsing.py          # MODULE 1 : ligne -> dict + tuple immuable
│   ├── pipeline.py         # MODULE 2 : filter / map / lambda / match-case
│   ├── analytics.py        # MODULE 3 : set / frozenset / defaultdict, agrégation 1 passe
│   ├── detection.py        # MODULE 3 : force brute (for + while + break/continue/else)
│   ├── rules.py            # MODULE 4 : apply_security_rules(*args, **kwargs)
│   ├── audit.py            # MODULE 4 : globals() / locals()
│   └── report.py           # rapport JSON signé + console + benchmark
├── tests/                  # pytest (1 fichier par module, cf. ci-dessous)
├── notebooks/rapport.ipynb # rapport exécuté + rapport.html
└── output/                 # rapports générés (ignoré par git)
```

Flux de données (tout est paresseux, un enregistrement traverse toute la chaîne
avant que le suivant ne soit lu) :

```text
read_multiple_sources (yield from) -> map(str.strip) -> filter(None)
  -> parse_stream (dict + tuple, erreurs comptées) -> filter(lambda) x3
  -> filter(build_filters(...)) -> map(normalize_record) -> map(route_record)
  -> StreamAggregator.update (une passe) -> detect_brute_force (tampons bornés)
  -> apply_security_rules(*règles, **config) -> rapport JSON / console / audit
```

## Format des logs et jeux de données

Cinq champs séparés par `|` (espaces parasites tolérés) :
`horodatage | niveau | ip | utilisateur | payload`.

| Format | Part | Exemple de payload | Résultat du parsing |
|---|---|---|---|
| JSON | ~60 % | `{"event": "login_failed", "port": 22, "proto": "TCP", "code": 401}` | `dict` + tuple `(ip, 22, "TCP")` |
| Texte | ~30 % | `GET /index.html 200` | `str` |
| Connexion | ~10 % | `CONN 172.16.0.8:443/TCP` | `str` + tuple `("172.16.0.8", 443, "TCP")` |

Le générateur (`scripts/generate_logs.py`, déterministe via `--seed`, écriture en
streaming) produit : niveaux à distribution réaliste, horodatages croissants sur
une journée par fichier avec profil jour/nuit, ~200 IP normales et 50
utilisateurs, attaques **entrelacées** avec le trafic (5 à 12 `login_failed`
consécutifs pour une IP, dont 15 % depuis des IP blacklistées et 25 %
**interrompues** par un `login_success`), rafales de CRITICAL, escalades
`permission_denied` -> `config_change`, et 3 % de bruit (lignes vides ou
blanches, tronquées, JSON invalide, niveau `DEBUGX`, IP `999.1.1`, horodatage
nul, casse incohérente, espaces parasites). `ground_truth.json` décrit la vérité
terrain vérifiée par les tests.

## Choix techniques

- **Mémoire constante.** Aucun `read()` / `readlines()` / `list(generator)` sur un
  flux de logs (vérifié par un test qui inspecte le code du moteur). Les
  agrégats sont bornés par le nombre d'entités distinctes (IP, utilisateurs,
  niveaux, heures), jamais par le nombre de lignes.
- **Détection en flux exacte.** `StreamAggregator` tamponne les tentatives de
  connexion de chaque IP ; dès qu'un écart supérieur à la fenêtre sépare deux
  tentatives (ou que l'IP est inactive depuis plus d'une fenêtre), aucune
  fenêtre ne peut plus les réunir : le tampon est analysé par
  `detect_brute_force` puis libéré. Un test vérifie que le résultat est
  **identique** à une détection globale sur toutes les données en mémoire.
- **Sémantique de la détection.** Fenêtre glissante de `window_seconds` à partir
  de chaque échec ; un `login_success` interrompt la séquence (`break`) ; les
  événements hors connexion sont ignorés (`continue`) ; une IP est signalée dès
  que le seuil est atteint (`break`, une alerte par IP) ; la clause `else` du
  `while` marque les IP dont le cycle d'analyse s'est terminé sans attaque.
- **Validation en deux temps.** Par défaut, le parseur vérifie la structure
  (5 champs, horodatage, JSON, connexion) et les trois `filter(lambda)` du
  pipeline écartent les niveaux inconnus, IP invalides et horodatages nuls ;
  `--strict` déplace la validation niveau/IP dans le parseur. Le total des rejets
  est identique dans les deux modes (testé).
- **Sécurité.** Rapport signé HMAC-SHA256 (`verify_signature` en temps
  constant), secrets masqués dans l'audit (`password`, `secret`, `token`, y
  compris les clés de dictionnaires), blacklist immuable (`frozenset`).

## Benchmark

Fichier de test : `python main.py generate --big` -> `data/big/big_01.log`,
**2 000 000 lignes, 220 Mio**. Mesures réalisées sur le poste de développement
(Windows 11, Python 3.11.4).

**Mémoire pic** (`tracemalloc`, N premières lignes du fichier, même processus) :

```bash
python main.py benchmark --input data/big --sizes 10000 100000 1000000 2000000
```

| Lignes traitées | Enregistrements valides | Données lues (≈) | Mémoire pic | Alertes force brute |
|---:|---:|---:|---:|---:|
| 10 000 | 9 784 | 1,1 Mio | **0,46 Mio** | 18 |
| 100 000 | 97 929 | 11 Mio | **0,49 Mio** | 109 |
| 1 000 000 | 979 477 | 110 Mio | **1,83 Mio** | 129 |
| 2 000 000 | 1 958 984 | 220 Mio | **1,96 Mio** | 134 |

Le volume lu est multiplié par 200, la mémoire pic par ~4 seulement, et elle
**plafonne vers 2 Mio** pour un fichier de 220 Mio. La légère hausse entre 100 000
et 1 000 000 de lignes vient de structures bornées qui se remplissent (compteurs
par minute sur une journée, liste d'escalades plafonnée à 50 par utilisateur,
ensembles d'IP) : entre 1 et 2 millions de lignes, la mémoire ne bouge presque
plus (+0,13 Mio). Le graphique « mémoire pic vs nombre de lignes » figure dans le
notebook.

**Débit réel** (sans instrumentation) :

```bash
python main.py benchmark --no-trace      # 2 000 000 lignes en 176 s : ~11 400 lignes/s
```

`tracemalloc` trace chaque allocation et divise le débit par ~6 à 10
(~1 950 lignes/s pendant la mesure de mémoire) ; sur les échantillons,
`python main.py run` traite ~18 000 lignes/s.

**Détection sur le gros fichier.** Les 126 attaques injectées sont toutes
retrouvées à l'identique (même nombre d'échecs, mêmes horodatages). Le moteur
signale en plus 8 IP internes : avec 2 millions de lignes sur une journée, le
trafic aléatoire produit par hasard, aux heures de pointe, 5 `login_failed`
consécutifs en moins de 60 s pour une même IP (vérifié dans le fichier, par
exemple `10.0.12.163` à 08:15:01–08:15:39). Ce sont donc de vraies séquences au
sens de la règle, absentes de la vérité terrain qui ne liste que les attaques
injectées. Sur les échantillons et sur le jeu de test généré avec une autre
graine, la correspondance avec `ground_truth.json` est exacte (vérifiée par les
tests).

## Correspondance barème → code

Numéros de ligne relevés par introspection (`inspect.getsourcelines`) sur la
version livrée.

| Critère | Fichier | Fonction / objet | Ligne |
|---|---|---|---|
| `yield` (générateur) | `engine/ingestion.py` | `read_log_file` | 49 |
| `yield from` | `engine/ingestion.py` | `read_multiple_sources` | 53 |
| `with` (fermeture garantie) | `engine/ingestion.py` | `read_log_file` | 47 |
| dict typé `LogRecord` (TypedDict) | `engine/models.py` | `(module)` | 39 |
| tuple `(IP, Port, Protocole)` | `engine/models.py` | `(module)` | 25 |
| construction du tuple | `engine/parsing.py` | `parse_connection` | 103 |
| `map(str.strip, ...)` | `engine/pipeline.py` | `strip_lines` | 71 |
| `filter(None, ...)` | `engine/pipeline.py` | `drop_empty` | 81 |
| `filter(lambda ...)` x3 | `engine/pipeline.py` | `build_pipeline` | 255 |
| `map(normalize_record)` | `engine/pipeline.py` | `build_pipeline` | 267 |
| `map(lambda ...)` | `engine/analytics.py` | `collect_error_ips` | 61 |
| fonctions passées en argument | `engine/pipeline.py` | `build_filters` | 84 |
| f-strings (format) | `engine/pipeline.py` | `normalize_record` | 153 |
| `match-case` | `engine/pipeline.py` | `route_entry` | 185 |
| case `str()` | `engine/pipeline.py` | `route_entry` | 187 |
| case dict + `\|` + guard | `engine/pipeline.py` | `route_entry` | 193 |
| case `{..., **rest}` | `engine/pipeline.py` | `route_entry` | 202 |
| case tuple | `engine/pipeline.py` | `route_entry` | 208 |
| `set` | `engine/analytics.py` | `collect_error_ips` | 63 |
| set comprehension | `engine/analytics.py` | `collect_error_ips_comprehension` | 70 |
| `frozenset` | `engine/analytics.py` | `load_blacklist` | 95 |
| union `\|` | `engine/analytics.py` | `compare_ip_sets` | 117 |
| intersection `&` | `engine/analytics.py` | `compare_ip_sets` | 118 |
| différence `-` | `engine/analytics.py` | `compare_ip_sets` | 119 |
| différence sym. `^` | `engine/analytics.py` | `compare_ip_sets` | 121 |
| `defaultdict(int)` | `engine/analytics.py` | `count_by_level` | 130 |
| `defaultdict(list)` | `engine/analytics.py` | `group_events_by_ip` | 173 |
| `defaultdict(lambda: defaultdict(int))` | `engine/analytics.py` | `count_user_levels` | 152 |
| agrégation une passe | `engine/analytics.py` | `StreamAggregator` | 252 |
| `for` | `engine/detection.py` | `detect_brute_force` | 92 |
| `while` | `engine/detection.py` | `detect_brute_force` | 97 |
| `continue` | `engine/detection.py` | `detect_brute_force` | 101 |
| `break` (succès) | `engine/detection.py` | `detect_brute_force` | 121 |
| `break` (seuil atteint) | `engine/detection.py` | `detect_brute_force` | 144 |
| `else` de boucle | `engine/detection.py` | `detect_brute_force` | 146 |
| `*args, **kwargs` | `engine/rules.py` | `apply_security_rules` | 330 |
| `callable()` | `engine/rules.py` | `apply_security_rules` | 359 |
| `inspect.signature` | `engine/rules.py` | `select_kwargs` | 310 |
| registre + décorateur | `engine/rules.py` | `register_rule` | 52 |
| fonction -> fonction | `engine/rules.py` | `make_threshold_rule` | 296 |
| `globals()` | `engine/audit.py` | `audit_scope` | 130 |
| `locals()` (propre) | `engine/audit.py` | `audit_scope` | 132 |
| `audit_scope(locals())` | `main.py` | `cmd_run` | 199 |
| exceptions personnalisées | `engine/exceptions.py` | `(module)` | 38 |
| levée d'exception | `engine/parsing.py` | `parse_line` | 157 |
| capture sans arrêt | `engine/parsing.py` | `parse_stream` | 203 |
| typage (`TypedDict`, alias) | `engine/models.py` | `(module)` | 113 |

## Répartition du travail (trinôme)

| Membre | Périmètre | Fichiers |
|---|---|---|
| Membre 1 | Module 1 + générateur | `engine/ingestion.py`, `engine/parsing.py`, `engine/models.py`, `scripts/generate_logs.py`, `tests/test_ingestion.py` (+ tests du générateur), `tests/test_parsing.py` |
| Membre 2 | Modules 2 + 3 | `engine/pipeline.py`, `engine/analytics.py`, `engine/detection.py`, `tests/test_pipeline.py`, `tests/test_analytics.py`, `tests/test_detection.py` |
| Membre 3 | Module 4 + main + rapport | `engine/rules.py`, `engine/audit.py`, `engine/report.py`, `main.py`, `notebooks/rapport.ipynb`, `tests/test_rules.py`, `tests/test_audit.py` (+ tests du rapport et de la CLI) |

Socle commun : `engine/config.py`, `engine/exceptions.py`, `tests/conftest.py`,
`README.md`.
