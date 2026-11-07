"""Configuration centrale du moteur : chemins, constantes et seuils par défaut.

Toutes les valeurs « magiques » du projet sont regroupées ici afin que les
modules restent lisibles et que les seuils soient modifiables en un seul
endroit (ou surchargés dynamiquement via ``**kwargs`` dans ``rules.py``).
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Final

# --------------------------------------------------------------------- chemins
PROJECT_ROOT: Final = Path(__file__).resolve().parent.parent
DATA_DIR: Final = PROJECT_ROOT / "data"
DEFAULT_INPUT_DIR: Final = DATA_DIR / "samples"
DEFAULT_BIG_DIR: Final = DATA_DIR / "big"
DEFAULT_BLACKLIST: Final = DATA_DIR / "blacklist.txt"
DEFAULT_OUTPUT_DIR: Final = PROJECT_ROOT / "output"
GROUND_TRUTH_FILE: Final = "ground_truth.json"
LOG_PATTERN: Final = "*.log"
ENCODING: Final = "utf-8"

# ------------------------------------------------------------ format des logs
FIELD_SEPARATOR: Final = "|"
FIELD_COUNT: Final = 5
CONNECTION_PREFIX: Final = "CONN "
LEVELS: Final = ("INFO", "WARNING", "ERROR", "CRITICAL")  # ordre de sévérité
VALID_LEVELS: Final = frozenset(LEVELS)
ERROR_LEVELS: Final = frozenset({"ERROR", "CRITICAL"})
VALID_PROTOCOLS: Final = frozenset({"TCP", "UDP"})
HTTP_METHODS: Final = frozenset(
    {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
)
SENSITIVE_PORTS: Final = frozenset({21, 23, 3389, 5900})
# Horodatage « nul » (epoch) : syntaxiquement valide mais métier invalide.
NULL_TIMESTAMP: Final = datetime(1970, 1, 1)

# ----------------------------------------------------------------- événements
LOGIN_FAILED: Final = "login_failed"
LOGIN_SUCCESS: Final = "login_success"
LOGIN_EVENTS: Final = frozenset({LOGIN_FAILED, LOGIN_SUCCESS})
PERMISSION_DENIED: Final = "permission_denied"
CONFIG_CHANGE: Final = "config_change"

# --------------------------------------------------- seuils de détection
DEFAULT_THRESHOLD: Final = 5  # échecs consécutifs pour une force brute
DEFAULT_WINDOW_SECONDS: Final = 60  # fenêtre glissante de la force brute
DEFAULT_CRITICAL_LIMIT: Final = 10  # nb max de CRITICAL tolérés par période
DEFAULT_CRITICAL_PERIOD_MINUTES: Final = 5
DEFAULT_ERROR_RATIO: Final = 0.5  # ratio d'erreurs « anormal » par utilisateur
DEFAULT_MIN_USER_EVENTS: Final = 10  # volume minimal pour juger un utilisateur
DEFAULT_ESCALATION_WINDOW: Final = 120  # s entre permission_denied et config_change
MAX_ESCALATIONS_PER_USER: Final = 50  # borne mémoire de l'agrégateur
TOP_N: Final = 10

# ------------------------------------------------------------------ audit
SENSITIVE_MARKERS: Final = ("password", "secret", "token")
PREVIEW_LENGTH: Final = 80
MASK: Final = "***MASQUÉ***"

# ------------------------------------------------------------------ rapport
SECRET_ENV_VAR: Final = "LOG_ENGINE_SECRET"
DEFAULT_SIGNING_SECRET: Final = "dev-only-change-me"  # démo : à surcharger
ENGINE_VERSION: Final = "1.0.0"
