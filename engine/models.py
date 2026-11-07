"""Types de données du moteur : TypedDict, tuples immuables, dataclasses.

- ``LogRecord`` (``TypedDict``) : un enregistrement de log = un **dict** typé.
- ``ConnectionMeta`` : alias du **tuple immuable** ``(IP, Port, Protocole)``.
- ``Connection`` : ``NamedTuple`` équivalent (accès par nom), toujours immuable.
- ``SecurityEvent`` : ``NamedTuple`` compact conservé pour la détection.
- ``Alert`` : alerte de sécurité (dataclass gelée = immuable).
- ``PipelineStats`` : compteurs d'ingestion (mutables, mis à jour en streaming).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, NamedTuple, TypedDict

from engine.exceptions import LogParseError

# --------------------------------------------------------------------------
# Tuple immuable (IP, Port, Protocole) : une fois construit, impossible de le
# modifier (``conn[1] = 80`` lève TypeError). Pour « changer » une connexion
# on construit un NOUVEAU tuple (cf. pipeline.normalize_record).
# --------------------------------------------------------------------------
ConnectionMeta = tuple[str, int, str]

# Payload d'un log : dict (format JSON) ou chaîne brute (texte / connexion)
Payload = dict[str, Any] | str


class Connection(NamedTuple):
    """Équivalent nommé de ``ConnectionMeta`` (reste un tuple immuable)."""

    ip: str
    port: int
    proto: str


class _LogRecordRequired(TypedDict):
    """Champs obligatoires d'un enregistrement de log."""

    timestamp: datetime
    level: str
    ip: str
    user_id: str
    payload: Payload
    connection: ConnectionMeta | None
    raw: str
    source_format: str  # "json" | "text" | "connection"


class LogRecord(_LogRecordRequired, total=False):
    """Enregistrement de log (dict typé) ; champs ajoutés par le pipeline.

    - ``message`` : résumé lisible formaté par f-string (normalisation) ;
    - ``route`` : catégorie déterminée par le routage ``match-case``.
    """

    message: str
    route: str


class SecurityEvent(NamedTuple):
    """Événement de sécurité compact (tuple immuable) utilisé par la détection."""

    timestamp: datetime
    event: str
    user_id: str
    ip: str


@dataclass(frozen=True)
class Alert:
    """Alerte de sécurité produite par la détection ou une règle.

    ``count`` = nombre d'échecs (force brute) ou d'occurrences (autres règles).
    """

    rule: str
    ip: str
    count: int
    start: datetime | None = None
    end: datetime | None = None
    blacklisted: bool = False
    user_id: str = ""
    severity: str = "HIGH"
    message: str = ""

    @property
    def duration_seconds(self) -> float:
        """Durée couverte par l'alerte (0 si les bornes sont inconnues)."""
        if self.start is None or self.end is None:
            return 0.0
        return (self.end - self.start).total_seconds()

    def to_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable de l'alerte."""
        return {
            "rule": self.rule,
            "ip": self.ip,
            "count": self.count,
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "duration_seconds": self.duration_seconds,
            "blacklisted": self.blacklisted,
            "user_id": self.user_id,
            "severity": self.severity,
            "message": self.message,
        }


# Prédicat de filtrage d'un enregistrement (utilisé par filter / build_filters)
Predicate = Callable[[LogRecord], bool]
# Contexte transmis aux règles de sécurité et signature d'une règle
RuleContext = dict[str, Any]
RuleFunc = Callable[..., list[Alert]]

# Étapes du pipeline dont on compte les éléments sortants
STAGE_READ = "read"
STAGE_NON_EMPTY = "non_empty"
STAGE_PARSED = "parsed"
STAGE_VALID_LEVEL = "valid_level"
STAGE_VALID_IP = "valid_ip"
STAGE_VALID_TIMESTAMP = "valid_timestamp"
STAGE_CUSTOM = "custom_filters"
STAGE_ROUTED = "routed"
FILTER_STAGES: tuple[tuple[str, str, str], ...] = (
    # (étape d'entrée, étape de sortie, libellé du filtre)
    (STAGE_PARSED, STAGE_VALID_LEVEL, "niveau_invalide"),
    (STAGE_VALID_LEVEL, STAGE_VALID_IP, "ip_invalide"),
    (STAGE_VALID_IP, STAGE_VALID_TIMESTAMP, "horodatage_nul"),
    (STAGE_VALID_TIMESTAMP, STAGE_CUSTOM, "filtres_personnalises"),
)


def _int_counter() -> defaultdict[str, int]:
    """Fabrique un compteur ``defaultdict(int)`` (aucune KeyError possible)."""
    return defaultdict(int)


@dataclass
class PipelineStats:
    """Compteurs mis à jour au fil de l'eau par les étapes du pipeline.

    ``stage_counts`` est un ``defaultdict(int)`` : lire ou incrémenter une
    étape jamais vue renvoie 0 au lieu de lever ``KeyError``.
    """

    stage_counts: defaultdict[str, int] = field(default_factory=_int_counter)
    errors_by_reason: defaultdict[str, int] = field(default_factory=_int_counter)
    error_samples: list[str] = field(default_factory=list)
    max_samples: int = 5

    def record_parse_error(self, error: LogParseError) -> None:
        """Comptabilise une erreur de parsing (et garde quelques exemples)."""
        self.errors_by_reason[error.reason] += 1
        if len(self.error_samples) < self.max_samples:
            self.error_samples.append(f"[{error.reason}] {error} :: {error.raw[:80]!r}")

    @property
    def lines_read(self) -> int:
        """Nombre de lignes lues dans les sources."""
        return self.stage_counts[STAGE_READ]

    @property
    def empty_lines(self) -> int:
        """Lignes vides ou blanches éliminées par ``filter(None, ...)``."""
        return self.stage_counts[STAGE_READ] - self.stage_counts[STAGE_NON_EMPTY]

    @property
    def parse_errors(self) -> int:
        """Nombre total de lignes rejetées par le parseur."""
        return sum(self.errors_by_reason.values())

    @property
    def valid_records(self) -> int:
        """Enregistrements sortis du pipeline (valides, normalisés, routés)."""
        return self.stage_counts[STAGE_ROUTED]

    @property
    def filtered_out(self) -> int:
        """Enregistrements parsés mais écartés par les filtres lambda."""
        return self.stage_counts[STAGE_PARSED] - self.stage_counts[STAGE_ROUTED]

    @property
    def rejected(self) -> int:
        """Total des rejets : erreurs de parsing + filtrage."""
        return self.parse_errors + self.filtered_out

    def filtered_by(self) -> dict[str, int]:
        """Nombre d'enregistrements écartés par chaque filtre."""
        return {
            label: self.stage_counts[before] - self.stage_counts[after]
            for before, after, label in FILTER_STAGES
        }

    def as_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable des statistiques."""
        return {
            "lines_read": self.lines_read,
            "empty_lines": self.empty_lines,
            "parse_errors": self.parse_errors,
            "filtered_out": self.filtered_out,
            "rejected": self.rejected,
            "valid_records": self.valid_records,
            "errors_by_reason": dict(sorted(self.errors_by_reason.items())),
            "filtered_by": self.filtered_by(),
            "stage_counts": dict(self.stage_counts),
            "error_samples": list(self.error_samples),
        }
