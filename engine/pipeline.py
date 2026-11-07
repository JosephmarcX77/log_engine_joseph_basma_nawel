"""MODULE 2 — Pipeline fonctionnel : ``filter``, ``map``, ``lambda``, ``match-case``.

Chaque étape retourne un **itérateur paresseux** : aucune liste intermédiaire
n'est construite. Un enregistrement traverse toute la chaîne avant que le
suivant ne soit lu ::

    read_multiple_sources -> map(str.strip) -> filter(None)
      -> parse_stream -> filter(lambda) x3 -> filter(build_filters(...))
      -> map(normalize_record) -> map(route_record)
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from itertools import islice
from pathlib import Path
from typing import TypeVar

from engine.config import (
    HTTP_METHODS,
    LEVELS,
    NULL_TIMESTAMP,
    SENSITIVE_PORTS,
    VALID_LEVELS,
)
from engine.exceptions import ConfigurationError
from engine.ingestion import read_multiple_sources
from engine.models import (
    STAGE_CUSTOM,
    STAGE_NON_EMPTY,
    STAGE_PARSED,
    STAGE_READ,
    STAGE_ROUTED,
    STAGE_VALID_IP,
    STAGE_VALID_LEVEL,
    STAGE_VALID_TIMESTAMP,
    ConnectionMeta,
    LogRecord,
    PipelineStats,
    Predicate,
)
from engine.parsing import clean_ip, is_valid_ip, normalize_level, parse_stream

T = TypeVar("T")

# Catégories produites par le routage ``match-case``
ROUTE_HTTP = "http_access"
ROUTE_TEXT = "raw_text"
ROUTE_SERVER_ERROR = "server_error"
ROUTE_SECURITY = "security_event"
ROUTE_EVENT = "event"
ROUTE_SENSITIVE_CONNECTION = "connection.sensitive"
ROUTE_CONNECTION = "connection"
ROUTE_UNKNOWN = "unknown"


# --------------------------------------------------------------------------
# Comptage des étapes (pour les statistiques) — reste un générateur paresseux
# --------------------------------------------------------------------------
def count_stage(items: Iterable[T], stats: PipelineStats, stage: str) -> Iterator[T]:
    """Laisse passer chaque élément en incrémentant ``stats.stage_counts[stage]``."""
    for item in items:
        stats.stage_counts[stage] += 1
        yield item


# --------------------------------------------------------------------------
# Filtrage
# --------------------------------------------------------------------------
def strip_lines(lines: Iterable[str]) -> Iterator[str]:
    """Supprime les espaces de début / fin de chaque ligne : ``map(str.strip, ...)``."""
    return map(str.strip, lines)


def drop_empty(lines: Iterable[str]) -> Iterator[str]:
    """Élimine les chaînes vides : ``filter(None, ...)`` garde les valeurs « vraies ».

    Une chaîne vide ``""`` est évaluée à ``False`` : combinée à ``strip``,
    cette étape élimine aussi les lignes ne contenant que des espaces.
    """
    return filter(None, lines)


def build_filters(*predicates: Predicate) -> Predicate:
    """Combine plusieurs prédicats (fonctions passées en argument) en un seul.

    Le prédicat retourné est vrai si TOUS les prédicats le sont (``all`` court-
    circuite au premier ``False``). Sans prédicat, tout est accepté.

    Raises:
        ConfigurationError: un des arguments n'est pas appelable.
    """
    for predicate in predicates:
        if not callable(predicate):
            raise ConfigurationError(f"prédicat non appelable : {predicate!r}")

    def combined(record: LogRecord) -> bool:
        return all(predicate(record) for predicate in predicates)

    return combined


def min_level_predicate(min_level: str) -> Predicate:
    """Fonction d'ordre supérieur : retourne un prédicat « niveau >= min_level »."""
    wanted = normalize_level(min_level)
    if wanted not in VALID_LEVELS:
        raise ConfigurationError(f"niveau minimal inconnu : {min_level!r}")
    threshold = LEVELS.index(wanted)
    return lambda record: LEVELS.index(normalize_level(record["level"])) >= threshold


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------
def summarize_payload(record: LogRecord) -> str:
    """Résumé court du payload pour le message formaté."""
    payload = record["payload"]
    if isinstance(payload, dict):
        event = payload.get("event", "?")
        code = payload.get("code", "-")
        return f"{event} (code={code})"
    return payload


def normalize_record(record: LogRecord) -> LogRecord:
    """Retourne une COPIE normalisée de l'enregistrement.

    - niveau en majuscules (`` Warning `` -> ``WARNING``) ;
    - utilisateur en minuscules (``USER_042`` -> ``user_042``) ;
    - IP nettoyée (forme canonique ``ipaddress``) ;
    - tuple de connexion RECONSTRUIT (un tuple est immuable : on ne le modifie
      pas, on en crée un nouveau) ;
    - ``message`` reformaté par f-string avec alignements.
    """
    level = normalize_level(record["level"])
    ip = clean_ip(record["ip"])
    user = record["user_id"].strip().lower()
    connection: ConnectionMeta | None = record["connection"]
    if connection is not None:
        conn_ip, port, proto = connection  # déballage du tuple
        connection = (clean_ip(conn_ip), port, proto.strip().upper())
    normalized = LogRecord(
        timestamp=record["timestamp"],
        level=level,
        ip=ip,
        user_id=user,
        payload=record["payload"],
        connection=connection,
        raw=record["raw"],
        source_format=record["source_format"],
    )
    normalized["message"] = (
        f"{record['timestamp']:%Y-%m-%d %H:%M:%S} [{level:<8}] {ip:>15} "
        f"{user:<10} {summarize_payload(record)}"
    )
    return normalized


# --------------------------------------------------------------------------
# Routage par Structural Pattern Matching
# --------------------------------------------------------------------------
def record_to_entry(record: LogRecord) -> object:
    """Construit l'objet à router : tuple, dict (niveau + payload) ou chaîne."""
    match record:
        case {
            "source_format": "connection",
            "connection": (str(), int(), str()) as conn,
        }:
            return conn
        case {"payload": dict() as payload}:
            return {**payload, "level": record["level"]}
        case {"payload": str() as text}:
            return text
        case _:
            return record


def route_entry(entry: object) -> str:
    """Route une entrée selon sa STRUCTURE, uniquement avec ``match-case``.

    Aucun ``if/elif/else`` : la décision repose sur des patterns de classe
    (``str()``), de mapping (``{"level": ...}``), de séquence (tuple), des
    alternatives (``|``), des captures (``as``, ``int(code)``) et des guards.
    """
    match entry:
        # 1) Chaîne brute — guard : la chaîne commence par une méthode HTTP
        case str() as raw if raw.split(" ", 1)[0] in HTTP_METHODS:
            return ROUTE_HTTP
        case str():
            return ROUTE_TEXT
        # 2) Dict d'erreur serveur : alternative "ERROR" | "CRITICAL", capture du
        #    code entier, guard code >= 500
        case {"level": "ERROR" | "CRITICAL", "code": int(code)} if code >= 500:
            return ROUTE_SERVER_ERROR
        # 2 bis) Événement de sécurité : alternatives sur le niveau ET l'événement
        case {
            "level": "ERROR" | "CRITICAL" | "WARNING",
            "event": "login_failed" | "permission_denied",
        }:
            return ROUTE_SECURITY
        # 3) Tout autre dict possédant un niveau : capture du reste (**rest)
        case {"level": str(level), **rest} if rest:
            return f"{ROUTE_EVENT}.{level.lower()}"
        # 4) Tuple de connexion (IP, Port, Protocole) — guard : port sensible
        case (str(), int(port), str()) if port in SENSITIVE_PORTS:
            return ROUTE_SENSITIVE_CONNECTION
        #    capture des 3 éléments ; guard : IP et port plausibles
        case (str(ip), int(port), str(proto)) if is_valid_ip(ip) and 0 < port < 65536:
            return f"{ROUTE_CONNECTION}.{proto.lower()}"
        # 5) Tout le reste
        case _:
            return ROUTE_UNKNOWN


def route_record(record: LogRecord) -> LogRecord:
    """Ajoute la clé ``route`` (calculée par ``route_entry``) à l'enregistrement."""
    record["route"] = route_entry(record_to_entry(record))
    return record


# --------------------------------------------------------------------------
# Composition
# --------------------------------------------------------------------------
def build_pipeline(
    sources: Iterable[Path],
    *,
    stats: PipelineStats | None = None,
    strict: bool = False,
    extra_predicates: Iterable[Predicate] = (),
    limit: int | None = None,
) -> Iterator[LogRecord]:
    """Chaîne toutes les étapes en un unique itérateur paresseux.

    ingestion -> strip -> filter(None) -> parse -> filtres lambda ->
    filtres personnalisés -> map(normalize) -> map(route).

    Args:
        sources: chemins des fichiers de logs.
        stats: compteurs à mettre à jour (créés si absents).
        strict: si ``False`` (défaut), niveau et IP sont validés par les
            filtres ``lambda`` ; si ``True``, directement par le parseur.
        extra_predicates: prédicats supplémentaires combinés par ``build_filters``.
        limit: nombre maximal de lignes lues (``itertools.islice``, paresseux).
    """
    stats = stats if stats is not None else PipelineStats()
    lines: Iterator[str] = read_multiple_sources(sources)
    if limit is not None:
        lines = islice(lines, limit)
    lines = count_stage(lines, stats, STAGE_READ)
    lines = count_stage(drop_empty(strip_lines(lines)), stats, STAGE_NON_EMPTY)
    parsed = parse_stream(lines, strict=strict, stats=stats)
    records = count_stage(parsed, stats, STAGE_PARSED)

    # Prédicat 1 — « niveau valide » : INFO / WARNING / ERROR / CRITICAL (casse libre)
    records = filter(lambda r: r["level"].strip().upper() in VALID_LEVELS, records)
    records = count_stage(records, stats, STAGE_VALID_LEVEL)
    # Prédicat 2 — « IP valide » : adresse IPv4 / IPv6 reconnue par ipaddress
    records = filter(lambda r: is_valid_ip(r["ip"]), records)
    records = count_stage(records, stats, STAGE_VALID_IP)
    # Prédicat 3 — « horodatage non nul » : strictement postérieur à l'epoch
    records = filter(lambda r: r["timestamp"] > NULL_TIMESTAMP, records)
    records = count_stage(records, stats, STAGE_VALID_TIMESTAMP)
    # Prédicats supplémentaires combinés (fonctions passées en argument)
    records = filter(build_filters(*extra_predicates), records)
    records = count_stage(records, stats, STAGE_CUSTOM)

    normalized = map(normalize_record, records)
    routed = map(route_record, normalized)
    return count_stage(routed, stats, STAGE_ROUTED)
