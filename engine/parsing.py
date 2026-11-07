"""MODULE 1 — Parsing : ligne brute -> ``LogRecord`` (dict) + tuple immuable.

Format attendu (5 champs séparés par ``|``, espaces parasites tolérés) ::

    horodatage | niveau | ip | utilisateur | payload

Le payload prend trois formes :

* JSON ``{"event": ..., "port": 22, "proto": "TCP", "code": 401}`` -> ``dict`` ;
* connexion ``CONN 172.16.0.8:443/TCP`` -> tuple ``(IP, Port, Protocole)`` ;
* texte brut ``GET /index.html 200`` -> ``str``.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from typing import Any

from engine.config import (
    CONNECTION_PREFIX,
    FIELD_COUNT,
    FIELD_SEPARATOR,
    VALID_LEVELS,
    VALID_PROTOCOLS,
)
from engine.exceptions import LogParseError
from engine.models import ConnectionMeta, LogRecord, Payload, PipelineStats

logger = logging.getLogger(__name__)


def is_valid_ip(text: str) -> bool:
    """Indique si ``text`` est une adresse IPv4/IPv6 valide (module ``ipaddress``)."""
    try:
        ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return True


def clean_ip(text: str) -> str:
    """Forme canonique d'une IP (``010.0.0.1`` refusé, ``::0001`` -> ``::1``).

    Une valeur invalide est simplement débarrassée de ses espaces.
    """
    stripped = text.strip()
    try:
        return str(ipaddress.ip_address(stripped))
    except ValueError:
        return stripped


def normalize_level(text: str) -> str:
    """Niveau en majuscules sans espaces (`` Warning `` -> ``WARNING``)."""
    return text.strip().upper()


def parse_timestamp(text: str) -> datetime:
    """Convertit un horodatage ISO 8601 en ``datetime`` naïf (UTC si fuseau fourni).

    Raises:
        LogParseError: format non reconnu.
    """
    try:
        value = datetime.fromisoformat(text.strip())
    except ValueError as exc:
        raise LogParseError(
            f"horodatage invalide {text!r}", reason="timestamp", raw=text
        ) from exc
    if value.tzinfo is not None:  # homogénéise : tout en UTC naïf
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def parse_connection(text: str) -> ConnectionMeta:
    """Analyse ``CONN ip:port/proto`` -> tuple immuable ``(ip, port, proto)``.

    Raises:
        LogParseError: structure, port ou protocole invalide.
    """
    body = text[len(CONNECTION_PREFIX):].strip()
    address, slash, proto = body.partition("/")
    ip, colon, port_text = address.rpartition(":")
    if not slash or not colon or not ip:
        raise LogParseError(
            f"connexion mal formée {text!r}", reason="connection", raw=text
        )
    try:
        port = int(port_text)
    except ValueError as exc:
        raise LogParseError(
            f"port non numérique {port_text!r}", reason="connection", raw=text
        ) from exc
    proto = proto.strip().upper()
    if not 0 <= port <= 65535 or proto not in VALID_PROTOCOLS:
        raise LogParseError(
            f"port/protocole invalide {port}/{proto}", reason="connection", raw=text
        )
    connection: ConnectionMeta = (ip.strip("[] "), port, proto)  # tuple immuable
    return connection


def parse_payload(text: str, ip: str) -> tuple[Payload, ConnectionMeta | None, str]:
    """Décode le payload : retourne ``(payload, connexion, format_source)``.

    * JSON -> ``dict`` ; la connexion ``(ip, port, proto)`` est construite si
      le JSON contient ``port`` (int) et ``proto`` (str) ;
    * ``CONN ...`` -> chaîne brute + tuple de connexion ;
    * sinon -> chaîne brute, sans connexion.

    Raises:
        LogParseError: JSON invalide ou connexion mal formée.
    """
    if text.startswith("{"):
        try:
            decoded: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LogParseError(
                f"JSON invalide ({exc.msg})", reason="json", raw=text
            ) from exc
        if not isinstance(decoded, dict):
            raise LogParseError(
                "le payload JSON n'est pas un objet", reason="json", raw=text
            )
        port, proto = decoded.get("port"), decoded.get("proto")
        connection: ConnectionMeta | None = None
        if isinstance(port, int) and isinstance(proto, str):
            connection = (ip, port, proto.upper())
        return decoded, connection, "json"
    if text.startswith(CONNECTION_PREFIX):
        return text, parse_connection(text), "connection"
    return text, None, "text"


def parse_line(line: str, *, strict: bool = True) -> LogRecord:
    """Transforme une ligne brute en ``LogRecord`` (dict typé).

    Étapes : découpage en 5 champs (tuple immuable), conversion de
    l'horodatage en ``datetime``, validation du niveau et de l'IP (si
    ``strict``), décodage du payload (JSON / connexion / texte).

    Args:
        line: la ligne brute.
        strict: si ``False``, le niveau et l'IP ne sont PAS validés ici : ce
            sont alors les filtres ``lambda`` du pipeline qui les écartent.

    Raises:
        LogParseError: ligne vide, champs manquants, horodatage, niveau, IP
            ou payload invalide.
    """
    raw = line.strip()
    if not raw:
        raise LogParseError("ligne vide", reason="empty", raw=line)
    fields = tuple(part.strip() for part in raw.split(FIELD_SEPARATOR, FIELD_COUNT - 1))
    if len(fields) != FIELD_COUNT:
        raise LogParseError(
            f"{len(fields)} champ(s) au lieu de {FIELD_COUNT}", reason="fields", raw=raw
        )
    if not all(fields):
        raise LogParseError("champ vide", reason="fields", raw=raw)
    timestamp_text, level, ip, user_id, payload_text = fields  # déballage du tuple
    timestamp = parse_timestamp(timestamp_text)
    if strict and normalize_level(level) not in VALID_LEVELS:
        raise LogParseError(f"niveau inconnu {level!r}", reason="level", raw=raw)
    if strict and not is_valid_ip(ip):
        raise LogParseError(f"IP invalide {ip!r}", reason="ip", raw=raw)
    payload, connection, source_format = parse_payload(payload_text, ip)
    if strict and connection is not None and not is_valid_ip(connection[0]):
        raise LogParseError(
            f"IP de connexion invalide {connection[0]!r}", reason="ip", raw=raw
        )
    return LogRecord(
        timestamp=timestamp,
        level=level,
        ip=ip,
        user_id=user_id,
        payload=payload,
        connection=connection,
        raw=raw,
        source_format=source_format,
    )


def parse_stream(
    lines: Iterable[str],
    *,
    strict: bool = True,
    stats: PipelineStats | None = None,
) -> Iterator[LogRecord]:
    """Générateur : parse chaque ligne, compte les erreurs et saute les invalides.

    Une ligne invalide ne lève pas d'exception vers l'appelant : l'erreur est
    journalisée (niveau DEBUG), comptée dans ``stats`` puis ``continue`` passe
    à la ligne suivante. Le pipeline n'est donc jamais interrompu.
    """
    for line in lines:
        try:
            record = parse_line(line, strict=strict)
        except LogParseError as exc:
            if stats is not None:
                stats.record_parse_error(exc)
            logger.debug("Ligne rejetée [%s] : %s | %.100r", exc.reason, exc, line)
            continue  # ligne invalide -> on passe directement à la suivante
        yield record
