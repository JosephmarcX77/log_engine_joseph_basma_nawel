"""Tests du MODULE 1 — parsing (dict, tuple immuable, erreurs personnalisées)."""

from __future__ import annotations

import inspect
from datetime import datetime

import pytest

from conftest import (
    BAD_IP_LINE,
    BAD_TIMESTAMP_LINE,
    CONN_LINE,
    INVALID_JSON_LINE,
    JSON_LINE,
    LOWER_LEVEL_LINE,
    MIXED_LINES,
    NULL_TIMESTAMP_LINE,
    SPACED_LINE,
    TEXT_LINE,
    TRUNCATED_LINE,
    UNKNOWN_LEVEL_LINE,
)
from engine.exceptions import LogEngineError, LogParseError
from engine.models import Connection, PipelineStats
from engine.parsing import (
    clean_ip,
    is_valid_ip,
    parse_connection,
    parse_line,
    parse_stream,
    parse_timestamp,
)

PREFIX = "2026-11-07T10:00:00 | INFO | 10.0.0.1 | u"


def test_parse_json_format() -> None:
    """Format JSON : payload ``dict`` + tuple ``(IP, Port, Protocole)``."""
    record = parse_line(JSON_LINE)
    assert record["timestamp"] == datetime(2026, 11, 7, 10, 15, 32)
    assert record["level"] == "ERROR"
    assert record["ip"] == "192.168.1.45"
    assert record["user_id"] == "user_042"
    assert isinstance(record["payload"], dict)
    assert record["payload"]["event"] == "login_failed"
    assert record["connection"] == ("192.168.1.45", 22, "TCP")
    assert record["source_format"] == "json"


def test_parse_text_format() -> None:
    """Format texte brut : payload ``str``, pas de connexion."""
    record = parse_line(TEXT_LINE)
    assert record["payload"] == "GET /index.html 200"
    assert record["connection"] is None
    assert record["source_format"] == "text"


def test_parse_connection_format() -> None:
    """Format connexion : le tuple est extrait de ``CONN ip:port/proto``."""
    record = parse_line(CONN_LINE)
    assert record["connection"] == ("172.16.0.8", 443, "TCP")
    assert record["source_format"] == "connection"


def test_connection_tuple_is_immutable() -> None:
    """Un tuple ne peut pas être modifié : toute affectation lève ``TypeError``."""
    connection = parse_line(CONN_LINE)["connection"]
    assert isinstance(connection, tuple)
    with pytest.raises(TypeError):
        connection[1] = 80  # type: ignore[index]
    named = Connection(*connection)
    assert named.port == 443 and named == connection  # NamedTuple == tuple
    with pytest.raises(AttributeError):
        named.port = 80  # type: ignore[misc]


def test_case_and_spaces_are_tolerated() -> None:
    """Casse incohérente et espaces parasites ne sont pas des erreurs."""
    lower = parse_line(LOWER_LEVEL_LINE)
    spaced = parse_line(SPACED_LINE)
    assert lower["level"] == "error"  # normalisé plus tard (pipeline)
    assert spaced["level"] == "Warning"
    assert spaced["payload"] == "POST /login 403"


@pytest.mark.parametrize(
    ("line", "reason"),
    [
        ("", "empty"),
        ("    ", "empty"),
        (TRUNCATED_LINE, "fields"),
        (INVALID_JSON_LINE, "json"),
        (UNKNOWN_LEVEL_LINE, "level"),
        (BAD_IP_LINE, "ip"),
        (BAD_TIMESTAMP_LINE, "timestamp"),
        ("2026-11-07T10:00:00 | INFO | 10.0.0.1 |  | GET / 200", "fields"),
        (f"{PREFIX} | CONN 10.0.0.1:http/TCP", "connection"),
        (f"{PREFIX} | CONN 10.0.0.1:80/ICMP", "connection"),
        (f"{PREFIX} | [1, 2]", None),
        (f'{PREFIX} | {{"a": [1, 2', "json"),
    ],
)
def test_corrupted_lines_raise_log_parse_error(line: str, reason: str | None) -> None:
    """Chaque type de corruption lève ``LogParseError`` avec la bonne catégorie."""
    if reason is None:  # "[1, 2]" n'est pas un objet JSON : simple texte brut
        assert parse_line(line)["source_format"] == "text"
        return
    with pytest.raises(LogParseError) as info:
        parse_line(line)
    assert info.value.reason == reason
    assert isinstance(info.value, LogEngineError)  # hiérarchie personnalisée


def test_lenient_mode_defers_level_and_ip_validation() -> None:
    """En mode non strict, niveau et IP sont validés plus tard par les lambdas."""
    assert parse_line(UNKNOWN_LEVEL_LINE, strict=False)["level"] == "DEBUGX"
    assert parse_line(BAD_IP_LINE, strict=False)["ip"] == "999.1.1"
    with pytest.raises(LogParseError):  # la structure reste toujours vérifiée
        parse_line(TRUNCATED_LINE, strict=False)


def test_null_timestamp_is_syntactically_valid() -> None:
    """L'epoch se parse : c'est le filtre « horodatage non nul » qui l'écarte."""
    assert parse_line(NULL_TIMESTAMP_LINE)["timestamp"].year == 1970


def test_timezone_aware_timestamp_is_converted_to_naive_utc() -> None:
    """Un horodatage avec fuseau est converti en UTC naïf."""
    assert parse_timestamp("2026-11-07T12:00:00+02:00") == datetime(2026, 11, 7, 10, 0)


def test_parse_connection_returns_tuple() -> None:
    """``parse_connection`` retourne un vrai ``tuple`` de 3 éléments."""
    assert parse_connection("CONN [::1]:22/tcp") == ("::1", 22, "TCP")


def test_ip_helpers() -> None:
    """Validation et nettoyage d'IP via le module ``ipaddress``."""
    assert is_valid_ip(" 10.0.0.1 ")
    assert not is_valid_ip("999.1.1")
    assert clean_ip(" ::0001 ") == "::1"
    assert clean_ip(" bad ") == "bad"


def test_parse_stream_counts_and_skips_invalid_lines() -> None:
    """``parse_stream`` est un générateur qui compte les erreurs sans les lever."""
    stats = PipelineStats()
    stream = parse_stream(MIXED_LINES, stats=stats)
    assert inspect.isgenerator(stream)
    records = list(stream)
    # 5 lignes valides + NULL_TIMESTAMP (syntaxiquement valide)
    assert len(records) == 6
    assert stats.parse_errors == len(MIXED_LINES) - 6
    assert stats.errors_by_reason["empty"] == 2
    assert stats.errors_by_reason["level"] == 1
    assert stats.errors_by_reason["ip"] == 1
    assert len(stats.error_samples) <= stats.max_samples
