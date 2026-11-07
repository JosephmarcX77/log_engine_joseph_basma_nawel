"""Tests du MODULE 2 — pipeline fonctionnel (filter / map / lambda / match-case)."""

from __future__ import annotations

import ast
import inspect
import textwrap
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from engine import pipeline
from engine.exceptions import ConfigurationError
from engine.ingestion import discover_sources
from engine.models import LogRecord, PipelineStats
from engine.pipeline import (
    ROUTE_HTTP,
    ROUTE_SECURITY,
    ROUTE_SENSITIVE_CONNECTION,
    ROUTE_SERVER_ERROR,
    ROUTE_TEXT,
    ROUTE_UNKNOWN,
    build_filters,
    build_pipeline,
    drop_empty,
    min_level_predicate,
    normalize_record,
    record_to_entry,
    route_entry,
    strip_lines,
)

RecordFactory = Callable[..., LogRecord]


def test_strip_and_filter_none_remove_blank_lines() -> None:
    """``map(str.strip)`` + ``filter(None)`` éliminent lignes vides et blanches."""
    lines = ["  a  ", "", "   ", "\t", "b"]
    cleaned = drop_empty(strip_lines(lines))
    assert isinstance(cleaned, filter)  # itérateur paresseux, pas une liste
    assert list(cleaned) == ["a", "b"]


def test_build_filters_combines_predicates(make_record: RecordFactory) -> None:
    """``build_filters`` combine des fonctions passées en argument (ET logique)."""
    combined = build_filters(
        lambda r: r["level"] == "ERROR",  # prédicat 1 : erreurs
        lambda r: r["ip"].startswith("10."),  # prédicat 2 : réseau 10.0.0.0/8
    )
    assert combined(make_record(level="ERROR", ip="10.1.1.1"))
    assert not combined(make_record(level="INFO", ip="10.1.1.1"))
    assert not combined(make_record(level="ERROR", ip="192.168.0.1"))
    assert build_filters()(make_record())  # aucun prédicat : tout passe


def test_build_filters_rejects_non_callables() -> None:
    """Un prédicat non appelable est une erreur de configuration."""
    with pytest.raises(ConfigurationError):
        build_filters("not callable")  # type: ignore[arg-type]


def test_min_level_predicate_is_a_higher_order_function(
    make_record: RecordFactory,
) -> None:
    """``min_level_predicate`` retourne une fonction (lambda)."""
    at_least_error = min_level_predicate("error")
    assert callable(at_least_error)
    assert at_least_error(make_record(level="CRITICAL"))
    assert not at_least_error(make_record(level="warning"))
    with pytest.raises(ConfigurationError):
        min_level_predicate("LOUD")


def test_normalize_record(make_record: RecordFactory) -> None:
    """Niveau en majuscules, utilisateur en minuscules, IP nettoyée, f-string."""
    original_conn = (" 10.0.0.001 ", 22, "tcp")
    record = make_record(
        level=" Warning ",
        user_id=" USER_042 ",
        ip=" 10.0.0.1 ",
        connection=original_conn,
    )
    normalized = normalize_record(record)
    assert normalized is not record  # copie : l'original n'est pas modifié
    assert normalized["level"] == "WARNING"
    assert normalized["user_id"] == "user_042"
    assert normalized["ip"] == "10.0.0.1"
    # le tuple n'est pas modifié : un NOUVEAU tuple est construit
    assert normalized["connection"] == ("10.0.0.001", 22, "TCP")
    assert record["connection"] is original_conn
    assert normalized["message"] == (
        "2026-11-07 10:00:00 [WARNING ]        10.0.0.1 user_042   "
        "file_access (code=200)"
    )


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ("GET /index.html 200", ROUTE_HTTP),  # str + guard
        ("free text", ROUTE_TEXT),  # str
        ({"level": "ERROR", "code": 503}, ROUTE_SERVER_ERROR),  # mapping + guard
        ({"level": "CRITICAL", "code": 500, "event": "x"}, ROUTE_SERVER_ERROR),  # |
        ({"level": "ERROR", "code": 401, "event": "login_failed"}, ROUTE_SECURITY),
        ({"level": "WARNING", "event": "permission_denied"}, ROUTE_SECURITY),
        ({"level": "ERROR", "code": 404}, "event.error"),  # guard code>=500 faux
        ({"level": "INFO", "event": "file_access"}, "event.info"),  # **rest
        ({"level": "INFO"}, ROUTE_UNKNOWN),  # **rest vide -> guard faux
        (("10.0.0.1", 3389, "TCP"), ROUTE_SENSITIVE_CONNECTION),  # tuple + guard
        (("10.0.0.1", 443, "TCP"), "connection.tcp"),  # tuple capturé
        (("10.0.0.1", 53, "UDP"), "connection.udp"),
        (("not-an-ip", 443, "TCP"), ROUTE_UNKNOWN),  # guard IP invalide
        ({"foo": 1}, ROUTE_UNKNOWN),  # case _
        (42, ROUTE_UNKNOWN),  # case _
    ],
)
def test_route_entry_branches(entry: object, expected: str) -> None:
    """Chaque branche du ``match-case`` est couverte."""
    assert route_entry(entry) == expected


def test_route_entry_uses_only_match_case() -> None:
    """Le routage n'utilise aucun ``if`` / ``elif`` / ``else`` (que du match)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(route_entry)))
    function = tree.body[0]
    assert isinstance(function, ast.FunctionDef)
    assert not any(isinstance(node, ast.If) for node in ast.walk(function))
    assert any(isinstance(node, ast.Match) for node in ast.walk(function))


def test_record_to_entry_per_format(make_record: RecordFactory) -> None:
    """Connexion -> tuple, JSON -> dict enrichi du niveau, texte -> str."""
    conn = make_record(source_format="connection", connection=("1.2.3.4", 22, "TCP"))
    assert record_to_entry(conn) == ("1.2.3.4", 22, "TCP")
    json_entry = record_to_entry(make_record(level="ERROR"))
    assert isinstance(json_entry, dict) and json_entry["level"] == "ERROR"
    text = make_record(payload="GET / 200", connection=None, source_format="text")
    assert record_to_entry(text) == "GET / 200"


def test_build_pipeline_is_lazy(mixed_log_file: Path) -> None:
    """Rien n'est lu tant que le pipeline n'est pas consommé."""
    stats = PipelineStats()
    stream = build_pipeline([mixed_log_file], stats=stats)
    assert isinstance(stream, Iterator) and not isinstance(stream, list)
    assert stats.lines_read == 0
    first = next(stream)
    assert stats.lines_read == 1 and first["route"] == ROUTE_SECURITY


@pytest.mark.parametrize("strict", [False, True])
def test_build_pipeline_counts(mixed_log_file: Path, strict: bool) -> None:
    """Statistiques : 12 lignes = 5 valides + 2 vides + 5 rejetées."""
    stats = PipelineStats()
    records = list(build_pipeline([mixed_log_file], stats=stats, strict=strict))
    assert len(records) == stats.valid_records == 5
    assert stats.lines_read == 12
    assert stats.empty_lines == 2
    assert stats.rejected == 5
    filtered = stats.filtered_by()
    assert filtered["horodatage_nul"] == 1
    if strict:  # niveau et IP rejetés dès le parsing
        assert stats.parse_errors == 4
        assert filtered["niveau_invalide"] == filtered["ip_invalide"] == 0
    else:  # niveau et IP rejetés par les filtres lambda
        assert stats.parse_errors == 2
        assert filtered["niveau_invalide"] == filtered["ip_invalide"] == 1
    assert {r["level"] for r in records} <= {"INFO", "WARNING", "ERROR", "CRITICAL"}
    assert all(r["user_id"] == r["user_id"].lower() for r in records)


def test_build_pipeline_extra_predicates_and_limit(mixed_log_file: Path) -> None:
    """Prédicats personnalisés (fonctions en argument) et ``limit`` (islice)."""
    only_errors = [min_level_predicate("ERROR")]
    errors = list(build_pipeline([mixed_log_file], extra_predicates=only_errors))
    assert [r["level"] for r in errors] == ["ERROR", "ERROR"]
    stats = PipelineStats()
    list(build_pipeline([mixed_log_file], stats=stats, limit=3))
    assert stats.lines_read == 3


def test_pipeline_uses_lambdas_filter_and_map() -> None:
    """Les constructions imposées apparaissent explicitement dans le code."""
    source = inspect.getsource(pipeline.build_pipeline)
    assert source.count("filter(lambda") >= 3
    assert "map(normalize_record" in source
    assert "filter(None" in inspect.getsource(pipeline.drop_empty)


def test_pipeline_matches_ground_truth(
    samples_dir: Path, ground_truth: dict[str, Any]
) -> None:
    """Sur les échantillons : vides / rejets / valides = vérité terrain."""
    stats = PipelineStats()
    level_counts: dict[str, int] = {}
    for record in build_pipeline(discover_sources(samples_dir), stats=stats):
        level_counts[record["level"]] = level_counts.get(record["level"], 0) + 1
    totals = ground_truth["totals"]
    assert stats.lines_read == totals["lines"]
    assert stats.empty_lines == totals["empty"]
    assert stats.rejected == totals["rejected"]
    assert stats.valid_records == totals["valid"]
    assert level_counts == ground_truth["valid_level_counts"]
