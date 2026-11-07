"""Tests du MODULE 3 — ensembles et ``defaultdict``, agrégation en une passe."""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable, Iterator
from datetime import timedelta
from pathlib import Path

import pytest

from conftest import BASE_TIME
from engine.analytics import (
    SWEEP_INTERVAL,
    StreamAggregator,
    collect_error_ips,
    collect_error_ips_comprehension,
    compare_ip_sets,
    count_by_level,
    count_by_user,
    count_user_levels,
    group_events_by_ip,
    load_blacklist,
    top_items,
)
from engine.exceptions import LogSourceError
from engine.models import LogRecord

RecordFactory = Callable[..., LogRecord]


@pytest.fixture
def records(make_record: RecordFactory) -> list[LogRecord]:
    """Petit jeu d'enregistrements variés."""
    return [
        make_record(level="INFO", ip="10.0.0.1", user_id="alice"),
        make_record(level="ERROR", ip="10.0.0.2", user_id="alice"),
        make_record(level="CRITICAL", ip="10.0.0.3", user_id="bob"),
        make_record(level="ERROR", ip="10.0.0.2", user_id="bob"),
        make_record(level="INFO", ip="10.0.0.4", user_id="carol", payload="GET / 200"),
    ]


def test_collect_error_ips_variants(records: list[LogRecord]) -> None:
    """``set`` des IP en erreur, en filter/map/lambda et en comprehension."""
    expected = {"10.0.0.2", "10.0.0.3"}
    assert collect_error_ips(records) == expected
    assert collect_error_ips_comprehension(records) == expected
    assert isinstance(collect_error_ips(records), set)


def test_load_blacklist_returns_immutable_frozenset(
    blacklist_file: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Commentaires, blancs et IP invalides ignorés ; résultat immuable."""
    with caplog.at_level(logging.WARNING):
        blacklist = load_blacklist(blacklist_file)
    assert blacklist == frozenset({"203.0.113.5", "198.51.100.7", "10.0.0.1"})
    assert isinstance(blacklist, frozenset)
    assert "not-an-ip" in caplog.text
    with pytest.raises(AttributeError):
        blacklist.add("1.2.3.4")  # type: ignore[attr-defined]
    assert hash(blacklist)  # hachable, contrairement à set


def test_load_blacklist_missing_file(tmp_path: Path) -> None:
    """Blacklist absente : ``LogSourceError``."""
    with pytest.raises(LogSourceError):
        load_blacklist(tmp_path / "absent.txt")


def test_compare_ip_sets_operators() -> None:
    """Union, intersection, différences et différence symétrique."""
    active = {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    blacklist = frozenset({"3.3.3.3", "4.4.4.4"})
    result = compare_ip_sets(active, blacklist)
    assert result["union"] == {"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}
    assert result["blacklisted_active"] == {"3.3.3.3"}  # alerte
    assert result["active_not_blacklisted"] == {"1.1.1.1", "2.2.2.2"}
    assert result["blacklisted_dormant"] == {"4.4.4.4"}
    assert result["symmetric_difference"] == {"1.1.1.1", "2.2.2.2", "4.4.4.4"}
    assert all(type(value) is set for value in result.values())
    # propriété : (A ^ B) == (A | B) - (A & B)
    assert result["symmetric_difference"] == (
        result["union"] - result["blacklisted_active"]
    )


def test_count_by_level_and_user_never_raise_key_error(
    records: list[LogRecord],
) -> None:
    """``defaultdict(int)`` : une clé absente vaut 0, sans ``KeyError``."""
    levels = count_by_level(records)
    assert isinstance(levels, defaultdict)
    assert levels == {"INFO": 2, "ERROR": 2, "CRITICAL": 1}
    assert levels["WARNING"] == 0  # clé jamais vue : 0, pas d'exception
    assert count_by_user(records) == {"alice": 2, "bob": 2, "carol": 1}


def test_count_user_levels_nested_defaultdict(records: list[LogRecord]) -> None:
    """``defaultdict(lambda: defaultdict(int))`` : comptage croisé."""
    crossed = count_user_levels(records)
    assert crossed["alice"]["ERROR"] == 1
    assert crossed["bob"]["CRITICAL"] == 1
    assert crossed["nobody"]["INFO"] == 0  # deux niveaux créés à la volée


def test_group_events_by_ip_defaultdict_list(records: list[LogRecord]) -> None:
    """``defaultdict(list)`` : seuls les payloads JSON avec ``event`` sont groupés."""
    groups = group_events_by_ip(records)
    assert set(groups) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}  # pas le texte brut
    assert len(groups["10.0.0.2"]) == 2
    assert groups["unknown"] == []


def test_top_items_sorted_by_count_then_name() -> None:
    """Tri décroissant par effectif, puis alphabétique."""
    assert top_items({"b": 2, "a": 2, "c": 5}, 2) == [("c", 5), ("a", 2)]


def test_stream_aggregator_single_pass(
    records: list[LogRecord], make_record: RecordFactory
) -> None:
    """Un générateur (consommable une fois) suffit à tout calculer en une passe."""

    def once() -> Iterator[LogRecord]:
        yield from records

    stream = once()
    aggregator = StreamAggregator(blacklist=frozenset({"10.0.0.3", "9.9.9.9"}))
    aggregator.consume(stream)
    assert next(stream, None) is None  # le flux est épuisé : une seule passe
    assert aggregator.total_records == len(records)
    assert aggregator.level_counts == count_by_level(records)
    assert aggregator.user_counts == count_by_user(records)
    assert aggregator.error_ips == collect_error_ips(records)
    assert aggregator.ip_sets()["blacklisted_active"] == {"10.0.0.3"}
    assert aggregator.ip_sets()["blacklisted_dormant"] == {"9.9.9.9"}
    assert aggregator.top_users(1) == [("alice", 2)]
    assert sum(aggregator.critical_by_minute.values()) == 1
    assert aggregator.first_seen == aggregator.last_seen == BASE_TIME


def test_stream_aggregator_detects_escalation(make_record: RecordFactory) -> None:
    """``permission_denied`` puis ``config_change`` du même utilisateur < fenêtre."""
    denied = {"event": "permission_denied", "port": 445, "proto": "TCP", "code": 403}
    change = {"event": "config_change", "port": 22, "proto": "TCP", "code": 200}
    later, too_late = timedelta(seconds=30), timedelta(hours=1)
    aggregator = StreamAggregator(escalation_window=120)
    aggregator.consume(
        [
            make_record(user_id="eve", payload=denied),
            make_record(user_id="eve", payload=change, timestamp=BASE_TIME + later),
            make_record(user_id="dan", payload=denied),
            make_record(user_id="dan", payload=change, timestamp=BASE_TIME + too_late),
        ]
    )
    assert set(aggregator.escalations) == {"eve"}


def test_stream_aggregator_buffers_stay_bounded(make_record: RecordFactory) -> None:
    """Les tampons de connexion sont libérés au fil de l'eau (mémoire bornée)."""
    failed = {"event": "login_failed", "port": 22, "proto": "TCP", "code": 401}
    aggregator = StreamAggregator()

    def stream() -> Iterator[LogRecord]:
        # 20 000 échecs isolés (1 toutes les 90 s), chacun d'une IP DIFFÉRENTE :
        # sans balayage, les 20 000 tampons resteraient en mémoire.
        for index in range(20_000):
            yield make_record(
                payload=failed,
                ip=f"10.{index // 250}.{index % 250}.1",
                timestamp=BASE_TIME + timedelta(seconds=90 * index),
            )

    aggregator.consume(stream())
    assert aggregator.brute_force_alerts == []
    # au plus les IP vues depuis le dernier balayage (+ l'enregistrement courant)
    assert aggregator.peak_buffered_events <= SWEEP_INTERVAL + 1
    assert aggregator.events_by_ip == {}  # tout a été analysé et libéré
