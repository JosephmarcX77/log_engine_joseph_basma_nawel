"""Tests du MODULE 3 — détection de force brute (for/while/break/continue/else)."""

from __future__ import annotations

import ast
import inspect
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from conftest import GeneratedDataset
from engine.analytics import StreamAggregator, group_events_by_ip, load_blacklist
from engine.config import DEFAULT_BLACKLIST
from engine.detection import DetectionTrace, detect_brute_force
from engine.exceptions import ConfigurationError
from engine.ingestion import discover_sources
from engine.models import SecurityEvent
from engine.pipeline import build_pipeline

EventFactory = Callable[..., SecurityEvent]
IP = "203.0.113.9"


def failures(make_event: EventFactory, *seconds: float) -> list[SecurityEvent]:
    """Construit des ``login_failed`` aux instants donnés (en secondes)."""
    return [make_event(second, "login_failed") for second in seconds]


def test_full_attack_raises_one_alert(make_event: EventFactory) -> None:
    """6 échecs en 15 s -> une alerte de 6 échecs, bornes correctes."""
    events = failures(make_event, 0, 3, 6, 9, 12, 15)
    trace = DetectionTrace()
    alerts = detect_brute_force({IP: events}, 5, 60, trace=trace)
    assert len(alerts) == 1
    alert = alerts[0]
    assert (alert.ip, alert.count, alert.duration_seconds) == (IP, 6, 15.0)
    assert alert.start == events[0].timestamp and alert.end == events[-1].timestamp
    assert IP not in trace.clean_ips  # break -> la clause else N'EST PAS exécutée


def test_below_threshold_reaches_loop_else(make_event: EventFactory) -> None:
    """Sans attaque, la boucle se termine sans break : branche ``else`` exécutée."""
    trace = DetectionTrace()
    alerts = detect_brute_force({IP: failures(make_event, 0, 5, 10, 15)}, trace=trace)
    assert alerts == []
    assert trace.clean_ips == {IP}


def test_login_success_interrupts_the_sequence(make_event: EventFactory) -> None:
    """3 échecs + succès + 3 échecs : aucune alerte (break sur login_success).

    Un comptage naïf de 6 échecs en 30 s aurait levé une alerte à tort.
    """
    events = [
        *failures(make_event, 0, 3, 6),
        make_event(9, "login_success"),
        *failures(make_event, 12, 15, 18),
    ]
    trace = DetectionTrace()
    assert detect_brute_force({IP: events}, trace=trace) == []
    assert trace.interrupted_sequences == 1
    assert trace.clean_ips == {IP}


def test_non_login_events_are_skipped(make_event: EventFactory) -> None:
    """Les événements hors connexion sont ignorés (continue), pas interruptifs."""
    events = [
        make_event(0, "login_failed"),
        make_event(1, "file_access"),
        make_event(2, "login_failed"),
        make_event(3, "permission_denied"),
        *failures(make_event, 4, 5, 6),
    ]
    alerts = detect_brute_force({IP: events})
    assert [alert.count for alert in alerts] == [5]


def test_window_is_sliding(make_event: EventFactory) -> None:
    """La fenêtre glisse : l'attaque commençant au 2e échec est trouvée."""
    events = failures(make_event, 0, 50, 55, 58, 62, 64, 66, 70)
    alerts = detect_brute_force({IP: events}, threshold=5, window_seconds=60)
    assert len(alerts) == 1
    assert alerts[0].count == 7
    assert alerts[0].start == events[1].timestamp


def test_spread_failures_depend_on_window(make_event: EventFactory) -> None:
    """5 échecs espacés de 20 s : hors fenêtre de 60 s, dans une fenêtre de 100 s."""
    events = failures(make_event, 0, 20, 40, 60, 80)
    assert detect_brute_force({IP: events}, window_seconds=60) == []
    assert len(detect_brute_force({IP: events}, window_seconds=100)) == 1


def test_one_alert_per_ip_after_threshold_break(make_event: EventFactory) -> None:
    """Après le seuil (break), l'IP n'est plus analysée : une seule alerte."""
    events = failures(make_event, 0, 1, 2, 3, 4, 1000, 1001, 1002, 1003, 1004)
    assert len(detect_brute_force({IP: events})) == 1


def test_multiple_ips_unsorted_input_and_blacklist(make_event: EventFactory) -> None:
    """Plusieurs IP, événements non triés, marquage blacklist et sévérité."""
    attacker = list(reversed(failures(make_event, 0, 1, 2, 3, 4)))
    other = [make_event(second, "login_failed", ip="198.51.100.1") for second in (0, 1)]
    alerts = detect_brute_force(
        {IP: attacker, "198.51.100.1": other}, blacklist=frozenset({IP})
    )
    assert [(a.ip, a.blacklisted, a.severity) for a in alerts] == [
        (IP, True, "CRITICAL")
    ]


@pytest.mark.parametrize(("threshold", "window"), [(0, 60), (5, 0), (-1, -5)])
def test_invalid_parameters(threshold: int, window: int) -> None:
    """Seuil < 1 ou fenêtre <= 0 : ``ConfigurationError``."""
    with pytest.raises(ConfigurationError):
        detect_brute_force({}, threshold=threshold, window_seconds=window)


def test_required_loop_constructs_are_present() -> None:
    """for + while (avec else) + break + continue dans ``detect_brute_force``."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(detect_brute_force)))
    nodes = list(ast.walk(tree))
    whiles = [node for node in nodes if isinstance(node, ast.While)]
    assert any(isinstance(node, ast.For) for node in nodes)
    assert whiles and whiles[0].orelse  # while ... else
    assert sum(isinstance(node, ast.Break) for node in nodes) >= 3
    assert sum(isinstance(node, ast.Continue) for node in nodes) >= 2


def _run_samples(samples_dir: Path) -> StreamAggregator:
    """Pipeline complet + agrégation en une passe sur les échantillons."""
    aggregator = StreamAggregator(blacklist=load_blacklist(DEFAULT_BLACKLIST))
    return aggregator.consume(build_pipeline(discover_sources(samples_dir)))


def test_detection_matches_ground_truth(
    samples_dir: Path, ground_truth: dict[str, Any]
) -> None:
    """Les alertes du moteur correspondent EXACTEMENT à ``ground_truth.json``."""
    aggregator = _run_samples(samples_dir)
    detected = {
        alert.ip: (alert.count, str(alert.start).replace(" ", "T"), alert.blacklisted)
        for alert in aggregator.brute_force_alerts
    }
    expected = {
        alert["ip"]: (alert["failures"], alert["start"], alert["blacklisted"])
        for alert in ground_truth["expected_alerts"]
    }
    assert detected == expected
    # les séquences interrompues par un login_success ne déclenchent rien
    assert not set(ground_truth["interrupted_only_ips"]) & set(detected)
    assert aggregator.detection_trace.interrupted_sequences >= len(
        ground_truth["interrupted_only_ips"]
    )


def test_streaming_detection_equals_global_detection(samples_dir: Path) -> None:
    """Détection en flux (tampons bornés) == détection globale (tout en mémoire)."""
    streaming = _run_samples(samples_dir).brute_force_alerts
    events_by_ip = group_events_by_ip(build_pipeline(discover_sources(samples_dir)))
    global_alerts = detect_brute_force(
        events_by_ip, blacklist=load_blacklist(DEFAULT_BLACKLIST)
    )
    assert streaming == global_alerts


def test_detection_matches_generated_ground_truth(
    generated_dataset: GeneratedDataset,
) -> None:
    """La détection est conforme à la vérité terrain sur une AUTRE graine."""
    logs, blacklist, truth = generated_dataset
    aggregator = StreamAggregator(blacklist=load_blacklist(blacklist))
    aggregator.consume(build_pipeline(discover_sources(logs)))
    detected = {(a.ip, a.count) for a in aggregator.brute_force_alerts}
    expected = {(a["ip"], a["failures"]) for a in truth["expected_alerts"]}
    assert detected == expected
