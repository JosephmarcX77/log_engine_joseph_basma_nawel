"""Tests de l'export des résultats (JSON signé + console) et du benchmark."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from conftest import MIXED_LINES, write_lines
from engine.analytics import StreamAggregator
from engine.benchmark import format_benchmark, run_benchmark, run_scaling_benchmark
from engine.exceptions import ReportError
from engine.models import Alert, PipelineStats
from engine.pipeline import build_pipeline
from engine.report import (
    build_report,
    render_console,
    sign_report,
    to_jsonable,
    verify_signature,
    write_json_report,
)
from engine.rules import apply_security_rules

PARAMETERS = {
    "threshold": 5,
    "window_seconds": 60,
    "critical_limit": 10,
    "period_minutes": 5,
}


@pytest.fixture
def report(mixed_log_file: Path) -> dict[str, object]:
    """Rapport complet construit sur le petit fichier mixte."""
    stats = PipelineStats()
    aggregator = StreamAggregator(blacklist=frozenset({"192.168.1.45"}))
    aggregator.consume(build_pipeline([mixed_log_file], stats=stats))
    rules = apply_security_rules(context=aggregator.context())
    return build_report(
        stats=stats,
        aggregator=aggregator,
        rules_report=rules,
        sources=[mixed_log_file],
        parameters=PARAMETERS,
        duration_seconds=0.5,
    )


def test_to_jsonable_converts_rich_types() -> None:
    """datetime, set, frozenset, Alert, Path et tuples deviennent du JSON natif."""
    value = {
        "when": datetime(2026, 11, 7, 10, 0),
        "ips": {"b", "a"},
        "frozen": frozenset({"z"}),
        "alert": Alert(rule="r", ip="1.2.3.4", count=1),
        "path": Path("x") / "y",
        "pair": ("a", 1),
    }
    converted = to_jsonable(value)
    assert converted["when"] == "2026-11-07T10:00:00"
    assert converted["ips"] == ["a", "b"] and converted["frozen"] == ["z"]
    assert converted["alert"]["ip"] == "1.2.3.4"
    assert converted["pair"] == ["a", 1]
    json.dumps(converted)


def test_report_content(report: dict[str, object]) -> None:
    """Le rapport contient toutes les sections attendues et est sérialisable."""
    sections = {"meta", "ingestion", "levels", "top_users", "ip_sets", "brute_force"}
    assert sections <= set(report)
    assert report["ingestion"]["valid_records"] == 5  # type: ignore[index]
    assert report["ip_sets"]["blacklisted_active"]["ips"] == [  # type: ignore[index]
        "192.168.1.45"
    ]
    json.dumps(report)


def test_signature_detects_tampering(report: dict[str, object]) -> None:
    """La signature HMAC-SHA256 détecte toute modification du rapport."""
    report["signature"] = sign_report(report, "k3y")
    assert verify_signature(report, "k3y")
    assert not verify_signature(report, "wrong-key")
    report["levels"] = {"INFO": 0}
    assert not verify_signature(report, "k3y")


def test_write_json_report(report: dict[str, object], tmp_path: Path) -> None:
    """Export dans ``report_<horodatage>.json`` ; erreur d'écriture -> ReportError."""
    path = write_json_report(report, tmp_path / "out")
    assert path.name.startswith("report_")
    assert json.loads(path.read_text(encoding="utf-8"))["meta"]["parameters"] == (
        PARAMETERS
    )
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(ReportError):
        write_json_report(report, blocker / "sub")


def test_render_console_sections(report: dict[str, object]) -> None:
    """La synthèse console présente les 6 sections."""
    text = render_console(report)
    for title in ("[1] INGESTION", "[2] RÉPARTITION", "[3] TOP", "[4] ENSEMBLES",
                  "[5] FORCE BRUTE", "[6] RÈGLES"):
        assert title in text
    assert "active & blacklist" in text


def test_benchmark_measures_memory(tmp_path: Path) -> None:
    """Le benchmark mesure un pic mémoire et un débit ; ``limit`` borne la lecture."""
    path = write_lines(tmp_path / "bench.log", list(MIXED_LINES) * 200)
    result = run_benchmark([path])
    assert result.lines_read == len(MIXED_LINES) * 200
    assert result.peak_bytes > 0 and result.lines_per_second > 0
    scaled = run_scaling_benchmark([path], [12, 120])
    assert [r.lines_read for r in scaled] == [12, 120]
    assert "pic mémoire" in format_benchmark(scaled)
    assert result.to_dict()["peak_mib"] >= 0
    untraced = run_benchmark([path], trace=False)
    assert untraced.peak_bytes == 0 and untraced.lines_read == result.lines_read
