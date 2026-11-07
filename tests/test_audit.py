"""Tests du MODULE 4 — audit d'introspection (globals() / locals()),
export des résultats (``report.py`` : JSON signé, console, benchmark)
et CLI de bout en bout (``main.py``)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

import main
from conftest import MIXED_LINES, GeneratedDataset, write_lines
from engine import audit as audit_module
from engine.analytics import StreamAggregator
from engine.audit import (
    audit_scope,
    describe_variable,
    export_audit,
    format_audit_table,
    is_sensitive,
    preview,
)
from engine.config import MASK, PREVIEW_LENGTH
from engine.exceptions import AuditError, ReportError
from engine.models import Alert, PipelineStats
from engine.pipeline import build_pipeline
from engine.report import (
    build_report,
    format_benchmark,
    render_console,
    run_benchmark,
    run_scaling_benchmark,
    sign_report,
    to_jsonable,
    verify_signature,
    write_json_report,
)
from engine.rules import apply_security_rules


def _audit_with_secrets() -> dict[str, Any]:
    """Simule un appelant avec des variables sensibles, puis s'audite."""
    db_password = "hunter2-very-secret"
    api_token = "tok_abcdef123456"
    config = {"signing_secret": "s3cr3t-value", "threshold": 5}
    numbers = list(range(1_000))
    label = "x" * 500
    assert db_password and api_token and config and numbers and label
    return audit_scope(locals(), global_vars=globals())


def _names(audit: dict[str, Any], scope: str) -> dict[str, dict[str, Any]]:
    """Index ``nom -> info`` d'un espace de noms audité."""
    return {info["name"]: info for info in audit["scopes"][scope]}


def test_audit_inspects_three_scopes() -> None:
    """locals() de l'appelant, locals() de l'audit et globals() sont inspectés."""
    audit = _audit_with_secrets()
    assert set(audit["scopes"]) == {"caller_locals", "audit_locals", "globals"}
    caller = _names(audit, "caller_locals")
    assert {"db_password", "api_token", "config", "numbers", "label"} <= set(caller)
    own = _names(audit, "audit_locals")
    assert {"local_vars", "global_vars", "exclude_dunders"} <= set(own)
    assert "_audit_with_secrets" in _names(audit, "globals")


def test_variable_details() -> None:
    """Nom, type, taille (sys.getsizeof) et aperçu tronqué à 80 caractères."""
    caller = _names(_audit_with_secrets(), "caller_locals")
    numbers = caller["numbers"]
    assert numbers["type"] == "list"
    assert numbers["size_bytes"] > 1_000
    assert len(caller["label"]["preview"]) <= PREVIEW_LENGTH
    assert all(len(info["preview"]) <= PREVIEW_LENGTH for info in caller.values())


def test_secrets_are_never_exported(tmp_path: Path) -> None:
    """Les valeurs sensibles sont masquées, y compris dans le JSON exporté."""
    audit = _audit_with_secrets()
    caller = _names(audit, "caller_locals")
    assert caller["db_password"]["masked"] and caller["db_password"]["preview"] == MASK
    assert caller["api_token"]["preview"] == MASK
    assert "s3cr3t-value" not in caller["config"]["preview"]  # clé sensible masquée
    path = export_audit(audit, tmp_path)
    assert path.name.startswith("audit_") and path.suffix == ".json"
    dumped = path.read_text(encoding="utf-8")
    for secret in ("hunter2-very-secret", "tok_abcdef123456", "s3cr3t-value"):
        assert secret not in dumped
    assert json.loads(dumped)["summary"]["caller_locals"]["masked"] >= 2


def test_dunders_and_modules_excluded_on_demand() -> None:
    """Les dunders et modules sont exclus par défaut, inclus si demandé."""
    default = _names(audit_scope({}, global_vars=vars(audit_module)), "globals")
    assert "__name__" not in default and "json" not in default
    full = audit_scope(
        {}, global_vars=vars(audit_module), exclude_dunders=False, exclude_modules=False
    )
    names = _names(full, "globals")
    assert "__name__" in names and "json" in names


def test_default_globals_is_audit_module() -> None:
    """Sans ``global_vars``, c'est ``globals()`` du module d'audit qui est inspecté."""
    assert "audit_scope" in _names(audit_scope(), "globals")


def test_helpers() -> None:
    """Détection des noms sensibles et aperçus robustes."""
    assert is_sensitive("DB_PASSWORD") and is_sensitive("refresh_token")
    assert not is_sensitive("threshold")
    assert describe_variable("user_secret", "abc")["preview"] == MASK

    class BrokenRepr:
        def __repr__(self) -> str:
            raise RuntimeError("boom")

    assert "BrokenRepr" in preview(BrokenRepr())  # pas d'exception propagée
    assert len(preview("y" * 10_000)) <= PREVIEW_LENGTH


def test_format_audit_table() -> None:
    """Le tableau console contient une section par espace de noms."""
    table = format_audit_table(_audit_with_secrets())
    assert "--- caller_locals" in table and "--- globals" in table
    assert "hunter2" not in table


def test_export_failure_raises_audit_error(tmp_path: Path) -> None:
    """Un dossier de sortie inutilisable lève ``AuditError``."""
    blocker = tmp_path / "file.txt"
    blocker.write_text("x", encoding="utf-8")
    with pytest.raises(AuditError):
        export_audit({"scopes": {}}, blocker / "sub")


# --------------------------------------------------------------------------
# Export des résultats : rapport JSON signé, console, benchmark (report.py)
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# CLI de bout en bout (main.py)
# --------------------------------------------------------------------------
def test_cli_run_writes_report(
    generated_dataset: GeneratedDataset,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main.py run`` : code 0, synthèse console et rapport JSON."""
    logs, blacklist, truth = generated_dataset
    code = main.main(
        ["run", "--input", str(logs), "--blacklist", str(blacklist),
         "--output", str(tmp_path)]
    )
    assert code == 0
    assert "[5] FORCE BRUTE" in capsys.readouterr().out
    report_path = next(tmp_path.glob("report_*.json"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["brute_force"]["count"] == len(truth["expected_alerts"])
    assert report["ingestion"]["valid_records"] == truth["totals"]["valid"]
    assert any(tmp_path.glob("engine_*.log"))  # journal des lignes rejetées


def test_cli_audit_masks_secret(
    generated_dataset: GeneratedDataset,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main.py audit`` : le secret de signature n'apparaît jamais en clair."""
    logs, blacklist, _ = generated_dataset
    monkeypatch.setenv("LOG_ENGINE_SECRET", "ultra-secret-signing-key")
    code = main.main(
        ["audit", "--input", str(logs), "--blacklist", str(blacklist),
         "--output", str(tmp_path)]
    )
    output = capsys.readouterr().out
    assert code == 0 and "AUDIT D'INTROSPECTION" in output
    audit_text = next(tmp_path.glob("audit_*.json")).read_text(encoding="utf-8")
    assert "ultra-secret-signing-key" not in audit_text + output
    audit = json.loads(audit_text)
    caller = {info["name"]: info for info in audit["scopes"]["caller_locals"]}
    assert caller["signing_secret"]["masked"] is True


def test_cli_benchmark(
    generated_dataset: GeneratedDataset, capsys: pytest.CaptureFixture[str]
) -> None:
    """``main.py benchmark --sizes`` affiche la courbe mémoire."""
    logs, blacklist, _ = generated_dataset
    code = main.main(
        ["benchmark", "--input", str(logs), "--blacklist", str(blacklist),
         "--sizes", "500", "5000"]
    )
    assert code == 0
    assert "pic mémoire" in capsys.readouterr().out


def test_cli_generate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """``main.py generate`` crée logs, blacklist et vérité terrain."""
    code = main.main(
        ["generate", "--output-dir", str(tmp_path / "gen"), "--files", "1",
         "--lines", "300", "--blacklist", str(tmp_path / "bl.txt")]
    )
    assert code == 0
    assert (tmp_path / "gen" / "ground_truth.json").exists()
    assert "Vérité terrain" in capsys.readouterr().out


@pytest.mark.parametrize(
    "argv",
    [
        ["run", "--input", "definitely/missing/dir"],
        ["run", "--threshold", "0"],
        ["run", "--blacklist", "missing-blacklist.txt"],
        ["generate", "--attack-ratio", "0.9", "--output-dir", "unused"],
        ["benchmark", "--input", "definitely/missing/dir"],
    ],
)
def test_cli_fatal_errors_exit_with_code_1(
    argv: list[str], tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Erreur fatale : code 1, message lisible, pas de traceback."""
    if argv[0] in ("run", "audit"):
        argv = [*argv, "--output", str(tmp_path)]
    assert main.main(argv) == 1
    error = capsys.readouterr().err
    assert error.startswith("Erreur") and "Traceback" not in error
