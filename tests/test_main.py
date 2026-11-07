"""Tests de bout en bout : CLI ``main.py`` et générateur de jeux de données."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

import main
from engine.analytics import StreamAggregator, load_blacklist
from engine.ingestion import discover_sources, read_log_file
from engine.pipeline import build_pipeline
from scripts.generate_logs import GeneratorConfig, generate_dataset


@pytest.fixture(scope="module")
def dataset(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[Path, Path, dict[str, Any]]:
    """Jeu de données généré avec une AUTRE graine que les échantillons."""
    root = tmp_path_factory.mktemp("dataset")
    config = GeneratorConfig(
        output_dir=root / "logs",
        files=2,
        lines=4_000,
        seed=7,
        blacklist_path=root / "blacklist.txt",
    )
    truth = generate_dataset(config)
    return root / "logs", root / "blacklist.txt", truth


def test_generator_is_deterministic(tmp_path: Path) -> None:
    """Même graine -> fichiers identiques ; graine différente -> fichiers différents."""

    def build(name: str, seed: int) -> str:
        config = GeneratorConfig(
            output_dir=tmp_path / name,
            files=1,
            lines=500,
            seed=seed,
            blacklist_path=tmp_path / f"{name}.txt",
        )
        generate_dataset(config)
        return (tmp_path / name / "server_01.log").read_text(encoding="utf-8")

    assert build("a", 1) == build("b", 1)
    assert build("a", 1) != build("c", 2)


def test_generator_output(dataset: tuple[Path, Path, dict[str, Any]]) -> None:
    """Horodatages croissants, totaux cohérents, blacklist de 15 IP."""
    logs, blacklist, truth = dataset
    assert sum(entry["lines"] for entry in truth["files"]) == truth["totals"]["lines"]
    for entry in truth["files"]:
        previous = datetime.min
        for line in read_log_file(logs / entry["name"]):
            if line.count("|") < 4:  # bruit : ligne vide ou tronquée
                continue
            try:
                current = datetime.fromisoformat(line.strip()[:19])
            except ValueError:
                continue
            if current.year == 1970:  # bruit : horodatage nul
                continue
            assert current >= previous
            previous = current
    assert len(load_blacklist(blacklist)) == 15
    assert truth["attack_sequences"]["interrupted"] > 0


def test_detection_matches_generated_ground_truth(
    dataset: tuple[Path, Path, dict[str, Any]],
) -> None:
    """La détection est conforme à la vérité terrain sur une autre graine."""
    logs, blacklist, truth = dataset
    aggregator = StreamAggregator(blacklist=load_blacklist(blacklist))
    aggregator.consume(build_pipeline(discover_sources(logs)))
    detected = {(a.ip, a.count) for a in aggregator.brute_force_alerts}
    expected = {(a["ip"], a["failures"]) for a in truth["expected_alerts"]}
    assert detected == expected


def test_cli_run_writes_report(
    dataset: tuple[Path, Path, dict[str, Any]],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main.py run`` : code 0, synthèse console et rapport JSON."""
    logs, blacklist, truth = dataset
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
    dataset: tuple[Path, Path, dict[str, Any]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """``main.py audit`` : le secret de signature n'apparaît jamais en clair."""
    logs, blacklist, _ = dataset
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
    dataset: tuple[Path, Path, dict[str, Any]], capsys: pytest.CaptureFixture[str]
) -> None:
    """``main.py benchmark --sizes`` affiche la courbe mémoire."""
    logs, blacklist, _ = dataset
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
