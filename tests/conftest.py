"""Fixtures partagées : petits fichiers temporaires (``tmp_path``), fabriques."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from engine.config import DEFAULT_INPUT_DIR, GROUND_TRUTH_FILE
from engine.models import LogRecord, SecurityEvent
from scripts.generate_logs import GeneratorConfig, generate_dataset

# Lignes valides (une par format) -------------------------------------------
JSON_LINE = (
    '2026-11-07T10:15:32 | ERROR | 192.168.1.45 | user_042 | '
    '{"event": "login_failed", "port": 22, "proto": "TCP", "code": 401}'
)
TEXT_LINE = "2026-11-07T10:15:33 | INFO | 10.0.0.12 | user_007 | GET /index.html 200"
CONN_LINE = (
    "2026-11-07T10:15:34 | WARNING | 172.16.0.8 | user_013 | CONN 172.16.0.8:443/TCP"
)
# Lignes valides après normalisation (casse / espaces parasites) -----------
LOWER_LEVEL_LINE = (
    "2026-11-07T10:15:35 | error | 10.0.0.13 | USER_008 | "
    '{"event": "service_crash", "port": 8080, "proto": "TCP", "code": 503}'
)
SPACED_LINE = (
    "  2026-11-07T10:15:36  |   Warning  |  10.0.0.14 | user_009 |  POST /login 403  "
)
# Lignes invalides -----------------------------------------------------------
TRUNCATED_LINE = "2026-11-07T10:15:37 | INFO | 10.0.0"
INVALID_JSON_LINE = (
    '2026-11-07T10:15:38 | INFO | 10.0.0.15 | user_010 | {"event": "file_ac'
)
UNKNOWN_LEVEL_LINE = "2026-11-07T10:15:39 | DEBUGX | 10.0.0.16 | user_011 | GET / 200"
BAD_IP_LINE = "2026-11-07T10:15:40 | INFO | 999.1.1 | user_012 | GET / 200"
NULL_TIMESTAMP_LINE = "1970-01-01T00:00:00 | INFO | 10.0.0.17 | user_013 | GET / 200"
BAD_TIMESTAMP_LINE = "2026-13-45T99:00:00 | INFO | 10.0.0.18 | user_014 | GET / 200"

VALID_LINES: tuple[str, ...] = (
    JSON_LINE,
    TEXT_LINE,
    CONN_LINE,
    LOWER_LEVEL_LINE,
    SPACED_LINE,
)
MIXED_LINES: tuple[str, ...] = (
    JSON_LINE,
    "",
    TEXT_LINE,
    "   \t ",
    CONN_LINE,
    TRUNCATED_LINE,
    INVALID_JSON_LINE,
    LOWER_LEVEL_LINE,
    UNKNOWN_LEVEL_LINE,
    BAD_IP_LINE,
    NULL_TIMESTAMP_LINE,
    SPACED_LINE,
)
BASE_TIME = datetime(2026, 11, 7, 10, 0, 0)
# (dossier des logs, fichier blacklist, vérité terrain)
GeneratedDataset = tuple[Path, Path, dict[str, Any]]


def write_lines(path: Path, lines: tuple[str, ...] | list[str]) -> Path:
    """Écrit ``lines`` dans ``path`` (une par ligne) et retourne le chemin."""
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.fixture
def mixed_log_file(tmp_path: Path) -> Path:
    """Fichier mêlant les 3 formats, du bruit valide et des lignes corrompues."""
    return write_lines(tmp_path / "mixed.log", MIXED_LINES)


@pytest.fixture
def two_log_files(tmp_path: Path) -> tuple[Path, Path]:
    """Deux petits fichiers distincts pour tester ``yield from``."""
    first = write_lines(tmp_path / "a.log", ["a1", "a2"])
    second = write_lines(tmp_path / "b.log", ["b1", "b2", "b3"])
    return first, second


@pytest.fixture
def blacklist_file(tmp_path: Path) -> Path:
    """Blacklist temporaire avec commentaire, ligne vide et IP invalide."""
    return write_lines(
        tmp_path / "blacklist.txt",
        ["# commentaire", "203.0.113.5", "", "198.51.100.7 ", "not-an-ip", "10.0.0.1"],
    )


@pytest.fixture
def make_record() -> Callable[..., LogRecord]:
    """Fabrique de ``LogRecord`` valides, personnalisables par mots-clés."""

    def factory(**overrides: Any) -> LogRecord:
        record = LogRecord(
            timestamp=BASE_TIME,
            level="INFO",
            ip="10.0.0.1",
            user_id="user_001",
            payload={"event": "file_access", "port": 445, "proto": "TCP", "code": 200},
            connection=("10.0.0.1", 445, "TCP"),
            raw="",
            source_format="json",
        )
        record.update(overrides)  # type: ignore[typeddict-item]
        return record

    return factory


@pytest.fixture
def make_event() -> Callable[..., SecurityEvent]:
    """Fabrique de ``SecurityEvent`` : ``make_event(secondes, nom, ip=...)``."""

    def factory(
        seconds: float, event: str, ip: str = "203.0.113.9", user: str = "admin"
    ) -> SecurityEvent:
        return SecurityEvent(BASE_TIME + timedelta(seconds=seconds), event, user, ip)

    return factory


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    """Répertoire des échantillons versionnés (``data/samples``)."""
    if not any(DEFAULT_INPUT_DIR.glob("*.log")):
        pytest.skip("échantillons absents : lancer `python main.py generate`")
    return DEFAULT_INPUT_DIR


@pytest.fixture(scope="session")
def ground_truth(samples_dir: Path) -> dict[str, Any]:
    """Vérité terrain produite par le générateur."""
    with (samples_dir / GROUND_TRUTH_FILE).open(encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


@pytest.fixture(scope="session")
def generated_dataset(tmp_path_factory: pytest.TempPathFactory) -> GeneratedDataset:
    """Jeu de données généré avec une AUTRE graine (7) que les échantillons."""
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
