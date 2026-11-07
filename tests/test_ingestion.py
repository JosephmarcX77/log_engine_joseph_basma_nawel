"""Tests du MODULE 1 — ingestion paresseuse (``yield`` / ``yield from``)."""

from __future__ import annotations

import inspect
import logging
import re
from collections.abc import Generator
from itertools import islice
from pathlib import Path

import pytest

from conftest import write_lines
from engine import ingestion
from engine.config import PROJECT_ROOT
from engine.exceptions import LogSourceError
from engine.ingestion import (
    discover_sources,
    read_log_file,
    read_multiple_sources,
    resolve_sources,
)


def test_read_log_file_is_a_generator(mixed_log_file: Path) -> None:
    """``read_log_file`` est une fonction génératrice (évaluation paresseuse)."""
    assert inspect.isgeneratorfunction(read_log_file)
    stream = read_log_file(mixed_log_file)
    assert inspect.isgenerator(stream)
    stream.close()


def test_read_log_file_yields_lines_without_newline(
    two_log_files: tuple[Path, Path],
) -> None:
    """Chaque ligne est produite sans son ``\\n`` final."""
    assert list(read_log_file(two_log_files[0])) == ["a1", "a2"]


def test_partial_consumption_reads_only_what_is_needed(tmp_path: Path) -> None:
    """On peut ne consommer que le début d'un gros fichier puis fermer le flux."""
    big = write_lines(tmp_path / "big.log", [f"line {i}" for i in range(50_000)])
    stream = read_log_file(big)
    assert isinstance(stream, Generator)
    assert list(islice(stream, 3)) == ["line 0", "line 1", "line 2"]
    assert next(stream) == "line 3"  # le générateur reprend là où il s'était arrêté
    stream.close()  # GeneratorExit -> le ``with`` ferme le fichier
    with pytest.raises(StopIteration):
        next(stream)


def test_missing_file_error_is_lazy(tmp_path: Path) -> None:
    """L'ouverture n'a lieu qu'au premier ``next()`` (générateur paresseux)."""
    stream = read_log_file(tmp_path / "absent.log")  # aucune erreur ici
    with pytest.raises(LogSourceError, match="introuvable"):
        next(stream)


def test_permission_error_is_wrapped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``PermissionError`` est convertie en ``LogSourceError``."""
    target = write_lines(tmp_path / "locked.log", ["x"])

    def deny(*_args: object, **_kwargs: object) -> None:
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "open", deny)
    with pytest.raises(LogSourceError, match="permission"):
        next(read_log_file(target))


def test_invalid_utf8_bytes_are_replaced(tmp_path: Path) -> None:
    """Les octets non UTF-8 sont remplacés au lieu de faire échouer la lecture."""
    path = tmp_path / "binary.log"
    path.write_bytes(b"ok\n\xff\xfe broken\n")
    lines = list(read_log_file(path))
    assert lines[0] == "ok"
    assert "�" in lines[1]


def test_read_multiple_sources_chains_with_yield_from(
    two_log_files: tuple[Path, Path],
) -> None:
    """``yield from`` enchaîne les fichiers dans l'ordre, sans liste intermédiaire."""
    stream = read_multiple_sources(two_log_files)
    assert inspect.isgenerator(stream)
    assert list(stream) == ["a1", "a2", "b1", "b2", "b3"]


def test_missing_source_is_skipped_with_warning(
    two_log_files: tuple[Path, Path],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Une source manquante est signalée puis ignorée : le flux continue."""
    first, second = two_log_files
    with caplog.at_level(logging.WARNING, logger="engine.ingestion"):
        lines = list(read_multiple_sources([first, tmp_path / "absent.log", second]))
    assert lines == ["a1", "a2", "b1", "b2", "b3"]
    assert "absent.log" in caplog.text


def test_discover_sources_sorted_and_filtered(tmp_path: Path) -> None:
    """Seuls les ``*.log`` sont produits, triés par nom."""
    for name in ("server_02.log", "server_01.log", "notes.txt"):
        write_lines(tmp_path / name, ["x"])
    assert inspect.isgenerator(discover_sources(tmp_path))
    found = discover_sources(tmp_path)
    assert [path.name for path in found] == ["server_01.log", "server_02.log"]


def test_discover_sources_accepts_a_file(two_log_files: tuple[Path, Path]) -> None:
    """Un chemin de fichier est produit tel quel."""
    assert list(discover_sources(two_log_files[0])) == [two_log_files[0]]


def test_discover_sources_missing_directory(tmp_path: Path) -> None:
    """Un dossier inexistant est une erreur fatale (``LogSourceError``)."""
    with pytest.raises(LogSourceError):
        list(discover_sources(tmp_path / "nope"))


def test_resolve_sources_mixes_files_and_directories(
    two_log_files: tuple[Path, Path], tmp_path: Path
) -> None:
    """``resolve_sources`` accepte des fichiers et des dossiers."""
    first, _ = two_log_files
    resolved = list(resolve_sources([first, tmp_path]))
    assert resolved[0] == first
    assert {path.name for path in resolved[1:]} == {"a.log", "b.log"}


def test_engine_never_loads_whole_files() -> None:
    """Aucun ``read()`` / ``readlines()`` dans le moteur (mémoire constante)."""
    forbidden = re.compile(r"\.(read|readlines)\(\)")
    offenders = [
        path.name
        for path in (PROJECT_ROOT / "engine").glob("*.py")
        if forbidden.search(path.read_text(encoding="utf-8"))
    ]
    assert offenders == []
    assert "yield from" in inspect.getsource(ingestion.read_multiple_sources)
