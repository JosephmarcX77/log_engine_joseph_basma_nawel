"""Tests du MODULE 4 — audit d'introspection (globals() / locals())."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from engine import audit as audit_module
from engine.audit import (
    audit_scope,
    describe_variable,
    export_audit,
    format_audit_table,
    is_sensitive,
    preview,
)
from engine.config import MASK, PREVIEW_LENGTH
from engine.exceptions import AuditError


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
