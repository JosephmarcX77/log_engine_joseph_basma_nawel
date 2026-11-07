"""MODULE 4 — Audit d'introspection : ``globals()`` et ``locals()``.

``audit_scope`` photographie trois espaces de noms :

* ``caller_locals`` : le ``locals()`` de l'appelant, passé en argument
  (``audit_scope(locals())`` depuis ``main.py``) ;
* ``audit_locals`` : le ``locals()`` de ``audit_scope`` elle-même ;
* ``globals`` : un ``globals()`` (celui du module d'audit par défaut, ou celui
  fourni par l'appelant).

Pour chaque variable : nom, type, taille approximative (``sys.getsizeof``,
taille superficielle) et aperçu ``repr`` tronqué à 80 caractères. Les
variables dont le nom contient ``password``, ``secret`` ou ``token`` sont
MASQUÉES (y compris les clés sensibles des dictionnaires) : aucune valeur
sensible n'est jamais affichée ni exportée en clair.
"""

from __future__ import annotations

import inspect
import json
import reprlib
import sys
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, TypedDict

from engine.config import MASK, PREVIEW_LENGTH, SENSITIVE_MARKERS
from engine.exceptions import AuditError


class VariableInfo(TypedDict):
    """Description d'une variable inspectée."""

    name: str
    type: str
    size_bytes: int
    preview: str
    masked: bool


# reprlib borne le coût du repr (conteneurs tronqués à quelques éléments)
_REPR = reprlib.Repr()
_REPR.maxstring = PREVIEW_LENGTH
_REPR.maxother = PREVIEW_LENGTH
_REPR.maxlist = _REPR.maxtuple = _REPR.maxset = _REPR.maxdict = 5
_REPR.maxlevel = 2


def is_sensitive(name: str) -> bool:
    """Indique si un nom de variable / clé désigne une donnée sensible."""
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _sanitize(value: Any) -> Any:
    """Masque les clés sensibles d'un mapping avant d'en calculer l'aperçu."""
    if isinstance(value, Mapping):
        return {
            key: MASK if isinstance(key, str) and is_sensitive(key) else item
            for key, item in value.items()
        }
    return value


def preview(value: Any, limit: int = PREVIEW_LENGTH) -> str:
    """Aperçu ``repr`` sur une ligne, tronqué à ``limit`` caractères."""
    try:
        text = _REPR.repr(_sanitize(value))
    except Exception as exc:  # un __repr__ défaillant ne doit pas casser l'audit
        text = f"<repr impossible : {type(exc).__name__}>"
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def describe_variable(name: str, value: Any) -> VariableInfo:
    """Décrit une variable (valeur masquée si son nom est sensible)."""
    masked = is_sensitive(name)
    try:
        size = sys.getsizeof(value)
    except TypeError:
        size = -1
    return VariableInfo(
        name=name,
        type=type(value).__name__,
        size_bytes=size,
        preview=MASK if masked else preview(value),
        masked=masked,
    )


def inspect_scope(
    scope: Mapping[str, Any],
    *,
    exclude_dunders: bool = True,
    exclude_modules: bool = True,
) -> list[VariableInfo]:
    """Décrit toutes les variables d'un espace de noms (triées par nom)."""
    infos: list[VariableInfo] = []
    for name, value in sorted(scope.items()):
        if exclude_dunders and name.startswith("__") and name.endswith("__"):
            continue
        if exclude_modules and inspect.ismodule(value):
            continue
        infos.append(describe_variable(name, value))
    return infos


def audit_scope(
    local_vars: Mapping[str, Any] | None = None,
    *,
    global_vars: Mapping[str, Any] | None = None,
    exclude_dunders: bool = True,
    exclude_modules: bool = True,
) -> dict[str, Any]:
    """Inspecte ``locals()`` de l'appelant, son propre ``locals()`` et ``globals()``.

    Args:
        local_vars: ``locals()`` de l'appelant (``audit_scope(locals())``).
        global_vars: ``globals()`` à inspecter (défaut : celui de ce module).
        exclude_dunders: ignorer les noms ``__xxx__``.
        exclude_modules: ignorer les modules importés.

    Returns:
        Dictionnaire JSON-sérialisable : métadonnées, synthèse et variables.
    """
    caller_scope: Mapping[str, Any] = local_vars if local_vars is not None else {}
    global_scope: Mapping[str, Any] = (
        global_vars if global_vars is not None else globals()
    )
    own_scope = dict(locals())  # locals() de audit_scope elle-même
    options = {"exclude_dunders": exclude_dunders, "exclude_modules": exclude_modules}
    scopes = {
        "caller_locals": inspect_scope(caller_scope, **options),
        "audit_locals": inspect_scope(own_scope, **options),
        "globals": inspect_scope(global_scope, **options),
    }
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "python": sys.version.split()[0],
        "options": options,
        "summary": {
            name: {
                "variables": len(infos),
                "total_size_bytes": sum(max(info["size_bytes"], 0) for info in infos),
                "masked": sum(info["masked"] for info in infos),
            }
            for name, infos in scopes.items()
        },
        "scopes": scopes,
    }


def export_audit(audit: Mapping[str, Any], output_dir: Path) -> Path:
    """Écrit l'audit dans ``output_dir/audit_<horodatage>.json``.

    Raises:
        AuditError: écriture impossible.
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"audit_{stamp}.json"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(audit, handle, indent=2, ensure_ascii=False, default=str)
    except OSError as exc:
        raise AuditError(f"impossible d'écrire l'audit {path} : {exc}") from exc
    return path


def format_audit_table(audit: Mapping[str, Any], max_rows: int = 30) -> str:
    """Tableau texte de l'audit (une section par espace de noms)."""
    lines: list[str] = []
    header = f"{'variable':<26} {'type':<18} {'taille (o)':>10}  aperçu"
    for scope_name, infos in audit["scopes"].items():
        summary = audit["summary"][scope_name]
        size = f"{summary['total_size_bytes']:,}".replace(",", " ")
        lines.append(
            f"--- {scope_name} : {summary['variables']} variable(s), "
            f"{size} o, {summary['masked']} masquée(s)"
        )
        lines.append(header)
        for info in infos[:max_rows]:
            lines.append(
                f"{info['name'][:26]:<26} {info['type'][:18]:<18} "
                f"{info['size_bytes']:>10}  {info['preview'][:60]}"
            )
        if len(infos) > max_rows:
            lines.append(f"... {len(infos) - max_rows} autre(s) variable(s)")
    return "\n".join(lines)
