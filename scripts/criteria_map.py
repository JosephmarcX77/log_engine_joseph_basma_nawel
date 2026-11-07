"""Correspondance barème -> emplacement dans le code (fichier, fonction, ligne).

Chaque construction imposée est retrouvée DYNAMIQUEMENT par introspection
(``inspect.getsourcelines``) : le tableau reste exact même si le code évolue.
Si une construction disparaît, ``locate`` lève une erreur.

Usage ::

    python scripts/criteria_map.py          # affiche le tableau Markdown
"""

from __future__ import annotations

import inspect
import io
import sys
from pathlib import Path
from typing import Any, NamedTuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:  # exécution directe du script
    sys.path.insert(0, str(PROJECT_ROOT))

import main  # noqa: E402
from engine import (  # noqa: E402
    analytics,
    audit,
    detection,
    exceptions,
    ingestion,
    models,
    parsing,
    pipeline,
    rules,
)


PIPE = "\\|"  # « | » échappé : sinon il couperait la cellule du tableau Markdown


class Criterion(NamedTuple):
    """Une construction imposée et l'objet Python où la chercher."""

    label: str
    target: Any
    needle: str


CRITERIA: tuple[Criterion, ...] = (
    Criterion("`yield` (générateur)", ingestion.read_log_file, "yield line"),
    Criterion("`yield from`", ingestion.read_multiple_sources, "yield from"),
    Criterion("`with` (fermeture garantie)", ingestion.read_log_file, "with handle:"),
    Criterion("dict typé `LogRecord` (TypedDict)", models, "class _LogRecordRequired"),
    Criterion("tuple `(IP, Port, Protocole)`", models, "ConnectionMeta = tuple"),
    Criterion("construction du tuple", parsing.parse_connection, "ConnectionMeta = ("),
    Criterion("`map(str.strip, ...)`", pipeline.strip_lines, "map(str.strip"),
    Criterion("`filter(None, ...)`", pipeline.drop_empty, "return filter(None"),
    Criterion("`filter(lambda ...)` x3", pipeline.build_pipeline, "filter(lambda"),
    Criterion("`map(normalize_record)`", pipeline.build_pipeline, "map(normalize_"),
    Criterion("`map(lambda ...)`", analytics.collect_error_ips, "map(lambda"),
    Criterion("fonctions passées en argument", pipeline.build_filters, "*predicates"),
    Criterion("f-strings (format)", pipeline.normalize_record, "[{level:<8}]"),
    Criterion("`match-case`", pipeline.route_entry, "match entry:"),
    Criterion("case `str()`", pipeline.route_entry, "case str() as raw"),
    Criterion(f"case dict + `{PIPE}` + guard", pipeline.route_entry, "if code >= 500"),
    Criterion("case `{..., **rest}`", pipeline.route_entry, "**rest}"),
    Criterion("case tuple", pipeline.route_entry, "case (str(ip), int(port)"),
    Criterion("`set`", analytics.collect_error_ips, "return set("),
    Criterion(
        "set comprehension", analytics.collect_error_ips_comprehension, "return {"
    ),
    Criterion("`frozenset`", analytics.load_blacklist, "return frozenset("),
    Criterion(f"union `{PIPE}`", analytics.compare_ip_sets, '"union": active |'),
    Criterion("intersection `&`", analytics.compare_ip_sets, "active & blacklist,"),
    Criterion("différence `-`", analytics.compare_ip_sets, "active - blacklist,"),
    Criterion("différence sym. `^`", analytics.compare_ip_sets, "active ^ blacklist,"),
    Criterion("`defaultdict(int)`", analytics.count_by_level, "= defaultdict(int)"),
    Criterion("`defaultdict(list)`", analytics.group_events_by_ip, "defaultdict(list)"),
    Criterion(
        "`defaultdict(lambda: defaultdict(int))`",
        analytics.count_user_levels,
        "lambda: defaultdict(int)\n",
    ),
    Criterion("agrégation une passe", analytics.StreamAggregator, "def update"),
    Criterion("`for`", detection.detect_brute_force, "for ip, raw_events in"),
    Criterion("`while`", detection.detect_brute_force, "while index < len(events)"),
    Criterion("`continue`", detection.detect_brute_force, "continue  # CONTINUE"),
    Criterion("`break` (succès)", detection.detect_brute_force, "login_success i"),
    Criterion("`break` (seuil atteint)", detection.detect_brute_force, "seuil atteint"),
    Criterion("`else` de boucle", detection.detect_brute_force, "else:\n"),
    Criterion("`*args, **kwargs`", rules.apply_security_rules, "*args: RuleFunc"),
    Criterion("`callable()`", rules.apply_security_rules, "if not callable(rule)"),
    Criterion("`inspect.signature`", rules.select_kwargs, "inspect.signature"),
    Criterion("registre + décorateur", rules.register_rule, "RULE_REGISTRY[func"),
    Criterion("fonction -> fonction", rules.make_threshold_rule, "return threshold_r"),
    Criterion("`globals()`", audit.audit_scope, "else globals()"),
    Criterion("`locals()` (propre)", audit.audit_scope, "dict(locals())"),
    Criterion("`audit_scope(locals())`", main.cmd_run, "audit_scope(locals()"),
    Criterion("exceptions personnalisées", exceptions, "class LogParseError"),
    Criterion("levée d'exception", parsing.parse_line, "raise LogParseError("),
    Criterion("capture sans arrêt", parsing.parse_stream, "except LogParseError"),
    Criterion("typage (`TypedDict`, alias)", models, "Predicate = Callable"),
)


def locate(target: Any, needle: str) -> tuple[str, str, int]:
    """Retourne ``(fichier relatif, objet, ligne)`` de la 1re occurrence de ``needle``.

    Raises:
        LookupError: ``needle`` est introuvable dans le source de ``target``.
    """
    lines, start = inspect.getsourcelines(target)
    start = max(start, 1)
    source_file = inspect.getsourcefile(target) or ""
    relative = Path(source_file).resolve().relative_to(PROJECT_ROOT).as_posix()
    name = getattr(target, "__qualname__", getattr(target, "__name__", "?"))
    if inspect.ismodule(target):
        name = "(module)"
    for offset, line in enumerate(lines):
        if needle in line:
            return relative, name, start + offset
    raise LookupError(f"{needle!r} introuvable dans {relative}:{name}")


def build_rows() -> list[tuple[str, str, str, int]]:
    """Lignes ``(critère, fichier, fonction, ligne)`` du tableau."""
    return [(c.label, *locate(c.target, c.needle)) for c in CRITERIA]


def build_markdown() -> str:
    """Tableau Markdown complet."""
    rows = ["| Critère | Fichier | Fonction / objet | Ligne |", "|---|---|---|---|"]
    rows.extend(
        f"| {label} | `{path}` | `{name}` | {line} |"
        for label, path, name, line in build_rows()
    )
    return "\n".join(rows)


if __name__ == "__main__":
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    print(build_markdown())
