"""Export des résultats : rapport JSON complet (signé HMAC) et synthèse console.

Le rapport JSON est signé avec HMAC-SHA256 (secret lu dans la variable
d'environnement ``LOG_ENGINE_SECRET``) : toute modification ultérieure du
fichier est détectable avec ``verify_signature``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from engine.analytics import StreamAggregator, top_items
from engine.config import ENGINE_VERSION, LEVELS, TOP_N
from engine.exceptions import ReportError
from engine.models import Alert, PipelineStats
from engine.rules import RulesReport

SIGNATURE_ALGORITHM = "HMAC-SHA256"
RULE = "=" * 88
SUBRULE = "-" * 88
IP_SET_LABELS: tuple[tuple[str, str, str], ...] = (
    ("union", "active | blacklist", "union : périmètre de surveillance"),
    ("blacklisted_active", "active & blacklist", "blacklistées ACTIVES -> ALERTE"),
    ("active_not_blacklisted", "active - blacklist", "inconnues -> à investiguer"),
    ("blacklisted_dormant", "blacklist - active", "blacklistées dormantes"),
    ("symmetric_difference", "active ^ blacklist", "statut incohérent (diff. sym.)"),
)


def to_jsonable(value: Any) -> Any:
    """Convertit récursivement une valeur en types JSON natifs."""
    if isinstance(value, Alert):
        return value.to_dict()
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (set, frozenset)):
        return sorted(to_jsonable(item) for item in value)
    if isinstance(value, Mapping):
        return {str(to_jsonable(key)): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def fmt_int(number: int) -> str:
    """Entier avec espace comme séparateur de milliers (``30 000``)."""
    return f"{number:,}".replace(",", " ")


def build_report(
    *,
    stats: PipelineStats,
    aggregator: StreamAggregator,
    rules_report: RulesReport,
    sources: Sequence[Path],
    parameters: Mapping[str, Any],
    duration_seconds: float,
) -> dict[str, Any]:
    """Assemble le rapport complet (dictionnaire JSON-sérialisable)."""
    ip_sets = aggregator.ip_sets()
    levels = {level: aggregator.level_counts.get(level, 0) for level in LEVELS}
    throughput = stats.lines_read / duration_seconds if duration_seconds > 0 else 0.0
    trace = aggregator.detection_trace
    report: dict[str, Any] = {
        "meta": {
            "engine_version": ENGINE_VERSION,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "duration_seconds": round(duration_seconds, 3),
            "lines_per_second": round(throughput),
            "sources": [str(path) for path in sources],
            "period": {"start": aggregator.first_seen, "end": aggregator.last_seen},
            "parameters": dict(parameters),
        },
        "ingestion": stats.as_dict(),
        "levels": levels,
        "formats": dict(aggregator.format_counts),
        "routes": dict(sorted(aggregator.route_counts.items())),
        "events": dict(sorted(aggregator.event_counts.items())),
        "top_users": [
            {"user": user, "count": count}
            for user, count in aggregator.top_users(TOP_N)
        ],
        "top_ips": [
            {"ip": ip, "count": count}
            for ip, count in top_items(aggregator.ip_counts, TOP_N)
        ],
        "hourly": dict(sorted(aggregator.hourly_counts.items())),
        "ip_sets": {
            name: {"count": len(ips), "ips": ips} for name, ips in ip_sets.items()
        },
        "brute_force": {
            "count": len(aggregator.brute_force_alerts),
            "alerts": aggregator.brute_force_alerts,
            "interrupted_sequences": trace.interrupted_sequences,
            "clean_ips": len(aggregator.clean_ips),
            "windows_scanned": trace.windows_scanned,
            "peak_buffered_events": aggregator.peak_buffered_events,
        },
        "rules": rules_report.to_dict(),
    }
    jsonable: dict[str, Any] = to_jsonable(report)
    return jsonable


def _canonical(report: Mapping[str, Any]) -> bytes:
    """Sérialisation canonique (clés triées) hors signature."""
    payload = {key: value for key, value in report.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")


def sign_report(report: Mapping[str, Any], secret: str) -> dict[str, str]:
    """Calcule la signature HMAC-SHA256 du rapport."""
    digest = hmac.new(secret.encode("utf-8"), _canonical(report), hashlib.sha256)
    return {"algorithm": SIGNATURE_ALGORITHM, "value": digest.hexdigest()}


def verify_signature(report: Mapping[str, Any], secret: str) -> bool:
    """Vérifie (en temps constant) que le rapport n'a pas été altéré."""
    signature = report.get("signature", {})
    expected = sign_report(report, secret)["value"]
    return hmac.compare_digest(str(signature.get("value", "")), expected)


def write_json_report(report: Mapping[str, Any], output_dir: Path) -> Path:
    """Écrit le rapport dans ``output_dir/report_<horodatage>.json``.

    Raises:
        ReportError: écriture impossible.
    """
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = output_dir / f"report_{stamp}.json"
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
    except OSError as exc:
        raise ReportError(f"impossible d'écrire le rapport {path} : {exc}") from exc
    return path


# --------------------------------------------------------------------------
# Rendu console
# --------------------------------------------------------------------------
def _bar(value: int, total: int, width: int = 30) -> str:
    """Barre horizontale proportionnelle (caractères ASCII)."""
    filled = round(width * value / total) if total else 0
    return "#" * filled


def _wrap_ips(ips: Sequence[str], per_line: int = 4) -> str:
    """IP présentées par groupes de ``per_line`` (indentées)."""
    rows = [ips[index : index + per_line] for index in range(0, len(ips), per_line)]
    return "\n".join("      " + ", ".join(row) for row in rows)


def _section(title: str) -> list[str]:
    """En-tête de section."""
    return ["", title, SUBRULE]


def _alert_lines(alerts: Iterable[Mapping[str, Any]], limit: int) -> list[str]:
    """Lignes de détail des alertes d'une règle (``limit`` premières)."""
    lines: list[str] = []
    for index, alert in enumerate(alerts):
        if index >= limit:
            lines.append("      ...")
            break
        who = alert["ip"] or alert["user_id"]
        if alert["user_id"] and alert["ip"]:
            who = f"{alert['user_id']}@{alert['ip']}"
        when = f" [{alert['start'][:16]}]" if alert["start"] else ""
        lines.append(
            f"      - [{alert['severity']:<8}] {who:<24} {alert['message']}{when}"
        )
    return lines


def render_console(report: Mapping[str, Any], *, max_alerts: int = 60) -> str:
    """Synthèse lisible du rapport pour la console."""
    meta, ingestion = report["meta"], report["ingestion"]
    params = meta["parameters"]
    sources = meta["sources"]
    names = ", ".join(Path(source).name for source in sources[:4])
    if len(sources) > 4:
        names += ", ..."
    lines = [
        RULE,
        f"  LOG ENGINE v{meta['engine_version']} — rapport d'analyse de sécurité",
        RULE,
        f"Sources     : {len(sources)} fichier(s) [{names}]",
        f"Période     : {meta['period']['start']}  ->  {meta['period']['end']}",
        f"Durée       : {meta['duration_seconds']:.2f} s "
        f"({fmt_int(meta['lines_per_second'])} lignes/s)",
        f"Paramètres  : seuil={params['threshold']} échecs, "
        f"fenêtre={params['window_seconds']} s, "
        f"CRITICAL max={params['critical_limit']}/{params['period_minutes']} min",
    ]

    lines += _section("[1] INGESTION")
    reasons = ", ".join(f"{k}: {v}" for k, v in ingestion["errors_by_reason"].items())
    filtered = ", ".join(f"{k}: {v}" for k, v in ingestion["filtered_by"].items() if v)
    lines += [
        f"  Lignes lues ................ {fmt_int(ingestion['lines_read']):>10}",
        f"  Lignes vides (filter None) . {fmt_int(ingestion['empty_lines']):>10}",
        f"  Erreurs de parsing ......... {fmt_int(ingestion['parse_errors']):>10}"
        f"   ({reasons or 'aucune'})",
        f"  Écartées par les lambdas ... {fmt_int(ingestion['filtered_out']):>10}"
        f"   ({filtered or 'aucune'})",
        f"  Total rejetées ............. {fmt_int(ingestion['rejected']):>10}",
        f"  Enregistrements valides .... {fmt_int(ingestion['valid_records']):>10}",
    ]

    lines += _section("[2] RÉPARTITION PAR NIVEAU")
    total = sum(report["levels"].values())
    for level, count in report["levels"].items():
        share = 100 * count / total if total else 0.0
        lines.append(
            f"  {level:<9} {fmt_int(count):>9}  {share:5.1f} %  {_bar(count, total)}"
        )

    lines += _section(f"[3] TOP {len(report['top_users'])} UTILISATEURS")
    for rank, entry in enumerate(report["top_users"], start=1):
        lines.append(f"  {rank:>2}. {entry['user']:<12} {fmt_int(entry['count']):>8}")

    lines += _section("[4] ENSEMBLES D'IP  (active = IP ayant généré ERROR/CRITICAL)")
    for key, operator, label in IP_SET_LABELS:
        entry = report["ip_sets"][key]
        detail = ""
        if key in ("blacklisted_active", "blacklisted_dormant"):
            detail = "\n" + _wrap_ips(entry["ips"][:12])
        lines.append(f"  {operator:<19} {entry['count']:>5}  {label}{detail}")

    brute = report["brute_force"]
    lines += _section(
        f"[5] FORCE BRUTE (>= {params['threshold']} échecs consécutifs "
        f"en {params['window_seconds']} s) : {brute['count']} alerte(s)"
    )
    lines.append(
        f"  {'IP':<16} {'échecs':>6}  {'début':<19}  {'fin':<8}  {'durée':>6}"
        f"  {'cible':<9} blacklist"
    )
    for index, alert in enumerate(brute["alerts"]):
        if index >= max_alerts:
            lines.append(f"  ... {brute['count'] - max_alerts} autre(s)")
            break
        lines.append(
            f"  {alert['ip']:<16} {alert['count']:>6}  {alert['start']:<19}  "
            f"{alert['end'][11:]:<8}  {alert['duration_seconds']:>5.0f}s"
            f"  {alert['user_id']:<9} {'OUI' if alert['blacklisted'] else '-'}"
        )
    lines.append(
        f"  Séquences interrompues par login_success : {brute['interrupted_sequences']}"
        f" | IP au cycle complet sans attaque (else) : {brute['clean_ips']}"
    )

    rules = report["rules"]
    lines += _section(f"[6] RÈGLES DE SÉCURITÉ : {rules['total_alerts']} alerte(s)")
    for name, outcome in rules["rules"].items():
        status = f"{outcome['count']} alerte(s)"
        if name in rules["errors"]:
            status = "ERREUR"
        lines.append(f"  {name:<32} {status}")
        if name != "rule_brute_force":
            lines += _alert_lines(outcome["alerts"], limit=5)
    for name, error in rules["errors"].items():
        lines.append(f"  !! {name} : {error}")
    lines.append(RULE)
    return "\n".join(lines)
