"""MODULE 4 — Moteur de règles : fonctions de première classe, ``*args`` / ``**kwargs``.

Une règle de sécurité est une **fonction simple** de signature commune ::

    regle(context: dict, *, <paramètres nommés avec valeurs par défaut>) -> list[Alert]

Les fonctions sont des objets comme les autres : elles sont **stockées** dans
un registre (dict ``{nom: fonction}``) par le décorateur ``@register_rule``,
**passées en argument** à ``apply_security_rules(*args, **kwargs)`` et
**retournées** par une fonction d'ordre supérieur (``make_threshold_rule``).
"""

from __future__ import annotations

import inspect
import logging
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta
from typing import Any, TypeVar

from engine.config import (
    DEFAULT_CRITICAL_LIMIT,
    DEFAULT_CRITICAL_PERIOD_MINUTES,
    DEFAULT_ERROR_RATIO,
    DEFAULT_ESCALATION_WINDOW,
    DEFAULT_MIN_USER_EVENTS,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS,
    ERROR_LEVELS,
    VALID_LEVELS,
)
from engine.detection import detect_brute_force
from engine.exceptions import RuleError, RuleExecutionError
from engine.models import Alert, RuleContext, RuleFunc

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., list[Alert]])

# Registre des règles : les fonctions y sont stockées comme des valeurs.
RULE_REGISTRY: dict[str, RuleFunc] = {}


def register_rule(func: F) -> F:
    """Décorateur : enregistre ``func`` dans ``RULE_REGISTRY`` et la retourne.

    Raises:
        RuleError: l'objet décoré n'est pas appelable.
    """
    if not callable(func):
        raise RuleError(f"une règle doit être appelable : {func!r}")
    RULE_REGISTRY[func.__name__] = func
    return func


def get_rule(name: str) -> RuleFunc:
    """Retourne la règle enregistrée sous ``name``.

    Raises:
        RuleError: règle inconnue.
    """
    try:
        return RULE_REGISTRY[name]
    except KeyError as exc:
        known = ", ".join(sorted(RULE_REGISTRY))
        raise RuleError(f"règle inconnue {name!r} (connues : {known})") from exc


class RulesReport(dict[str, list[Alert]]):
    """Rapport ``{nom_de_règle: alertes}`` + erreurs des règles qui ont échoué."""

    def __init__(self) -> None:
        """Crée un rapport vide."""
        super().__init__()
        self.errors: dict[str, str] = {}

    @property
    def total_alerts(self) -> int:
        """Nombre total d'alertes, toutes règles confondues."""
        return sum(len(alerts) for alerts in self.values())

    def to_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable."""
        return {
            "total_alerts": self.total_alerts,
            "rules": {
                name: {"count": len(alerts), "alerts": [a.to_dict() for a in alerts]}
                for name, alerts in self.items()
            },
            "errors": dict(self.errors),
        }


# --------------------------------------------------------------------------
# Règles de sécurité (fonctions simples, enregistrées par décorateur)
# --------------------------------------------------------------------------
@register_rule
def rule_blacklisted_ip_active(
    context: RuleContext, *, blacklist: frozenset[str] | None = None
) -> list[Alert]:
    """Alerte pour chaque IP blacklistée observée dans les logs (``&``)."""
    reference: frozenset[str] = (
        blacklist if blacklist is not None else context.get("blacklist", frozenset())
    )
    seen: set[str] = context["seen_ips"]
    activity: Mapping[str, int] = context.get("ip_counts", {})
    return [
        Alert(
            rule="blacklisted_ip_active",
            ip=ip,
            count=activity.get(ip, 1),
            blacklisted=True,
            severity="CRITICAL",
            message=f"IP blacklistée active ({activity.get(ip, 1)} événement(s))",
        )
        for ip in sorted(seen & reference)
    ]


@register_rule
def rule_brute_force(
    context: RuleContext,
    *,
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    blacklist: frozenset[str] | None = None,
) -> list[Alert]:
    """Force brute : relance la détection, ou reprend les alertes du streaming.

    * contexte « brut » (``events_by_ip``) -> ``detect_brute_force`` complet ;
    * contexte issu de ``StreamAggregator`` (``brute_force_alerts``) -> les
      alertes déjà calculées en flux, filtrées sur le seuil demandé.
    """
    reference = blacklist if blacklist is not None else context.get("blacklist")
    match context:
        case {"events_by_ip": Mapping() as events_by_ip}:
            return detect_brute_force(
                events_by_ip,
                threshold,
                window_seconds,
                blacklist=reference or frozenset(),
            )
        case {"brute_force_alerts": list() as alerts}:
            return [alert for alert in alerts if alert.count >= threshold]
        case _:
            raise RuleError("contexte sans données de connexion pour la force brute")


@register_rule
def rule_critical_burst(
    context: RuleContext,
    *,
    critical_limit: int = DEFAULT_CRITICAL_LIMIT,
    period_minutes: int = DEFAULT_CRITICAL_PERIOD_MINUTES,
) -> list[Alert]:
    """Rafale : plus de ``critical_limit`` CRITICAL sur ``period_minutes`` minutes.

    Fenêtre glissante sur les compteurs par minute ; les fenêtres qui se
    chevauchent sont fusionnées en une seule alerte (pic = maximum observé).
    """
    per_minute: Mapping[datetime, int] = context["critical_by_minute"]
    minutes = sorted(per_minute)
    period = timedelta(minutes=period_minutes)
    alerts: list[Alert] = []
    burst: list[Any] | None = None  # [début, fin, pic]
    left = 0
    total = 0
    for minute in minutes:
        total += per_minute[minute]
        while minute - minutes[left] >= period:  # la fenêtre glisse
            total -= per_minute[minutes[left]]
            left += 1
        if total <= critical_limit:
            continue
        if burst is not None and minutes[left] <= burst[1]:
            burst[1], burst[2] = minute, max(burst[2], total)  # chevauchement
            continue
        if burst is not None:
            alerts.append(_burst_alert(burst, critical_limit, period_minutes))
        burst = [minutes[left], minute, total]
    if burst is not None:
        alerts.append(_burst_alert(burst, critical_limit, period_minutes))
    return alerts


def _burst_alert(burst: list[Any], limit: int, period_minutes: int) -> Alert:
    """Construit l'alerte d'une rafale ``[début, fin, pic]``."""
    start, end, peak = burst
    return Alert(
        rule="critical_burst",
        ip="*",
        count=peak,
        start=start,
        end=end + timedelta(seconds=59),
        severity="CRITICAL",
        message=f"{peak} CRITICAL en moins de {period_minutes} min (limite {limit})",
    )


@register_rule
def rule_suspicious_user(
    context: RuleContext,
    *,
    error_ratio: float = DEFAULT_ERROR_RATIO,
    min_events: int = DEFAULT_MIN_USER_EVENTS,
) -> list[Alert]:
    """Utilisateur dont la part d'ERROR/CRITICAL dépasse ``error_ratio``."""
    alerts: list[Alert] = []
    user_levels: Mapping[str, Mapping[str, int]] = context["user_level_counts"]
    for user, levels in sorted(user_levels.items()):
        total = sum(levels.values())
        errors = sum(levels.get(level, 0) for level in ERROR_LEVELS)
        if total < min_events or errors / total < error_ratio:
            continue
        alerts.append(
            Alert(
                rule="suspicious_user",
                ip="",
                count=errors,
                user_id=user,
                severity="MEDIUM",
                message=f"{errors}/{total} événements en erreur ({errors / total:.0%})",
            )
        )
    return alerts


@register_rule
def rule_privilege_escalation(
    context: RuleContext, *, escalation_window: int = DEFAULT_ESCALATION_WINDOW
) -> list[Alert]:
    """``permission_denied`` suivi d'un ``config_change`` du même utilisateur."""
    alerts: list[Alert] = []
    escalations: Mapping[str, list[tuple[datetime, datetime, str]]] = context[
        "escalations"
    ]
    for user, occurrences in sorted(escalations.items()):
        hits = [
            (denied, changed, ip)
            for denied, changed, ip in occurrences
            if (changed - denied).total_seconds() <= escalation_window
        ]
        if not hits:
            continue
        first, last = hits[0], hits[-1]
        alerts.append(
            Alert(
                rule="privilege_escalation",
                ip=first[2],
                count=len(hits),
                start=first[0],
                end=last[1],
                user_id=user,
                severity="HIGH",
                message=(
                    f"config_change {(first[1] - first[0]).seconds} s après un "
                    f"permission_denied ({len(hits)} occurrence(s))"
                ),
            )
        )
    return alerts


def make_threshold_rule(level: str, limit: int) -> RuleFunc:
    """Fonction d'ordre supérieur : RETOURNE une nouvelle règle (closure).

    La règle produite alerte sur chaque utilisateur ayant plus de ``limit``
    événements de niveau ``level``. Elle accepte ``**config`` : le moteur lui
    transmet donc toute la configuration (qu'elle ignore).

    Raises:
        RuleError: niveau inconnu ou limite négative.
    """
    wanted = level.strip().upper()
    if wanted not in VALID_LEVELS or limit < 0:
        raise RuleError(f"paramètres invalides : level={level!r}, limit={limit}")

    def threshold_rule(context: RuleContext, **config: Any) -> list[Alert]:
        """Règle générée par ``make_threshold_rule``."""
        user_levels: Mapping[str, Mapping[str, int]] = context["user_level_counts"]
        return [
            Alert(
                rule=f"{wanted.lower()}_over_{limit}",
                ip="",
                count=levels.get(wanted, 0),
                user_id=user,
                severity="LOW",
                message=f"{levels.get(wanted, 0)} événements {wanted} (> {limit})",
            )
            for user, levels in sorted(user_levels.items())
            if levels.get(wanted, 0) > limit
        ]

    threshold_rule.__name__ = f"rule_{wanted.lower()}_over_{limit}"
    threshold_rule.__qualname__ = threshold_rule.__name__
    return threshold_rule


# --------------------------------------------------------------------------
# Fonction maître
# --------------------------------------------------------------------------
def select_kwargs(
    func: Callable[..., Any], config: Mapping[str, Any]
) -> dict[str, Any]:
    """Ne garde que les paramètres nommés acceptés par ``func`` (``inspect``).

    Si ``func`` déclare ``**kwargs``, toute la configuration lui est transmise.
    """
    try:
        parameters = inspect.signature(func).parameters
    except (TypeError, ValueError):  # objet appelable sans signature lisible
        return {}
    if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        return dict(config)
    accepted = (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    return {
        name: value
        for name, value in config.items()
        if name in parameters and parameters[name].kind in accepted
    }


def _resolve_rule(candidate: RuleFunc | str) -> RuleFunc | str:
    """Un nom de règle est remplacé par la fonction enregistrée (si elle existe)."""
    if isinstance(candidate, str):
        return RULE_REGISTRY.get(candidate, candidate)
    return candidate


def apply_security_rules(*args: RuleFunc | str, **kwargs: Any) -> RulesReport:
    """Exécute un nombre variable de règles avec une configuration dynamique.

    Args:
        *args: les règles à appliquer (fonctions, objets de première classe),
            ou leurs noms dans le registre. Sans argument : toutes les règles
            enregistrées.
        **kwargs: configuration dynamique. Clés réservées :
            ``context`` (obligatoire, dict de données agrégées) et
            ``stop_on_first`` (arrêt à la première règle qui alerte). Les
            autres clés (``threshold=5``, ``window_seconds=60``,
            ``critical_limit=10``, ...) ne sont injectées qu'aux règles qui
            les déclarent.

    Returns:
        ``RulesReport`` : ``{rule.__name__: [alertes]}`` + ``errors``.

    Raises:
        RuleError: ``context`` absent ou invalide.
    """
    context = kwargs.pop("context", None)
    if not isinstance(context, dict):
        raise RuleError("apply_security_rules exige context=<dict>")
    stop_on_first = bool(kwargs.pop("stop_on_first", False))
    rules: tuple[RuleFunc | str, ...] = args if args else tuple(RULE_REGISTRY.values())
    report = RulesReport()

    for candidate in rules:
        rule = _resolve_rule(candidate)
        if not callable(rule):  # vérification explicite : objet appelable ?
            report.errors[repr(candidate)] = "objet non appelable (règle ignorée)"
            logger.warning("Règle ignorée, objet non appelable : %r", candidate)
            continue
        name = getattr(rule, "__name__", type(rule).__name__)
        options = select_kwargs(rule, kwargs)
        try:
            alerts = rule(context, **options)
        except Exception as exc:  # une règle défaillante n'arrête pas les autres
            error = RuleExecutionError(name, exc)
            logger.error("%s", error)
            report.errors[name] = str(error)
            report[name] = []
            continue
        report[name] = list(alerts)
        logger.debug("Règle %s : %d alerte(s) (options %s)", name, len(alerts), options)
        if stop_on_first and alerts:
            logger.info("stop_on_first : arrêt après %s", name)
            break
    return report
