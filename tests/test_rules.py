"""Tests du MODULE 4 — moteur de règles (*args, **kwargs, fonctions objets)."""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from engine.analytics import StreamAggregator, load_blacklist
from engine.config import DEFAULT_BLACKLIST
from engine.exceptions import RuleError
from engine.ingestion import discover_sources
from engine.models import Alert, RuleContext, SecurityEvent
from engine.pipeline import build_pipeline
from engine.rules import (
    RULE_REGISTRY,
    apply_security_rules,
    get_rule,
    make_threshold_rule,
    register_rule,
    rule_blacklisted_ip_active,
    rule_brute_force,
    rule_critical_burst,
    rule_privilege_escalation,
    rule_suspicious_user,
    select_kwargs,
)

T0 = datetime(2026, 11, 7, 10, 0)


@pytest.fixture
def context() -> RuleContext:
    """Contexte minimal couvrant toutes les règles intégrées."""
    user_levels: defaultdict[str, defaultdict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    user_levels["admin"].update({"ERROR": 18, "INFO": 2})
    user_levels["alice"].update({"INFO": 40, "ERROR": 2})
    critical = {T0 + timedelta(minutes=m): 4 for m in range(3)}  # 12 en 3 min
    critical[T0 + timedelta(hours=2)] = 1
    events = [
        SecurityEvent(T0 + timedelta(seconds=s), "login_failed", "root", "203.0.113.9")
        for s in range(6)
    ]
    return {
        "seen_ips": {"203.0.113.9", "10.0.0.1"},
        "blacklist": frozenset({"203.0.113.9", "198.51.100.1"}),
        "ip_counts": {"203.0.113.9": 6, "10.0.0.1": 3},
        "events_by_ip": {"203.0.113.9": events},
        "critical_by_minute": critical,
        "user_level_counts": user_levels,
        "escalations": {
            "eve": [(T0, T0 + timedelta(seconds=30), "10.0.0.5")],
            "dan": [(T0, T0 + timedelta(seconds=600), "10.0.0.6")],
        },
    }


def test_builtin_rules_are_registered() -> None:
    """Le décorateur ``@register_rule`` stocke les fonctions dans un dict."""
    for name in (
        "rule_blacklisted_ip_active",
        "rule_brute_force",
        "rule_critical_burst",
        "rule_suspicious_user",
        "rule_privilege_escalation",
    ):
        assert callable(RULE_REGISTRY[name])
    assert get_rule("rule_brute_force") is rule_brute_force
    with pytest.raises(RuleError):
        get_rule("rule_unknown")


def test_register_rule_returns_the_function_itself() -> None:
    """Le décorateur retourne la fonction (objet de première classe) inchangée."""

    def rule_temp(context: RuleContext) -> list[Alert]:
        return []

    try:
        assert register_rule(rule_temp) is rule_temp
        assert RULE_REGISTRY["rule_temp"] is rule_temp
    finally:
        del RULE_REGISTRY["rule_temp"]


def test_each_rule(context: RuleContext) -> None:
    """Chaque règle intégrée produit les alertes attendues."""
    assert [a.ip for a in rule_blacklisted_ip_active(context)] == ["203.0.113.9"]
    assert [a.count for a in rule_brute_force(context)] == [6]
    assert rule_brute_force(context, threshold=10) == []
    bursts = rule_critical_burst(context, critical_limit=10)
    assert [(a.count, a.start) for a in bursts] == [(12, T0)]
    assert [a.user_id for a in rule_suspicious_user(context)] == ["admin"]
    assert [a.user_id for a in rule_privilege_escalation(context)] == ["eve"]
    wide = rule_privilege_escalation(context, escalation_window=900)
    assert [a.user_id for a in wide] == ["dan", "eve"]


def test_brute_force_rule_reads_streaming_alerts(context: RuleContext) -> None:
    """Sans ``events_by_ip``, la règle reprend les alertes calculées en flux."""
    alert = Alert(rule="brute_force", ip="1.2.3.4", count=7)
    assert rule_brute_force({"brute_force_alerts": [alert]}) == [alert]
    assert rule_brute_force({"brute_force_alerts": [alert]}, threshold=8) == []
    with pytest.raises(RuleError):
        rule_brute_force({})


def test_make_threshold_rule_returns_a_function(context: RuleContext) -> None:
    """Fonction d'ordre supérieur : la règle retournée est une closure nommée."""
    rule = make_threshold_rule("error", 10)
    assert callable(rule) and rule.__name__ == "rule_error_over_10"
    assert [a.user_id for a in rule(context, anything="ignored")] == ["admin"]
    with pytest.raises(RuleError):
        make_threshold_rule("LOUD", 1)


def test_select_kwargs_uses_signature() -> None:
    """Seuls les kwargs déclarés sont injectés ; ``**config`` reçoit tout."""
    config = {"threshold": 3, "critical_limit": 2, "unused": True}
    assert select_kwargs(rule_brute_force, config) == {"threshold": 3}
    assert select_kwargs(make_threshold_rule("INFO", 1), config) == config
    assert select_kwargs(len, config) == {}


def test_apply_security_rules_variable_rules_and_kwargs(context: RuleContext) -> None:
    """Nombre variable de règles (*args) et configuration dynamique (**kwargs)."""
    one = apply_security_rules(rule_brute_force, context=context, threshold=5)
    assert list(one) == ["rule_brute_force"]
    three = apply_security_rules(
        rule_brute_force,
        rule_critical_burst,
        make_threshold_rule("ERROR", 1),
        context=context,
        threshold=100,  # injecté seulement dans rule_brute_force
        critical_limit=20,  # injecté seulement dans rule_critical_burst
    )
    assert list(three) == [
        "rule_brute_force",
        "rule_critical_burst",
        "rule_error_over_1",
    ]
    assert three["rule_brute_force"] == [] and three["rule_critical_burst"] == []
    assert [a.user_id for a in three["rule_error_over_1"]] == ["admin", "alice"]
    assert three.total_alerts == 2 and three.errors == {}


def test_apply_security_rules_defaults_to_registry(context: RuleContext) -> None:
    """Sans règle explicite, toutes les règles enregistrées sont appliquées."""
    report = apply_security_rules(context=context)
    assert set(report) == set(RULE_REGISTRY)
    by_name = apply_security_rules("rule_suspicious_user", context=context)
    assert list(by_name) == ["rule_suspicious_user"]


def test_failing_rule_does_not_stop_the_others(
    context: RuleContext, caplog: pytest.LogCaptureFixture
) -> None:
    """Une règle qui plante est capturée ; les suivantes s'exécutent."""

    def rule_broken(ctx: RuleContext) -> list[Alert]:
        raise ZeroDivisionError("division by zero")

    with caplog.at_level(logging.ERROR):
        report = apply_security_rules(
            rule_broken,
            rule_suspicious_user,
            42,  # type: ignore[arg-type]
            context=context,
        )
    assert report["rule_broken"] == []
    assert "ZeroDivisionError" in report.errors["rule_broken"]
    assert len(report["rule_suspicious_user"]) == 1
    assert "42" in report.errors  # objet non appelable : ignoré et signalé
    assert "rule_broken" in caplog.text


def test_stop_on_first(context: RuleContext) -> None:
    """``stop_on_first=True`` arrête après la première règle qui alerte."""
    report = apply_security_rules(
        rule_blacklisted_ip_active,
        rule_brute_force,
        context=context,
        stop_on_first=True,
    )
    assert list(report) == ["rule_blacklisted_ip_active"]


def test_missing_context_is_an_error() -> None:
    """``context`` est obligatoire."""
    with pytest.raises(RuleError):
        apply_security_rules(rule_brute_force)


def test_rules_on_samples(samples_dir: Path, ground_truth: dict[str, Any]) -> None:
    """Sur les échantillons : rafales et escalades injectées sont détectées."""
    aggregator = StreamAggregator(blacklist=load_blacklist(DEFAULT_BLACKLIST))
    aggregator.consume(build_pipeline(discover_sources(samples_dir)))
    report = apply_security_rules(context=aggregator.context())
    assert len(report["rule_brute_force"]) == len(ground_truth["expected_alerts"])
    blacklisted = {a.ip for a in report["rule_blacklisted_ip_active"]}
    expected_active = set(ground_truth["blacklist"]["attackers"]) | set(
        ground_truth["blacklist"]["active_normal"]
    )
    assert blacklisted == expected_active
    assert not blacklisted & set(ground_truth["blacklist"]["dormant"])
    escalated = {a.user_id for a in report["rule_privilege_escalation"]}
    assert {e["user"] for e in ground_truth["escalations"]} <= escalated
    bursts = report["rule_critical_burst"]
    for injected in ground_truth["critical_bursts"]:
        start = datetime.fromisoformat(injected["start"])
        assert any(a.start and a.end and a.start <= start <= a.end for a in bursts)
    suspicious = {a.user_id for a in report["rule_suspicious_user"]}
    assert suspicious and suspicious <= {"admin", "root", "oracle", "postgres", "test"}
