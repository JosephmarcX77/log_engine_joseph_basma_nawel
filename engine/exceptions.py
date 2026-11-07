"""Exceptions personnalisées du moteur.

Hiérarchie ::

    LogEngineError                 (racine : attrapée par main.py -> code 1)
    ├── ConfigurationError         paramètre invalide (seuil négatif, ...)
    ├── LogSourceError             source de logs illisible / introuvable
    ├── LogParseError              ligne de log invalide (non fatale)
    ├── RuleError                  problème de règle de sécurité
    │   └── RuleExecutionError     une règle a levé une exception
    ├── ReportError                échec d'écriture du rapport
    └── AuditError                 échec de l'audit d'introspection
"""

from __future__ import annotations

from pathlib import Path


class LogEngineError(Exception):
    """Racine de toutes les erreurs métier du moteur."""


class ConfigurationError(LogEngineError):
    """Paramètre de configuration invalide."""


class LogSourceError(LogEngineError):
    """Une source de logs ne peut pas être ouverte ou lue."""

    def __init__(self, path: Path, reason: str) -> None:
        """Mémorise le chemin fautif et la raison de l'échec."""
        super().__init__(f"Source de logs inaccessible '{path}' : {reason}")
        self.path = path
        self.reason = reason


class LogParseError(LogEngineError):
    """Une ligne de log ne respecte pas le format attendu.

    Cette erreur est *non fatale* : ``parse_stream`` la compte et passe à la
    ligne suivante sans interrompre le pipeline.
    """

    def __init__(self, message: str, *, reason: str = "invalid", raw: str = "") -> None:
        """Mémorise la catégorie d'erreur (``reason``) et la ligne brute."""
        super().__init__(message)
        self.reason = reason
        self.raw = raw


class RuleError(LogEngineError):
    """Règle de sécurité mal définie ou mal configurée."""


class RuleExecutionError(RuleError):
    """Une règle de sécurité a échoué pendant son exécution."""

    def __init__(self, rule_name: str, original: Exception) -> None:
        """Encapsule l'exception d'origine levée par la règle ``rule_name``."""
        super().__init__(
            f"La règle '{rule_name}' a échoué : {type(original).__name__}: {original}"
        )
        self.rule_name = rule_name
        self.original = original


class ReportError(LogEngineError):
    """Le rapport ne peut pas être produit ou écrit."""


class AuditError(LogEngineError):
    """L'audit d'introspection ne peut pas être produit ou exporté."""
