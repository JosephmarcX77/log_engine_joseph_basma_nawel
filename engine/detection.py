"""MODULE 3 — Force brute : ``for`` + ``while`` + ``break`` / ``continue`` / ``else``.

Algorithme (fenêtre glissante, par IP) ::

    POUR chaque IP (for)
        index <- 0
        TANT QUE index < nb_événements (while)       <- fenêtre glissante
            si l'événement n'est pas un login_failed : index++ ; CONTINUE
            POUR chaque événement de la fenêtre (for imbriqué)
                pas une tentative de connexion   -> CONTINUE
                hors fenêtre temporelle          -> BREAK
                login_success                    -> BREAK (séquence interrompue)
                sinon                            -> échec compté
            si échecs >= seuil : alerte ; BREAK  (attaque confirmée)
            index <- position suivante (glissement ou saut après le succès)
        SINON (else du while, exécuté seulement SANS break)
            cycle de détection complet : aucune attaque pour cette IP
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from engine.config import (
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS,
    LOGIN_EVENTS,
    LOGIN_FAILED,
    LOGIN_SUCCESS,
)
from engine.exceptions import ConfigurationError
from engine.models import Alert, SecurityEvent

BRUTE_FORCE_RULE = "brute_force"


@dataclass
class DetectionTrace:
    """Trace facultative de la détection (pour le rapport et les tests)."""

    clean_ips: set[str] = field(default_factory=set)  # branche ``else`` atteinte
    interrupted_sequences: int = 0  # ``break`` sur login_success
    windows_scanned: int = 0


def validate_detection_parameters(threshold: int, window_seconds: float) -> None:
    """Vérifie les paramètres de détection.

    Raises:
        ConfigurationError: seuil < 1 ou fenêtre <= 0.
    """
    if threshold < 1:
        raise ConfigurationError(f"le seuil doit être >= 1 (reçu {threshold})")
    if window_seconds <= 0:
        raise ConfigurationError(f"la fenêtre doit être > 0 s (reçu {window_seconds})")


def detect_brute_force(
    events_by_ip: Mapping[str, Sequence[SecurityEvent]],
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    *,
    blacklist: frozenset[str] = frozenset(),
    trace: DetectionTrace | None = None,
) -> list[Alert]:
    """Détecte les IP ayant au moins ``threshold`` échecs de connexion consécutifs.

    « Consécutifs » = sans ``login_success`` intercalé, dans une fenêtre de
    ``window_seconds`` secondes.

    Une seule alerte est produite par IP : dès que le seuil est atteint,
    l'analyse de l'IP s'arrête (``break``). Une IP dont la boucle ``while``
    se termine sans ``break`` exécute la clause ``else`` : son cycle de
    détection est complet et aucune attaque n'a été trouvée.

    Args:
        events_by_ip: événements de sécurité groupés par IP.
        threshold: nombre d'échecs déclenchant l'alerte.
        window_seconds: taille de la fenêtre glissante, mesurée depuis le
            premier échec de la fenêtre.
        blacklist: IP blacklistées (marquage et sévérité de l'alerte).
        trace: si fourni, reçoit les IP « propres » et des statistiques.

    Raises:
        ConfigurationError: paramètres invalides.
    """
    validate_detection_parameters(threshold, window_seconds)
    alerts: list[Alert] = []

    # BOUCLE FOR : une itération par adresse IP
    for ip, raw_events in events_by_ip.items():
        events = sorted(raw_events, key=lambda event: event.timestamp)
        index = 0

        # BOUCLE WHILE : avance le point de départ de la fenêtre glissante
        while index < len(events):
            start = events[index]
            if start.event != LOGIN_FAILED:
                index += 1
                continue  # CONTINUE : une fenêtre ne s'ouvre que sur un échec

            failures = 0
            last_failure = start
            resume = index + 1  # par défaut : la fenêtre glisse d'un événement
            if trace is not None:
                trace.windows_scanned += 1

            # BOUCLE FOR imbriquée : parcours des événements de la fenêtre
            for position in range(index, len(events)):
                event = events[position]
                if event.event not in LOGIN_EVENTS:
                    continue  # CONTINUE : pas une tentative de connexion
                elapsed = (event.timestamp - start.timestamp).total_seconds()
                if elapsed > window_seconds:
                    break  # BREAK : on sort de la fenêtre temporelle
                if event.event == LOGIN_SUCCESS:
                    resume = position + 1  # on reprend APRÈS le succès
                    if trace is not None:
                        trace.interrupted_sequences += 1
                    break  # BREAK : un login_success interrompt la séquence
                failures += 1
                last_failure = event

            if failures >= threshold:
                blacklisted = ip in blacklist
                alerts.append(
                    Alert(
                        rule=BRUTE_FORCE_RULE,
                        ip=ip,
                        count=failures,
                        start=start.timestamp,
                        end=last_failure.timestamp,
                        blacklisted=blacklisted,
                        user_id=start.user_id,
                        severity="CRITICAL" if blacklisted else "HIGH",
                        message=(
                            f"{failures} échecs de connexion consécutifs en "
                            f"{(last_failure.timestamp - start.timestamp).seconds} s "
                            f"(cible : {start.user_id})"
                        ),
                    )
                )
                break  # BREAK : seuil atteint -> attaque confirmée, IP suivante
            index = resume
        else:
            # ELSE de la boucle WHILE : exécuté UNIQUEMENT si aucun ``break`` n'a
            # eu lieu, c.-à-d. si tous les événements de l'IP ont été analysés
            # sans atteindre le seuil -> « cycle de détection complet, aucune
            # attaque ».
            if trace is not None:
                trace.clean_ips.add(ip)

    # tri chronologique (les dates ISO se trient comme des chaînes)
    return sorted(alerts, key=lambda alert: (str(alert.start), alert.ip))
