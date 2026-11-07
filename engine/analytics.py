"""MODULE 3 — Agrégation : ensembles (``set`` / ``frozenset``) et ``defaultdict``.

Deux familles de fonctions :

* des fonctions unitaires (``collect_error_ips``, ``count_by_level``, ...)
  qui consomment un itérable — pratiques pour les tests et le notebook ;
* ``StreamAggregator``, qui met à jour TOUS les indicateurs en **une seule
  passe** : le flux du pipeline est un générateur, consommable une seule
  fois, il ne doit donc pas être reparcouru.

Pourquoi aucune ``KeyError`` n'est possible : un ``defaultdict(int)`` appelle
``int()`` (-> 0) pour toute clé absente, un ``defaultdict(list)`` appelle
``list()`` (-> ``[]``), et ``defaultdict(lambda: defaultdict(int))`` crée à la
volée un sous-compteur pour chaque nouvel utilisateur. ``counts[k] += 1``
fonctionne donc dès la première occurrence de ``k``, sans test préalable.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from datetime import datetime
from pathlib import Path

from engine.config import (
    CONFIG_CHANGE,
    DEFAULT_ESCALATION_WINDOW,
    DEFAULT_THRESHOLD,
    DEFAULT_WINDOW_SECONDS,
    ERROR_LEVELS,
    LOGIN_EVENTS,
    MAX_ESCALATIONS_PER_USER,
    PERMISSION_DENIED,
    TOP_N,
)
from engine.detection import (
    DetectionTrace,
    detect_brute_force,
    validate_detection_parameters,
)
from engine.ingestion import read_log_file
from engine.models import Alert, LogRecord, RuleContext, SecurityEvent
from engine.parsing import clean_ip, is_valid_ip

logger = logging.getLogger(__name__)

# Fréquence (en enregistrements) du balayage des tampons de connexion inactifs
SWEEP_INTERVAL = 1_000
# (horodatage du permission_denied, horodatage du config_change, ip)
Escalation = tuple[datetime, datetime, str]


# --------------------------------------------------------------------------
# Ensembles
# --------------------------------------------------------------------------
def collect_error_ips(records: Iterable[LogRecord]) -> set[str]:
    """``set`` des IP ayant généré au moins un ERROR ou CRITICAL.

    Version fonctionnelle : ``filter(lambda)`` sélectionne les erreurs,
    ``map(lambda)`` extrait l'IP, ``set`` supprime les doublons.
    """
    return set(
        map(lambda r: r["ip"], filter(lambda r: r["level"] in ERROR_LEVELS, records))
    )


def collect_error_ips_comprehension(records: Iterable[LogRecord]) -> set[str]:
    """Même résultat que ``collect_error_ips`` avec une *set comprehension*."""
    return {record["ip"] for record in records if record["level"] in ERROR_LEVELS}


def _iter_blacklist(path: Path) -> Iterator[str]:
    """Produit les IP valides d'un fichier de blacklist (lecture en streaming)."""
    for line in read_log_file(path):
        entry = line.split("#", 1)[0].strip()  # commentaires et blancs ignorés
        if not entry:
            continue
        if not is_valid_ip(entry):
            logger.warning("Blacklist %s : entrée invalide ignorée %r", path, entry)
            continue
        yield clean_ip(entry)


def load_blacklist(path: Path) -> frozenset[str]:
    """Charge la blacklist dans un ``frozenset`` IMMUABLE.

    Un ``frozenset`` ne possède ni ``add`` ni ``discard`` : la liste de
    référence ne peut pas être altérée par erreur pendant l'analyse, et elle
    est hachable (utilisable comme clé de dict ou élément d'un autre set).

    Raises:
        LogSourceError: fichier introuvable ou illisible.
    """
    return frozenset(_iter_blacklist(path))


def compare_ip_sets(
    active: set[str], blacklist: frozenset[str]
) -> dict[str, set[str]]:
    """Compare les IP actives (en erreur) à la blacklist (opérateurs d'ensembles).

    Interprétation métier :

    * ``active | blacklist`` (**union**) : périmètre complet de surveillance,
      toutes les IP qui méritent l'attention de l'équipe sécurité ;
    * ``active & blacklist`` (**intersection**) : IP blacklistées ET actives
      -> **ALERTE**, une source connue comme malveillante est en action ;
    * ``active - blacklist`` (**différence**) : IP en erreur inconnues de la
      blacklist -> à investiguer, candidates à l'ajout ;
    * ``blacklist - active`` (**différence**) : IP blacklistées dormantes ->
      aucune activité suspecte observée, entrées à revoir / nettoyer ;
    * ``active ^ blacklist`` (**différence symétrique**) : IP dont le statut
      est incohérent (actives non listées OU listées non actives).
    """
    return {
        "union": active | blacklist,
        "blacklisted_active": active & blacklist,
        "active_not_blacklisted": active - blacklist,
        "blacklisted_dormant": set(blacklist - active),
        "symmetric_difference": active ^ blacklist,
    }


# --------------------------------------------------------------------------
# Accumulation dynamique (defaultdict)
# --------------------------------------------------------------------------
def count_by_level(records: Iterable[LogRecord]) -> defaultdict[str, int]:
    """Compte les enregistrements par niveau avec ``defaultdict(int)``."""
    counts: defaultdict[str, int] = defaultdict(int)
    for record in records:
        counts[record["level"]] += 1  # clé absente -> int() == 0, pas de KeyError
    return counts


def count_by_user(records: Iterable[LogRecord]) -> defaultdict[str, int]:
    """Compte les enregistrements par utilisateur avec ``defaultdict(int)``."""
    counts: defaultdict[str, int] = defaultdict(int)
    for record in records:
        counts[record["user_id"]] += 1
    return counts


def count_user_levels(
    records: Iterable[LogRecord],
) -> defaultdict[str, defaultdict[str, int]]:
    """Comptage croisé utilisateur x niveau.

    Structure : ``defaultdict(lambda: defaultdict(int))``.
    """
    counts: defaultdict[str, defaultdict[str, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    for record in records:
        counts[record["user_id"]][record["level"]] += 1  # 2 niveaux créés à la volée
    return counts


def to_security_event(record: LogRecord) -> SecurityEvent | None:
    """Extrait un ``SecurityEvent`` d'un enregistrement JSON portant un ``event``."""
    payload = record["payload"]
    if not isinstance(payload, dict):
        return None
    event = payload.get("event")
    if not isinstance(event, str):
        return None
    return SecurityEvent(record["timestamp"], event, record["user_id"], record["ip"])


def group_events_by_ip(
    records: Iterable[LogRecord],
) -> defaultdict[str, list[SecurityEvent]]:
    """Regroupe les événements de sécurité par IP avec ``defaultdict(list)``."""
    groups: defaultdict[str, list[SecurityEvent]] = defaultdict(list)
    for record in records:
        event = to_security_event(record)
        if event is not None:
            groups[event.ip].append(event)  # clé absente -> list() == []
    return groups


def top_items(counts: Mapping[str, int], n: int = TOP_N) -> list[tuple[str, int]]:
    """Les ``n`` clés les plus fréquentes (tri décroissant, puis alphabétique)."""
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:n]


# --------------------------------------------------------------------------
# Agrégation en une seule passe
# --------------------------------------------------------------------------
class StreamAggregator:
    """Met à jour sets et ``defaultdict`` à CHAQUE enregistrement (une passe).

    Mémoire bornée : les compteurs dépendent du nombre d'IP / utilisateurs /
    niveaux / heures distincts, jamais du nombre de lignes. Pour la force
    brute, seuls les événements de connexion « récents » de chaque IP sont
    tamponnés dans ``events_by_ip`` : dès qu'un écart supérieur à la fenêtre
    sépare deux tentatives d'une IP (ou que l'IP est inactive depuis plus
    d'une fenêtre, cf. ``_sweep``), aucune fenêtre ne peut plus les réunir.
    Le tampon est alors analysé par ``detect_brute_force`` puis libéré
    (résultat identique à une analyse globale, mais en mémoire bornée).
    """

    def __init__(
        self,
        *,
        blacklist: frozenset[str] = frozenset(),
        threshold: int = DEFAULT_THRESHOLD,
        window_seconds: int = DEFAULT_WINDOW_SECONDS,
        escalation_window: int = DEFAULT_ESCALATION_WINDOW,
    ) -> None:
        """Initialise des accumulateurs vides.

        Raises:
            ConfigurationError: paramètres de détection invalides.
        """
        validate_detection_parameters(threshold, window_seconds)
        self.blacklist = blacklist
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.escalation_window = escalation_window
        self.total_records = 0
        # --- defaultdict(int) : compteurs simples
        self.level_counts: defaultdict[str, int] = defaultdict(int)
        self.user_counts: defaultdict[str, int] = defaultdict(int)
        self.ip_counts: defaultdict[str, int] = defaultdict(int)
        self.route_counts: defaultdict[str, int] = defaultdict(int)
        self.format_counts: defaultdict[str, int] = defaultdict(int)
        self.event_counts: defaultdict[str, int] = defaultdict(int)
        self.hourly_counts: defaultdict[datetime, int] = defaultdict(int)
        self.critical_by_minute: defaultdict[datetime, int] = defaultdict(int)
        # --- defaultdict imbriqué : utilisateur x niveau
        self.user_level_counts: defaultdict[str, defaultdict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # --- defaultdict(list) : tampons d'événements de connexion par IP
        self.events_by_ip: defaultdict[str, list[SecurityEvent]] = defaultdict(list)
        self.escalations: defaultdict[str, list[Escalation]] = defaultdict(list)
        # --- ensembles
        self.seen_ips: set[str] = set()
        self.error_ips: set[str] = set()
        self.flagged_ips: set[str] = set()
        # --- résultats de détection
        self.brute_force_alerts: list[Alert] = []
        self.detection_trace = DetectionTrace()
        self.first_seen: datetime | None = None
        self.last_seen: datetime | None = None
        self.peak_buffered_events = 0
        self._buffered_events = 0
        self._last_denied: dict[str, datetime] = {}

    # ----------------------------------------------------------- mise à jour
    def update(self, record: LogRecord) -> None:
        """Intègre UN enregistrement dans tous les indicateurs."""
        timestamp = record["timestamp"]
        level = record["level"]
        ip = record["ip"]
        user = record["user_id"]
        self.total_records += 1
        self.level_counts[level] += 1
        self.user_counts[user] += 1
        self.ip_counts[ip] += 1
        self.user_level_counts[user][level] += 1
        self.route_counts[record.get("route", "unrouted")] += 1
        self.format_counts[record["source_format"]] += 1
        self.hourly_counts[timestamp.replace(minute=0, second=0, microsecond=0)] += 1
        self.seen_ips.add(ip)
        if level in ERROR_LEVELS:
            self.error_ips.add(ip)
        if level == "CRITICAL":
            self.critical_by_minute[timestamp.replace(second=0, microsecond=0)] += 1
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp
        event = to_security_event(record)
        if event is not None:
            self.event_counts[event.event] += 1
            self._track_security_event(event)
        if self.total_records % SWEEP_INTERVAL == 0:
            self._sweep(timestamp)

    def _track_security_event(self, event: SecurityEvent) -> None:
        """Aiguille un événement vers la force brute ou l'escalade de privilèges."""
        if event.event in LOGIN_EVENTS:
            self._buffer_login(event)
        elif event.event == PERMISSION_DENIED:
            self._last_denied[event.user_id] = event.timestamp
        elif event.event == CONFIG_CHANGE:
            self._check_escalation(event)

    def _buffer_login(self, event: SecurityEvent) -> None:
        """Tamponne une tentative de connexion ; analyse le tampon s'il est clos."""
        ip = event.ip
        if ip in self.flagged_ips:
            return  # IP déjà en alerte : son analyse est terminée (break)
        buffer = self.events_by_ip.get(ip)
        if buffer:
            gap = (event.timestamp - buffer[-1].timestamp).total_seconds()
            if gap > self.window_seconds or gap < 0:
                self._flush(ip)
        self.events_by_ip[ip].append(event)
        self._buffered_events += 1
        self.peak_buffered_events = max(
            self.peak_buffered_events, self._buffered_events
        )

    def _sweep(self, now: datetime) -> None:
        """Analyse et libère les tampons inactifs depuis plus d'une fenêtre.

        Le flux étant chronologique, toute tentative future d'une telle IP
        arrivera avec un écart > fenêtre : le tampon est donc déjà clos. Ce
        balayage borne la mémoire au nombre d'IP actives dans la dernière
        fenêtre (et émet les alertes au fil de l'eau, sans attendre la fin).
        """
        stale = [
            ip
            for ip, events in self.events_by_ip.items()
            if (now - events[-1].timestamp).total_seconds() > self.window_seconds
        ]
        for ip in stale:
            self._flush(ip)

    def _flush(self, ip: str) -> None:
        """Analyse puis libère le tampon de connexions d'une IP."""
        events = self.events_by_ip.pop(ip, [])
        self._buffered_events -= len(events)
        alerts = detect_brute_force(
            {ip: events},
            self.threshold,
            self.window_seconds,
            blacklist=self.blacklist,
            trace=self.detection_trace,
        )
        if alerts:
            self.brute_force_alerts.extend(alerts)
            self.flagged_ips.add(ip)

    def _check_escalation(self, event: SecurityEvent) -> None:
        """Repère un ``config_change`` survenant peu après un ``permission_denied``."""
        denied_at = self._last_denied.pop(event.user_id, None)
        if denied_at is None:
            return
        delay = (event.timestamp - denied_at).total_seconds()
        if not 0 <= delay <= self.escalation_window:
            return
        occurrences = self.escalations[event.user_id]  # defaultdict(list)
        if len(occurrences) < MAX_ESCALATIONS_PER_USER:  # borne mémoire
            occurrences.append((denied_at, event.timestamp, event.ip))

    # ------------------------------------------------------------- résultats
    def consume(self, records: Iterable[LogRecord]) -> StreamAggregator:
        """Consomme tout le flux (une seule passe) puis finalise l'agrégation."""
        for record in records:
            self.update(record)
        return self.finalize()

    def finalize(self) -> StreamAggregator:
        """Analyse les tampons de connexion restants (fin de flux)."""
        for ip in list(self.events_by_ip):
            self._flush(ip)
        self.brute_force_alerts.sort(key=lambda alert: (str(alert.start), alert.ip))
        return self

    @property
    def clean_ips(self) -> set[str]:
        """IP analysées dont le cycle de détection s'est terminé sans attaque."""
        return self.detection_trace.clean_ips - self.flagged_ips

    def top_users(self, n: int = TOP_N) -> list[tuple[str, int]]:
        """Les ``n`` utilisateurs les plus actifs."""
        return top_items(self.user_counts, n)

    def ip_sets(self) -> dict[str, set[str]]:
        """Opérations d'ensembles entre IP en erreur et blacklist."""
        return compare_ip_sets(self.error_ips, self.blacklist)

    def context(self) -> RuleContext:
        """Contexte transmis aux règles de sécurité (``rules.py``)."""
        return {
            "seen_ips": self.seen_ips,
            "error_ips": self.error_ips,
            "blacklist": self.blacklist,
            "brute_force_alerts": self.brute_force_alerts,
            "critical_by_minute": self.critical_by_minute,
            "user_level_counts": self.user_level_counts,
            "escalations": self.escalations,
            "level_counts": self.level_counts,
            "ip_counts": self.ip_counts,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }
