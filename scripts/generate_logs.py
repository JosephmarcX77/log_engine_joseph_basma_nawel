"""Générateur de jeux de données de logs synthétiques, réalistes et déterministes.

Usage ::

    python scripts/generate_logs.py                      # 3 fichiers x 10 000 lignes
    python scripts/generate_logs.py --files 5 --lines 50000 --seed 7
    python scripts/generate_logs.py --big                # 1 fichier de 2 000 000 lignes

Trois formats de lignes sont mélangés (séparateur `` | ``) :

1. JSON structuré (~60 %) ::

       2026-11-07T10:15:32 | ERROR | 192.168.1.45 | user_042 | {"event": ...}

2. Texte brut (~30 %) ::

       2026-11-07T10:15:33 | INFO | 10.0.0.12 | user_007 | GET /index.html 200

3. Connexion (~10 %) ::

       2026-11-07T10:15:34 | WARNING | 172.16.0.8 | user_013 | CONN 172.16.0.8:443/TCP

Les fichiers sont écrits EN STREAMING : chaque ligne est formatée puis écrite
immédiatement, aucune liste de lignes n'est construite en mémoire. Seules de
petites structures bornées sont conservées : la file de priorité des
événements d'attaque à venir (quelques dizaines d'éléments), des compteurs et
la vérité terrain (une entrée par séquence d'attaque).

Les séquences d'attaque sont *entrelacées* avec le trafic normal (comme dans
de vrais logs) grâce à une file de priorité ``heapq`` ordonnée par horodatage :
les horodatages restent croissants dans chaque fichier.
"""

from __future__ import annotations

import argparse
import heapq
import io
import json
import math
import random
import sys
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from itertools import accumulate
from pathlib import Path
from typing import Any, Callable, TextIO

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "samples"
DEFAULT_BIG_DIR = PROJECT_ROOT / "data" / "big"
DEFAULT_BLACKLIST = PROJECT_ROOT / "data" / "blacklist.txt"
GROUND_TRUTH_NAME = "ground_truth.json"
BIG_LINES = 2_000_000
LAST_DAY = date(2026, 11, 7)

SEPARATOR = " | "
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"
NULL_TIMESTAMP = "1970-01-01T00:00:00"

# Paramètres de détection pour lesquels la vérité terrain est calculée
# (identiques aux valeurs par défaut du moteur, cf. engine/config.py).
DETECTION_THRESHOLD = 5
DETECTION_WINDOW_SECONDS = 60

# --- Profil journalier : poids relatif du trafic pour chaque heure (0h -> 23h)
HOURLY_WEIGHTS: tuple[int, ...] = (
    2, 1, 1, 1, 1, 2, 4, 7, 10, 12, 12, 11, 9, 11, 12, 12, 11, 9, 7, 6, 5, 4, 3, 2,
)
HOURLY_CUM: tuple[int, ...] = tuple(accumulate(HOURLY_WEIGHTS))

# --- Utilisateurs : popularité décroissante (loi de type Zipf)
USER_COUNT = 50
USER_CUM_WEIGHTS: tuple[float, ...] = tuple(
    accumulate(1.0 / (rank**0.8) for rank in range(1, USER_COUNT + 1))
)
ATTACK_TARGETS: tuple[str, ...] = ("admin", "root", "oracle", "postgres", "test")

# --- Événements JSON et leurs poids
JSON_EVENTS: tuple[str, ...] = (
    "login_success",
    "login_failed",
    "file_access",
    "permission_denied",
    "config_change",
    "service_crash",
)
JSON_EVENT_CUM: tuple[float, ...] = tuple(accumulate((26, 5, 50, 2, 2, 1.5)))
FILES: tuple[str, ...] = (
    "/srv/data/report.csv",
    "/etc/passwd",
    "/home/shared/budget.xlsx",
    "/var/www/index.html",
    "/opt/app/config.yaml",
)
SERVICES: tuple[str, ...] = ("nginx", "payment-api", "auth-service", "postgres")
SETTINGS: tuple[str, ...] = ("firewall", "sudoers", "ssh_config", "cron", "dns")

# --- Format texte (requêtes HTTP)
HTTP_METHODS: tuple[str, ...] = ("GET", "POST", "PUT", "DELETE")
HTTP_METHOD_CUM: tuple[float, ...] = tuple(accumulate((70, 20, 6, 4)))
HTTP_PATHS: tuple[str, ...] = (
    "/index.html",
    "/login",
    "/api/v1/users",
    "/api/v1/orders",
    "/static/app.js",
    "/admin",
    "/health",
    "/search?q=logs",
    "/download/report.pdf",
)
HTTP_STATUSES: tuple[int, ...] = (
    200, 201, 204, 301, 304, 400, 401, 403, 404, 500, 502, 503,
)
HTTP_STATUS_CUM: tuple[float, ...] = tuple(
    accumulate((60, 5, 3, 4, 6, 3, 2, 2, 8, 3, 2, 2))
)

# --- Format connexion : (port, protocole, poids)
CONNECTION_TARGETS: tuple[tuple[int, str], ...] = (
    (443, "TCP"),
    (80, "TCP"),
    (22, "TCP"),
    (53, "UDP"),
    (3306, "TCP"),
    (5432, "TCP"),
    (8080, "TCP"),
    (123, "UDP"),
    (3389, "TCP"),
    (21, "TCP"),
)
CONNECTION_CUM: tuple[float, ...] = tuple(
    accumulate((30, 15, 12, 12, 8, 6, 8, 4, 3, 2))
)
SENSITIVE_PORTS = frozenset({21, 23, 3389})

# --- Bruit : (type, poids). Les types de VALID_NOISE restent des lignes valides
# une fois normalisées (casse, espaces), les autres doivent être rejetées.
NOISE_KINDS: tuple[str, ...] = (
    "empty",
    "whitespace",
    "truncated",
    "invalid_json",
    "unknown_level",
    "bad_ip",
    "null_timestamp",
    "level_case",
    "extra_spaces",
    "user_case",
)
NOISE_CUM: tuple[float, ...] = tuple(accumulate((3, 2, 3, 3, 2, 2, 1, 3, 3, 1)))
EMPTY_NOISE = frozenset({"empty", "whitespace"})
VALID_NOISE = frozenset({"level_case", "extra_spaces", "user_case"})
BAD_IPS: tuple[str, ...] = (
    "999.1.1", "256.12.0.1", "10.0.0", "192.168.1.300", "abc.d.e.f",
)

# --- Attaques
INTERRUPTED_SHARE = 0.25  # part des séquences interrompues par un login_success
BLACKLISTED_ATTACK_SHARE = 0.15  # part des séquences menées depuis une IP blacklistée
# Longueur moyenne d'une séquence (complète : 8.5 lignes, interrompue : 6.5 lignes)
MEAN_ATTACK_LENGTH = (1 - INTERRUPTED_SHARE) * 8.5 + INTERRUPTED_SHARE * 6.5
ATTACK_MARGIN = 40  # pas de nouvelle attaque dans les dernières lignes du fichier
BURST_SIZE = 15  # nombre de CRITICAL injectés en rafale (une rafale par fichier)
ESCALATIONS_PER_FILE = 2

# Entrée de la file de priorité : (offset_s, numéro, niveau, ip, utilisateur, payload)
PendingEvent = tuple[float, int, str, str, str, str]


@dataclass(frozen=True)
class GeneratorConfig:
    """Paramètres d'une génération de jeu de données."""

    output_dir: Path = DEFAULT_OUTPUT_DIR
    files: int = 3
    lines: int = 10_000
    seed: int = 42
    attack_ratio: float = 0.02
    noise_ratio: float = 0.03
    blacklist_path: Path = DEFAULT_BLACKLIST
    file_prefix: str = "server"

    def validate(self) -> None:
        """Vérifie la cohérence des paramètres, lève ``ValueError`` sinon."""
        if self.files < 1:
            raise ValueError("--files doit être >= 1")
        if self.lines < 1:
            raise ValueError("--lines doit être >= 1")
        if not 0.0 <= self.attack_ratio < 0.5:
            raise ValueError("--attack-ratio doit être dans [0, 0.5[")
        if not 0.0 <= self.noise_ratio < 0.5:
            raise ValueError("--noise-ratio doit être dans [0, 0.5[")


@dataclass(frozen=True)
class IpPools:
    """Réservoirs d'IP et d'utilisateurs, dérivés uniquement de la graine."""

    normal: tuple[str, ...]
    attackers: tuple[str, ...]
    blacklisted_attackers: tuple[str, ...]
    blacklisted_normal: tuple[str, ...]
    dormant: tuple[str, ...]
    users: tuple[str, ...]

    @property
    def blacklist(self) -> tuple[str, ...]:
        """Toutes les IP blacklistées (attaquantes, actives normales, dormantes)."""
        return self.blacklisted_attackers + self.blacklisted_normal + self.dormant


@dataclass
class GroundTruth:
    """Vérité terrain accumulée pendant la génération (structures bornées)."""

    config: GeneratorConfig
    pools: IpPools
    files: list[dict[str, Any]] = field(default_factory=list)
    noise: Counter[str] = field(default_factory=Counter)
    level_counts: Counter[str] = field(default_factory=Counter)
    attacks: list[dict[str, Any]] = field(default_factory=list)
    bursts: list[dict[str, Any]] = field(default_factory=list)
    escalations: list[dict[str, Any]] = field(default_factory=list)

    def expected_alerts(self) -> list[dict[str, Any]]:
        """Première séquence complète de chaque IP = alerte attendue du moteur.

        Le moteur arrête l'analyse d'une IP dès la première attaque confirmée
        (``break``) : une seule alerte par IP est donc attendue.
        """
        expected: dict[str, dict[str, Any]] = {}
        for attack in self.attacks:
            if attack["kind"] == "full" and attack["ip"] not in expected:
                expected[attack["ip"]] = {
                    "ip": attack["ip"],
                    "failures": attack["failures"],
                    "start": attack["start"],
                    "end": attack["end"],
                    "blacklisted": attack["blacklisted"],
                    "file": attack["file"],
                }
        return sorted(expected.values(), key=lambda alert: alert["ip"])

    def to_dict(self) -> dict[str, Any]:
        """Sérialise la vérité terrain en dictionnaire JSON."""
        total = sum(entry["lines"] for entry in self.files)
        empty = sum(self.noise[kind] for kind in EMPTY_NOISE)
        rejected = sum(
            count
            for kind, count in self.noise.items()
            if kind not in EMPTY_NOISE and kind not in VALID_NOISE
        )
        expected = self.expected_alerts()
        alerted = {alert["ip"] for alert in expected}
        interrupted_only = sorted(
            {a["ip"] for a in self.attacks if a["kind"] == "interrupted"} - alerted
        )
        return {
            "generator": {
                "seed": self.config.seed,
                "files": self.config.files,
                "lines_per_file": self.config.lines,
                "attack_ratio": self.config.attack_ratio,
                "noise_ratio": self.config.noise_ratio,
            },
            "detection_parameters": {
                "threshold": DETECTION_THRESHOLD,
                "window_seconds": DETECTION_WINDOW_SECONDS,
            },
            "files": self.files,
            "totals": {
                "lines": total,
                "empty": empty,
                "rejected": rejected,
                "valid": total - empty - rejected,
            },
            "noise": dict(sorted(self.noise.items())),
            "valid_level_counts": dict(sorted(self.level_counts.items())),
            "attack_sequences": {
                "total": len(self.attacks),
                "full": sum(1 for a in self.attacks if a["kind"] == "full"),
                "interrupted": sum(
                    1 for a in self.attacks if a["kind"] == "interrupted"
                ),
            },
            "expected_alerts": expected,
            "interrupted_only_ips": interrupted_only,
            "attacks": self.attacks,
            "critical_bursts": self.bursts,
            "escalations": self.escalations,
            "blacklist": {
                "attackers": list(self.pools.blacklisted_attackers),
                "active_normal": list(self.pools.blacklisted_normal),
                "dormant": list(self.pools.dormant),
            },
        }


def _unique_ip(taken: set[str], factory: Callable[[], str]) -> str:
    """Tire une IP avec ``factory`` jusqu'à en obtenir une jamais utilisée."""
    candidate = factory()
    while candidate in taken:
        candidate = factory()
    taken.add(candidate)
    return candidate


def _public_ip_factory(
    rng: random.Random, first_octets: tuple[int, ...]
) -> Callable[[], str]:
    """Fabrique d'IP publiques dont le premier octet est pris dans ``first_octets``."""

    def factory() -> str:
        return (
            f"{rng.choice(first_octets)}.{rng.randint(0, 255)}."
            f"{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        )

    return factory


def _private_ip_factory(
    rng: random.Random, prefix: str, third_max: int | None
) -> Callable[[], str]:
    """Fabrique d'IP privées ``prefix.x`` (ou ``prefix.y.x`` si ``third_max``)."""

    def factory() -> str:
        if third_max is None:
            return f"{prefix}.{rng.randint(2, 254)}"
        return f"{prefix}.{rng.randint(0, third_max)}.{rng.randint(2, 254)}"

    return factory


def build_ip_pools(seed: int) -> IpPools:
    """Construit les réservoirs d'IP de façon déterministe à partir de ``seed``.

    - ~200 IP « normales » : 170 privées + 30 publiques ;
    - 120 IP attaquantes dédiées + 6 attaquantes blacklistées ;
    - blacklist de 15 IP : 6 attaquantes, 4 normales actives, 5 dormantes.
    """
    rng = random.Random(f"pools-{seed}")
    taken: set[str] = set()
    private: list[str] = []
    ranges: tuple[tuple[str, int, int | None], ...] = (
        ("192.168.1", 60, None),
        ("10.0", 60, 20),
        ("172.16", 50, 31),
    )
    for prefix, count, third_max in ranges:
        private_factory = _private_ip_factory(rng, prefix, third_max)
        private.extend(_unique_ip(taken, private_factory) for _ in range(count))
    public_factory = _public_ip_factory(
        rng, (23, 31, 37, 51, 62, 77, 81, 89, 94, 151, 176)
    )
    public = [_unique_ip(taken, public_factory) for _ in range(30)]
    attack_factory = _public_ip_factory(rng, (5, 45, 91, 103, 185, 194, 222))
    attackers = tuple(_unique_ip(taken, attack_factory) for _ in range(120))
    blacklisted_attackers = tuple(_unique_ip(taken, attack_factory) for _ in range(6))
    dormant_factory = _public_ip_factory(rng, (41, 58, 116, 196))
    dormant = tuple(_unique_ip(taken, dormant_factory) for _ in range(5))
    blacklisted_normal = tuple(rng.sample(public, 4))
    users = [f"user_{index:03d}" for index in range(1, USER_COUNT + 1)]
    rng.shuffle(users)  # ordre de popularité
    return IpPools(
        normal=tuple(private + public),
        attackers=attackers,
        blacklisted_attackers=blacklisted_attackers,
        blacklisted_normal=blacklisted_normal,
        dormant=dormant,
        users=tuple(users),
    )


class AttackerPicker:
    """Distribue les IP attaquantes à tour de rôle (round-robin déterministe).

    Le tourniquet garantit qu'une même IP n'est réutilisée que très longtemps
    après sa séquence précédente : deux séquences d'une même IP ne peuvent pas
    fusionner dans une même fenêtre de détection.
    """

    def __init__(self, pools: IpPools, rng: random.Random) -> None:
        """Initialise le tourniquet sur les réservoirs ``pools``."""
        self._pools = pools
        self._rng = rng
        self._regular = 0
        self._blacklisted = 0

    def next(self) -> tuple[str, bool]:
        """Retourne ``(ip, blacklistée)`` pour la prochaine séquence d'attaque."""
        if self._rng.random() < BLACKLISTED_ATTACK_SHARE:
            pool = self._pools.blacklisted_attackers
            ip = pool[self._blacklisted % len(pool)]
            self._blacklisted += 1
            return ip, True
        pool = self._pools.attackers
        ip = pool[self._regular % len(pool)]
        self._regular += 1
        return ip, False


def slot_offset(fraction: float) -> float:
    """Inverse de la répartition journalière : fraction de [0, 1[ -> secondes.

    Le trafic suit ``HOURLY_WEIGHTS`` (pic en journée, creux la nuit).
    """
    target = fraction * HOURLY_CUM[-1]
    hour = min(bisect_right(HOURLY_CUM, target), 23)
    previous = HOURLY_CUM[hour - 1] if hour else 0
    within = (target - previous) / HOURLY_WEIGHTS[hour]
    return (hour + min(within, 0.9999)) * 3600.0


def _json_payload(data: dict[str, Any]) -> str:
    """Sérialise un payload JSON au format des logs."""
    return json.dumps(data, separators=(", ", ": "))


class FileGenerator:
    """Génère UN fichier de logs, ligne par ligne, directement dans ``handle``."""

    def __init__(
        self,
        *,
        handle: TextIO,
        file_name: str,
        day: date,
        lines: int,
        rng: random.Random,
        pools: IpPools,
        picker: AttackerPicker,
        truth: GroundTruth,
        attack_ratio: float,
        noise_ratio: float,
    ) -> None:
        """Prépare la génération d'un fichier (aucune ligne n'est encore écrite)."""
        self.handle = handle
        self.file_name = file_name
        self.lines = lines
        self.rng = rng
        self.pools = pools
        self.picker = picker
        self.truth = truth
        self.noise_ratio = noise_ratio
        self.start_probability = attack_ratio / MEAN_ATTACK_LENGTH
        self.day_start = datetime.combine(day, datetime.min.time())
        self.pending: list[PendingEvent] = []
        self.sequence = 0
        self.emitted = 0
        if lines >= 100:
            self.burst_slot = rng.randint(lines // 5, 4 * lines // 5)
            self.escalation_slots = frozenset(
                rng.sample(range(lines // 10, 9 * lines // 10), ESCALATIONS_PER_FILE)
            )
        else:  # fichiers minuscules (tests) : pas d'événements spéciaux
            self.burst_slot = -1
            self.escalation_slots = frozenset()

    # ------------------------------------------------------------------ outils
    def _timestamp(self, offset: float) -> str:
        """Convertit un décalage en secondes depuis minuit en horodatage ISO."""
        return (self.day_start + timedelta(seconds=offset)).strftime(TIMESTAMP_FORMAT)

    def _write(self, line: str) -> None:
        """Écrit immédiatement une ligne (écriture en streaming)."""
        self.handle.write(line + "\n")
        self.emitted += 1

    def _push(
        self, offset: float, level: str, ip: str, user: str, payload: str
    ) -> None:
        """Planifie un événement futur dans la file de priorité."""
        self.sequence += 1
        heapq.heappush(self.pending, (offset, self.sequence, level, ip, user, payload))

    def _slot_offset(self, slot: int) -> float:
        """Horodatage (s) du créneau normal ``slot`` : strictement croissant."""
        return slot_offset((slot + self.rng.random()) / self.lines)

    # --------------------------------------------------------- trafic normal
    def _json_fields(self) -> tuple[str, str]:
        """Tire un événement JSON : retourne ``(niveau, payload)``."""
        rng = self.rng
        event = rng.choices(JSON_EVENTS, cum_weights=JSON_EVENT_CUM)[0]
        match event:
            case "login_success":
                port = rng.choice((22, 443, 3389))
                return "INFO", _json_payload(
                    {"event": event, "port": port, "proto": "TCP", "code": 200}
                )
            case "login_failed":
                port = rng.choice((22, 443, 3389))
                return "ERROR", _json_payload(
                    {"event": event, "port": port, "proto": "TCP", "code": 401}
                )
            case "file_access":
                missing = rng.random() < 0.15
                return ("WARNING" if missing else "INFO"), _json_payload(
                    {
                        "event": event,
                        "port": 445,
                        "proto": "TCP",
                        "code": 404 if missing else 200,
                        "path": rng.choice(FILES),
                    }
                )
            case "permission_denied":
                return "WARNING", _json_payload(
                    {"event": event, "port": 445, "proto": "TCP", "code": 403}
                )
            case "config_change":
                level = "WARNING" if rng.random() < 0.3 else "INFO"
                return level, _json_payload(
                    {
                        "event": event,
                        "port": 22,
                        "proto": "TCP",
                        "code": 200,
                        "setting": rng.choice(SETTINGS),
                    }
                )
            case _:  # service_crash
                level = "CRITICAL" if rng.random() < 0.6 else "ERROR"
                return level, _json_payload(
                    {
                        "event": event,
                        "port": 8080,
                        "proto": "TCP",
                        "code": rng.choice((500, 502, 503)),
                        "service": rng.choice(SERVICES),
                    }
                )

    def _normal_fields(self) -> tuple[str, str, str, str, str]:
        """Tire une ligne normale : ``(niveau, ip, utilisateur, payload, format)``."""
        rng = self.rng
        ip = rng.choice(self.pools.normal)
        user = rng.choices(self.pools.users, cum_weights=USER_CUM_WEIGHTS)[0]
        draw = rng.random()
        if draw < 0.60:
            level, payload = self._json_fields()
            return level, ip, user, payload, "json"
        if draw < 0.90:
            method = rng.choices(HTTP_METHODS, cum_weights=HTTP_METHOD_CUM)[0]
            status = rng.choices(HTTP_STATUSES, cum_weights=HTTP_STATUS_CUM)[0]
            level = "ERROR" if status >= 500 else "WARNING" if status >= 400 else "INFO"
            request = f"{method} {rng.choice(HTTP_PATHS)} {status}"
            return level, ip, user, request, "text"
        port, proto = rng.choices(CONNECTION_TARGETS, cum_weights=CONNECTION_CUM)[0]
        level = "WARNING" if port in SENSITIVE_PORTS else "INFO"
        return level, ip, user, f"CONN {ip}:{port}/{proto}", "connection"

    def _write_normal(self, timestamp: str) -> None:
        """Écrit une ligne de trafic normal."""
        level, ip, user, payload, _ = self._normal_fields()
        self._write(SEPARATOR.join((timestamp, level, ip, user, payload)))
        self.truth.level_counts[level] += 1

    # ------------------------------------------------------------------ bruit
    def _write_noise(self, timestamp: str) -> None:
        """Écrit une ligne bruitée (vide, corrompue, ou valide mais mal formatée)."""
        rng = self.rng
        kind = rng.choices(NOISE_KINDS, cum_weights=NOISE_CUM)[0]
        level, ip, user, payload, _ = self._normal_fields()
        fields = [timestamp, level, ip, user, payload]
        match kind:
            case "empty":
                line = ""
            case "whitespace":
                line = rng.choice(("   ", "\t", "  \t  "))
            case "truncated":
                # Coupure AVANT le 4e séparateur : il reste au plus 4 champs.
                full = SEPARATOR.join(fields)
                position = -1
                for _ in range(4):
                    position = full.index(SEPARATOR, position + 1)
                line = full[: rng.randint(1, position)]
            case "invalid_json":
                fields[1], json_text = self._json_fields()
                corruptions = (
                    json_text[: rng.randint(5, len(json_text) - 2)],
                    json_text.replace(", ", " ", 1),
                    json_text.replace('"', "'"),
                    json_text + "}",
                )
                fields[4] = rng.choice(corruptions)
                line = SEPARATOR.join(fields)
            case "unknown_level":
                fields[1] = "DEBUGX"
                line = SEPARATOR.join(fields)
            case "bad_ip":
                fields[2] = rng.choice(BAD_IPS)
                line = SEPARATOR.join(fields)
            case "null_timestamp":
                fields[0] = NULL_TIMESTAMP
                line = SEPARATOR.join(fields)
            case "level_case":
                fields[1] = rng.choice((level.lower(), f" {level.capitalize()} "))
                line = SEPARATOR.join(fields)
            case "extra_spaces":
                separator = rng.choice(("  |  ", " |   ", "   | "))
                line = "  " + separator.join(fields) + "   "
            case _:  # user_case
                fields[3] = user.upper()
                line = SEPARATOR.join(fields)
        self._write(line)
        self.truth.noise[kind] += 1
        if kind in VALID_NOISE:
            self.truth.level_counts[level] += 1

    # ------------------------------------------------- scénarios d'attaque
    def _schedule_attack(self, base: float) -> None:
        """Planifie une séquence de ``login_failed`` consécutifs pour une IP.

        25 % des séquences sont interrompues par un ``login_success`` : 2 à 4
        échecs, un succès, puis 1 à 4 échecs. Aucune des deux parties
        n'atteint le seuil : le moteur NE doit PAS lever d'alerte (alors qu'un
        comptage naïf sans ``break`` dépasserait souvent 5 échecs).
        """
        rng = self.rng
        ip, blacklisted = self.picker.next()
        user = rng.choice(ATTACK_TARGETS)
        interrupted = rng.random() < INTERRUPTED_SHARE
        if interrupted:
            before, after = rng.randint(2, 4), rng.randint(1, 4)
            names = (
                ["login_failed"] * before
                + ["login_success"]
                + ["login_failed"] * after
            )
        else:
            before, after = rng.randint(5, 12), 0
            names = ["login_failed"] * before
        offset = base + rng.uniform(0.5, 3.0)
        failure_offsets: list[float] = []
        for name in names:
            failed = name == "login_failed"
            payload = _json_payload(
                {
                    "event": name,
                    "port": 22,
                    "proto": "TCP",
                    "code": 401 if failed else 200,
                }
            )
            level = "ERROR" if failed else "INFO"
            self._push(offset, level, ip, user, payload)
            self.truth.level_counts[level] += 1
            if failed:
                failure_offsets.append(offset)
            offset += rng.uniform(1.0, 4.0)
        self.truth.attacks.append(
            {
                "ip": ip,
                "kind": "interrupted" if interrupted else "full",
                "failures": before,
                "failures_after_success": after,
                "target_user": user,
                "start": self._timestamp(failure_offsets[0]),
                "end": self._timestamp(failure_offsets[before - 1]),
                "blacklisted": blacklisted,
                "file": self.file_name,
            }
        )

    def _schedule_burst(self, base: float) -> None:
        """Planifie une rafale de CRITICAL (``service_crash``) sur ~2 minutes."""
        rng = self.rng
        offset = base + 1.0
        first = offset
        for _ in range(BURST_SIZE):
            payload = _json_payload(
                {
                    "event": "service_crash",
                    "port": 8080,
                    "proto": "TCP",
                    "code": 503,
                    "service": "payment-api",
                }
            )
            user = rng.choice(self.pools.users)
            self._push(offset, "CRITICAL", rng.choice(self.pools.normal), user, payload)
            self.truth.level_counts["CRITICAL"] += 1
            last = offset
            offset += rng.uniform(3.0, 8.0)
        self.truth.bursts.append(
            {
                "file": self.file_name,
                "start": self._timestamp(first),
                "end": self._timestamp(last),
                "count": BURST_SIZE,
            }
        )

    def _schedule_escalation(self, base: float) -> None:
        """Planifie un ``permission_denied`` suivi d'un ``config_change``."""
        rng = self.rng
        user = rng.choice(self.pools.users[10:])
        ip = rng.choice(self.pools.normal)
        denied_at = base + rng.uniform(1.0, 3.0)
        changed_at = denied_at + rng.uniform(10.0, 60.0)
        denied = {
            "event": "permission_denied",
            "port": 445,
            "proto": "TCP",
            "code": 403,
        }
        changed = {
            "event": "config_change",
            "port": 22,
            "proto": "TCP",
            "code": 200,
            "setting": "sudoers",
        }
        self._push(denied_at, "WARNING", ip, user, _json_payload(denied))
        self._push(changed_at, "WARNING", ip, user, _json_payload(changed))
        self.truth.level_counts["WARNING"] += 2
        self.truth.escalations.append(
            {
                "file": self.file_name,
                "user": user,
                "ip": ip,
                "denied_at": self._timestamp(denied_at),
                "changed_at": self._timestamp(changed_at),
            }
        )

    # ------------------------------------------------------------ boucle
    def run(self) -> int:
        """Écrit le fichier complet et retourne le nombre de lignes écrites.

        Fusion de deux flux triés par horodatage : les créneaux de trafic
        normal (croissants) et la file de priorité des événements planifiés.
        Un événement planifié est écrit dès que son horodatage précède celui
        du prochain créneau normal.
        """
        slot = 0
        next_offset = self._slot_offset(slot)
        while self.emitted < self.lines or self.pending:
            due = self.pending and (
                self.pending[0][0] <= next_offset or self.emitted >= self.lines
            )
            if due:
                offset, _, level, ip, user, payload = heapq.heappop(self.pending)
                stamp = self._timestamp(offset)
                self._write(SEPARATOR.join((stamp, level, ip, user, payload)))
                continue
            if self.emitted >= self.lines:
                break
            timestamp = self._timestamp(next_offset)
            if self.rng.random() < self.noise_ratio:
                self._write_noise(timestamp)
            else:
                self._write_normal(timestamp)
            if (
                self.emitted < self.lines - ATTACK_MARGIN
                and self.rng.random() < self.start_probability
            ):
                self._schedule_attack(next_offset)
            if slot == self.burst_slot:
                self._schedule_burst(next_offset)
            if slot in self.escalation_slots:
                self._schedule_escalation(next_offset)
            slot += 1
            next_offset = self._slot_offset(slot) if slot < self.lines else math.inf
        return self.emitted


def write_blacklist(path: Path, pools: IpPools, seed: int) -> None:
    """Écrit la blacklist (une IP par ligne, ordre mélangé de façon déterministe)."""
    rng = random.Random(f"blacklist-{seed}")
    entries = list(pools.blacklist)
    rng.shuffle(entries)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write("# Blacklist d'IP - generee par scripts/generate_logs.py\n")
        handle.write(f"# seed={seed} - une IP par ligne, '#' = commentaire\n")
        for ip in entries:
            handle.write(f"{ip}\n")


def generate_dataset(config: GeneratorConfig) -> dict[str, Any]:
    """Génère les fichiers de logs, la blacklist et la vérité terrain.

    Retourne la vérité terrain (également écrite dans ``ground_truth.json``).
    """
    config.validate()
    pools = build_ip_pools(config.seed)
    truth = GroundTruth(config=config, pools=pools)
    picker = AttackerPicker(pools, random.Random(f"attackers-{config.seed}"))
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    for stale in output_dir.glob(f"{config.file_prefix}_*.log"):
        stale.unlink()  # anciens fichiers d'une génération précédente
    for index in range(config.files):
        day = LAST_DAY - timedelta(days=config.files - 1 - index)
        file_name = f"{config.file_prefix}_{index + 1:02d}.log"
        rng = random.Random(f"file-{config.seed}-{index}")
        path = output_dir / file_name
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            written = FileGenerator(
                handle=handle,
                file_name=file_name,
                day=day,
                lines=config.lines,
                rng=rng,
                pools=pools,
                picker=picker,
                truth=truth,
                attack_ratio=config.attack_ratio,
                noise_ratio=config.noise_ratio,
            ).run()
        truth.files.append(
            {"name": file_name, "date": day.isoformat(), "lines": written}
        )
    write_blacklist(config.blacklist_path, pools, config.seed)
    result = truth.to_dict()
    truth_path = output_dir / GROUND_TRUTH_NAME
    with truth_path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return result


def _fmt(number: int) -> str:
    """Formate un entier avec séparateur de milliers (espace)."""
    return f"{number:,}".replace(",", " ")


def format_summary(truth: dict[str, Any], output_dir: Path) -> str:
    """Construit le résumé texte affiché en fin de génération."""
    totals = truth["totals"]
    sequences = truth["attack_sequences"]
    expected = truth["expected_alerts"]
    lines = [
        f"Fichiers générés dans {output_dir} :",
        *(
            f"  - {entry['name']:<16} {entry['date']}  "
            f"{_fmt(entry['lines']):>11} lignes"
            for entry in truth["files"]
        ),
        f"Lignes totales        : {_fmt(totals['lines'])}",
        f"  vides attendues     : {_fmt(totals['empty'])}",
        f"  rejets attendus     : {_fmt(totals['rejected'])}",
        f"  valides attendues   : {_fmt(totals['valid'])}",
        f"Séquences d'attaque   : {sequences['total']} "
        f"({sequences['full']} complètes, {sequences['interrupted']} interrompues)",
        f"Rafales CRITICAL      : {len(truth['critical_bursts'])}",
        f"Escalades injectées   : {len(truth['escalations'])}",
        f"IP attendues en alerte (seuil {DETECTION_THRESHOLD}, "
        f"fenêtre {DETECTION_WINDOW_SECONDS} s) : {len(expected)}",
    ]
    shown = expected[:20]
    lines.extend(
        f"  - {alert['ip']:<16} {alert['failures']:>2} échecs"
        f"{'  [BLACKLISTÉE]' if alert['blacklisted'] else ''}"
        for alert in shown
    )
    if len(expected) > len(shown):
        hidden = len(expected) - len(shown)
        lines.append(f"  ... et {hidden} autres (voir ground_truth.json)")
    lines.append(
        "IP interrompues (aucune alerte attendue) : "
        f"{len(truth['interrupted_only_ips'])}"
    )
    lines.append(f"Vérité terrain : {output_dir / GROUND_TRUTH_NAME}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur d'arguments de la ligne de commande."""
    parser = argparse.ArgumentParser(
        description="Génère des fichiers de logs synthétiques déterministes."
    )
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    parser.add_argument("--files", type=int, default=3, help="nombre de fichiers")
    parser.add_argument("--lines", type=int, default=10_000, help="lignes par fichier")
    parser.add_argument("--seed", type=int, default=42, help="graine aléatoire")
    parser.add_argument(
        "--attack-ratio",
        type=float,
        default=0.02,
        help="proportion de lignes appartenant à des séquences d'attaque",
    )
    parser.add_argument(
        "--noise-ratio", type=float, default=0.03, help="proportion de lignes bruitées"
    )
    parser.add_argument("--blacklist", type=Path, default=DEFAULT_BLACKLIST)
    parser.add_argument(
        "--big",
        action="store_true",
        help=f"1 fichier de {_fmt(BIG_LINES)} lignes dans data/big/ (benchmark)",
    )
    return parser


def config_from_args(args: argparse.Namespace) -> GeneratorConfig:
    """Convertit les arguments CLI en ``GeneratorConfig`` (gère ``--big``)."""
    if args.big:
        return GeneratorConfig(
            output_dir=(
                DEFAULT_BIG_DIR
                if args.output_dir == DEFAULT_OUTPUT_DIR
                else args.output_dir
            ),
            files=1,
            lines=BIG_LINES,
            seed=args.seed,
            attack_ratio=args.attack_ratio,
            noise_ratio=args.noise_ratio,
            blacklist_path=args.blacklist,
            file_prefix="big",
        )
    return GeneratorConfig(
        output_dir=args.output_dir,
        files=args.files,
        lines=args.lines,
        seed=args.seed,
        attack_ratio=args.attack_ratio,
        noise_ratio=args.noise_ratio,
        blacklist_path=args.blacklist,
    )


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée CLI du générateur. Retourne le code de sortie."""
    if isinstance(sys.stdout, io.TextIOWrapper):  # console Windows (cp1252)
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        config = config_from_args(args)
        truth = generate_dataset(config)
    except (ValueError, OSError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1
    print(format_summary(truth, config.output_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
