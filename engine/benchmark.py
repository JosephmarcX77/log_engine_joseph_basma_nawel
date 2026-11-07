"""Benchmark mémoire / débit du pipeline complet (``tracemalloc``).

Objectif : démontrer que la mémoire pic reste (quasi) constante quand le
nombre de lignes traitées augmente, grâce aux générateurs et à l'agrégation
bornée. ``run_scaling_benchmark`` traite successivement les N premières
lignes (``itertools.islice``, paresseux) pour plusieurs valeurs de N.
"""

from __future__ import annotations

import time
import tracemalloc
from collections.abc import Iterable, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from engine.analytics import StreamAggregator
from engine.config import DEFAULT_THRESHOLD, DEFAULT_WINDOW_SECONDS
from engine.models import PipelineStats
from engine.pipeline import build_pipeline


@dataclass(frozen=True)
class BenchmarkResult:
    """Mesures d'une exécution du pipeline."""

    lines_read: int
    valid_records: int
    seconds: float
    peak_bytes: int
    current_bytes: int
    alerts: int

    @property
    def lines_per_second(self) -> float:
        """Débit en lignes par seconde."""
        return self.lines_read / self.seconds if self.seconds > 0 else 0.0

    @property
    def peak_mib(self) -> float:
        """Mémoire pic (Mio) allouée pendant le traitement."""
        return self.peak_bytes / (1024 * 1024)

    def to_dict(self) -> dict[str, Any]:
        """Représentation JSON-sérialisable."""
        data = asdict(self)
        data["lines_per_second"] = round(self.lines_per_second)
        data["peak_mib"] = round(self.peak_mib, 3)
        return data


def run_benchmark(
    sources: Sequence[Path],
    *,
    limit: int | None = None,
    blacklist: frozenset[str] = frozenset(),
    threshold: int = DEFAULT_THRESHOLD,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
) -> BenchmarkResult:
    """Exécute pipeline + agrégation sous ``tracemalloc`` et mesure le pic.

    Le pic est mesuré relativement à la mémoire déjà allouée avant le
    traitement : il ne reflète que ce que le pipeline consomme.
    """
    was_tracing = tracemalloc.is_tracing()
    if not was_tracing:
        tracemalloc.start()
    tracemalloc.reset_peak()
    baseline, _ = tracemalloc.get_traced_memory()
    started = time.perf_counter()
    stats = PipelineStats()
    aggregator = StreamAggregator(
        blacklist=blacklist, threshold=threshold, window_seconds=window_seconds
    )
    aggregator.consume(build_pipeline(sources, stats=stats, limit=limit))
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    if not was_tracing:
        tracemalloc.stop()
    return BenchmarkResult(
        lines_read=stats.lines_read,
        valid_records=stats.valid_records,
        seconds=elapsed,
        peak_bytes=max(peak - baseline, 0),
        current_bytes=max(current - baseline, 0),
        alerts=len(aggregator.brute_force_alerts),
    )


def run_scaling_benchmark(
    sources: Sequence[Path], sizes: Iterable[int], **options: Any
) -> list[BenchmarkResult]:
    """Benchmark pour chaque taille de ``sizes`` (N premières lignes)."""
    return [run_benchmark(sources, limit=size, **options) for size in sizes]


def format_benchmark(results: Sequence[BenchmarkResult]) -> str:
    """Tableau texte des résultats."""
    header = (
        f"{'lignes lues':>13} {'valides':>12} {'durée (s)':>10} "
        f"{'lignes/s':>10} {'pic mémoire':>13} {'alertes':>8}"
    )
    lines = [header, "-" * len(header)]
    for result in results:
        lines.append(
            f"{result.lines_read:>13,} {result.valid_records:>12,} "
            f"{result.seconds:>10.2f} {result.lines_per_second:>10,.0f} "
            f"{result.peak_mib:>9.2f} Mio {result.alerts:>8,}".replace(",", " ")
        )
    return "\n".join(lines)
