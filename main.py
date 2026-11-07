"""Point d'entrée CLI unique : pilote tout le pipeline d'analyse de logs.

Commandes ::

    python main.py generate [--lines N --files N --seed S | --big]
    python main.py run --input data/samples --blacklist data/blacklist.txt
                       [--threshold 5 --window 60] [--output output/]
    python main.py audit        # run + rapport d'introspection globals()/locals()
    python main.py benchmark --input data/big [--sizes 10000 100000 1000000]

Code de sortie : 0 si tout s'est bien passé, 1 en cas d'erreur fatale
(message lisible sur stderr, jamais de traceback brut sauf avec ``--debug``).
"""

from __future__ import annotations

import argparse
import io
import logging
import os
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from engine import config
from engine.analytics import StreamAggregator, load_blacklist
from engine.audit import audit_scope, export_audit, format_audit_table
from engine.benchmark import format_benchmark, run_benchmark, run_scaling_benchmark
from engine.exceptions import ConfigurationError, LogEngineError
from engine.ingestion import resolve_sources
from engine.models import PipelineStats, Predicate
from engine.pipeline import build_pipeline, min_level_predicate
from engine.report import (
    build_report,
    render_console,
    sign_report,
    write_json_report,
)
from engine.rules import RULE_REGISTRY, apply_security_rules, make_threshold_rule
from scripts.generate_logs import (
    BIG_LINES,
    DEFAULT_BIG_DIR,
    GeneratorConfig,
    format_summary,
    generate_dataset,
)

logger = logging.getLogger("log_engine")
Handler = Callable[[argparse.Namespace], int]


# --------------------------------------------------------------------------
# Configuration de la sortie et des logs
# --------------------------------------------------------------------------
def configure_stdout() -> None:
    """Force l'UTF-8 sur stdout/stderr (console Windows en cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        if isinstance(stream, io.TextIOWrapper):
            stream.reconfigure(encoding="utf-8", errors="replace")


def configure_logging(
    verbose: bool, log_file: Path | None = None
) -> list[logging.Handler]:
    """Console : WARNING (DEBUG si ``-v``). Fichier facultatif : tout en DEBUG.

    Le fichier ``output/engine_<horodatage>.log`` reçoit notamment le détail
    de chaque ligne rejetée par le parseur (le pipeline n'est jamais stoppé).
    Retourne les handlers ajoutés (retirés par ``release_logging``).
    """
    root = logging.getLogger()
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(logging.Formatter("%(levelname)s %(name)s : %(message)s"))
    handlers: list[logging.Handler] = [console]
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s : %(message)s")
        )
        handlers.append(file_handler)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(logging.DEBUG if verbose or log_file else logging.WARNING)
    return handlers


def release_logging(handlers: list[logging.Handler]) -> None:
    """Retire et ferme les handlers ajoutés par ``configure_logging``."""
    root = logging.getLogger()
    for handler in handlers:
        root.removeHandler(handler)
        handler.close()


# --------------------------------------------------------------------------
# Commandes
# --------------------------------------------------------------------------
def cmd_generate(args: argparse.Namespace) -> int:
    """Génère les jeux de données (délègue à ``scripts/generate_logs.py``)."""
    generator = GeneratorConfig(
        output_dir=DEFAULT_BIG_DIR if args.big else args.output_dir,
        files=1 if args.big else args.files,
        lines=BIG_LINES if args.big else args.lines,
        seed=args.seed,
        attack_ratio=args.attack_ratio,
        noise_ratio=args.noise_ratio,
        blacklist_path=args.blacklist,
        file_prefix="big" if args.big else "server",
    )
    try:
        truth = generate_dataset(generator)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    print(format_summary(truth, generator.output_dir))
    return 0


def _collect_sources(inputs: list[Path]) -> list[Path]:
    """Liste des fichiers à traiter (des chemins, pas leur contenu).

    Raises:
        ConfigurationError: aucun fichier ``.log`` trouvé.
    """
    sources = list(resolve_sources(inputs))
    if not sources:
        joined = ", ".join(str(path) for path in inputs)
        raise ConfigurationError(f"aucun fichier *.log trouvé dans : {joined}")
    return sources


def cmd_run(args: argparse.Namespace, *, with_audit: bool = False) -> int:
    """Pipeline complet : ingestion -> analyse -> règles -> rapport (-> audit)."""
    started = time.perf_counter()
    sources = _collect_sources(args.input)
    blacklist = load_blacklist(args.blacklist)
    stats = PipelineStats()
    extra_predicates: list[Predicate] = []
    if args.min_level:
        extra_predicates.append(min_level_predicate(args.min_level))

    # 1 passe : générateurs -> filtres -> normalisation -> routage -> agrégation
    records = build_pipeline(
        sources, stats=stats, strict=args.strict, extra_predicates=extra_predicates
    )
    aggregator = StreamAggregator(
        blacklist=blacklist,
        threshold=args.threshold,
        window_seconds=args.window,
        escalation_window=args.escalation_window,
    )
    aggregator.consume(records)

    # Règles : fonctions passées en argument (*args) + configuration (**kwargs)
    parameters = {
        "threshold": args.threshold,
        "window_seconds": args.window,
        "critical_limit": args.critical_limit,
        "period_minutes": args.critical_period,
        "error_ratio": args.error_ratio,
        "min_events": args.min_events,
        "escalation_window": args.escalation_window,
    }
    rules_report = apply_security_rules(
        *RULE_REGISTRY.values(),
        make_threshold_rule("CRITICAL", args.critical_per_user),
        context=aggregator.context(),
        blacklist=blacklist,
        **parameters,
    )
    duration = time.perf_counter() - started

    report = build_report(
        stats=stats,
        aggregator=aggregator,
        rules_report=rules_report,
        sources=sources,
        parameters={**parameters, "strict": args.strict, "min_level": args.min_level},
        duration_seconds=duration,
    )
    signing_secret = os.environ.get(
        config.SECRET_ENV_VAR, config.DEFAULT_SIGNING_SECRET
    )
    report["signature"] = sign_report(report, signing_secret)
    print(render_console(report))
    report_path = write_json_report(report, args.output)
    print(f"Rapport JSON : {report_path}")
    print(f"Signature    : {report['signature']['algorithm']} "
          f"{report['signature']['value'][:16]}...")

    if with_audit:
        # Introspection en fin de pipeline : locals() de cette fonction + globals()
        audit = audit_scope(locals(), global_vars=globals())
        audit_path = export_audit(audit, args.output)
        print()
        print("AUDIT D'INTROSPECTION (globals() / locals())")
        print(format_audit_table(audit))
        print(f"Audit JSON   : {audit_path}")
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Pipeline complet suivi de l'audit d'introspection."""
    return cmd_run(args, with_audit=True)


def cmd_benchmark(args: argparse.Namespace) -> int:
    """Mesure la mémoire pic (tracemalloc) et le débit sur un gros fichier."""
    try:
        sources = _collect_sources(args.input)
    except LogEngineError as exc:
        raise ConfigurationError(
            f"{exc} — générez d'abord le gros fichier : python main.py generate --big"
        ) from exc
    blacklist = load_blacklist(args.blacklist)
    total_bytes = sum(path.stat().st_size for path in sources)
    print(f"Benchmark sur {len(sources)} fichier(s), {total_bytes / 2**20:,.1f} Mio")
    options = {
        "blacklist": blacklist,
        "threshold": args.threshold,
        "window_seconds": args.window,
        "trace": not args.no_trace,
    }
    if args.no_trace:
        print("Mode --no-trace : débit seul (tracemalloc désactivé)")
    else:
        print("Mesure sous tracemalloc (débit ~10x plus faible qu'en production)")
    if args.sizes:
        results = run_scaling_benchmark(sources, args.sizes, **options)
    else:
        results = [run_benchmark(sources, **options)]
    print(format_benchmark(results))
    peaks = [result.peak_mib for result in results]
    if len(peaks) > 1 and not args.no_trace:
        growth = peaks[-1] / peaks[0] if peaks[0] else float("inf")
        lines_growth = results[-1].lines_read / max(results[0].lines_read, 1)
        print(
            f"Lignes x{lines_growth:,.0f} -> mémoire pic x{growth:.2f} "
            "(mémoire indépendante de la taille du fichier)"
        )
    return 0


# --------------------------------------------------------------------------
# Analyse des arguments
# --------------------------------------------------------------------------
def _add_analysis_arguments(parser: argparse.ArgumentParser) -> None:
    """Options communes à ``run`` et ``audit``."""
    parser.add_argument(
        "--input", type=Path, nargs="+", default=[config.DEFAULT_INPUT_DIR],
        help="fichier(s) ou dossier(s) de logs (*.log)",
    )
    parser.add_argument("--blacklist", type=Path, default=config.DEFAULT_BLACKLIST)
    parser.add_argument("--output", type=Path, default=config.DEFAULT_OUTPUT_DIR)
    parser.add_argument(
        "--threshold", type=int, default=config.DEFAULT_THRESHOLD,
        help="échecs consécutifs pour une force brute",
    )
    parser.add_argument(
        "--window", type=int, default=config.DEFAULT_WINDOW_SECONDS,
        help="fenêtre glissante de détection (s)",
    )
    parser.add_argument(
        "--critical-limit", type=int, default=config.DEFAULT_CRITICAL_LIMIT
    )
    parser.add_argument(
        "--critical-period", type=int, default=config.DEFAULT_CRITICAL_PERIOD_MINUTES,
        help="période (min) de la règle de rafale CRITICAL",
    )
    parser.add_argument("--critical-per-user", type=int, default=20)
    parser.add_argument("--error-ratio", type=float, default=config.DEFAULT_ERROR_RATIO)
    parser.add_argument(
        "--min-events", type=int, default=config.DEFAULT_MIN_USER_EVENTS
    )
    parser.add_argument(
        "--escalation-window", type=int, default=config.DEFAULT_ESCALATION_WINDOW
    )
    parser.add_argument(
        "--min-level", choices=config.LEVELS, default=None,
        help="ne conserver que les logs de ce niveau ou plus graves",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="niveau et IP validés par le parseur plutôt que par les lambdas",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construit l'analyseur de la ligne de commande (sous-commandes)."""
    parser = argparse.ArgumentParser(
        prog="main.py", description="Engine de traitement et d'analyse de logs."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="logs DEBUG")
    parser.add_argument(
        "--debug", action="store_true", help="afficher la trace des erreurs"
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMANDE")

    gen = sub.add_parser("generate", help="générer les jeux de données de test")
    gen.add_argument("--output-dir", type=Path, default=config.DEFAULT_INPUT_DIR)
    gen.add_argument("--files", type=int, default=3)
    gen.add_argument("--lines", type=int, default=10_000)
    gen.add_argument("--seed", type=int, default=42)
    gen.add_argument("--attack-ratio", type=float, default=0.02)
    gen.add_argument("--noise-ratio", type=float, default=0.03)
    gen.add_argument("--blacklist", type=Path, default=config.DEFAULT_BLACKLIST)
    gen.add_argument("--big", action="store_true", help="1 fichier de 2M lignes")
    gen.set_defaults(handler=cmd_generate)

    run = sub.add_parser("run", help="exécuter le pipeline complet")
    _add_analysis_arguments(run)
    run.set_defaults(handler=cmd_run)

    audit = sub.add_parser("audit", help="pipeline + audit globals()/locals()")
    _add_analysis_arguments(audit)
    audit.set_defaults(handler=cmd_audit)

    bench = sub.add_parser("benchmark", help="mémoire pic et débit (tracemalloc)")
    bench.add_argument(
        "--input", type=Path, nargs="+", default=[config.DEFAULT_BIG_DIR]
    )
    bench.add_argument("--blacklist", type=Path, default=config.DEFAULT_BLACKLIST)
    bench.add_argument("--threshold", type=int, default=config.DEFAULT_THRESHOLD)
    bench.add_argument("--window", type=int, default=config.DEFAULT_WINDOW_SECONDS)
    bench.add_argument(
        "--sizes", type=int, nargs="*", default=None,
        help="traiter les N premières lignes pour chaque N (courbe mémoire)",
    )
    bench.add_argument(
        "--no-trace", action="store_true", help="mesurer le débit sans tracemalloc"
    )
    bench.set_defaults(handler=cmd_benchmark)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Point d'entrée : retourne 0 (succès) ou 1 (erreur fatale gérée)."""
    configure_stdout()
    args = build_parser().parse_args(argv)
    log_file = None
    if args.command in ("run", "audit"):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = args.output / f"engine_{stamp}.log"
    handler: Handler = args.handler
    log_handlers: list[logging.Handler] = []
    try:
        log_handlers = configure_logging(args.verbose, log_file)
        return handler(args)
    except LogEngineError as exc:
        logger.debug("Erreur fatale", exc_info=True)
        print(f"Erreur : {exc}", file=sys.stderr)
        if args.debug:
            raise
        return 1
    except KeyboardInterrupt:
        print("Interrompu par l'utilisateur.", file=sys.stderr)
        return 1
    except Exception as exc:  # filet de sécurité : pas de traceback brut
        logger.debug("Erreur inattendue", exc_info=True)
        print(f"Erreur inattendue ({type(exc).__name__}) : {exc}", file=sys.stderr)
        if args.debug:
            raise
        return 1
    finally:
        release_logging(log_handlers)


if __name__ == "__main__":
    sys.exit(main())
