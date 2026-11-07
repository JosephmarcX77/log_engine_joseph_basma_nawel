"""MODULE 1 — Ingestion paresseuse des sources de logs (générateurs).

Pourquoi la mémoire reste constante (O(1) par rapport à la taille du fichier)
------------------------------------------------------------------------------
* ``read_log_file`` est une fonction génératrice : chaque ``yield`` suspend la
  fonction et ne rend qu'UNE ligne au consommateur. L'itération ``for line in
  handle`` s'appuie sur le tampon de lecture du système (quelques Ko) : le
  fichier n'est jamais chargé en entier (aucun ``read()`` / ``readlines()``).
* ``read_multiple_sources`` enchaîne les fichiers avec ``yield from`` : le
  sous-générateur d'un fichier est entièrement consommé (puis fermé, grâce au
  ``with``) avant d'ouvrir le suivant. À tout instant : 1 fichier ouvert,
  1 ligne en mémoire, quel que soit le volume total.
* ``discover_sources`` ne produit que des chemins (``Path``), pas de contenu.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from pathlib import Path

from engine.config import ENCODING, LOG_PATTERN
from engine.exceptions import LogSourceError

logger = logging.getLogger(__name__)


def read_log_file(path: Path) -> Iterator[str]:
    """Produit (``yield``) les lignes d'un fichier une par une, sans ``\\n`` final.

    Le fichier est ouvert dans un ``with`` : il est fermé automatiquement à la
    fin de l'itération, en cas d'exception ou si le consommateur abandonne le
    générateur (``close()`` -> ``GeneratorExit``). Les octets non UTF-8 sont
    remplacés (``errors="replace"``) plutôt que de faire échouer la lecture.

    Raises:
        LogSourceError: fichier introuvable, accès refusé ou erreur d'E/S.
    """
    try:
        handle = path.open("r", encoding=ENCODING, errors="replace")
    except FileNotFoundError as exc:
        raise LogSourceError(path, "fichier introuvable") from exc
    except PermissionError as exc:
        raise LogSourceError(path, "permission refusée") from exc
    except OSError as exc:  # répertoire, périphérique invalide, ...
        raise LogSourceError(path, f"erreur d'ouverture ({exc.strerror})") from exc
    with handle:
        for line in handle:  # lecture tamponnée, une ligne à la fois
            yield line.rstrip("\r\n")


def read_multiple_sources(paths: Iterable[Path]) -> Iterator[str]:
    """Enchaîne plusieurs sources en un seul flux grâce à ``yield from``.

    ``yield from read_log_file(path)`` délègue l'itération au sous-générateur :
    chaque ligne est transmise directement au consommateur, sans liste
    intermédiaire. Une source manquante ou illisible est signalée par un
    *warning* puis ignorée : le flux continue avec la source suivante.
    """
    for path in paths:
        try:
            yield from read_log_file(path)
        except LogSourceError as exc:
            logger.warning("%s -> source ignorée", exc)
            continue


def discover_sources(directory: Path, pattern: str = LOG_PATTERN) -> Iterator[Path]:
    """Produit les fichiers de ``directory`` correspondant à ``pattern`` (triés).

    Si ``directory`` désigne directement un fichier, il est produit tel quel.
    Le tri par nom garantit un ordre chronologique pour les fichiers nommés
    ``server_01.log``, ``server_02.log``, ...

    Raises:
        LogSourceError: le chemin n'existe pas.
    """
    if not directory.exists():
        raise LogSourceError(directory, "chemin introuvable")
    if directory.is_file():
        yield directory
        return
    yield from sorted(directory.glob(pattern))


def resolve_sources(
    inputs: Iterable[Path], pattern: str = LOG_PATTERN
) -> Iterator[Path]:
    """Produit les fichiers de logs de plusieurs entrées (fichiers ou dossiers)."""
    for entry in inputs:
        yield from discover_sources(entry, pattern)
