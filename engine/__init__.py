"""Engine de traitement et d'analyse de flux de logs sécurisé.

Architecture du pipeline (tout est paresseux, mémoire constante) ::

    sources (.log)
      └─ ingestion.read_multiple_sources   yield / yield from
          └─ map(str.strip) -> filter(None)
              └─ parsing.parse_stream       dict + tuple (IP, Port, Proto)
                  └─ filter(lambda ...) x3  niveau / IP / horodatage
                      └─ map(normalize_record)   f-strings
                          └─ map(route_record)   match-case
                              └─ analytics.StreamAggregator (1 passe)
                                  ├─ set / frozenset  | & - ^
                                  ├─ defaultdict(int / list / imbriqué)
                                  └─ detection.detect_brute_force
                                      └─ rules.apply_security_rules(*args, **kwargs)
                                          └─ report (JSON + console) / audit
"""

from engine.config import ENGINE_VERSION

__all__ = ["__version__"]
__version__ = ENGINE_VERSION
