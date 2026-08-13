"""DRISHTI — defensive Android malware triage.

Module boundaries follow docs/00_GUIDING_MAP.md §7:

    m1_ingest  -> m2_static -> m5_ml -> m4_genai -> m6_score -> m7_report
                       |          ^
                       v          |
                   m3_dynamic ----+

Every cross-module type is a pydantic model in `drishti.contracts`. A module takes
contract objects in and returns contract objects out; no dicts cross a boundary.

`m6_score` reads from the evidence ledger, never from the analysers directly. That
invariant is what makes "every score point traces back to an artefact" true rather
than marketing.
"""

__version__ = "0.1.0"
