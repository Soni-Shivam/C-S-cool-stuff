"""Corpus sample list — the boundary between list building and extraction.

docs/01_DATA_CONTRACTS.md A9.

`build_sample_list.py` runs on a laptop against AndroZoo's metadata index, which carries
no APK bytes. `corpus_extract.py` consumes these rows on the extractor VM, where the APKs
actually land. Two machines, one contract.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from drishti.contracts.base import DrishtiModel

#: Three-way, because PHASE_2 T2.4 calibrates on a held-out third split. Calibrating on
#: test is a leak, and it is the kind a good judge asks about.
Split = Literal["train", "calib", "test"]

#: Four bands. The 2024-2026 band is the one that makes the time split honest — v1's
#: corpus had only 117 rows from 2024-25 while the paper names those families as primary
#: targets.
TIME_BANDS: tuple[str, ...] = ("<=2017", "2018-2020", "2021-2023", "2024-2026")

#: VirusTotal detections at or above this count are labelled malware. Strong consensus.
MALWARE_MIN_VT = 10


class CorpusSample(DrishtiModel):
    """One row of the corpus sample list."""

    sha256: str = Field(min_length=64, max_length=64)
    label: int = Field(ge=0, le=1)
    split: Split
    time_band: str
    dex_date: str
    pkg_name: str = ""
    #: Provenance and audit only. **Never wire this into the scorer** — AndroZoo's labels
    #: are VirusTotal counts, so a VT-derived signal in `R` makes composite-score metrics
    #: circular. `reputation.py` refuses a label-derived feed by default.
    vt_detection: int = Field(ge=0)
    #: Bytes, from the index. Summed to report exact corpus size before any transfer, so
    #: the download size is measured rather than estimated.
    apk_size: int = Field(ge=0)
