"""The staged-sample catalogue. docs/01_DATA_CONTRACTS.md addendum A21.

A `SampleEntry` describes a sample sitting on the analysis VM well enough to choose
it and to say afterwards whether the verdict was right. It deliberately cannot
describe the file's *content*: there is no bytes field, no path field, and no route
that serves one. The sample stays on the VM (CLAUDE.md hard boundary) and the
browser only ever names an id.

`label` and `vt_detection` are ground truth, and they are the reason this model is
separate from `FileMeta` rather than an extension of it. Ground truth is a
**display** fact: it is shown next to the verdict so a human can see whether the
system was right. It is never an input to the analysis. Merging it into the ingest
contract would put a VT-derived field inside the object the pipeline reads, and the
first accidental use of it would make every composite score circular — the exact
failure `m5_ml/reputation.py` refuses a label-derived feed to prevent.
"""

from __future__ import annotations

from typing import Literal

from drishti.contracts.base import DrishtiModel


class SampleEntry(DrishtiModel):
    """One analysable sample staged on the VM, with its known nature.

    `label` follows the corpus convention: 1 malicious, 0 benign, and None for a
    sample whose nature is not a corpus label — our own canary is inert by
    construction, which is a different kind of fact from "VirusTotal saw nothing".
    """

    id: str
    package: str
    filename: str
    sha256: str
    size_bytes: int
    label: Literal[0, 1] | None = None
    vt_detection: int | None = None
    note: str | None = None

    @property
    def ground_truth(self) -> str:
        """The label as a word, for a reader rather than a corpus loader."""
        if self.label == 1:
            return "malicious"
        if self.label == 0:
            return "benign"
        return "unlabelled"
