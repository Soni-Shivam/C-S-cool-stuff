"""Smoke tests for the package skeleton.

Deliberately thin. T0.1 builds the skeleton; the modules it declares are filled in
by later tasks. What matters now is that the import graph is sound and the layout
matches 00_GUIDING_MAP.md §8, so the three tracks can work in parallel without a
package-layout argument at hour 20.
"""

from __future__ import annotations

import importlib

import pytest

import drishti

#: The module boundaries from 00_GUIDING_MAP.md §7-8. These names are a contract
#: between the three tracks — renaming one is a cross-track decision.
EXPECTED_MODULES = [
    "drishti.contracts",
    "drishti.ledger",
    "drishti.m1_ingest",
    "drishti.m2_static",
    "drishti.m3_dynamic",
    "drishti.m4_genai",
    "drishti.m5_ml",
    "drishti.m6_score",
    "drishti.m7_report",
    "drishti.api",
]


def test_version_is_set() -> None:
    assert drishti.__version__ == "0.1.0"


@pytest.mark.parametrize("module_name", EXPECTED_MODULES)
def test_module_boundary_exists_and_imports(module_name: str) -> None:
    """Each declared module boundary is a real, importable package."""
    assert importlib.import_module(module_name) is not None
