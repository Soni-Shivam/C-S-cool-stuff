"""Allowlisted hooks and stimuli available to M3/M4.

Catalogue entries are identifiers plus pre-reviewed parameters. There is no field
for generated shell, JavaScript, or executable code.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict


class CatalogueEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    kind: Literal["hook", "stimulus"]
    description: str
    max_uses: int = 3


CATALOGUE: dict[str, CatalogueEntry] = {
    entry.id: entry for entry in (
        CatalogueEntry(id="hook.sms_body", kind="hook", description="Observe SMS body API access; body is always redacted"),
        CatalogueEntry(id="hook.cipher_do_final", kind="hook", description="Observe Cipher.doFinal and capture only redacted plaintext preview"),
        CatalogueEntry(id="hook.dex_loader", kind="hook", description="Observe local dynamic class loading"),
        CatalogueEntry(id="hook.network_open", kind="hook", description="Observe connections to the local fake C2"),
        CatalogueEntry(id="hook.clipboard", kind="hook", description="Observe clipboard access without exporting content"),
        CatalogueEntry(id="hook.device_properties", kind="hook", description="Observe non-sensitive device-property reads"),
        CatalogueEntry(id="stimulus.ui_monkey", kind="stimulus", description="Bounded deterministic UI events", max_uses=3),
        CatalogueEntry(id="stimulus.synthetic_sms", kind="stimulus", description="Inject synthetic SMS history containing no real recipient data", max_uses=3),
        CatalogueEntry(id="stimulus.synthetic_contacts", kind="stimulus", description="Inject synthetic contact history", max_uses=2),
        CatalogueEntry(id="stimulus.locale_sim_time", kind="stimulus", description="Select an approved locale/SIM/device/time profile", max_uses=3),
        CatalogueEntry(id="stimulus.inert_banking_apps", kind="stimulus", description="Install pre-built inert banking fixtures", max_uses=1),
        CatalogueEntry(id="stimulus.fake_c2_template", kind="stimulus", description="Serve a no-upstream response from an approved local template", max_uses=3),
    )
}


def require_allowlisted(ids: list[str], kind: Literal["hook", "stimulus"]) -> list[CatalogueEntry]:
    entries: list[CatalogueEntry] = []
    for identifier in ids:
        entry = CATALOGUE.get(identifier)
        if entry is None or entry.kind != kind:
            raise ValueError(f"unapproved {kind} catalogue id: {identifier}")
        entries.append(entry)
    return entries
