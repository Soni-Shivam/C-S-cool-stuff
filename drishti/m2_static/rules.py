"""Permission-combination analysis for Android manifests."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml  # type: ignore[import-untyped]

from drishti.contracts.static_report import Component, ComponentKind, PermissionCombo, Severity

_RULES_PATH = Path(__file__).with_name("rules") / "permission_combos.yaml"


@dataclass(frozen=True)
class PermissionRule:
    """One declarative permission combination rule."""

    rule_id: str
    all_of: tuple[str, ...]
    any_of: tuple[str, ...]
    severity: Severity
    description: str
    mitre: str | None
    component_type: ComponentKind | None
    service_binding: str | None


def effective_exported(*, explicit: bool | None, has_intent_filter: bool, target_sdk: int) -> bool:
    """Return Android's effective exported status without trusting a missing attribute."""
    del target_sdk  # API 31 makes omission a build error; legacy semantics remain the fact model.
    return explicit if explicit is not None else has_intent_filter


def load_permission_rules(path: Path = _RULES_PATH) -> tuple[PermissionRule, ...]:
    """Load the version-controlled, auditable combination taxonomy."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("permission rule file must contain a list")
    rules: list[PermissionRule] = []
    for item in raw:
        component = item.get("plus_component_type")
        rules.append(
            PermissionRule(
                rule_id=str(item["id"]),
                all_of=tuple(str(value) for value in item.get("all_of", [])),
                any_of=tuple(str(value) for value in item.get("any_of", [])),
                severity=Severity(str(item["severity"])),
                description=str(item["description"]),
                mitre=str(item["mitre"]) if item.get("mitre") else None,
                component_type=ComponentKind(component) if component else None,
                service_binding=(
                    str(item["requires_service_binding"])
                    if item.get("requires_service_binding")
                    else None
                ),
            )
        )
    return tuple(rules)


def evaluate_permission_combos(
    *, permissions: set[str], components: tuple[Component, ...]
) -> tuple[PermissionCombo, ...]:
    """Match high-signal combinations and retain only their direct manifest evidence."""
    short = {permission.rsplit(".", 1)[-1] for permission in permissions}
    matches: list[PermissionCombo] = []
    for rule in load_permission_rules():
        if not set(rule.all_of).issubset(short):
            continue
        if rule.any_of and not set(rule.any_of).intersection(short):
            continue
        if rule.component_type and not any(c.kind is rule.component_type for c in components):
            continue
        if rule.service_binding and not any(
            c.kind is ComponentKind.SERVICE and c.permission == rule.service_binding
            for c in components
        ):
            continue
        matched = tuple(
            sorted(
                permission
                for permission in permissions
                if permission.rsplit(".", 1)[-1] in rule.all_of
            )
        )
        matches.append(
            PermissionCombo(
                rule_id=rule.rule_id,
                permissions=matched,
                severity=rule.severity,
                description=rule.description,
                mitre=rule.mitre,
            )
        )
    return tuple(matches)
