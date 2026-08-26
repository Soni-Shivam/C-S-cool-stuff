"""Emit `ui/src/api/verdict.gen.ts` from `drishti.contracts.verdict`.

Contract addendum A15 is explicit: "Do not add a second `Verdict` shape anywhere — a
JSON schema, a TypeScript interface, or a Kotlin data class that is hand-maintained
alongside this one is the same defect wearing a different hat. Generate from this, or
import it." This script is the "generate from this" half, and
`tests/contract/test_api_surface.py` fails when the checked-in output has drifted from a
fresh generation, so the rule is mechanical rather than remembered.

It reads `Verdict.model_json_schema()` — the same schema FastAPI publishes at
`/openapi.json` — so a field added to the pydantic model appears here without anyone
editing this file. Deliberately narrow: it handles the shapes the verdict contract
actually uses (string/int/float/bool, string enums, `$ref`, nullable, arrays of scalars
and refs) and raises on anything else rather than emitting a silently wrong type.

Run with `python ui/scripts/gen_verdict_types.py` (or `--check` to verify only).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

# Importable when run as a script from anywhere in the repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from drishti.contracts.verdict import Verdict

OUTPUT = Path(__file__).resolve().parents[1] / "src" / "api" / "verdict.gen.ts"

HEADER = """/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Emitted from `drishti/contracts/verdict.py` by `ui/scripts/gen_verdict_types.py`.
 * `drishti/contracts/verdict.py` is the single source of truth for this shape
 * (contract addendum A15); a hand-maintained copy of it here would be exactly the
 * drift that contract exists to prevent, so this file is generated and a contract
 * test fails when it no longer matches the model.
 *
 * Regenerate:  python ui/scripts/gen_verdict_types.py
 */
"""

SCALARS = {"string": "string", "integer": "number", "number": "number", "boolean": "boolean"}


def _fail(where: str, schema: dict[str, Any]) -> str:
    raise NotImplementedError(
        f"{where}: this generator does not handle {schema!r}. Extend it deliberately "
        "rather than letting the TypeScript quietly disagree with the pydantic model."
    )


def _type_of(schema: dict[str, Any], where: str) -> str:
    """One JSON-Schema node as a TypeScript type expression."""
    if "$ref" in schema:
        return schema["$ref"].rsplit("/", 1)[-1]
    if "anyOf" in schema:
        parts = [_type_of(option, where) for option in schema["anyOf"]]
        # `X | null` is the pydantic optional; keep the union order stable.
        return " | ".join(dict.fromkeys(parts))
    if "enum" in schema:
        return " | ".join(f"'{value}'" for value in schema["enum"])
    kind = schema.get("type")
    if kind == "null":
        return "null"
    if kind == "array":
        return f"{_type_of(schema['items'], where)}[]"
    if kind in SCALARS:
        return SCALARS[kind]
    return _fail(where, schema)


def _doc(text: str | None, indent: str) -> list[str]:
    if not text:
        return []
    lines = [line.rstrip() for line in text.strip().splitlines()]
    return [f"{indent}/**", *[f"{indent} * {line}".rstrip() for line in lines], f"{indent} */"]


def _interface(name: str, schema: dict[str, Any]) -> str:
    """Every property is emitted as required, and that is not an oversight.

    JSON Schema marks a field with a default as not-`required`, but that describes what
    a *request* may omit. This type describes a *response*, and pydantic serialises every
    field on the model — so `behaviors_detected` arrives as `[]`, never absent. Emitting
    `?` here would push a `| undefined` into the UI for a case the API cannot produce,
    and the honest empty-versus-missing distinction the panels draw would then have three
    states to carry instead of two.
    """
    lines = [*_doc(schema.get("description"), ""), f"export interface {name} {{"]
    for field, spec in schema.get("properties", {}).items():
        lines.extend(_doc(spec.get("description"), "  "))
        lines.append(f"  {field}: {_type_of(spec, f'{name}.{field}')}")
    lines.append("}")
    return "\n".join(lines)


def _alias(name: str, schema: dict[str, Any]) -> str:
    values = " | ".join(f"'{value}'" for value in schema["enum"])
    return f"export type {name} = {values}"


def render() -> str:
    schema = Verdict.model_json_schema()
    blocks: list[str] = [HEADER]
    for name, definition in sorted(schema.get("$defs", {}).items()):
        blocks.append(
            _alias(name, definition) if "enum" in definition else _interface(name, definition)
        )
    blocks.append(_interface("Verdict", schema))
    return "\n\n".join(blocks) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    args = parser.parse_args()

    rendered = render()
    if args.check:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != rendered:
            print(f"{OUTPUT} is stale — run: python ui/scripts/gen_verdict_types.py")
            return 1
        print(f"{OUTPUT} is up to date")
        return 0

    OUTPUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
