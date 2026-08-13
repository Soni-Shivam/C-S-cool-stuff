from pathlib import Path

import yara

_DEFAULT_RULES_DIR = Path(__file__).resolve().parent.parent / "data" / "yara"


def compile_rules(rules_dir: str | Path | None = None) -> yara.Rules:
    rules_dir = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
    filepaths = {p.stem: str(p) for p in sorted(rules_dir.glob("*.yar"))}
    if not filepaths:
        raise FileNotFoundError(f"no .yar rules found in {rules_dir}")
    return yara.compile(filepaths=filepaths)


def scan_bytes(data: bytes, rules: yara.Rules) -> list[str]:
    return sorted(m.rule for m in rules.match(data=data))
