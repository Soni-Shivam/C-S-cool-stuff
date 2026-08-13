"""`python -m drishti.ledger.cli verify --job job_x`

A green/red table. This is a demo asset as much as a debugging tool: running it live
takes four seconds and proves the trust claim better than a slide can
(docs/PHASE_0_FOUNDATIONS.md T0.4).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from drishti.ledger.store import LedgerStore

DEFAULT_DB = Path("data/drishti.db")
DEFAULT_KEY = Path("data/ledger_ed25519.key")

_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _colour(text: str, code: str, *, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def cmd_verify(args: argparse.Namespace) -> int:
    colour = sys.stdout.isatty() and not args.no_colour
    store = LedgerStore(args.db, args.key)
    try:
        result = store.verify_chain(args.job)
        nodes = store.query(job_id=args.job)

        print(f"job      {args.job}")
        print(f"db       {args.db}")
        print(f"pubkey   {store.public_key_hex}")
        print(f"nodes    {result.node_count}")
        print()

        if args.verbose:
            print(f"{'seq':>5}  {'type':<18} {'source':<22} node_hash")
            for node in nodes:
                print(
                    f"{node.seq:>5}  {node.type.value:<18} {node.source_tool:<22} "
                    f"{_colour(node.node_hash[:16], _DIM, enabled=colour)}"
                )
            print()

        if result.ok:
            print(_colour(f"CHAIN OK  {result.node_count} nodes verified", _GREEN, enabled=colour))
            return 0

        print(_colour("CHAIN BROKEN", _RED, enabled=colour))
        print(f"  first bad seq : {result.first_bad_seq}")
        print(f"  reason        : {result.reason}")
        return 1
    finally:
        store.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="drishti.ledger.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a job's hash chain and signatures")
    verify.add_argument("--job", required=True, help="job id, e.g. job_01932ab90e2f")
    verify.add_argument("--db", type=Path, default=DEFAULT_DB)
    verify.add_argument("--key", type=Path, default=DEFAULT_KEY)
    verify.add_argument("-v", "--verbose", action="store_true", help="list every node")
    verify.add_argument("--no-colour", action="store_true")
    verify.set_defaults(func=cmd_verify)

    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
