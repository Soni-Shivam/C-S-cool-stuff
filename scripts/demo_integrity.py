#!/usr/bin/env python3
"""Two stage demos of the evidence ledger's integrity guarantees.

    python scripts/demo_integrity.py reject   # an AI claim without evidence is refused
    python scripts/demo_integrity.py tamper   # an edited ledger is detected, at an exact seq

Both run against a throwaway database and a throwaway signing key, so neither can
touch a real job. They are safe to run on stage, repeatedly, in any order.

These exist because the two claims they demonstrate are the ones a judge is most
entitled to disbelieve. Asserting "our AI cannot hallucinate findings" and "our
evidence is tamper-evident" in a slide is worth nothing; making the code refuse,
live, is worth the whole section.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drishti.contracts import EvidenceType
from drishti.ledger.store import (
    APPEND_ONLY_TRIGGERS,
    LedgerStore,
    UngroundedClaimError,
)
from drishti.util import new_id

# Demo output is read off a projector by people who are not looking at a terminal all
# day. Colour carries the verdict faster than the words do.
BOLD, DIM, RED, GREEN, YELLOW, CYAN, RESET = (
    "\033[1m",
    "\033[2m",
    "\033[31m",
    "\033[32m",
    "\033[33m",
    "\033[36m",
    "\033[0m",
)


def _rule(title: str) -> None:
    print(f"\n{BOLD}{CYAN}── {title} {'─' * max(0, 66 - len(title))}{RESET}")


def _ok(msg: str) -> None:
    print(f"  {GREEN}✓{RESET} {msg}")


def _no(msg: str) -> None:
    print(f"  {RED}✗{RESET} {msg}")


def _note(msg: str) -> None:
    print(f"    {DIM}{msg}{RESET}")


def _fresh_store(tmp: Path) -> tuple[LedgerStore, str]:
    """A throwaway ledger with one job already open."""
    store = LedgerStore(tmp / "demo.db", tmp / "demo.key")
    job_id = new_id("job")
    store.open(job_id)
    return store, job_id


def demo_reject(tmp: Path) -> int:
    """Show that an AI claim citing no resolvable evidence is refused, not warned about."""
    store, job_id = _fresh_store(tmp)

    _rule("1. Ground truth: a real static finding goes in first")
    sink = store.append(
        type=EvidenceType.SINK_HIT,
        source_tool="m2_static.sinks",
        content={
            "sink": "Landroid/telephony/SmsManager;->sendTextMessage",
            "entrypoint": "in.gov.rto.challan.BootReceiver.onReceive",
            "hops": 4,
        },
        location="classes.dex:in/gov/rto/challan/BootReceiver.smali:88",
        confidence=1.0,
    )
    _ok(f"SINK_HIT appended  seq={sink.seq}  id={sink.id}")
    _note(f"node_hash {sink.node_hash[:32]}…")

    _rule("2. The model asserts a finding and cites NOTHING")
    try:
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="m4_genai.interpreter",
            content={
                "claim": "This application exfiltrates one-time passwords to a C2 server.",
                "evidence_refs": [],
            },
        )
        _no("ACCEPTED — this is a defect, the ledger should have refused this")
        return 1
    except UngroundedClaimError as exc:
        _ok(f"{BOLD}REFUSED{RESET} — {exc}")
        _note("The claim was plausible, well-formed, and probably even true.")
        _note("It still does not enter the ledger, so it cannot reach the report.")

    _rule("3. The model cites evidence that does not exist")
    fabricated = "ev_00000000deadbeef"
    try:
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="m4_genai.interpreter",
            content={
                "claim": "This application exfiltrates one-time passwords to a C2 server.",
                "evidence_refs": [fabricated],
            },
        )
        _no("ACCEPTED — this is a defect, a fabricated citation must not resolve")
        return 1
    except UngroundedClaimError as exc:
        _ok(f"{BOLD}REFUSED{RESET} — {exc}")
        _note("A hallucinated citation is caught by resolution, not by string shape.")

    _rule("4. The same claim, cited to the real finding")
    claim = store.append(
        type=EvidenceType.AI_CLAIM,
        source_tool="m4_genai.interpreter",
        content={
            "claim": "This application forwards received SMS to a remote endpoint.",
            "evidence_refs": [sink.id],
        },
        confidence=0.82,
        parents=(sink.id,),
    )
    _ok(f"ACCEPTED  seq={claim.seq}  id={claim.id}  confidence={claim.confidence}")
    _note(f"cites {sink.id} — which a reader can open and check for themselves")

    _rule("5. The rejections left no trace in the sequence")
    chain = store.verify_chain(job_id)
    seqs = [n.seq for n in store.query(job_id=job_id)]
    _ok(f"chain ok={chain.ok}  nodes={chain.node_count}  seqs={seqs}")
    _note("Two claims were refused, yet the sequence is contiguous with no gaps:")
    _note("grounding is checked INSIDE the write transaction, so a rejected node")
    _note("never consumes a seq and never leaves a hole for an auditor to wonder about.")

    print(
        f"\n{BOLD}The model does not get to decide what counts as evidence.{RESET}\n"
        f"{DIM}Every AI sentence in a DRISHTI report resolves to a node like {sink.id},\n"
        f"or it was never written.{RESET}"
    )
    store.close()
    return 0


def demo_tamper(tmp: Path) -> int:
    """Show defence in depth: SQL refuses the edit, and the chain catches it anyway."""
    store, job_id = _fresh_store(tmp)

    _rule("1. Build a short chain of real findings")
    findings = [
        (EvidenceType.FILE_META, {"sha256": "a3f1…", "size": 4_182_233}),
        (EvidenceType.MANIFEST_ENTRY, {"permission": "android.permission.RECEIVE_SMS"}),
        (EvidenceType.PERMISSION_COMBO, {"combo": "SMS+INTERNET+BOOT", "severity": "high"}),
        (EvidenceType.SINK_HIT, {"sink": "SmsManager->sendTextMessage", "hops": 4}),
        (EvidenceType.SCORE_FACTOR, {"factor": "B", "value": 0.91}),
    ]
    for etype, content in findings:
        node = store.append(type=etype, source_tool="demo", content=content)
        _ok(f"seq={node.seq}  {etype.value}")

    before = store.verify_chain(job_id)
    _ok(f"{BOLD}chain verifies: ok={before.ok}  nodes={before.node_count}{RESET}")

    target_seq = 3
    _rule(f"2. An insider edits the finding at seq={target_seq}, through raw SQL")
    _note("Not via the API — straight at the SQLite file, bypassing the application.")
    store.close()

    conn = sqlite3.connect(tmp / "demo.db", isolation_level=None)
    forged = '{"sink": "nothing to see here", "hops": 0}'
    try:
        conn.execute(
            "UPDATE evidence SET content = ? WHERE job_id = ? AND seq = ?",
            (forged, job_id, target_seq),
        )
        _no("the UPDATE succeeded — the append-only triggers are missing")
    except sqlite3.IntegrityError as exc:
        _ok(f"{BOLD}SQL REFUSED{RESET} — {exc}")
        _note(f"Triggers {', '.join(APPEND_ONLY_TRIGGERS)} make the table append-only")
        _note("in the database itself, not merely in the Python that writes to it.")

    _rule("3. Now assume the attacker owns the file and drops the triggers")
    for trigger in APPEND_ONLY_TRIGGERS:
        conn.execute(f"DROP TRIGGER IF EXISTS {trigger}")
    conn.execute(
        "UPDATE evidence SET content = ? WHERE job_id = ? AND seq = ?",
        (forged, job_id, target_seq),
    )
    changed = conn.execute(
        "SELECT content FROM evidence WHERE job_id = ? AND seq = ?", (job_id, target_seq)
    ).fetchone()[0]
    conn.close()
    _no(f"UPDATE succeeded at the SQL layer — row now reads {changed}")
    _note("At this point the database has been successfully rewritten.")

    _rule("4. Verify the chain again")
    store2 = LedgerStore(tmp / "demo.db", tmp / "demo.key")
    after = store2.verify_chain(job_id)
    if after.ok:
        _no("chain still reports ok — this is a defect, tampering must be detected")
        store2.close()
        return 1
    _ok(f"{BOLD}{RED}TAMPERING DETECTED{RESET}")
    print(f"      ok            : {RED}{after.ok}{RESET}")
    print(f"      first_bad_seq : {RED}{BOLD}{after.first_bad_seq}{RESET}")
    print(f"      reason        : {RED}{after.reason}{RESET}")
    print(f"      nodes walked  : {after.node_count}")

    if after.first_bad_seq != target_seq:
        _no(f"expected the break at seq={target_seq}, got {after.first_bad_seq}")
        store2.close()
        return 1
    _ok(f"the break is reported at exactly the edited node, seq={target_seq}")
    _note("Not 'the ledger is broken somewhere'. An auditor gets the precise node.")

    print(
        f"\n{BOLD}This is not a log file. It is a signed hash chain.{RESET}\n"
        f"{DIM}Rewriting one field invalidates that node's hash, which breaks the link\n"
        f"every later node carries. Editing evidence without detection means forging\n"
        f"an Ed25519 signature for every node from {target_seq} to the end.{RESET}"
    )
    store2.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "demo",
        choices=("reject", "tamper", "both"),
        help="reject = ungrounded AI claim refused; tamper = edited ledger detected",
    )
    args = parser.parse_args(argv)

    with tempfile.TemporaryDirectory(prefix="drishti-demo-") as raw:
        tmp = Path(raw)
        if args.demo == "reject":
            return demo_reject(tmp)
        if args.demo == "tamper":
            return demo_tamper(tmp)
        rc = demo_reject(tmp)
        print()
        with tempfile.TemporaryDirectory(prefix="drishti-demo-") as raw2:
            return rc or demo_tamper(Path(raw2))


if __name__ == "__main__":
    raise SystemExit(main())
