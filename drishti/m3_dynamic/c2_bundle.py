"""Orchestrator-side builder: turn observed pass-1 flows into a grounded inert bundle.

docs/PHASE_5_FRONTIER.md T5.4. The *builder*; `drishti/contracts/c2_bundle.py` is the
*contract* of the same basename — always import both fully qualified.

Detonation is two-pass. Pass 1 runs the sample against a blackholed network and captures
the requests it made to a C2 that never answered. This module reads those `CapturedFlow`s
and precomputes one provably-inert response per dead host, so pass 2 can answer them and
watch the dormant payload unroll. It runs **here, on the orchestrator**, because
`drishti-runtime` has no NAT and the detonator cannot reach a model; the bundle is staged
across as bytes on disk.

Three properties, each pinned by a test in `tests/unit/test_c2_bundle_builder.py`:

  * **Grounded or refused.** An entry cites the pass-1 evidence it was inferred from. An
    entry we cannot cite is a guess about what the malware expected, and this system's
    whole claim is that it does not guess. A bundle with zero entries is a legitimate
    outcome; an invented entry is not.
  * **Inert or dropped.** `assert_inert` runs inside `synthesise_response`; anything that
    comes back without `provably_inert` is discarded rather than served.
  * **Deterministic.** `C2Bundle.matches()` promises a stable answer only for stable
    `entries`. Everything here iterates in observation order — never a set, never an
    unordered dict — so two builds of one sample stage byte-identical bundles and a
    divergence between passes is always the sample's doing, never ours.
"""

from __future__ import annotations

import re
from typing import Any

from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry
from drishti.contracts.dynamic_trace import CapturedFlow
from drishti.logging import get_logger
from drishti.m3_dynamic.generative_c2 import (
    C2Request,
    C2ResponseKind,
    C2SchemaHint,
    _looks_like_beacon,
    derive_hints,
    synthesise_response,
)
from drishti.util import now

log = get_logger(__name__)

#: Last-resort ceiling, used only when settings cannot be resolved. The budget's real
#: home is `Settings.llm_max_calls_per_job`, which `LLMClient._check_budgets` enforces;
#: duplicating the number here would mean a deployment that lowered the config did not
#: lower this cap. Kept as a fallback so the builder stays importable and testable
#: without an environment — see `_job_call_budget`.
_FALLBACK_MAX_LLM_CALLS_PER_JOB = 25

#: The prefix `drishti.m3_dynamic.redaction` writes in place of a secret. See
#: `_clean_path_prefix` for why the builder has to cut the path here.
_REDACTION_MARKER = "[REDACTED:"

#: The kinds we are willing to label a served response with. `CapturedFlow.served_kind`
#: is an unbounded-vocabulary string capped at 32 chars, and it is what the report renders
#: as "this content is ours". Enum membership is strictly stronger than a length check.
_VALID_KINDS: frozenset[str] = frozenset(kind.value for kind in C2ResponseKind)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
#: Sentinel digest for a bundle refused over a bad `sha256`. Matches no real sample.
_NULL_SHA256 = "0" * 64


def _job_call_budget(max_calls: int | None) -> int:
    """The per-job LLM call ceiling: configured, never duplicated, never raisable.

    `Settings.llm_max_calls_per_job` is the single source of truth — it is what
    `LLMClient._check_budgets` enforces, so a deployment that lowers it must lower this
    cap too. Settings are read lazily and defensively: a missing `.env` must not stop a
    pure-function test from importing or calling the builder, so an unresolvable setting
    degrades to `_FALLBACK_MAX_LLM_CALLS_PER_JOB` rather than raising.
    """
    ceiling = _FALLBACK_MAX_LLM_CALLS_PER_JOB
    try:
        from drishti.config import get_settings

        ceiling = int(get_settings().llm_max_calls_per_job)
    except Exception as exc:  # no env, no keys, no problem — the cap still binds
        log.debug("c2_bundle_settings_unavailable", error=str(exc))
    if max_calls is None:
        return max(0, ceiling)
    # An explicit argument may only tighten the configured budget.
    return max(0, min(int(max_calls), ceiling))


def build_c2_bundle(
    sha256: str,
    flows: list[CapturedFlow],
    static_report: Any,
    *,
    client: Any | None = None,
    ledger: Any | None = None,
    max_calls: int | None = None,
) -> C2Bundle:
    """Precompute the inert responses to stage for pass 2 of one sample's detonation.

    Groups pass-1 flows by host, drops developer noise, fuses each host's observed
    request with the static schema hint, and spends **one** model call per distinct
    beacon host. An entry is emitted only when the response is provably inert, its kind
    is a real `C2ResponseKind`, and it cites pass-1 evidence.

    `max_calls` defaults to the configured per-job LLM budget and can only lower it.

    **This function does not raise.** A bad digest, a broken ledger or an unavailable
    provider costs entries, never the detonation — losing a run that already spent an
    emulator boot on real malware is far more expensive than losing a bundle.
    """
    if not _SHA256_RE.fullmatch(sha256 or ""):
        # Caller bug, caught before a single model call is spent — the constructor at the
        # bottom would otherwise raise a ValidationError only after the whole budget was
        # gone. The all-zero digest is an unmistakable sentinel that matches no sample,
        # and the bundle is empty, so it can never answer a request for one.
        log.error("c2_bundle_bad_sha256", sha256=str(sha256)[:80])
        return C2Bundle(sha256=_NULL_SHA256, built_at=now(), synthesis_client="none")

    hints = derive_hints(static_report)  # host -> C2SchemaHint, grounded in static evidence
    budget = _job_call_budget(max_calls)

    # Insertion-ordered: the first flow observed for a host is the one we answer, and the
    # order hosts were first seen in becomes the order of `entries`. This is the whole of
    # the determinism guarantee — do not replace with a set or a sorted-by-anything-else.
    by_host: dict[str, CapturedFlow] = {}
    for flow in flows:
        url = f"{flow.scheme}://{flow.host}{flow.path}"
        if _looks_like_beacon(url, flow.host) and flow.host not in by_host:
            by_host[flow.host] = flow

    entries: list[C2BundleEntry] = []
    calls = 0
    for host, flow in by_host.items():
        hint = hints.get(host)
        if hint is None or not hint.evidence_refs:
            # Ungrounded: no static evidence ties this host to the sample, so any answer
            # we synthesised would be a guess. Stay silent and let the host stay dead.
            log.info("c2_bundle_host_ungrounded", host=host)
            continue
        if calls >= budget:
            log.warning("c2_bundle_budget_reached", host=host, cap=budget)
            break
        entry = _entry_for(host, flow, hint, client=client, ledger=ledger)
        calls += 1
        if entry is not None:
            entries.append(entry)

    log.info(
        "c2_bundle_built",
        sha256=sha256[:12],
        hosts=len(by_host),
        entries=len(entries),
        calls=calls,
    )
    return C2Bundle(
        sha256=sha256,
        entries=tuple(entries),
        built_at=now(),
        synthesis_client=_client_name(client),
    )


def _entry_for(
    host: str,
    flow: CapturedFlow,
    hint: C2SchemaHint,
    *,
    client: Any | None,
    ledger: Any | None,
) -> C2BundleEntry | None:
    """One host's staged response, or None when it fails a gate.

    Every rejection is logged with its reason, because "the bundle has fewer entries than
    hosts" must be explicable from the run log rather than guessed at.
    """
    request = C2Request(
        host=host,
        url=f"{flow.scheme}://{host}{flow.path}",
        method=flow.method,
        body_preview=flow.req_body_preview,
        t_ms=flow.t_ms_epoch,
    )
    try:
        response = synthesise_response(request, hint, client=client, ledger=ledger)
    except Exception as exc:  # a broken model, ledger or hint costs one entry, not the run
        log.warning("c2_bundle_host_failed", host=host, error=str(exc))
        return None

    if not response.provably_inert:
        log.warning("c2_bundle_entry_not_inert", host=host)
        return None

    kind = response.response_kind
    if kind not in _VALID_KINDS:
        # Fail safe rather than fail open: with no entry, the proxy's sinkhole answers.
        log.warning("c2_bundle_entry_unknown_kind", host=host, kind=str(kind)[:64])
        return None

    candidate = C2BundleEntry(
        host=host,
        path_prefix=_clean_path_prefix(flow.path),
        response_kind=kind,
        served_status=response.served_status,
        served_content_type=response.served_content_type,
        served_body=response.served_body,
        # Read off the kind actually served, not the kind the hint hoped for: after a
        # fail-closed fallback the two differ, and the flag has to describe the bytes.
        is_payload_url=kind == C2ResponseKind.INERT_PAYLOAD_STUB.value,
        # Straight from the response, with no fallback to `hint.evidence_refs`.
        # `synthesise_response` already carries the hint's refs through and prepends the
        # ledger node id, so a fallback here would only paper over a synthesis that lost
        # its grounding — which is precisely the case the check below has to catch.
        derived_from=tuple(response.evidence_refs),
    )
    if not candidate.derived_from:
        # The contract lets an empty `derived_from` be constructed precisely so the
        # builder can build-then-reject. This is the rejection.
        log.warning("c2_bundle_entry_ungrounded", host=host)
        return None
    return candidate


def _clean_path_prefix(path: str) -> str:
    """The leading portion of an observed path that is safe to match on.

    `CapturedFlow.path` reaches us **redacted**, and the redaction is greedy in a way that
    matters here. Measured on the real rule (`[^\\s,;]{2,}` for a credential — URL paths
    contain no whitespace, so the match runs to the end of the path):

        raw       /log/password=hunter2/next
        redacted  /log/[REDACTED:CREDENTIAL]

    Two consequences. A `path_prefix` containing the marker can never match the live
    request, so the entry would be dead weight staged onto the VM. And the marker is not
    a stand-in for one segment — it swallowed the rest of the path, so nothing after it
    can be reconstructed.

    So: cut at the first marker and keep the clean head (`/log/`). That prefix does match,
    and it is honestly *broader* than the true endpoint rather than pretending to
    precision we redacted away. Do not "tidy" this into stripping the marker or matching
    the redacted text — both silently produce an entry that never fires.
    """
    head = path.split(_REDACTION_MARKER, 1)[0]
    return head or "/"


def _client_name(client: Any | None) -> str:
    """The model that produced the bundle, per `C2Bundle.synthesis_client`'s contract.

    `LLMClient` stores its resolved model on `_model` and exposes no public `model`, so a
    class-name fallback would have recorded the literal string "LLMClient" on every real
    bundle — a provenance field that cannot answer "which model wrote this". `_model` is
    read first for that reason; the class name survives only as a last resort, for a
    client type that genuinely has no model to name.

    Never reads an API key or anything else secret — this string is written to disk and
    staged onto the detonator.
    """
    if client is None:
        return "none"
    for attribute in ("model", "_model", "model_name"):
        value = getattr(client, attribute, None)
        if isinstance(value, str) and value:
            return value
    return type(client).__name__
