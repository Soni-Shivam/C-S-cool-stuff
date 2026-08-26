"""`ObservationArtifact` -> `DynamicTrace`. The one conversion, used by both paths.

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.6.

The detonator writes an `ObservationArtifact`; the rest of the system reads a
`DynamicTrace`. That conversion happens twice in the product's life — once offline when
a captured artifact is frozen into a replayable fixture, and once online when
`LiveSandboxSource` collects a fresh run off the sealed VM — and it must be the *same*
conversion, or a replay and a live run of the same detonation would disagree while both
looked authoritative. This module is that single function;
`scripts/observation_to_trace.py` is a CLI over it, and
`tests/contract/test_observation_ingest_parity.py` is what stops it becoming a copy.

Three rules are enforced here rather than remembered:

* **Aggregate before anything reaches the ledger or a prompt** (CLAUDE.md rule 11). One
  real sample called `Cipher.doFinal` 1,925 times in 103 seconds; a node per event would
  have blown both the ledger sanity band and the 12k-token prompt budget. Grouping keys
  on `(technique, mitre, hook)` and keeps an occurrence count, so the *rate* stays
  visible to a human without being able to move a score.
* **`detonated` is a written-down rule, not a judgement.** The sample installed, ran
  under instrumentation, and produced at least one observation. Anything less is
  `inconclusive` — never benign, because environment-aware stalling and a clean app are
  indistinguishable from the outside (CLAUDE.md honesty requirements).
* **A measurement is never `synthetic`.** `ObservationArtifact` pins `simulated` to
  `False` at the type level, so anything derived from one is a real execution. The flag
  exists to mark hand-authored fixtures, and this path can never produce one.
* **Network flows arrive from two layers and are reconciled into one.** The `URL.open*`
  hooks see the sample *deciding* to connect; the on-VM proxy sees the request. Both are
  lifted, converted to the run's own relative clock, grouped by `(host, path, method)`
  and capped — see `_merge_flows` for why "who answered" and "whose destination it is"
  are two different questions (docs/01_DATA_CONTRACTS.md A19).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from drishti.contracts.dynamic_trace import (
    ApiEvent,
    CapturedFlow,
    DecryptedBlob,
    DexLoadEvent,
    DynamicTrace,
    EvasionObservation,
    NetworkFlow,
    ObservationArtifact,
    TraceSourceKind,
)
from drishti.logging import get_logger
from drishti.m3_dynamic import evasion
from drishti.m3_dynamic.normaliser import MAX_OBSERVATION_GROUPS, ObservationGroup, aggregate

log = get_logger(__name__)

#: Hard cap on network flows reaching the trace, and through it the ledger and a prompt.
#: Mirrors `normaliser.MAX_OBSERVATION_GROUPS` and exists for the identical reason
#: (CLAUDE.md rule 11): one real sample fired 1,925 `Cipher.doFinal` events in 103
#: seconds, and a beaconing sample emits network flows at the same order of rate. A row
#: per request would blow the ledger sanity band and the 12k-token prompt budget.
MAX_CAPTURED_FLOWS = MAX_OBSERVATION_GROUPS


def _offset_ms(stamp: str, start: str) -> int:
    """Milliseconds from the run's own start, so replay keeps the real relative timing."""
    try:
        delta = datetime.fromisoformat(stamp.replace("Z", "+00:00")) - datetime.fromisoformat(
            start.replace("Z", "+00:00")
        )
    except ValueError:
        return 0
    return max(0, int(delta.total_seconds() * 1000))


def _epoch_ms(stamp: str) -> int | None:
    """Wall-clock milliseconds for an ISO stamp, or None when it cannot be read.

    A stamp without an offset is read as UTC. The harness writes offsets, but reading a
    naive stamp as *local* time would shift every captured flow by the analyst's timezone
    and silently misalign the two clocks this module reconciles.
    """
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.timestamp() * 1000)


# ─── host provenance ─────────────────────────────────────────────────────────
# `synthesised` says who wrote the RESPONSE. These say whose DESTINATION it is, and
# that is the question IOC publication turns on (docs/01_DATA_CONTRACTS.md A19).

#: Single-label names that are ours by definition. An unqualified name is never
#: published anyway, but naming these keeps the intent readable.
_LAB_HOSTNAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

#: A URL inside a body. Used to find the hosts a response WE authored pointed the sample
#: at: if it went there, it went because of something we told it.
_URL_IN_TEXT = re.compile(r"[a-z][a-z0-9+.\-]*://([^\s\"'\\/?#,;)\]}<>]+)", re.IGNORECASE)


def bare_host(host: str) -> str:
    """Lower-cased host with any port, brackets and trailing dot removed."""
    name = (host or "").strip().lower().rstrip(".")
    if name.startswith("["):  # [::1]:8080
        return name[1:].split("]", 1)[0]
    if name.count(":") == 1:  # host:port — an unbracketed IPv6 literal has more
        return name.split(":", 1)[0]
    return name


def _as_ip(name: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(name)
    except ValueError:
        return None


def is_lab_destination(host: str) -> bool:
    """True when `host` is DRISHTI's own infrastructure, not a destination the sample chose.

    `assert_inert` rewrites every URL-shaped value it sanitises to
    `http://127.0.0.1:9/inert`, and the emulator reaches the analysis host at `10.0.2.2`.
    A sample that follows either produces a perfectly ordinary-looking flow, and
    publishing it would export our own injected string to a SOC as adversary
    infrastructure. Anything not globally routable — loopback, RFC1918, link-local
    (which is where the `169.254.169.254` metadata address lives), reserved — is ours or
    is unusable as an indicator, and either way is not published. Unreadable input fails
    closed for the same reason.
    """
    name = bare_host(host)
    if not name or name in _LAB_HOSTNAMES:
        return True
    address = _as_ip(name)
    if address is not None:
        return not address.is_global
    return False


def indicator_kind(host: str) -> str | None:
    """`"domain"`, `"ipv4"`, `"ipv6"` for a publishable host, or None to withhold it.

    Fails toward NOT publishing. A routable IP is an address, never a `domain-name` —
    a recipient's tooling matches on the SDO type, so the wrong one is both a lie and a
    silent miss. A single-label name is withheld: it is not something a SOC can block.
    """
    name = bare_host(host)
    if is_lab_destination(name):
        return None
    address = _as_ip(name)
    if address is not None:
        return "ipv6" if address.version == 6 else "ipv4"
    return "domain" if "." in name else None


def _authored_hosts(flows: tuple[CapturedFlow, ...]) -> frozenset[str]:
    """Hosts named inside a response body WE wrote. Those destinations are ours."""
    hosts: set[str] = set()
    for flow in flows:
        if not flow.synthesised:
            continue  # a host the ATTACKER named is evidence, and stays publishable
        for match in _URL_IN_TEXT.finditer(flow.resp_body_preview or ""):
            host = bare_host(match.group(1))
            if host:
                hosts.add(host)
    return frozenset(hosts)


def _instance_id(artifact: ObservationArtifact) -> str | None:
    """The VM instance the run happened on, as recorded in the harness diagnostics."""
    return next(
        (d.split(":", 1)[1] for d in artifact.diagnostics if d.startswith("containment:")),
        None,
    )


def _evasion_observations(
    artifact: ObservationArtifact, groups_start: str
) -> tuple[EvasionObservation, ...]:
    """Lift the evasion detector's verdict onto the contract.

    Without this the frontier cannot fire on a real capture: `_frontier` reads
    `trace.evasion_observations` to decide what to synthesise, and a trace that dropped
    them on the floor during conversion would make every captured run look like a sample
    that never probed its environment.
    """
    normalised = aggregate([event.model_dump(mode="json") for event in artifact.observations])
    verdict = evasion.detect(normalised, installed_and_ran=bool(artifact.observations))
    if not verdict.stalled:
        return ()

    first_seen = {
        (event.technique, event.mitre, event.source_hook): event.occurred_at
        for event in reversed(artifact.observations)
    }
    lookup = {group.hook: group for group in normalised.groups}
    observations: list[EvasionObservation] = []
    for item in verdict.observations:
        group = lookup.get(item.probe)
        stamp = (
            first_seen.get((group.technique, group.mitre, group.hook), groups_start)
            if group
            else groups_start
        )
        observations.append(
            EvasionObservation(
                probe_kind=item.probe,
                # The detector names the morph that would answer the probe; the queried
                # target is what the sample actually asked about, when the hook recorded
                # it. `first_detail` is already redacted inside the guest.
                queried=(group.first_detail if group and group.first_detail else item.probe),
                result="MISS",
                t_ms=_offset_ms(stamp, groups_start),
                followed_by_stall=True,
                inferred_requirement=item.morph,
            )
        )
    return tuple(observations)


#: Dex paths that live inside the *installed* package rather than being written at
#: runtime. A split APK loading its own `classes.dex` is ordinary behaviour; calling it
#: drift would put a false positive straight into the `D` term.
_APK_INTERNAL_DEX_PREFIXES = ("/data/app/", "/system/", "/vendor/", "/product/")

#: Markers the hooks put in front of the value they captured. Parsing is deliberately
#: anchored on these: a detail that does not carry its marker yields no structured
#: record, rather than a record built out of a guess.
_DEX_MARKER = "path="
_URL_MARKER = "to="
_PLAINTEXT_MARKER = "plaintext="


def _after(detail: str, marker: str) -> str | None:
    """The value a hook wrote after its marker, or None if the marker is absent."""
    _, sep, rest = detail.partition(marker)
    value = rest.strip()
    return value if sep and value else None


def _structured(
    groups: tuple[ObservationGroup, ...], offsets: dict[str, int]
) -> tuple[tuple[DexLoadEvent, ...], tuple[NetworkFlow, ...], tuple[DecryptedBlob, ...]]:
    """Lift the evidence the hooks captured out of their flat `detail` strings.

    `ObservationEvent` carries one redacted string per observation, so the dropped-dex
    path, the C2 URL and the pre-encryption plaintext all arrive as prose. Leaving them
    there made the Sandbox tab report zero of each for samples that had genuinely
    produced them, and held `D` at zero for every run.

    Aggregation happens first and is preserved: 1,925 identical crypto operations are
    one record carrying `occurrences=1925`, never 1,925 records (CLAUDE.md rule 11).
    """
    dex: list[DexLoadEvent] = []
    flows: list[NetworkFlow] = []
    blobs: list[DecryptedBlob] = []

    for group in groups:
        detail = group.first_detail or ""
        t_ms = offsets.get(group.hook, 0)

        if group.hook.startswith("DexClassLoader") or group.mitre == "T1407":
            path = _after(detail, _DEX_MARKER)
            if path:
                dex.append(
                    DexLoadEvent(
                        t_ms=t_ms,
                        loader=group.hook,
                        path=path,
                        in_original_apk=path.startswith(_APK_INTERNAL_DEX_PREFIXES),
                    )
                )
            continue

        if group.hook.startswith("URL.open") or group.mitre in {"T1437", "T1095"}:
            url = _after(detail, _URL_MARKER)
            if url and "://" in url:
                flows.append(
                    NetworkFlow(
                        t_ms=t_ms,
                        method="GET",  # the hook records the connection, not the verb
                        url=url,
                        host=url.split("://", 1)[1].split("/", 1)[0],
                        # Neither flag may be inferred from an API hook: no proxy ran,
                        # and a real observation is not a synthesised C2 response.
                        tls_intercepted=False,
                        synthesised=False,
                        # One real sample fired this hook 305 times. The rate is a
                        # finding; 305 rows would be a budget overrun (rule 11).
                        occurrences=group.occurrences,
                    )
                )
            continue

        if group.hook.startswith("Cipher.") or group.mitre == "T1521":
            plaintext = _after(detail, _PLAINTEXT_MARKER)
            if plaintext:
                blobs.append(
                    DecryptedBlob(
                        t_ms=t_ms,
                        plaintext_preview=plaintext[:512],
                        length_bytes=len(plaintext),
                        contains_url="://" in plaintext,
                        contains_dex_magic=plaintext.startswith("dex\n"),
                        occurrences=group.occurrences,
                    )
                )

    return tuple(dex), tuple(flows), tuple(blobs)


def _lift_captured_flows(flows: tuple[CapturedFlow, ...], start: str) -> tuple[NetworkFlow, ...]:
    """Proxy captures -> trace flows, on the run's own clock.

    `CapturedFlow.t_ms_epoch` is wall-clock (~1.79e12); every `t_ms` on the trace side is
    an offset from the run's start. Lifting without converting leaves one beacon rendered
    twice — once "observed" at 4.2s from the hook and once "synthesised" in 2026 from the
    proxy — because no key containing time can ever collide across the two sources.

    `tls_intercepted` is hardcoded `False` and stays that way: the detonator captures
    cleartext HTTP and never installs a system CA (CLAUDE.md verified lab fact 7).
    """
    base = _epoch_ms(start)
    lifted: list[NetworkFlow] = []
    for flow in flows:
        path = flow.path or "/"
        lifted.append(
            NetworkFlow(
                # An unreadable start, or a flow stamped before it, reads as t=0 rather
                # than as a negative offset or a leaked epoch.
                t_ms=max(0, flow.t_ms_epoch - base) if base is not None else 0,
                method=flow.method.upper(),
                url=f"{flow.scheme}://{flow.host}{path}",
                host=flow.host,
                status=flow.status,
                req_body_preview=flow.req_body_preview,
                resp_body_preview=flow.resp_body_preview or None,
                synthesised=flow.synthesised,
                tls_intercepted=False,
            )
        )
    return tuple(lifted)


def _url_path(url: str) -> str:
    """The path part of a URL, without query or fragment. `/` when there is none."""
    rest = url.split("://", 1)[-1]
    _, sep, tail = rest.partition("/")
    path = f"/{tail}" if sep else "/"
    return path.split("?", 1)[0].split("#", 1)[0] or "/"


@dataclass
class _FlowGroup:
    """One `(host, path, method)` destination, with how often the sample went there."""

    flow: NetworkFlow
    count: int
    from_proxy: bool
    index: int


def _merge_flows(
    hook_flows: tuple[NetworkFlow, ...],
    captured: tuple[NetworkFlow, ...],
    authored_hosts: frozenset[str],
) -> tuple[tuple[NetworkFlow, ...], int]:
    """Reconcile both views of the sample's traffic into capped, counted rows.

    Returns the rows and how many groups the cap dropped.

    Three things happen here, and each fixes a specific way the report lies without it:

    * **Grouping by `(host, path, method)` with a count** (CLAUDE.md rule 11). A beaconing
      sample emits thousands of identical requests; the rate is a finding, a row per
      request is a budget overrun.
    * **The proxy's view subsumes the hook's for the same `(host, path)`.** The hook sees
      the sample decide to connect and records no verb (`_structured` writes `GET` as a
      placeholder); the proxy sees the request, its real method, its status and its body.
      Two rows for one request would show the C2 contacted twice. Counts merge with
      `max`, never summed — two views of one request are still one request, and a hook
      count above the proxy's means connections that never became proxied requests.
    * **Destination provenance is derived**, from the host and from the bodies we
      authored, so it covers the hook path too — which hardcodes `synthesised=False` and
      would otherwise export our own sinkhole as adversary infrastructure.
    """
    groups: dict[tuple[str, str, str], _FlowGroup] = {}
    for flow, from_proxy in [(f, False) for f in hook_flows] + [(f, True) for f in captured]:
        key = (bare_host(flow.host), _url_path(flow.url), flow.method.upper())
        # A hook flow already carries its group's count (one real sample fired
        # `URL.openConnection` 305 times); a captured flow is one request.
        seen = max(1, flow.occurrences)
        existing = groups.get(key)
        if existing is None:
            groups[key] = _FlowGroup(flow, seen, from_proxy, len(groups))
            continue
        existing.count += seen
        earliest = min(existing.flow.t_ms, flow.t_ms)
        if from_proxy and not existing.from_proxy:
            existing.flow = flow
            existing.from_proxy = True
        existing.flow = existing.flow.model_copy(update={"t_ms": earliest})

    # A hook group whose (host, path) the proxy also saw is the same traffic seen one
    # layer down. Fold it in rather than showing it twice.
    proxy_keys: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for key, group in groups.items():
        if group.from_proxy:
            proxy_keys.setdefault((key[0], key[1]), []).append(key)
    for key in list(groups):
        group = groups[key]
        candidates = proxy_keys.get((key[0], key[1]), [])
        if group.from_proxy or not candidates:
            continue
        target = groups[max(candidates, key=lambda k: (groups[k].count, -groups[k].index))]
        target.count = max(target.count, group.count)
        target.flow = target.flow.model_copy(
            update={"t_ms": min(target.flow.t_ms, group.flow.t_ms)}
        )
        del groups[key]

    # Rank for the cap, emit in first-seen order. Ranking by count means a one-off is
    # dropped before a 30x beacon; emitting in the original order means the cap changes
    # what survives, never how the survivors are ordered.
    ranked = sorted(groups.values(), key=lambda g: (-g.count, g.index))
    kept = {g.index for g in ranked[:MAX_CAPTURED_FLOWS]}
    dropped = len(ranked) - len(kept)
    if dropped:
        log.warning("network_flows_capped", dropped=dropped, cap=MAX_CAPTURED_FLOWS)

    out: list[NetworkFlow] = []
    for group in sorted((g for g in groups.values() if g.index in kept), key=lambda g: g.index):
        host = bare_host(group.flow.host)
        out.append(
            group.flow.model_copy(
                update={
                    "occurrences": group.count,
                    "injected_destination": is_lab_destination(host) or host in authored_hosts,
                }
            )
        )
    return tuple(out), dropped


def artifact_to_trace(
    artifact: ObservationArtifact,
    *,
    source: TraceSourceKind = TraceSourceKind.LIVE,
    morphs_applied: tuple[str, ...] = (),
) -> DynamicTrace:
    """Normalise one captured detonation into the trace contract.

    `source` defaults to LIVE because that is what produced the artifact. Only
    `ReplayTraceSource` may stamp REPLAY, and it does so on load rather than trusting
    whatever a fixture file happens to say.
    """
    events = [event.model_dump(mode="json") for event in artifact.observations]
    normalised = aggregate(events)

    start = artifact.observations[0].occurred_at if artifact.observations else artifact.started_at
    first_seen: dict[tuple[str, str, str], str] = {}
    for event in artifact.observations:
        first_seen.setdefault((event.technique, event.mitre, event.source_hook), event.occurred_at)

    api_events = tuple(
        ApiEvent(
            t_ms=_offset_ms(first_seen.get((g.technique, g.mitre, g.hook), start), start),
            api=g.hook,
            args=(g.first_detail,) if g.first_detail else (),
            count=g.occurrences,
        )
        for g in normalised.groups
    )

    offsets = {
        g.hook: _offset_ms(first_seen.get((g.technique, g.mitre, g.hook), start), start)
        for g in normalised.groups
    }
    dex_loads, hook_flows, decrypted_blobs = _structured(normalised.groups, offsets)

    # Both layers of the same traffic, on one clock, grouped and capped. `start` is the
    # trace's zero point, so the proxy's wall-clock stamps convert against it.
    network_flows, dropped_flows = _merge_flows(
        hook_flows,
        _lift_captured_flows(artifact.captured_flows, start),
        _authored_hosts(artifact.captured_flows),
    )
    errors = list(normalised.errors)
    if dropped_flows:
        errors.append(
            f"{dropped_flows} network flow group(s) dropped at the {MAX_CAPTURED_FLOWS} cap"
        )

    detonated = bool(artifact.observations) and artifact.outcome == "completed"

    return DynamicTrace(
        run_id=f"run_{artifact.sha256[:12]}",
        source=source,
        detonated=detonated,
        detonation_reason=(
            f"{len(artifact.observations)} instrumented observations across "
            f"{len(normalised.techniques)} distinct MITRE techniques"
            if detonated
            else "no observations were produced; treat as inconclusive, not benign"
        ),
        outcome=artifact.outcome,
        api_events=api_events,
        network_flows=network_flows,
        decrypted_blobs=decrypted_blobs,
        dex_loads=dex_loads,
        evasion_observations=_evasion_observations(artifact, start),
        morphs_applied=morphs_applied,
        emulator_image=artifact.metadata.emulator_image,
        vm_instance_id=_instance_id(artifact),
        harness_version=artifact.metadata.harness_version,
        containment_verified=artifact.metadata.containment_verified,
        captured_at=artifact.started_at,
        # Never derived from the artifact: an ObservationArtifact is a measurement by
        # construction (`simulated: Literal[False]`), so this path cannot mark one
        # hand-authored no matter what else went wrong in the run.
        synthetic=False,
        errors=tuple(errors),
        partial=bool(errors) or artifact.outcome != "completed",
    )
