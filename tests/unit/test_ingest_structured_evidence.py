"""The harness measured dex loads, C2 URLs and pre-encryption plaintext. Keep them.

`ObservationEvent` is deliberately flat — technique, mitre, hook, and one redacted
`detail` string — because the wire contract crossing out of the detonation VM is kept as
narrow as it can be. The consequence is that the structured evidence the hooks *did*
capture arrives as prose:

    DexClassLoader.$init   loaded dex path=/data/user/0/com.x/cache/ngzvnyttctwi
    URL.openConnection     opened connection to=http://vgf....cfd/api/mirrors
    Cipher.doFinal         crypto op plaintext={"xc":"gSWI",...}

Dropping that on the floor during conversion is what made the Sandbox tab report
`0 network flows · 0 dex loads · 0 decrypted blobs` for samples that had produced 11
`DexClassLoader.$init` calls, 305 `URL.openConnection` calls and 505 `Cipher.doFinal`
calls between them. It also kept the `D` drift term at zero for every run, because
`D` reads `dex_loads[*].in_original_apk`.

The discipline being tested is *conservative* parsing. A field is populated only when
the marker that carries it is actually present; a detail that does not match leaves the
structured record unbuilt rather than half-invented. `in_original_apk` in particular is
derived from the path, never defaulted into an accusation — it is the strongest single
input to `D`, and asserting it without evidence is the failure mode this whole project
is organised against.
"""

from __future__ import annotations

from drishti.contracts.dynamic_trace import ObservationArtifact
from drishti.m3_dynamic.ingest import artifact_to_trace
from tests.unit._observation_builders import artifact_with


def _trace(*details: tuple[str, str, str]):
    """(hook, mitre, detail) triples -> a converted trace."""
    return artifact_to_trace(artifact_with(*details))


# ── dex loads (T1407) ────────────────────────────────────────────────────────
def test_a_runtime_dex_load_is_lifted_with_its_path() -> None:
    trace = _trace(
        ("DexClassLoader.$init", "T1407", "loaded dex path=/data/user/0/com.x/cache/ngzvnyttctwi")
    )
    assert len(trace.dex_loads) == 1
    load = trace.dex_loads[0]
    assert load.loader == "DexClassLoader.$init"
    assert load.path == "/data/user/0/com.x/cache/ngzvnyttctwi"


def test_a_dex_under_app_private_storage_is_not_in_the_original_apk() -> None:
    """`/data/user/...` is written at runtime; an APK-internal dex lives in /data/app.

    This is the D term's input, so it is derived from the path rather than defaulted.
    """
    trace = _trace(
        ("DexClassLoader.$init", "T1407", "loaded dex path=/data/user/0/com.x/app_DynamicOptDex/a")
    )
    assert trace.dex_loads[0].in_original_apk is False


def test_a_dex_inside_the_installed_apk_is_not_called_a_dropper() -> None:
    """A split APK loading its own dex is normal. Calling it drift would be a false D."""
    trace = _trace(
        ("DexClassLoader.$init", "T1407", "loaded dex path=/data/app/com.x-1/base.apk!/classes.dex")
    )
    assert trace.dex_loads[0].in_original_apk is True


def test_a_dex_load_with_no_recoverable_path_claims_nothing() -> None:
    """No path means no basis for an `in_original_apk` verdict, so no record is built."""
    trace = _trace(("DexClassLoader.$init", "T1407", "loaded dex"))
    assert trace.dex_loads == ()


# ── network flows (T1437) ────────────────────────────────────────────────────
def test_an_outbound_connection_is_lifted_with_host_and_url() -> None:
    trace = _trace(
        ("URL.openConnection", "T1437", "opened connection to=http://evil.example/api/mirrors")
    )
    assert len(trace.network_flows) == 1
    flow = trace.network_flows[0]
    assert flow.url == "http://evil.example/api/mirrors"
    assert flow.host == "evil.example"
    assert flow.tls_intercepted is False, "no proxy ran; this came from an API hook"
    assert flow.synthesised is False, "a real observation is not a synthesised C2 response"


def test_a_malformed_url_does_not_become_a_flow() -> None:
    trace = _trace(("URL.openConnection", "T1437", "opened connection"))
    assert trace.network_flows == ()


# ── decrypted blobs (T1521) ──────────────────────────────────────────────────
def test_plaintext_before_encryption_is_kept() -> None:
    trace = _trace(("Cipher.doFinal", "T1521", 'crypto op plaintext={"xc":"gSWI","lB":"pittsep"}'))
    assert len(trace.decrypted_blobs) == 1
    blob = trace.decrypted_blobs[0]
    assert blob.plaintext_preview.startswith('{"xc"')
    assert blob.contains_url is False


def test_a_blob_carrying_a_url_is_flagged() -> None:
    trace = _trace(("Cipher.doFinal", "T1521", "crypto op plaintext=POST http://c2.example/x"))
    assert trace.decrypted_blobs[0].contains_url is True


# ── aggregation still governs (CLAUDE.md rule 11) ────────────────────────────
def test_occurrences_are_carried_not_expanded() -> None:
    """1,925 identical crypto ops are one record with a count, never 1,925 records."""
    same = ("Cipher.doFinal", "T1521", "crypto op plaintext=aaa")
    trace = artifact_to_trace(artifact_with(*([same] * 50)))
    assert len(trace.decrypted_blobs) == 1
    assert trace.decrypted_blobs[0].occurrences == 50


def test_an_unrecognised_hook_adds_no_structured_records() -> None:
    """Only hooks whose shape is known are lifted. The rest stay as api_events."""
    trace = _trace(("PackageManager.getPackageInfo", "T1418", "queried com.example"))
    assert trace.dex_loads == ()
    assert trace.network_flows == ()
    assert trace.decrypted_blobs == ()
    assert trace.api_events, "the event itself is still reported"


# ── the real corpus ──────────────────────────────────────────────────────────
def test_the_committed_captures_actually_yield_evidence() -> None:
    """A parser that silently matches nothing would pass every test above."""
    import pathlib

    totals = {"dex": 0, "net": 0, "blob": 0}
    for path in pathlib.Path("data/fixtures/observations").glob("*.json"):
        artifact = ObservationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        if not artifact.observations:
            continue
        trace = artifact_to_trace(artifact)
        totals["dex"] += len(trace.dex_loads)
        totals["net"] += len(trace.network_flows)
        totals["blob"] += len(trace.decrypted_blobs)
    assert totals["dex"] > 0, "11 DexClassLoader.$init events were captured"
    assert totals["net"] > 0, "305 URL.openConnection events were captured"
    assert totals["blob"] > 0, "505 Cipher.doFinal events were captured"
