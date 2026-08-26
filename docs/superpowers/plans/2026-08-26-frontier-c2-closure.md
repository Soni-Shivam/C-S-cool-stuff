# Frontier C2 Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire DRISHTI's built-but-unplugged `generative_c2.py` into the live detonation path — capture the sample's real C2 requests, synthesise a grounded inert response off-VM using the Gemini/Groq key, serve it (plus an inert second stage) on the sealed detonator, and prove it end to end.

**Architecture:** Two-pass frontier loop. Pass 1 detonates with a mitmproxy capture addon that records every flow into the artifact. The orchestrator (which has network egress) calls the LLM once per dead-C2 host to fill scalar values, runs the deterministic inertness gate, and writes a `C2Bundle`. Pass 2 re-detonates with a composed proxy that serves the bundle offline and hands back an inert DEX on a payload fetch. The LLM is never called from inside the sealed VM — it cannot reach the internet by firewall.

**Tech Stack:** Python 3.11 (app) / 3.10-clean (VM), pydantic contracts, mitmproxy (VM only), Frida, pytest, `gcloud`/IAP for the lab.

**Spec:** `docs/superpowers/specs/2026-08-26-frontier-c2-closure-design.md`

## Global Constraints

- **Contracts first.** New cross-module types are pydantic models in `drishti/contracts/`. Add the field to `docs/01_DATA_CONTRACTS.md` first, then the model. Never pass a raw dict across a module boundary.
- **The sealed VM has no egress.** No code that runs on the detonator may call an LLM, `googleapis.com`, or `groq.com`. Synthesis happens on the orchestrator; the VM reads a pre-built bundle only.
- **Every external call degrades.** LLM/adb/mitmproxy calls return partial results with `errors` populated; a failing sub-analyser never fails the job.
- **No ungrounded claims.** A `C2BundleEntry` with empty `derived_from` is refused. An all-ungrounded bundle yields **no pass 2**.
- **Provable inertness is the gate.** Every served body passes `assert_inert()`; an entry that fails is dropped, never served.
- **Honesty flags track reality:** `synthesised` is set on flows we answered; `tls_intercepted` is always `False` (we capture cleartext, we do not install a system CA); `behaviour_changed` is a trace diff, never a flag; a `synthesised=True` flow is never published as an IOC.
- **Redaction fail-closed.** Every string leaving the guest passes `redaction.redact_text`; contracts refuse to construct on unredacted sensitive text.
- **Budgets are asserts.** LLM calls ≤25/job. The bundle builder counts each host call against that budget.
- **Style:** `ruff` formatted, type hints on public functions, `structlog` one line per event, `set -euo pipefail` and idempotent shell in `infra/gcp/`. `make test` green before moving on.

## Exact signatures this plan builds on (verified in-tree)

```python
# drishti/contracts/dynamic_trace.py
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
class StrictWireModel(DrishtiModel): ...           # extra="forbid", strict wire
class ObservationArtifact(StrictWireModel):
    observations: tuple[ObservationEvent, ...] = ()
    # ← Task 1 adds:  captured_flows: tuple[CapturedFlow, ...] = ()
class NetworkFlow(DrishtiModel):
    t_ms:int; method:str; url:str; host:str; req_headers:dict; req_body_preview:str
    req_body_sha256:str|None; status:int|None; resp_body_preview:str|None
    synthesised:bool=False; tls_intercepted:bool=False
class SyntheticC2Response(DrishtiModel):
    behaviour_changed: bool | None = None          # measured in Task 6

# drishti/m3_dynamic/generative_c2.py
class C2ResponseKind(StrEnum): CONNECTIVITY_OK|COMMAND_POLL|REGISTRATION_ACK|CONFIG|INERT_PAYLOAD_STUB
@dataclass(frozen=True) class C2SchemaHint:
    response_kind:C2ResponseKind=CONNECTIVITY_OK; expected_keys:tuple=(); command_key:str|None=None
    url_keys:tuple=(); evidence_refs:tuple=()
@dataclass(frozen=True) class C2Request: host:str; url:str; method:str="GET"; body_preview:str=""; t_ms:int=0
def assert_inert(payload, hint:C2SchemaHint) -> InertResult    # raises NotProvablyInertError
def synthesise_response(request:C2Request, hint:C2SchemaHint, *, client=None, ledger=None) -> SyntheticC2Response
def derive_hints(static) -> dict[str, C2SchemaHint]            # host -> hint, from StaticReport
def inert_payload_bytes() -> bytes                             # 0x70-byte functionless DEX header
def _looks_like_beacon(url:str, host:str) -> bool
class GenerativeC2Addon: __init__(self, hints, *, client=None, ledger=None); .served: list[SyntheticC2Response]

# drishti/m3_dynamic/redaction.py
def redact_text(value, *, message_body=False, limit=512) -> str
def contains_sensitive_text(value:str) -> bool

# drishti/contracts/evidence.py  EvidenceType has: NETWORK_FLOW, GENERATIVE_C2, EVASION_CHECK, MORPH_ACTION
# drishti/ledger/store.py        LedgerStore.append(...)
# drishti/m4_genai/agents/adversarial_elicitor.py  plan_morphs(observations, ledger, job_id, client) -> MorphPlan
```

---

### Task 1: `CapturedFlow` contract + `captured_flows` field

**Files:**
- Modify: `drishti/contracts/dynamic_trace.py` (add `CapturedFlow`, extend `ObservationArtifact`)
- Modify: `drishti/contracts/__init__.py` (export `CapturedFlow`)
- Modify: `docs/01_DATA_CONTRACTS.md` (document the field first)
- Test: `tests/contract/test_captured_flow.py`

**Interfaces:**
- Produces: `CapturedFlow(t_ms_epoch:int, method:str, scheme:str, host:str, path:str, status:int|None, req_body_preview:str, resp_body_preview:str, synthesised:bool=False, served_kind:str|None=None)` — a `StrictWireModel` with a `detail`-style redaction validator on both body previews. `ObservationArtifact.captured_flows: tuple[CapturedFlow, ...] = Field(default=(), strict=False)`.

- [ ] **Step 1: Document the field in the data-contracts doc.** In `docs/01_DATA_CONTRACTS.md`, under the `ObservationArtifact` section, add a `captured_flows` row and a `CapturedFlow` sub-schema table: the fields above, one sentence each, noting bodies are redacted and `synthesised`/`served_kind` are set only for flows the proxy answered.

- [ ] **Step 2: Write the failing test.**

```python
# tests/contract/test_captured_flow.py
import pytest
from drishti.contracts.dynamic_trace import CapturedFlow, ObservationArtifact

def test_captured_flow_round_trips():
    f = CapturedFlow(t_ms_epoch=1_700_000_000_000, method="POST", scheme="http",
                     host="gate.evil.tk", path="/register", status=200,
                     req_body_preview="id=abc", resp_body_preview='{"status":"ok"}')
    assert CapturedFlow.model_validate_json(f.model_dump_json()) == f

def test_captured_flow_refuses_unredacted_body():
    # a bare card number must not construct
    with pytest.raises(ValueError):
        CapturedFlow(t_ms_epoch=0, method="GET", scheme="http", host="h", path="/",
                     status=None, req_body_preview="4111111111111111",
                     resp_body_preview="")

def test_artifact_accepts_captured_flows(minimal_artifact_kwargs):
    art = ObservationArtifact(**minimal_artifact_kwargs, captured_flows=(
        CapturedFlow(t_ms_epoch=1, method="GET", scheme="http", host="h", path="/",
                     status=200, req_body_preview="", resp_body_preview=""),))
    assert len(art.captured_flows) == 1
```

Add a `minimal_artifact_kwargs` fixture to `tests/contract/test_captured_flow.py` (or reuse `tests/unit/_observation_builders.py` if it already builds a minimal artifact — check first) providing the required `ObservationArtifact` fields (`sha256`, `outcome`, `metadata`, `started_at`, `finished_at`).

- [ ] **Step 3: Run test to verify it fails.** Run: `pytest tests/contract/test_captured_flow.py -v` — Expected: FAIL, `ImportError: cannot import name 'CapturedFlow'`.

- [ ] **Step 4: Implement.** In `dynamic_trace.py`, add after `NetworkFlow`:

```python
class CapturedFlow(StrictWireModel):
    """One HTTP flow the detonator's proxy observed, redacted before it left the guest.

    Distinct from NetworkFlow (which the pipeline builds): this is the raw capture
    written on the VM. `synthesised`/`served_kind` are set only for a flow the
    Generative C2 answered. `tls_intercepted` is deliberately absent — we capture
    cleartext HTTP and never claim TLS interception.
    """
    t_ms_epoch: int
    method: Annotated[str, StringConstraints(min_length=1, max_length=16)]
    scheme: Annotated[str, StringConstraints(min_length=1, max_length=8)]
    host: Annotated[str, StringConstraints(max_length=253)]
    path: Annotated[str, StringConstraints(max_length=512)] = "/"
    status: int | None = None
    req_body_preview: Annotated[str, StringConstraints(max_length=512)] = ""
    resp_body_preview: Annotated[str, StringConstraints(max_length=512)] = ""
    synthesised: bool = False
    served_kind: str | None = None

    @field_validator("req_body_preview", "resp_body_preview")
    @classmethod
    def _reject_unredacted(cls, value: str) -> str:
        from drishti.m3_dynamic.redaction import contains_sensitive_text
        if contains_sensitive_text(value):
            raise ValueError("captured flow body contains unredacted sensitive text")
        return value
```

Extend `ObservationArtifact` (in the "fields the real harness emits" block):

```python
    #: HTTP flows the on-VM proxy captured, redacted at the guest boundary.
    captured_flows: tuple[CapturedFlow, ...] = Field(default=(), strict=False)
```

Export `CapturedFlow` in `drishti/contracts/__init__.py` (both the import and `__all__`).

- [ ] **Step 5: Run test to verify it passes.** Run: `pytest tests/contract/test_captured_flow.py -v` — Expected: PASS (3 tests).

- [ ] **Step 6: Run the contract suite for drift.** Run: `pytest tests/contract/ -q` — Expected: PASS (existing round-trip gate must still be green with the new model).

- [ ] **Step 7: Commit.**

```bash
git add drishti/contracts/dynamic_trace.py drishti/contracts/__init__.py docs/01_DATA_CONTRACTS.md tests/contract/test_captured_flow.py
git commit -m "feat(contracts): CapturedFlow + ObservationArtifact.captured_flows"
```

---

### Task 2: Capture addon + `parse_flow_log`

**Files:**
- Create: `drishti/m3_dynamic/proxy/__init__.py`
- Create: `drishti/m3_dynamic/proxy/capture_addon.py`
- Test: `tests/unit/test_capture_addon.py`

**Interfaces:**
- Consumes: `CapturedFlow` (Task 1), `redact_text` (redaction).
- Produces: `parse_flow_log(text: str) -> list[CapturedFlow]` (pure, testable without mitmproxy); `class FlowCaptureAddon` with a `response(self, flow)` method that appends one JSON line per flow to `DRISHTI_FLOW_LOG`. One JSON object per line: `{t_ms_epoch, method, scheme, host, path, status, req_body_preview, resp_body_preview}`.

- [ ] **Step 1: Write the failing test.**

```python
# tests/unit/test_capture_addon.py
from drishti.m3_dynamic.proxy.capture_addon import parse_flow_log
from drishti.contracts.dynamic_trace import CapturedFlow

def test_parse_flow_log_reads_jsonl():
    text = ('{"t_ms_epoch":1,"method":"GET","scheme":"http","host":"gate.evil.tk",'
            '"path":"/checkin","status":200,"req_body_preview":"","resp_body_preview":"ok"}\n')
    flows = parse_flow_log(text)
    assert flows == [CapturedFlow(t_ms_epoch=1, method="GET", scheme="http",
                                  host="gate.evil.tk", path="/checkin", status=200,
                                  req_body_preview="", resp_body_preview="ok")]

def test_parse_flow_log_skips_blank_and_malformed_lines():
    text = '\n{"not":"a flow"}\n{bad json\n'
    assert parse_flow_log(text) == []   # tolerant: a corrupt line is dropped, not fatal
```

- [ ] **Step 2: Run test to verify it fails.** Run: `pytest tests/unit/test_capture_addon.py -v` — Expected: FAIL, `ModuleNotFoundError`.

- [ ] **Step 3: Implement.** `drishti/m3_dynamic/proxy/__init__.py` empty. `capture_addon.py`:

```python
"""mitmproxy capture addon. Writes redacted flows as JSONL; the harness reads the tail.

Runs only on the sealed detonator. The parse half is pure so it is tested here without
mitmproxy present, mirroring GenerativeC2Addon: a dumb adapter over a pure function.
"""
from __future__ import annotations
import json, os
from pathlib import Path
from drishti.contracts.dynamic_trace import CapturedFlow
from drishti.m3_dynamic.redaction import redact_text

def parse_flow_log(text: str) -> list[CapturedFlow]:
    out: list[CapturedFlow] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(CapturedFlow.model_validate_json(line))
        except Exception:
            continue  # a corrupt or non-flow line is dropped, never fatal
    return out

class FlowCaptureAddon:  # pragma: no cover - needs mitmproxy at runtime
    def __init__(self, log_path: str | None = None) -> None:
        self._path = Path(log_path or os.environ.get("DRISHTI_FLOW_LOG", "/opt/drishti/results/flows.jsonl"))
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def response(self, flow) -> None:
        req, resp = flow.request, flow.response
        record = {
            "t_ms_epoch": int(getattr(req, "timestamp_start", 0.0) * 1000),
            "method": str(req.method), "scheme": str(req.scheme),
            "host": str(req.host), "path": str(req.path).split("?", 1)[0][:512],
            "status": int(resp.status_code) if resp else None,
            "req_body_preview": redact_text(_text(req)),
            "resp_body_preview": redact_text(_text(resp)),
        }
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=True) + "\n")

def _text(msg) -> str:  # pragma: no cover - needs mitmproxy
    try:
        return (msg.get_text(strict=False) or "")[:512]
    except Exception:
        return ""
```

- [ ] **Step 4: Run test to verify it passes.** Run: `pytest tests/unit/test_capture_addon.py -v` — Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add drishti/m3_dynamic/proxy/ tests/unit/test_capture_addon.py
git commit -m "feat(m3): mitmproxy flow-capture addon + pure JSONL parser"
```

---

### Task 3: `C2Bundle` contract

**Files:**
- Create: `drishti/contracts/c2_bundle.py`
- Modify: `drishti/contracts/__init__.py`
- Modify: `docs/01_DATA_CONTRACTS.md`
- Test: `tests/contract/test_c2_bundle.py`

**Interfaces:**
- Produces: `C2BundleEntry(host:str, path_prefix:str, response_kind:str, served_status:int, served_content_type:str, served_body:str, is_payload_url:bool=False, derived_from:tuple[str,...]=())` and `C2Bundle(sha256:Sha256, entries:tuple[C2BundleEntry,...], built_at:str, synthesis_client:str="")`. Both `DrishtiModel`. `C2Bundle.matches(host, path) -> C2BundleEntry | None` returns the entry whose `host==host and path.startswith(path_prefix)`, longest prefix first.

- [ ] **Step 1: Document in `docs/01_DATA_CONTRACTS.md`** — a `C2Bundle` / `C2BundleEntry` schema section: fields above, and the invariant "an entry with empty `derived_from` is never emitted by the builder."

- [ ] **Step 2: Write the failing test.**

```python
# tests/contract/test_c2_bundle.py
import pytest
from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry

SHA = "a" * 64

def test_bundle_round_trips():
    b = C2Bundle(sha256=SHA, built_at="2026-08-26T00:00:00Z", synthesis_client="groq/llama",
        entries=(C2BundleEntry(host="gate.evil.tk", path_prefix="/reg",
            response_kind="registration_ack", served_status=200,
            served_content_type="application/json", served_body='{"status":"ok"}',
            derived_from=("ledger://0x1",)),))
    assert C2Bundle.model_validate_json(b.model_dump_json()) == b

def test_matches_longest_prefix():
    e_short = C2BundleEntry(host="h", path_prefix="/", response_kind="connectivity_ok",
        served_status=200, served_content_type="application/json", served_body="{}",
        derived_from=("ledger://x",))
    e_long = C2BundleEntry(host="h", path_prefix="/api/v2", response_kind="config",
        served_status=200, served_content_type="application/json", served_body="{}",
        derived_from=("ledger://y",))
    b = C2Bundle(sha256="b"*64, built_at="t", entries=(e_short, e_long))
    assert b.matches("h", "/api/v2/poll") is e_long
    assert b.matches("h", "/other") is e_short
    assert b.matches("other", "/") is None
```

- [ ] **Step 3: Run test to verify it fails.** Run: `pytest tests/contract/test_c2_bundle.py -v` — Expected: FAIL, `ModuleNotFoundError`.

- [ ] **Step 4: Implement `c2_bundle.py`:**

```python
"""The pre-computed, grounded, inert C2 responses staged to the detonator.

Built on the orchestrator (which has LLM egress), read by the on-VM proxy (which does
not). An entry always cites the pass-1 evidence it was derived from — the builder
refuses to emit an ungrounded one.
"""
from __future__ import annotations
from pydantic import Field
from drishti.contracts.base import DrishtiModel
from drishti.contracts.dynamic_trace import Sha256

class C2BundleEntry(DrishtiModel):
    host: str
    path_prefix: str = "/"
    response_kind: str
    served_status: int = 200
    served_content_type: str = "application/json"
    served_body: str = ""
    is_payload_url: bool = False
    derived_from: tuple[str, ...] = ()

class C2Bundle(DrishtiModel):
    sha256: Sha256
    entries: tuple[C2BundleEntry, ...] = ()
    built_at: str = ""
    synthesis_client: str = ""

    def matches(self, host: str, path: str) -> C2BundleEntry | None:
        best: C2BundleEntry | None = None
        for e in self.entries:
            if e.host == host and path.startswith(e.path_prefix):
                if best is None or len(e.path_prefix) > len(best.path_prefix):
                    best = e
        return best
```

Export both in `drishti/contracts/__init__.py`.

- [ ] **Step 5: Run test to verify it passes.** Run: `pytest tests/contract/test_c2_bundle.py -v` — Expected: PASS.

- [ ] **Step 6: Commit.**

```bash
git add drishti/contracts/c2_bundle.py drishti/contracts/__init__.py docs/01_DATA_CONTRACTS.md tests/contract/test_c2_bundle.py
git commit -m "feat(contracts): C2Bundle + C2BundleEntry with longest-prefix match"
```

---

### Task 4: `synthesise_response(fill=...)` + bundle builder

**Files:**
- Modify: `drishti/m3_dynamic/generative_c2.py` (add `fill` param)
- Create: `drishti/m3_dynamic/c2_bundle.py` (builder — note: distinct from the contract module of the same basename, lives under `m3_dynamic/`)
- Test: `tests/unit/test_c2_bundle_builder.py`

**Interfaces:**
- Consumes: `synthesise_response`, `derive_hints`, `_looks_like_beacon`, `assert_inert`, `C2Request`, `C2SchemaHint` (generative_c2); `CapturedFlow` (Task 1); `C2Bundle`, `C2BundleEntry` (Task 3); `LedgerStore`.
- Produces: `build_c2_bundle(sha256:str, flows:list[CapturedFlow], static_report, *, client=None, ledger=None, max_calls:int=25) -> C2Bundle`. Groups flows by host, drops noise via `_looks_like_beacon`, fuses observed request with `derive_hints`, calls `synthesise_response` once per host, emits an entry only when it is inert **and** grounded.

- [ ] **Step 1: Add `fill` to `synthesise_response`.** In `generative_c2.py`, change the signature to `def synthesise_response(request, hint, *, client=None, ledger=None, fill: dict | None = None)`. Where it currently does `if client is not None: proposed, reasoning = _ask_model(...)`, guard it:

```python
    if fill is not None:
        proposed, reasoning = fill, fill.get("reasoning", "")
    elif client is not None:
        proposed, reasoning = _ask_model(request, hint, kind, client)
```

Everything downstream (`_template`, `assert_inert`, the fail-closed fallback) is unchanged — `fill` is inert-checked exactly like a model answer.

- [ ] **Step 2: Write the failing tests.**

```python
# tests/unit/test_c2_bundle_builder.py
from types import SimpleNamespace
from drishti.contracts.dynamic_trace import CapturedFlow
from drishti.m3_dynamic.generative_c2 import synthesise_response, C2Request, C2SchemaHint
from drishti.m3_dynamic.c2_bundle import build_c2_bundle

def _static(urls=(), crypto=(), pkg=(), refs=()):
    return SimpleNamespace(urls=list(urls), crypto_constants=list(crypto),
                           package_strings=list(pkg), ledger_refs=list(refs))

def _flow(host, path="/checkin", method="GET"):
    return CapturedFlow(t_ms_epoch=1, method=method, scheme="http", host=host,
                        path=path, status=None, req_body_preview="", resp_body_preview="")

def test_fill_short_circuits_the_model():
    # fill is used verbatim (then inert-checked); no client is consulted
    r = synthesise_response(C2Request(host="h", url="http://h/checkin"),
                            C2SchemaHint(), fill={"interval": 60, "id": "x", "reasoning": "pre"})
    assert r.provably_inert and r.reasoning == "pre"

def test_builder_drops_noise_hosts():
    flows = [_flow("clients3.google.com"), _flow("gate.evil.tk", "/register")]
    bundle = build_c2_bundle("a"*64, flows, _static(urls=["hxxp://gate.evil.tk/register"],
                             refs=["ledger://n1"]))
    hosts = {e.host for e in bundle.entries}
    assert "clients3.google.com" not in hosts
    assert "gate.evil.tk" in hosts

def test_builder_refuses_ungrounded_entry():
    # a beacon host with no static evidence ref -> no derived_from -> dropped
    flows = [_flow("gate.evil.tk", "/register")]
    bundle = build_c2_bundle("a"*64, flows, _static(urls=[], refs=[]))
    assert bundle.entries == ()

def test_builder_one_call_per_host_budget():
    calls = {"n": 0}
    class C:
        def complete_as(self, **kw):
            calls["n"] += 1
            return None  # forces the canned inert fallback, still an entry
    flows = [_flow("gate.evil.tk", "/a"), _flow("gate.evil.tk", "/b"), _flow("c2.bad.su", "/x")]
    build_c2_bundle("a"*64, flows,
                    _static(urls=["hxxp://gate.evil.tk/a","hxxp://c2.bad.su/x"], refs=["ledger://n"]),
                    client=C())
    assert calls["n"] <= 2   # one per distinct beacon host, not per flow
```

- [ ] **Step 3: Run tests to verify they fail.** Run: `pytest tests/unit/test_c2_bundle_builder.py -v` — Expected: FAIL (`ModuleNotFoundError` for the builder; the `fill` test fails until Step 1 lands — it may pass already if Step 1 done, that is fine).

- [ ] **Step 4: Implement `drishti/m3_dynamic/c2_bundle.py`:**

```python
"""Orchestrator-side builder: turn observed pass-1 flows into a grounded inert bundle.

One LLM call per dead-C2 host, each answer run through assert_inert inside
synthesise_response, each entry grounded in a pass-1 evidence ref. Runs where the LLM
key lives; never on the detonator.
"""
from __future__ import annotations
from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry
from drishti.contracts.dynamic_trace import CapturedFlow
from drishti.logging import get_logger
from drishti.m3_dynamic.generative_c2 import (
    C2Request, C2ResponseKind, derive_hints, synthesise_response, _looks_like_beacon,
)
from drishti.util import utcnow  # or the project's timestamp helper; check drishti/util.py

log = get_logger(__name__)

def build_c2_bundle(sha256, flows, static_report, *, client=None, ledger=None, max_calls=25):
    hints = derive_hints(static_report)                       # host -> C2SchemaHint (grounded)
    by_host: dict[str, CapturedFlow] = {}
    for f in flows:
        url = f"{f.scheme}://{f.host}{f.path}"
        if _looks_like_beacon(url, f.host) and f.host not in by_host:
            by_host[f.host] = f                                # first flow per host
    entries: list[C2BundleEntry] = []
    calls = 0
    for host, flow in by_host.items():
        hint = hints.get(host)
        if hint is None or not hint.evidence_refs:
            continue                                           # ungrounded -> refuse
        if calls >= max_calls:
            log.warning("c2_bundle_budget_reached", host=host, cap=max_calls)
            break
        req = C2Request(host=host, url=f"{flow.scheme}://{host}{flow.path}",
                        method=flow.method, body_preview=flow.req_body_preview, t_ms=flow.t_ms_epoch)
        resp = synthesise_response(req, hint, client=client, ledger=ledger)
        calls += 1
        if not resp.provably_inert:
            continue                                           # never serve a non-inert body
        is_payload = hint.response_kind == C2ResponseKind.INERT_PAYLOAD_STUB
        entries.append(C2BundleEntry(
            host=host, path_prefix=flow.path or "/", response_kind=resp.response_kind,
            served_status=resp.served_status, served_content_type=resp.served_content_type,
            served_body=resp.served_body, is_payload_url=is_payload,
            derived_from=tuple(resp.evidence_refs) or tuple(hint.evidence_refs)))
    log.info("c2_bundle_built", sha256=sha256[:12], hosts=len(by_host), entries=len(entries), calls=calls)
    return C2Bundle(sha256=sha256, entries=tuple(entries), built_at=utcnow(), synthesis_client=_client_name(client))

def _client_name(client) -> str:
    return getattr(client, "model", None) or type(client).__name__ if client else "none"
```

Check `drishti/util.py` (or `drishti/m3_dynamic/harness.py:utcnow`) for the exact timestamp helper name before finalising the import; use the one already in the codebase.

- [ ] **Step 5: Run tests to verify they pass.** Run: `pytest tests/unit/test_c2_bundle_builder.py -v` — Expected: PASS (4).

- [ ] **Step 6: Commit.**

```bash
git add drishti/m3_dynamic/generative_c2.py drishti/m3_dynamic/c2_bundle.py tests/unit/test_c2_bundle_builder.py
git commit -m "feat(m3): grounded C2 bundle builder + synthesise_response(fill=)"
```

---

### Task 5: Composed detonator proxy

**Files:**
- Create: `infra/gcp/drishti_proxy.py`
- Modify: `infra/gcp/runtime_prepare.sh` (launch `drishti_proxy.py`, keep `fake_c2.py` deletable)
- Modify: `infra/gcp/packer/builder_setup.sh` and `detonator_provision.sh` if they name `fake_c2.py` explicitly (grep first)
- Test: `tests/unit/test_drishti_proxy.py`

**Interfaces:**
- Consumes: `FlowCaptureAddon` (Task 2), `C2Bundle` (Task 3), `inert_payload_bytes` (generative_c2).
- Produces: `class BundleResponder` with pure `decide(host, path) -> tuple[int, bytes, str] | None` (status, body, content-type), tested without mitmproxy; a module-level `addons = [...]` list mitmproxy loads. Reads `DRISHTI_C2_BUNDLE` (a `C2Bundle` JSON path) and `DRISHTI_FLOW_LOG`.

- [ ] **Step 1: Write the failing test.**

```python
# tests/unit/test_drishti_proxy.py
from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry
import importlib.util, pathlib
spec = importlib.util.spec_from_file_location("drishti_proxy",
    pathlib.Path("infra/gcp/drishti_proxy.py"))
proxy = importlib.util.module_from_spec(spec); spec.loader.exec_module(proxy)

def _bundle():
    return C2Bundle(sha256="a"*64, built_at="t", entries=(
        C2BundleEntry(host="gate.evil.tk", path_prefix="/reg", response_kind="registration_ack",
            served_status=200, served_content_type="application/json",
            served_body='{"status":"ok"}', derived_from=("ledger://x",)),
        C2BundleEntry(host="gate.evil.tk", path_prefix="/payload", response_kind="inert_payload_stub",
            served_status=200, served_content_type="application/json",
            served_body='{"url":"http://gate.evil.tk/payload/x.dex"}', is_payload_url=True,
            derived_from=("ledger://y",)),))

def test_responder_serves_matching_entry():
    r = proxy.BundleResponder(_bundle())
    status, body, ctype = r.decide("gate.evil.tk", "/reg/1")
    assert status == 200 and b'"status":"ok"' in body

def test_responder_serves_inert_dex_on_payload_path():
    r = proxy.BundleResponder(_bundle())
    status, body, ctype = r.decide("gate.evil.tk", "/payload/x.dex")
    assert body[:8] == b"dex\n035\x00" and ctype == "application/octet-stream"

def test_responder_passes_unknown_host_to_fallback():
    r = proxy.BundleResponder(_bundle())
    assert r.decide("clients3.google.com", "/") is None
```

- [ ] **Step 2: Run test to verify it fails.** Run: `pytest tests/unit/test_drishti_proxy.py -v` — Expected: FAIL (file missing).

- [ ] **Step 3: Implement `infra/gcp/drishti_proxy.py`:**

```python
"""Composed mitmproxy addon chain for the sealed detonator. Calls NO LLM.

capture (always) -> bundle responder (if DRISHTI_C2_BUNDLE) -> inert second stage
-> static sinkhole fallback. Everything served is pre-computed and inert; egress is
blackholed, so this is the sample's only interlocutor.
"""
from __future__ import annotations
import json, os
from pathlib import Path
from drishti.contracts.c2_bundle import C2Bundle
from drishti.m3_dynamic.generative_c2 import inert_payload_bytes
from drishti.m3_dynamic.proxy.capture_addon import FlowCaptureAddon

_SINKHOLE = json.dumps({"status": "sinkholed", "commands": []}).encode()

class BundleResponder:
    def __init__(self, bundle: C2Bundle | None) -> None:
        self._bundle = bundle

    def decide(self, host: str, path: str):
        if self._bundle is None:
            return None
        entry = self._bundle.matches(host, path)
        if entry is None:
            return None
        if entry.is_payload_url:
            return (200, inert_payload_bytes(), "application/octet-stream")
        return (entry.served_status, entry.served_body.encode("utf-8"), entry.served_content_type)

    def request(self, flow):  # pragma: no cover - needs mitmproxy
        from mitmproxy import http
        decided = self.decide(flow.request.host, flow.request.path.split("?", 1)[0])
        if decided is None:
            body = self._sinkhole_or_none(flow)
            if body is not None:
                flow.response = http.Response.make(200, body, {"Content-Type": "application/json",
                                                               "X-DRISHTI-No-Upstream": "true"})
            return
        status, payload, ctype = decided
        flow.response = http.Response.make(status, payload,
            {"Content-Type": ctype, "X-DRISHTI-Synthesised": "true", "X-DRISHTI-No-Upstream": "true"})

    @staticmethod
    def _sinkhole_or_none(flow):  # pragma: no cover - needs mitmproxy
        return _SINKHOLE   # fallback: a dead C2 gets an inert ack, never a connection error

def _load_bundle() -> C2Bundle | None:
    path = os.environ.get("DRISHTI_C2_BUNDLE")
    if not path or not Path(path).is_file():
        return None
    return C2Bundle.model_validate_json(Path(path).read_text(encoding="utf-8"))

addons = [FlowCaptureAddon(), BundleResponder(_load_bundle())]  # pragma: no cover
```

- [ ] **Step 4: Run test to verify it passes.** Run: `pytest tests/unit/test_drishti_proxy.py -v` — Expected: PASS (3).

- [ ] **Step 5: Point `runtime_prepare.sh` at the composed proxy.** Replace the `mitmdump ... -s /opt/drishti/fake_c2.py` line with:

```bash
pkill -f 'mitmdump.*drishti_proxy.py' 2>/dev/null || true
DRISHTI_FLOW_LOG=/opt/drishti/results/flows.jsonl \
nohup /opt/drishti/venv/bin/mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set confdir=/opt/drishti/mitmproxy \
  -s /opt/drishti/drishti_proxy.py >/var/log/drishti-proxy.log 2>&1 &
```

`DRISHTI_C2_BUNDLE` is unset here (pass 1 has no bundle); the per-run wrapper in Task 7 sets it for pass 2. Grep `infra/` for other `fake_c2` references and repoint or delete them; keep `fake_c2.py` in the tree only if a test still imports it (it does not after Task 5 — remove it and its provision copy).

- [ ] **Step 6: Commit.**

```bash
git add infra/gcp/drishti_proxy.py infra/gcp/runtime_prepare.sh tests/unit/test_drishti_proxy.py
git commit -m "feat(infra): composed detonator proxy — capture + bundle + inert stage + sinkhole"
```

---

### Task 6: Ingest lift + honesty flags + STIX exclusion

**Files:**
- Modify: `drishti/m3_dynamic/ingest.py` (lift `captured_flows` into `NetworkFlow`)
- Modify: `drishti/m3_dynamic/morph.py` or wherever `behaviour_changed` should be set — check `diff_traces` (it exists in `morph.py`); set the flag in the frontier merge, Task 7
- Test: `tests/contract/test_observation_ingest_parity.py` (extend), `tests/unit/test_ingest_flows.py`, `tests/contract/test_stix_excludes_synthesised.py`

**Interfaces:**
- Consumes: `artifact.captured_flows` (Task 1), `NetworkFlow`.
- Produces: `artifact_to_trace` now populates `network_flows` from **both** the Frida URL hook groups and `captured_flows`, deduped by `(host, path, t_ms // 1000)`. A captured flow with `synthesised=True` yields `NetworkFlow(synthesised=True, tls_intercepted=False)`.

- [ ] **Step 1: Write the failing tests.**

```python
# tests/unit/test_ingest_flows.py
from drishti.m3_dynamic.ingest import artifact_to_trace
from drishti.contracts.dynamic_trace import CapturedFlow

def test_captured_flows_lift_into_network_flows(artifact_with_flows):
    trace = artifact_to_trace(artifact_with_flows)
    hosts = {f.host for f in trace.network_flows}
    assert "gate.evil.tk" in hosts
    assert all(f.tls_intercepted is False for f in trace.network_flows)

def test_synthesised_flag_survives_ingest(artifact_with_synthesised_flow):
    trace = artifact_to_trace(artifact_with_synthesised_flow)
    answered = [f for f in trace.network_flows if f.host == "gate.evil.tk"]
    assert answered and answered[0].synthesised is True
```

```python
# tests/contract/test_stix_excludes_synthesised.py
# Build a DynamicTrace with one synthesised and one real NetworkFlow, run the STIX
# export, assert the synthesised host does NOT appear in any indicator/observed-data.
```

Add `artifact_with_flows` / `artifact_with_synthesised_flow` fixtures using the minimal-artifact builder plus a `captured_flows=(...)` tuple.

- [ ] **Step 2: Run tests to verify they fail.** Run: `pytest tests/unit/test_ingest_flows.py tests/contract/test_stix_excludes_synthesised.py -v` — Expected: FAIL.

- [ ] **Step 3: Implement the lift in `ingest.py`.** After the existing `dex_loads, network_flows, decrypted_blobs = _structured(...)` line, merge captured flows:

```python
    captured = _lift_captured_flows(artifact.captured_flows, start)
    network_flows = _dedupe_flows(network_flows + captured)
```

Add:

```python
def _lift_captured_flows(flows, start_iso) -> tuple[NetworkFlow, ...]:
    out = []
    for f in flows:
        out.append(NetworkFlow(
            t_ms=f.t_ms_epoch, method=f.method, host=f.host,
            url=f"{f.scheme}://{f.host}{f.path}", req_body_preview=f.req_body_preview,
            status=f.status, resp_body_preview=f.resp_body_preview or None,
            synthesised=f.synthesised, tls_intercepted=False))
    return tuple(out)

def _dedupe_flows(flows) -> tuple[NetworkFlow, ...]:
    seen, out = set(), []
    for f in flows:
        key = (f.host, f.url, f.t_ms // 1000)
        if key in seen:
            continue
        seen.add(key); out.append(f)
    return tuple(out)
```

Confirm the STIX exporter already filters `synthesised` (spec says it does — `m7_report`); if the new test fails because a code path leaks synthesised flows, add the filter there and note it in the commit.

- [ ] **Step 4: Run tests to verify they pass.** Run: `pytest tests/unit/test_ingest_flows.py tests/contract/test_stix_excludes_synthesised.py tests/contract/test_observation_ingest_parity.py -v` — Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add drishti/m3_dynamic/ingest.py drishti/m7_report/ tests/unit/test_ingest_flows.py tests/contract/test_stix_excludes_synthesised.py
git commit -m "feat(m3): lift captured flows into the trace; STIX excludes synthesised"
```

---

### Task 7: Detonator wiring + frontier C2 morph

**Files:**
- Modify: `scripts/dynamic_analyze.py` (`--c2-bundle`, set proxy env)
- Modify: `infra/gcp/detonator_run.sh` (`c2 <sha>` subcommand)
- Modify: `drishti/m3_dynamic/detonator.py` (stage `<sha>.c2.json`, pass `--c2-bundle` for a `GENERATIVE_C2` morph)
- Modify: `drishti/pipeline.py` (`_frontier`: emit a `GENERATIVE_C2` morph grounded in a captured-flow node + build the bundle)
- Test: `tests/unit/test_detonator_client.py` (extend — it already asserts the command surface against `detonator_run.sh`), `tests/unit/test_frontier_c2.py`

**Interfaces:**
- Consumes: `build_c2_bundle` (Task 4), `C2Bundle` (Task 3), `MorphKind.GENERATIVE_C2`, `resolve_trace_source`.
- Produces: `detonator_run.sh c2 <sha> [duration]` runs pass 2 with `DRISHTI_C2_BUNDLE=results/<sha>.c2.json`. `RemoteDetonatorClient.stage` also uploads the bundle when present. `pipeline._frontier` returns a `MorphPlan` that may contain a `Morph(kind=GENERATIVE_C2, derived_from=(<flow-node-id>,))`.

- [ ] **Step 1: Extend the command-surface test first.** In `tests/unit/test_detonator_client.py`, add a case asserting that when a plan contains a `GENERATIVE_C2` morph, the client issues `c2 <sha>` (not `morph <sha> generative_c2`, which would demand a `.js`). Assert the `c2` verb exists in `detonator_run.sh`'s `case` block (parse the file as the existing test does).

- [ ] **Step 2: Write the frontier test.**

```python
# tests/unit/test_frontier_c2.py
# Given a pass-1 trace whose network_flows include a dead beacon host and a ledger
# with a NETWORK_FLOW node, assert pipeline._frontier emits a Morph(kind=GENERATIVE_C2)
# whose derived_from resolves to that node; and that a trace with no beacon emits none.
```

- [ ] **Step 3: Run to verify fail.** Run: `pytest tests/unit/test_detonator_client.py tests/unit/test_frontier_c2.py -v` — Expected: FAIL.

- [ ] **Step 4: Implement.**
  - `dynamic_analyze.py`: add `parser.add_argument("--c2-bundle", type=Path, default=None)`; when set, `os.environ["DRISHTI_C2_BUNDLE"] = str(path)` before the proxy is (re)started, and record the bundle sha in diagnostics.
  - `detonator_run.sh`: add a `c2()` function mirroring `morph()` but staging `--c2-bundle "${DRISHTI_ROOT}/scratch/${sha}.c2.json"` and writing `results/${sha}.c2.json`; add `c2) shift; verify; c2 "$@" ;;` to the `case`, and the usage line.
  - `detonator.py`: in `stage`, also `scp`/push `<sha>.c2.json` if it exists locally; in `detonate`, when `any(m.kind == MorphKind.GENERATIVE_C2 for m in morphs)`, call the `c2` verb.
  - `pipeline._frontier`: after grounding evasion observations, also scan `trace.network_flows` for a dead-beacon host (reuse `_looks_like_beacon`); if found, append a `Morph(kind=MorphKind.GENERATIVE_C2, params={}, rationale=..., derived_from=(<node id of the NETWORK_FLOW evidence>,))` and build the bundle via `build_c2_bundle`, staging it next to the APK for the live source.

- [ ] **Step 5: Run to verify pass.** Run: `pytest tests/unit/test_detonator_client.py tests/unit/test_frontier_c2.py -v` — Expected: PASS.

- [ ] **Step 6: Full suite.** Run: `make test` — Expected: PASS (baseline 1,614 + the new tests, 0 failures).

- [ ] **Step 7: Commit.**

```bash
git add scripts/dynamic_analyze.py infra/gcp/detonator_run.sh drishti/m3_dynamic/detonator.py drishti/pipeline.py tests/unit/test_detonator_client.py tests/unit/test_frontier_c2.py
git commit -m "feat(m3): wire generative-C2 bundle through the detonator and frontier loop"
```

---

### Task 8: Live proof on the sealed detonator

**Files:**
- Create: `tests/lab/test_c2_live.py` (`@pytest.mark.gcp`)
- Modify: `docs/M3_DETONATOR_RUNBOOK.md` (§6.2 the C2 flow), `STATUS.md` (measured result)

**Interfaces:** none new — this exercises the whole chain live.

> This task spends money and needs the operator (you) at the keys for `make lab-up`/`lab-down`. It is a checkpoint, not an autonomous step. **Gate:** if Step 4 does not capture the canary's own GET, STOP — fix capture (Task 2) before touching real samples.

- [ ] **Step 1: Write the lab gate test.**

```python
# tests/lab/test_c2_live.py
import pytest
pytestmark = pytest.mark.gcp

def test_canary_get_is_captured():
    # deploy proxy, detonate the canary (one HTTP GET to a configured local host),
    # collect the artifact, assert >=1 CapturedFlow whose host matches the canary target.
    ...
```

- [ ] **Step 2: Deploy.** `bash infra/gcp/detonator_deploy.sh` (ships `drishti/`, the proxy, hooks over IAP). Confirm `drishti_proxy.py` landed at `/opt/drishti/`.

- [ ] **Step 3: `make lab-up`.** Start `m3-detonator`. Confirm `make lab-status` shows RUNNING.

- [ ] **Step 4: Canary capture gate.** `bash infra/gcp/detonator_run.sh detonate <canary-sha>` then `detonator_collect.sh`. Assert a `CapturedFlow` for the canary's GET is present. **If absent, STOP and fix capture.**

- [ ] **Step 5: Real samples.** Stage 5–10 corpus samples with beacon-like URLs (`scripts/fetch_detonation_candidates.py` + a URL-string filter). For each: `detonate <sha>` (pass 1, capture) → pull artifact → `build_c2_bundle` on the laptop → `detonator_run.sh c2 <sha>` (pass 2, serve) → collect.

- [ ] **Step 6: Measure.** Record to `STATUS.md` under a new dated subsection: flows captured/run, hosts hinted, C2 answered, `behaviour_changed` count, any inert-DEX load observed. Numbers only — no estimates. Update the P4/P5 task lines (T4.4 capture now real; T5.4 Tier 2 now live).

- [ ] **Step 7: `make lab-down`.** Stop the detonator. Confirm `make lab-status` shows TERMINATED. **No GCP resource left running by this work.**

- [ ] **Step 8: Commit.**

```bash
git add tests/lab/test_c2_live.py docs/M3_DETONATOR_RUNBOOK.md STATUS.md
git commit -m "test(lab): live generative-C2 capture+serve proof; STATUS measured result"
```

---

## Self-review notes

- **Spec coverage:** §3.1→T1, §3.2→T2, §3.3→T3, §3.4+§3.6→T4, §3.5→T5, §3.7→T6, §3.8→T7, §5 lab + §6 live-run→T8. §4 honesty properties: synthesised-not-IOC→T6; `tls_intercepted` false→T1/T6; `behaviour_changed` diff→T6/T7; all-ungrounded→no pass 2→T4/T7; `provably_inert` gate→T4. All covered.
- **Type consistency:** `CapturedFlow` fields identical across T1/T2/T6; `C2Bundle.matches` used in T3/T5; `build_c2_bundle` signature identical T4/T7; `synthesise_response(fill=)` T4/used nowhere else.
- **Naming caution flagged in-plan:** two modules share the basename `c2_bundle.py` — `drishti/contracts/c2_bundle.py` (models) vs `drishti/m3_dynamic/c2_bundle.py` (builder). Imports in the plan are fully qualified so this is unambiguous; called out in T4 Files.
- **Open verifications the implementer must do (noted at point of use):** the exact timestamp helper in `drishti/util.py` (T4 Step 4); whether the STIX exporter already filters `synthesised` (T6 Step 3); whether a minimal-artifact builder already exists in `tests/unit/_observation_builders.py` to reuse for fixtures (T1 Step 2).
