# PHASE 0 — FOUNDATIONS

**Window:** H00 → H06 (all three tracks, together)
**Owner:** everyone. Nobody starts their own track until P0 is `DONE`.
**Exit criteria:** `make e2e` uploads an APK, produces a `Job` that walks through
stub stages, writes ≥5 ledger nodes, and `verify_chain()` returns `ok=True`. The UI
shows the job. Nothing is analysed yet — the *skeleton is load-bearing*.

> The temptation at H00 is to start writing the exciting part. Resist it. Six hours
> of scaffolding buys you the ability to integrate three parallel workstreams
> without a schema war at hour 60. Teams that skip this phase lose 10+ hours later.

---

## Parallel background task — start at H00:00, before anything else

```bash
# Terminal 1 — this runs for hours. Start it NOW.
python scripts/fetch_datasets.py --drebin --cicmaldroid --malwarebazaar-recent 200
```
Downloads are the long pole for Phase 2 (risk R2). Kick them off, then write the
script properly while they run. If a source is gated (AndroZoo needs an API key
request that takes days), skip it — note it in `STATUS.md` and move on.

---

## T0.1 — Repo skeleton + tooling (H00:00 → H00:45) · Track C leads

```bash
mkdir drishti && cd drishti && git init
```

Create, exactly:

```
pyproject.toml          # uv or poetry; python = "3.11"
.gitignore              # *.apk (allowlist canary/), .env, models/*.pkl,
                        # .cache/, logs/, data/samples/, *.pcap
.env.example
Makefile
STATUS.md               # seeded from the roadmap task lists
README.md               # 10 lines; expand at H70
docker-compose.yml
```

**Dependencies** (pin them; a surprise breaking release at H50 is a bad way to die):

```toml
[project.dependencies]
fastapi = "^0.115"
uvicorn = {extras=["standard"], version="^0.32"}
pydantic = "^2.9"
pydantic-settings = "^2.6"
androguard = "^4.1"          # NOT 3.x — 4.x API differs substantially
networkx = "^3.4"
xgboost = "^2.1"
scikit-learn = "^1.5"
shap = "^0.46"
anthropic = "^0.39"
chromadb = "^0.5"            # cut-listed; keep optional
sentence-transformers = "^3.2"
cryptography = "^43"         # Ed25519
structlog = "^24.4"
jinja2 = "^3.1"
frida = "^16.5"
frida-tools = "^13"
mitmproxy = "^11"
python-multipart = "*"
sse-starlette = "*"
[dependency-groups.dev]
pytest, pytest-asyncio, pytest-cov, ruff, mypy
```

**Makefile** — the team's shared vocabulary:

```makefile
install:   uv sync
up:        docker compose up -d && uvicorn drishti.api.main:app --reload --port 8080
ui:        cd ui && npm run dev
test:      pytest tests/unit tests/contract -q
e2e:       pytest tests/e2e -q -s
lint:      ruff check . && ruff format --check .
demo:      python scripts/demo_reset.py && $(MAKE) up
freeze:    git tag -a freeze-$$(date +%H%M) -m "code freeze"
ledger:    python -m drishti.ledger.cli verify --job $(JOB)
```

**Acceptance:** `make install && make lint` green. Push. CI runs.

---

## T0.2 — Config (H00:30 → H01:00) · Track C

`drishti/config.py` — one settings object, `pydantic-settings`, read from `.env`.
Nothing anywhere else reads `os.environ`.

```python
class Settings(BaseSettings):
    anthropic_api_key: SecretStr
    llm_model: str = "claude-sonnet-4-5"
    llm_max_calls_per_job: int = 25
    llm_cache_dir: Path = Path(".cache/llm")
    llm_cache_enabled: bool = True

    db_path: Path = Path("data/drishti.db")
    ledger_key_path: Path = Path("data/ledger_ed25519.key")

    static_timeout_s: int = 90
    sandbox_enabled: bool = True
    sandbox_mode: Literal["live","replay","auto"] = "auto"
    sandbox_duration_s: int = 120
    emulator_serial: str = "emulator-5554"
    mitm_port: int = 8081

    mobsf_enabled: bool = False
    mobsf_url: str = "http://localhost:8000"
    vlm_enabled: bool = True
    rag_enabled: bool = True

    model_config = SettingsConfigDict(env_file=".env", env_prefix="DRISHTI_")
```

`sandbox_mode="auto"` means: try live, fall back to replay if
`LiveSandboxSource.available()` is False. This is the Replay-Mode parachute wired
in from hour one.

---

## T0.3 — All contracts, verbatim (H00:45 → H02:15) · Track A + B pair

Transcribe `01_DATA_CONTRACTS.md` into `drishti/contracts/*.py`. This is
mechanical; do it *carefully and completely*, including the models the phase that
needs them hasn't started yet. Every phase after this imports from here and never
redefines a shape.

Then write `tests/contract/test_roundtrip.py`, which iterates every subclass of
`DrishtiModel` found via `__subclasses__()`, constructs it from a factory registry,
and asserts JSON round-trip equality.

**Acceptance:** `pytest tests/contract/test_roundtrip.py` passes for ≥20 models.

---

## T0.4 — Evidence Ledger (H01:00 → H03:00) · Track B — **highest priority in P0**

This is the differentiator. It gets the most care in the least glamorous phase.

### `ledger/crypto.py`

```python
def normalise(obj: Any) -> Any:
    """Recursively round floats to 6dp, sort dict keys, convert tuples→lists."""

def canonical_json(obj: dict) -> str:
    return json.dumps(normalise(obj), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)

def node_hash(node_dict: dict) -> str:
    payload = {k: v for k, v in node_dict.items()
               if k not in ("node_hash", "signature")}
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()

def load_or_create_key(path: Path) -> Ed25519PrivateKey: ...
def sign(key, digest_hex: str) -> str: ...
def verify(pubkey, digest_hex: str, sig_hex: str) -> bool: ...
```

Float normalisation is not pedantry. `0.1+0.2` serialising differently on two
machines silently breaks chain verification, and you will lose two hours at 3am
finding it.

### `ledger/store.py` — schema

```sql
CREATE TABLE IF NOT EXISTS evidence (
  id TEXT PRIMARY KEY, job_id TEXT NOT NULL, seq INTEGER NOT NULL,
  type TEXT NOT NULL, source_tool TEXT NOT NULL,
  content TEXT NOT NULL,          -- canonical json
  location TEXT, confidence REAL NOT NULL,
  parents TEXT NOT NULL,          -- json array
  timestamp TEXT NOT NULL,
  prev_hash TEXT NOT NULL, node_hash TEXT NOT NULL, signature TEXT NOT NULL,
  UNIQUE(job_id, seq)
);
CREATE INDEX idx_ev_job_type ON evidence(job_id, type);
CREATE TRIGGER ev_no_update BEFORE UPDATE ON evidence
  BEGIN SELECT RAISE(ABORT,'evidence ledger is append-only'); END;
CREATE TRIGGER ev_no_delete BEFORE DELETE ON evidence
  BEGIN SELECT RAISE(ABORT,'evidence ledger is append-only'); END;
```

`PRAGMA journal_mode=WAL;` at connection open.

### `append()` invariants — enforce all four

1. `seq` = previous max seq + 1, inside a transaction (`BEGIN IMMEDIATE`).
2. `prev_hash` = previous node's `node_hash`, or `"0"*64` for seq 0.
3. If `type == AI_CLAIM` and `content["evidence_refs"]` is empty → `raise
   UngroundedClaimError`. Same if any ref doesn't exist in this job.
4. All `parents` must exist in this job.

### `verify_chain()`

Walk seq 0..n: recompute `node_hash`, compare; verify signature; check
`prev_hash` linkage. Return the exact `first_bad_seq`. Write the tamper test now:

```python
def test_tamper_detected(tmp_ledger):
    nodes = [tmp_ledger.append(...) for _ in range(50)]
    raw_sqlite_update(tmp_ledger.db, nodes[17].id, content='{"evil":true}')
    v = tmp_ledger.verify_chain()
    assert v.ok is False and v.first_bad_seq == 17
```

**This test is a demo asset.** Run it live on stage. It takes four seconds and it
proves the trust claim better than any slide.

### `ledger/verifier.py`

```python
class Verifier:
    def check_claim(self, claim: GroundedClaim,
                    allowed_types: set[EvidenceType] | None = None) -> VerifierStatus:
        # 1. refs non-empty            → REJECTED_NO_EVIDENCE
        # 2. every ref resolves        → REJECTED_BAD_REF
        # 3. ref types plausible for the claim's agent → REJECTED_TYPE_MISMATCH
        #    (e.g. an OTP-exfil claim citing only a CERTIFICATE node is suspicious)
        # 4. else PASS
    def filter(self, claims) -> tuple[list[GroundedClaim], list[GroundedClaim]]:
        """Returns (passed, rejected). NEVER all-or-nothing — see risk R4."""
```

**Acceptance:** `pytest tests/contract/test_ledger_chain.py
tests/contract/test_ai_claim_requires_evidence.py` green. Also add a CLI:
`python -m drishti.ledger.cli verify --job job_x` prints a green/red table.

---

## T0.5 — Job runner + pipeline skeleton (H02:00 → H03:30) · Track C

No Celery. `drishti/api/jobs.py`:

```python
class JobRunner:
    """Single ThreadPoolExecutor(max_workers=2). Jobs are I/O-bound (subprocess,
    HTTP), so threads are fine and we skip a broker entirely."""
    def submit(self, apk_path: Path, filename: str) -> Job
    def get(self, job_id: str) -> Job
    def stream(self, job_id: str) -> AsyncIterator[StageEvent]   # for SSE
    def _set_stage(self, job_id, stage, **meta)  # writes stage_history + logs
```

`drishti/pipeline.py`:

```python
def run_pipeline(job: Job, ctx: Context) -> Job:
    ledger = ctx.ledger.open(job.id)
    with stage(job, JobStage.INGEST):     meta    = m1.ingest(...)
    with stage(job, JobStage.STATIC):     static  = m2.analyse(...)
    with stage(job, JobStage.ML):         ml      = m5.predict(static)
    with stage(job, JobStage.GENAI_STATIC): partial_ai = m4.analyse_static(...)
    with stage(job, JobStage.SCORE_PRELIM):
        job.preliminary = m6.score(static, ml, partial_ai, None, meta.intel)
        ctx.emit_preliminary(job)
    ...
```

Every stage in P0 is a **stub returning a schema-valid empty object** that appends
one ledger node. `contextmanager stage()` handles timing, stage transition,
exception → `ERROR` ledger node + `JobStage.FAILED`, and structured logging.

**Acceptance:** `POST /api/jobs` with any file → job walks all stages in ~2s → 13
ledger nodes → `verify_chain().ok`.

---

## T0.6 — API surface (H03:00 → H04:00) · Track C

Freeze these routes now; the UI is built against them and must not chase changes.

```
POST   /api/jobs                  multipart apk        → {job_id}
GET    /api/jobs                                       → [Job] (newest first)
GET    /api/jobs/{id}                                  → Job
GET    /api/jobs/{id}/events      SSE                  → StageEvent stream
GET    /api/jobs/{id}/static                           → StaticReport
GET    /api/jobs/{id}/ml                               → MLPrediction
GET    /api/jobs/{id}/genai                            → GenAIVerdict
GET    /api/jobs/{id}/dynamic                          → DynamicTrace
GET    /api/jobs/{id}/score                            → CompositeScore
GET    /api/jobs/{id}/ledger?type=&since_seq=          → [EvidenceNode]
GET    /api/jobs/{id}/ledger/verify                    → ChainVerification
GET    /api/evidence/{node_id}                         → EvidenceNode  (drill-down)
GET    /api/jobs/{id}/report.html                      → rendered report
GET    /api/jobs/{id}/artifacts/yara                   → text/plain
GET    /api/jobs/{id}/artifacts/stix                   → application/json
GET    /api/jobs/{id}/artifacts/bundle.zip             → application/zip (the case file)
GET    /api/samples                                    → [SampleEntry] (metadata only)
POST   /api/samples/{id}/analyse                       → {job_id} (staged sample, A21)
POST   /api/jobs/{id}/actions/{action}/confirm         → ProposedAction (human gate)
GET    /api/logs/stream           SSE                  → the live log for the demo
```

Return 404 with `{"stage": job.stage}` for not-yet-produced artefacts so the UI can
render "pending" rather than erroring.

---

## T0.7 — `TraceSource` abstraction + fixture format (H03:30 → H04:15) · Track C

Implement the ABC (§3.1 of contracts) and `ReplayTraceSource` **now**, backed by
a hand-written fixture at `data/fixtures/traces/DEMO_SHA.json`:

```json
{"pre_morph":  {"detonated": false, "api_events": [...],
                "evasion_observations": [{"probe_kind":"installed_package",
                                          "queried":"com.sbi.yono","result":"MISS",
                                          "followed_by_stall":true}]},
 "post_morph": {"detonated": true, "detonation_reason":"exfil_observed",
                "network_flows":[...], "dex_loads":[...]}}
```

Write the fixture by hand with plausible values. Later, Phase 4 overwrites it with
a **real captured trace**. The rest of the system never notices the difference.

`LiveSandboxSource` is a stub raising `NotAvailable` until Phase 4.

**Acceptance:** `test_trace_source_interface.py` green for both implementations.

---

## T0.8 — UI shell (H04:00 → H05:30) · Track C

`ui/` — Vite + React + TS + Tailwind. Single page, four regions, all wired to real
endpoints returning stub data:

```
┌────────────────────────────────────────────────────────────┐
│ DRISHTI            [drop APK here]        job_01932… ● live │
├──────────────┬─────────────────────────────────────────────┤
│  SCORE       │  TABS: Overview · Static · AI · Sandbox ·   │
│   ┌────┐     │        Frontier · Ledger · Report            │
│   │ 92 │     │                                             │
│   └────┘     │  <tab content>                              │
│  CRITICAL    │                                             │
│  conf 0.86   │                                             │
│              │                                             │
│  ▸ R    6.2  │                                             │
│  ▸ F_AI 41.5 │                                             │
│  ▸ G    9.0  │                                             │
│  ▸ D    4.0  │                                             │
├──────────────┴─────────────────────────────────────────────┤
│ LIVE LOG  [M3] queried PackageManager('com.sbi.yono') MISS │
└────────────────────────────────────────────────────────────┘
```

Design notes that pay off on stage: dark theme, monospace for the log, the score
ring animates when it changes from preliminary to final (judges *see* the deep
analysis land), and the factor breakdown is always visible — it is the answer to
"how did you get 92?".

**Acceptance:** upload → job id appears → stage badges tick over via SSE → stub
score renders.

---

## T0.9 — Sandbox VM / container groundwork (H04:00 → H06:00) · Track C, background

Start the emulator work now, in parallel, because it has the longest debug tail.

1. Decide host: a dedicated laptop with hardware virtualisation (KVM/HAXM). Not a
   VM-inside-a-VM. Not a cloud box without nested virt.
2. `sdkmanager` + `avdmanager`: create AVD `drishti-x86_64-api30-googleapis`
   (**not** `google_play` — Play images are non-rootable and this kills you).
3. Boot with:
   `emulator -avd drishti -writable-system -no-snapshot-load -netdelay none
    -netspeed full -http-proxy 10.0.2.2:8081 -no-audio -gpu swiftshader_indirect`
4. `adb root && adb remount`, push `frida-server` matching the host `frida` version
   **exactly** (mismatched versions fail with an opaque error — pin both).
5. Verify: `frida-ps -U` lists processes. **This single command working is the P4
   go/no-go signal.** If it isn't working by H06, log it in `STATUS.md` and plan
   for Replay Mode from the start rather than discovering it at H40.
6. `adb emu snapshot save clean_base` — snapshot restore between samples is both a
   safety control and a time-saver.

Network isolation check (do it now, not later): from inside the emulator,
`ping 8.8.8.8` must fail and all HTTP must land in mitmproxy. Screenshot this for
the responsible-use slide.

---

## T0.10 — Ingest module M1, for real (H05:00 → H06:00) · Track A

Small enough to finish in P0, and it unblocks everyone's testing.

```python
def ingest(path: Path, ledger) -> FileMeta:
    # 1. sha256 + size + magic check (PK zip, has AndroidManifest.xml)
    # 2. split-APK: if a .apks/.xapk/zip-of-apks, extract, identify base by
    #    manifest without "split" attr, merge feature splits' dex list
    # 3. androguard APK() → package, label, versionName/Code, min/target sdk
    # 4. dedupe: SELECT * FROM analysed WHERE sha256=? → short-circuit w/ cached
    # 5. threat intel: local known_bad_hashes.txt + MalwareBazaar API if key set
    #    (accelerator ONLY — never the sole verdict; sets override flag)
    # 6. append FILE_META + optional THREAT_INTEL nodes
```

Guard: reject > 300MB, reject non-zip, reject zip-bombs (check uncompressed size
ratio). A malformed upload crashing the API at H70 is an avoidable embarrassment.

---

## Phase 0 Definition of Done

- [ ] `make lint test` green; CI runs contract tests on push
- [ ] All contracts in `drishti/contracts/`, round-trip tested
- [ ] Ledger appends, chains, signs, verifies, detects tampering at exact seq
- [ ] `AI_CLAIM` without evidence is rejected at the store layer
- [ ] Pipeline walks 13 stub stages; SSE emits stage events
- [ ] `ReplayTraceSource` works off a hand-written fixture
- [ ] UI shell renders score panel, tabs, live log
- [ ] Real `ingest()` handles a real APK incl. split reassembly
- [ ] `frida-ps -U` result recorded in `STATUS.md` (go/no-go for P4)
- [ ] Datasets downloading or downloaded
- [ ] `git tag p0-done`

**If P0 runs past H07, cut T0.8 (UI shell) to a static HTML page and proceed.**
The UI can be rebuilt in P6; the contracts and ledger cannot.
