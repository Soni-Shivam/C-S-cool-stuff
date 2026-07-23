# DRISHTI Foundation (Ledger + Scoring) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build DRISHTI's trust spine — the append-only, hash-chained, Ed25519-signed evidence ledger with a claim-verifier gate, plus the composite risk-scoring engine implementing the paper's exact formulas — as a scaffolded, test-driven Python package.

**Architecture:** A single installable Python package `drishti` under `backend/`. Pure-logic modules (`ledger`, `scoring`) are built first with full pytest coverage. Shared pydantic schemas live in `drishti/models.py`; environment-driven settings in `drishti/config.py`. No web/analysis dependencies yet — this plan produces a library you can `import` and test.

**Tech Stack:** Python 3.11+, pydantic v2, cryptography (Ed25519), pytest. Managed via `pyproject.toml`.

## Global Constraints

- Python 3.11+; type hints on all public functions.
- pydantic v2 for all data schemas.
- Evidence ledger node schema is exactly: `{id, type, source_tool, content, location, confidence, timestamp, refs, prev_hash, hash}` (paper §5).
- Scoring weights are fixed: `w_R=0.25, w_AI=0.50, w_G=0.15, w_D=0.10` (paper Table 4).
- Severity bands: 85–100 Critical, 65–84 High, 40–64 Medium, 0–39 Low (paper Table 5).
- Confirmed-malicious-hash override ⇒ `S=100, C=1.0`.
- Timestamps are injectable (caller-supplied) so runs are reproducible; never call wall-clock inside pure logic.
- Secrets only via env; never logged.
- Frequent commits: one per task.

---

### Task 1: Project scaffold & package skeleton

**Files:**
- Create: `backend/pyproject.toml`
- Create: `backend/drishti/__init__.py`
- Create: `backend/drishti/config.py`
- Create: `backend/tests/__init__.py`
- Create: `backend/tests/test_config.py`
- Create: `backend/.env.example`

**Interfaces:**
- Produces: `drishti.config.Settings` (pydantic-settings) with fields `gemini_api_key: str|None`, `gemini_model: str|None`, `androzoo_api_key: str|None`, `ledger_signing_key: str|None`, `embeddings_model: str`; and `get_settings() -> Settings` (cached).

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[project]
name = "drishti"
version = "0.1.0"
description = "DRISHTI — GenAI-native Android malware triage pipeline"
requires-python = ">=3.11"
dependencies = [
    "pydantic>=2.6",
    "pydantic-settings>=2.2",
    "cryptography>=42.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-cov>=5.0"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["."]
include = ["drishti*"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["."]
```

- [ ] **Step 2: Write the failing test** — `backend/tests/test_config.py`

```python
from drishti.config import get_settings


def test_settings_default_embeddings_model():
    s = get_settings()
    assert s.embeddings_model  # non-empty default
    assert s.gemini_api_key is None  # unset by default in test env


def test_settings_reads_env(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-3.1-pro-preview")
    get_settings.cache_clear()
    s = get_settings()
    assert s.gemini_api_key == "test-key"
    assert s.gemini_model == "gemini-3.1-pro-preview"
    get_settings.cache_clear()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_config.py -v`
Expected: FAIL (ModuleNotFoundError: drishti.config)

- [ ] **Step 4: Write `drishti/__init__.py`**

```python
__version__ = "0.1.0"
```

- [ ] **Step 5: Write `drishti/config.py`**

```python
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    gemini_api_key: str | None = None
    gemini_model: str | None = None
    androzoo_api_key: str | None = None
    ledger_signing_key: str | None = None
    embeddings_model: str = "sentence-transformers/all-MiniLM-L6-v2"


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 6: Write `.env.example`**

```
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.1-pro-preview
ANDROZOO_API_KEY=
LEDGER_SIGNING_KEY=
EMBEDDINGS_MODEL=sentence-transformers/all-MiniLM-L6-v2
```

- [ ] **Step 7: Create empty `backend/tests/__init__.py`** (empty file)

- [ ] **Step 8: Run tests to verify they pass**

Run: `cd backend && python -m pip install -e ".[dev]" && python -m pytest tests/test_config.py -v`
Expected: PASS (2 passed)

- [ ] **Step 9: Commit**

```bash
git add backend/pyproject.toml backend/drishti backend/tests backend/.env.example
git commit -m "feat: scaffold drishti package with settings"
```

---

### Task 2: Core schemas (EvidenceNode)

**Files:**
- Create: `backend/drishti/models.py`
- Create: `backend/tests/test_models.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `drishti.models.EvidenceNode` (pydantic model) with fields `id: str`, `type: str`, `source_tool: str`, `content: str`, `location: str | None = None`, `confidence: float = 1.0`, `timestamp: str`, `refs: list[str] = []`, `prev_hash: str = ""`, `hash: str = ""`; method `canonical_payload() -> str` returning deterministic JSON of all fields except `hash`.

- [ ] **Step 1: Write the failing test** — `backend/tests/test_models.py`

```python
from drishti.models import EvidenceNode


def test_canonical_payload_excludes_hash_and_is_deterministic():
    n = EvidenceNode(
        id="n1", type="manifest", source_tool="androguard",
        content="RECEIVE_SMS declared", location="manifest#L42",
        confidence=0.9, timestamp="2026-07-23T00:00:00Z",
        refs=[], prev_hash="0" * 64, hash="SHOULD_NOT_APPEAR",
    )
    payload = n.canonical_payload()
    assert "SHOULD_NOT_APPEAR" not in payload
    assert '"id":"n1"' in payload.replace(" ", "")
    # deterministic: same object -> same payload
    assert payload == n.canonical_payload()


def test_defaults():
    n = EvidenceNode(id="n1", type="ioc", source_tool="static",
                     content="hxxp://evil", timestamp="2026-07-23T00:00:00Z")
    assert n.confidence == 1.0
    assert n.refs == []
    assert n.location is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_models.py -v`
Expected: FAIL (cannot import EvidenceNode)

- [ ] **Step 3: Write `drishti/models.py`**

```python
import json

from pydantic import BaseModel, Field


class EvidenceNode(BaseModel):
    id: str
    type: str
    source_tool: str
    content: str
    location: str | None = None
    confidence: float = 1.0
    timestamp: str
    refs: list[str] = Field(default_factory=list)
    prev_hash: str = ""
    hash: str = ""

    def canonical_payload(self) -> str:
        data = self.model_dump(exclude={"hash"})
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_models.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add backend/drishti/models.py backend/tests/test_models.py
git commit -m "feat: add EvidenceNode schema with canonical payload"
```

---

### Task 3: Evidence ledger — append & hash chain

**Files:**
- Create: `backend/drishti/ledger/__init__.py`
- Create: `backend/drishti/ledger/ledger.py`
- Create: `backend/tests/test_ledger_chain.py`

**Interfaces:**
- Consumes: `drishti.models.EvidenceNode`.
- Produces: `drishti.ledger.Ledger` with:
  - `append(type, source_tool, content, *, location=None, confidence=1.0, timestamp, refs=None) -> EvidenceNode` (assigns id `n<k>`, sets `prev_hash`, computes `hash`).
  - `nodes -> list[EvidenceNode]`
  - `head_hash -> str` (hash of last node, or `"0"*64` if empty)
  - `_compute_hash(node) -> str` = `sha256((prev_hash + node.canonical_payload()).encode())`.

- [ ] **Step 1: Write the failing test** — `backend/tests/test_ledger_chain.py`

```python
import hashlib

from drishti.ledger import Ledger

TS = "2026-07-23T00:00:00Z"


def test_first_node_links_to_genesis():
    led = Ledger()
    n = led.append("manifest", "androguard", "perm X", timestamp=TS)
    assert n.id == "n1"
    assert n.prev_hash == "0" * 64
    assert n.hash != ""


def test_hash_is_sha256_of_prevhash_plus_payload():
    led = Ledger()
    n = led.append("ioc", "static", "hxxp://evil", timestamp=TS)
    expected = hashlib.sha256((("0" * 64) + n.canonical_payload()).encode()).hexdigest()
    assert n.hash == expected


def test_chain_links_sequentially():
    led = Ledger()
    a = led.append("manifest", "androguard", "a", timestamp=TS)
    b = led.append("cert", "androguard", "b", timestamp=TS)
    assert b.prev_hash == a.hash
    assert led.head_hash == b.hash
    assert [x.id for x in led.nodes] == ["n1", "n2"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_ledger_chain.py -v`
Expected: FAIL (cannot import Ledger)

- [ ] **Step 3: Write `drishti/ledger/ledger.py`**

```python
import hashlib

from drishti.models import EvidenceNode

GENESIS = "0" * 64


class Ledger:
    def __init__(self) -> None:
        self._nodes: list[EvidenceNode] = []

    @property
    def nodes(self) -> list[EvidenceNode]:
        return list(self._nodes)

    @property
    def head_hash(self) -> str:
        return self._nodes[-1].hash if self._nodes else GENESIS

    def _compute_hash(self, node: EvidenceNode) -> str:
        return hashlib.sha256((node.prev_hash + node.canonical_payload()).encode()).hexdigest()

    def append(
        self,
        type: str,
        source_tool: str,
        content: str,
        *,
        location: str | None = None,
        confidence: float = 1.0,
        timestamp: str,
        refs: list[str] | None = None,
    ) -> EvidenceNode:
        node = EvidenceNode(
            id=f"n{len(self._nodes) + 1}",
            type=type,
            source_tool=source_tool,
            content=content,
            location=location,
            confidence=confidence,
            timestamp=timestamp,
            refs=refs or [],
            prev_hash=self.head_hash,
        )
        node.hash = self._compute_hash(node)
        self._nodes.append(node)
        return node
```

- [ ] **Step 4: Write `drishti/ledger/__init__.py`**

```python
from drishti.ledger.ledger import GENESIS, Ledger

__all__ = ["Ledger", "GENESIS"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_ledger_chain.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add backend/drishti/ledger backend/tests/test_ledger_chain.py
git commit -m "feat: evidence ledger append + hash chain"
```

---

### Task 4: Ledger verification & tamper detection

**Files:**
- Modify: `backend/drishti/ledger/ledger.py`
- Create: `backend/tests/test_ledger_verify.py`

**Interfaces:**
- Consumes: `Ledger`, `EvidenceNode`.
- Produces: `Ledger.verify_chain() -> bool` (recomputes each hash and checks linkage).

- [ ] **Step 1: Write the failing test** — `backend/tests/test_ledger_verify.py`

```python
from drishti.ledger import Ledger

TS = "2026-07-23T00:00:00Z"


def test_valid_chain_verifies():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    led.append("cert", "androguard", "b", timestamp=TS)
    assert led.verify_chain() is True


def test_tampered_content_fails_verification():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    led.append("cert", "androguard", "b", timestamp=TS)
    led.nodes[0].content = "TAMPERED"          # mutate a returned copy? must mutate internal
    led._nodes[0].content = "TAMPERED"         # tamper internal node
    assert led.verify_chain() is False


def test_empty_ledger_verifies():
    assert Ledger().verify_chain() is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_ledger_verify.py -v`
Expected: FAIL (no attribute verify_chain)

- [ ] **Step 3: Add `verify_chain` to `drishti/ledger/ledger.py`** (append method to the `Ledger` class)

```python
    def verify_chain(self) -> bool:
        prev = GENESIS
        for node in self._nodes:
            if node.prev_hash != prev:
                return False
            if self._compute_hash(node) != node.hash:
                return False
            prev = node.hash
        return True
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_ledger_verify.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add backend/drishti/ledger/ledger.py backend/tests/test_ledger_verify.py
git commit -m "feat: ledger chain verification + tamper detection"
```

---

### Task 5: Ledger signing (Ed25519)

**Files:**
- Create: `backend/drishti/ledger/signing.py`
- Modify: `backend/drishti/ledger/__init__.py`
- Create: `backend/tests/test_ledger_signing.py`

**Interfaces:**
- Consumes: `Ledger.head_hash`.
- Produces:
  - `drishti.ledger.signing.generate_key() -> str` (Ed25519 private key, hex).
  - `sign_ledger(led, private_hex) -> dict{signature, pubkey}` (signature over `head_hash`, hex).
  - `verify_signature(head_hash, signature_hex, pubkey_hex) -> bool`.

- [ ] **Step 1: Write the failing test** — `backend/tests/test_ledger_signing.py`

```python
from drishti.ledger import Ledger
from drishti.ledger.signing import generate_key, sign_ledger, verify_signature

TS = "2026-07-23T00:00:00Z"


def test_sign_and_verify_roundtrip():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    key = generate_key()
    sig = sign_ledger(led, key)
    assert verify_signature(led.head_hash, sig["signature"], sig["pubkey"]) is True


def test_verify_fails_on_wrong_hash():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)
    key = generate_key()
    sig = sign_ledger(led, key)
    assert verify_signature("f" * 64, sig["signature"], sig["pubkey"]) is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_ledger_signing.py -v`
Expected: FAIL (cannot import signing)

- [ ] **Step 3: Write `drishti/ledger/signing.py`**

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_key() -> str:
    key = Ed25519PrivateKey.generate()
    return key.private_bytes_raw().hex()


def sign_ledger(led, private_hex: str) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_hex))
    signature = key.sign(led.head_hash.encode())
    pub = key.public_key().public_bytes_raw()
    return {"signature": signature.hex(), "pubkey": pub.hex()}


def verify_signature(head_hash: str, signature_hex: str, pubkey_hex: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pubkey_hex))
    try:
        pub.verify(bytes.fromhex(signature_hex), head_hash.encode())
        return True
    except InvalidSignature:
        return False
```

- [ ] **Step 4: Update `drishti/ledger/__init__.py`**

```python
from drishti.ledger.ledger import GENESIS, Ledger
from drishti.ledger.signing import generate_key, sign_ledger, verify_signature

__all__ = ["Ledger", "GENESIS", "generate_key", "sign_ledger", "verify_signature"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_ledger_signing.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add backend/drishti/ledger backend/tests/test_ledger_signing.py
git commit -m "feat: Ed25519 ledger signing + verification"
```

---

### Task 6: Verifier gate (claim citation check)

**Files:**
- Create: `backend/drishti/ledger/verifier.py`
- Modify: `backend/drishti/ledger/__init__.py`
- Create: `backend/tests/test_verifier.py`

**Interfaces:**
- Consumes: `Ledger`.
- Produces: `verify_claim(claim_refs: list[str], led: Ledger) -> bool` (PASS iff every ref is an existing node id); `filter_verified_claims(claims: list[dict], led) -> list[dict]` where each claim has an `evidence_refs` key.

- [ ] **Step 1: Write the failing test** — `backend/tests/test_verifier.py`

```python
from drishti.ledger import Ledger
from drishti.ledger.verifier import filter_verified_claims, verify_claim

TS = "2026-07-23T00:00:00Z"


def _ledger():
    led = Ledger()
    led.append("manifest", "androguard", "a", timestamp=TS)  # n1
    led.append("api_sink", "androguard", "b", timestamp=TS)  # n2
    return led


def test_claim_with_existing_refs_passes():
    led = _ledger()
    assert verify_claim(["n1", "n2"], led) is True


def test_claim_with_missing_ref_rejected():
    led = _ledger()
    assert verify_claim(["n1", "n99"], led) is False


def test_claim_with_no_refs_rejected():
    led = _ledger()
    assert verify_claim([], led) is False


def test_filter_drops_unverified_claims():
    led = _ledger()
    claims = [
        {"text": "grounded", "evidence_refs": ["n1"]},
        {"text": "hallucinated", "evidence_refs": ["n42"]},
    ]
    kept = filter_verified_claims(claims, led)
    assert [c["text"] for c in kept] == ["grounded"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_verifier.py -v`
Expected: FAIL (cannot import verifier)

- [ ] **Step 3: Write `drishti/ledger/verifier.py`**

```python
def verify_claim(claim_refs, led) -> bool:
    if not claim_refs:
        return False
    existing = {n.id for n in led.nodes}
    return all(ref in existing for ref in claim_refs)


def filter_verified_claims(claims, led):
    return [c for c in claims if verify_claim(c.get("evidence_refs", []), led)]
```

- [ ] **Step 4: Update `drishti/ledger/__init__.py`** to also export verifier funcs

```python
from drishti.ledger.ledger import GENESIS, Ledger
from drishti.ledger.signing import generate_key, sign_ledger, verify_signature
from drishti.ledger.verifier import filter_verified_claims, verify_claim

__all__ = [
    "Ledger", "GENESIS",
    "generate_key", "sign_ledger", "verify_signature",
    "verify_claim", "filter_verified_claims",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_verifier.py -v`
Expected: PASS (4 passed)

- [ ] **Step 6: Commit**

```bash
git add backend/drishti/ledger backend/tests/test_verifier.py
git commit -m "feat: verifier gate for grounded GenAI claims"
```

---

### Task 7: Scoring — fused AI signal & composite score

**Files:**
- Create: `backend/drishti/scoring/__init__.py`
- Create: `backend/drishti/scoring/engine.py`
- Create: `backend/tests/test_scoring.py`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `fused_ai(p_cal: float, b: float) -> float` = `p_cal + b - p_cal*b`.
  - `composite_score(r, f_ai, g, d) -> float` = `100*min(1, 0.25*r + 0.50*f_ai + 0.15*g + 0.10*d)`.
  - Weight constants `W_R=0.25, W_AI=0.50, W_G=0.15, W_D=0.10`.

- [ ] **Step 1: Write the failing test** — `backend/tests/test_scoring.py`

```python
import pytest

from drishti.scoring.engine import composite_score, fused_ai


def test_fused_ai_joint_probability():
    # 0.6 + 0.5 - 0.3 = 0.8
    assert fused_ai(0.6, 0.5) == pytest.approx(0.8)


def test_fused_ai_bounds():
    assert fused_ai(0.0, 0.0) == 0.0
    assert fused_ai(1.0, 0.0) == 1.0
    assert fused_ai(1.0, 1.0) == 1.0


def test_composite_score_clamps_to_100():
    assert composite_score(1.0, 1.0, 1.0, 1.0) == 100.0


def test_composite_score_all_zero():
    assert composite_score(0.0, 0.0, 0.0, 0.0) == 0.0


def test_composite_score_weighted_sum():
    # 0.25*0.4 + 0.50*0.8 + 0.15*0.2 + 0.10*0.0 = 0.1+0.4+0.03+0 = 0.53
    assert composite_score(0.4, 0.8, 0.2, 0.0) == pytest.approx(53.0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_scoring.py -v`
Expected: FAIL (cannot import engine)

- [ ] **Step 3: Write `drishti/scoring/engine.py`**

```python
W_R = 0.25
W_AI = 0.50
W_G = 0.15
W_D = 0.10


def fused_ai(p_cal: float, b: float) -> float:
    """Joint probability of non-mutually-exclusive events (paper §4.6)."""
    return p_cal + b - (p_cal * b)


def composite_score(r: float, f_ai: float, g: float, d: float) -> float:
    weighted = W_R * r + W_AI * f_ai + W_G * g + W_D * d
    return 100.0 * min(1.0, weighted)
```

- [ ] **Step 4: Write `drishti/scoring/__init__.py`**

```python
from drishti.scoring.engine import composite_score, fused_ai

__all__ = ["fused_ai", "composite_score"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_scoring.py -v`
Expected: PASS (5 passed)

- [ ] **Step 6: Commit**

```bash
git add backend/drishti/scoring backend/tests/test_scoring.py
git commit -m "feat: composite risk score + fused AI signal"
```

---

### Task 8: Scoring — confidence, severity bands, override

**Files:**
- Modify: `backend/drishti/scoring/engine.py`
- Modify: `backend/drishti/scoring/__init__.py`
- Create: `backend/tests/test_scoring_bands.py`

**Interfaces:**
- Consumes: scoring engine.
- Produces:
  - `confidence(gamma: float, p_cal: float, b: float) -> float` = `gamma*(1-abs(p_cal-b))`.
  - `severity_band(score: float) -> str` returning `"Critical"|"High"|"Medium"|"Low"`.
  - `score_verdict(*, r, p_cal, b, g, d, gamma, confirmed_malicious=False) -> dict{score:int, confidence:float, band:str}` applying the override.

- [ ] **Step 1: Write the failing test** — `backend/tests/test_scoring_bands.py`

```python
import pytest

from drishti.scoring.engine import confidence, score_verdict, severity_band


@pytest.mark.parametrize("score,band", [
    (100, "Critical"), (85, "Critical"),
    (84, "High"), (65, "High"),
    (64, "Medium"), (40, "Medium"),
    (39, "Low"), (0, "Low"),
])
def test_severity_bands_boundaries(score, band):
    assert severity_band(score) == band


def test_confidence_high_when_signals_agree():
    assert confidence(1.0, 0.9, 0.9) == pytest.approx(1.0)


def test_confidence_drops_when_signals_disagree():
    # gamma=0.8, |0.9-0.4|=0.5 -> 0.8*0.5 = 0.4
    assert confidence(0.8, 0.9, 0.4) == pytest.approx(0.4)


def test_confirmed_hash_override():
    v = score_verdict(r=0.0, p_cal=0.0, b=0.0, g=0.0, d=0.0, gamma=0.2,
                      confirmed_malicious=True)
    assert v["score"] == 100
    assert v["confidence"] == 1.0
    assert v["band"] == "Critical"


def test_score_verdict_normal_path():
    v = score_verdict(r=0.4, p_cal=0.6, b=0.5, g=0.2, d=0.0, gamma=0.9)
    # f_ai=0.8 -> composite = 0.25*0.4+0.5*0.8+0.15*0.2+0 = 0.53 -> 53
    assert v["score"] == 53
    assert v["band"] == "Medium"
    # confidence = 0.9*(1-|0.6-0.5|) = 0.9*0.9 = 0.81
    assert v["confidence"] == pytest.approx(0.81)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && python -m pytest tests/test_scoring_bands.py -v`
Expected: FAIL (cannot import confidence/severity_band/score_verdict)

- [ ] **Step 3: Extend `drishti/scoring/engine.py`** (append)

```python
def confidence(gamma: float, p_cal: float, b: float) -> float:
    return gamma * (1.0 - abs(p_cal - b))


def severity_band(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 65:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def score_verdict(*, r, p_cal, b, g, d, gamma, confirmed_malicious=False) -> dict:
    if confirmed_malicious:
        return {"score": 100, "confidence": 1.0, "band": "Critical"}
    f_ai = fused_ai(p_cal, b)
    s = composite_score(r, f_ai, g, d)
    return {
        "score": int(round(s)),
        "confidence": round(confidence(gamma, p_cal, b), 4),
        "band": severity_band(s),
    }
```

- [ ] **Step 4: Update `drishti/scoring/__init__.py`**

```python
from drishti.scoring.engine import (
    composite_score,
    confidence,
    fused_ai,
    score_verdict,
    severity_band,
)

__all__ = [
    "fused_ai", "composite_score", "confidence",
    "severity_band", "score_verdict",
]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && python -m pytest tests/test_scoring_bands.py -v`
Expected: PASS (all parametrized + 4 passed)

- [ ] **Step 6: Commit**

```bash
git add backend/drishti/scoring backend/tests/test_scoring_bands.py
git commit -m "feat: confidence, severity bands, confirmed-hash override"
```

---

### Task 9: Full-suite green + coverage checkpoint

**Files:**
- Create: `backend/README.md`

- [ ] **Step 1: Run the whole suite**

Run: `cd backend && python -m pytest -v`
Expected: PASS (all tests from Tasks 1–8 green)

- [ ] **Step 2: Write `backend/README.md`** documenting install (`pip install -e ".[dev]"`), test command, and the modules delivered (config, models, ledger, scoring).

- [ ] **Step 3: Commit**

```bash
git add backend/README.md
git commit -m "docs: backend foundation readme"
```

---

## Self-Review

**Spec coverage (foundation subset):**
- Evidence ledger schema §5.1 → Task 2, 3. ✓
- Hash chain + tamper detection → Task 3, 4. ✓
- Ed25519 signing → Task 5. ✓
- Verifier gate (grounded claims) §10 → Task 6. ✓
- `fused_ai`, composite `S`, weights §6/Table 4 → Task 7. ✓
- `confidence`, severity bands, override §6/Table 5 → Task 8. ✓
- Config/secrets via env §13 → Task 1. ✓
- Deferred to later plans (correctly out of this plan's scope): M1/M2/M4/M5/M3/M7, API, frontend, paper.

**Placeholder scan:** none — every step has concrete code/commands.

**Type consistency:** `Ledger.append` signature (keyword-only `timestamp`, `refs`) is used consistently across Tasks 3–6 tests. `score_verdict` keyword args match between Task 8 definition and tests. `verify_claim(claim_refs, led)` order consistent across verifier module and tests.
