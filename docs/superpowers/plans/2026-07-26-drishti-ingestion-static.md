# DRISHTI M1 Ingestion + M2 Static Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add real APK ingestion (hashing + threat-intel fast-pass) and static analysis (Androguard manifest/permission/certificate parsing, permission-combo risk detection, IOC extraction, YARA scanning), each writing evidence nodes into the ledger.

**Architecture:** Split analysis *logic* (pure functions over parsed data — exhaustively unit-tested) from the *Androguard adapter* (I/O over an APK, integration-tested against a real sample later). M1 does hashing + intel; M2 parses + applies rules + YARA. Both append `EvidenceNode`s.

**Tech Stack:** androguard 4.x, yara-python, pydantic, pytest.

## Global Constraints

- Never execute an APK. Static parsing only.
- Permission-combo catalog & MITRE ids per paper §4.2 and Table 6.
- Every finding appends an evidence node; risk findings carry `confidence` and `location`.
- Pure logic (rules, IOC regex, cert heuristics) has zero Androguard dependency.

---

### Task 1: M1 — APK hashing & bundle

**Files:**
- Create: `backend/drishti/ingestion/__init__.py`, `backend/drishti/ingestion/ingest.py`
- Create: `backend/tests/test_ingestion.py`
- Create: `backend/drishti/data/known_bad_hashes.txt`

**Interfaces:**
- Produces: `ApkBundle{path, sha256, size_bytes, is_split, intel_hit, intel_family}`;
  `sha256_file(path)->str`; `load_known_bad(path)->dict[str,str]`;
  `ingest(apk_path, led, timestamp, known_bad=None)->ApkBundle` (appends `ingest` node; if intel hit, a second `intel` node).

- [ ] Step 1: Test — sha256 of a known byte string matches hashlib; intel hit sets `intel_family`; ledger gets an `ingest` node.
- [ ] Step 2: Run → fail.
- [ ] Step 3: Implement `ingest.py` (stream file in chunks for sha256; size via stat; `is_split` false for single apk; intel lookup in provided dict).
- [ ] Step 4: Run → pass.
- [ ] Step 5: Commit `feat: M1 ingestion — hashing + threat-intel fast-pass`.

### Task 2: M2 — permission-combo & IOC rules (pure)

**Files:**
- Create: `backend/drishti/static/__init__.py`, `backend/drishti/static/rules.py`
- Create: `backend/tests/test_static_rules.py`

**Interfaces:**
- Produces: `PermissionCombo{id,label,severity,permissions,mitre}`; `PERMISSION_COMBOS`;
  `detect_permission_combos(perms:set[str])->list[PermissionCombo]`;
  `extract_iocs(strings:list[str])->dict{urls,ips,crypto}`;
  `signature_severity(combos)->float` (max severity, 0..1).

- [ ] Step 1: Tests — RECEIVE_SMS+READ_SMS → OTP combo; BIND_ACCESSIBILITY_SERVICE → accessibility; SYSTEM_ALERT_WINDOW+BIND_ACCESSIBILITY_SERVICE → banker combo present; IOC regex pulls url/ipv4/BTC/ETH; `signature_severity` returns max.
- [ ] Step 2: Run → fail.
- [ ] Step 3: Implement catalog + detectors + regexes.
- [ ] Step 4: Run → pass.
- [ ] Step 5: Commit `feat: M2 permission-combo + IOC rules`.

### Task 3: M2 — certificate heuristics (pure)

**Files:** Modify `rules.py`; Create `backend/tests/test_cert.py`.

**Interfaces:** `analyze_certificate(subject, issuer, is_self_signed)->dict{self_signed, brand_mismatch, note}`.

- [ ] Steps: test self-signed flag + brand-mismatch heuristic (issuer CN not matching a known brand token in package) → implement → pass → commit `feat: M2 certificate heuristics`.

### Task 4: M2 — YARA scanning

**Files:**
- Create: `backend/drishti/static/yara_scan.py`, `backend/drishti/data/yara/android_generic.yar`
- Create: `backend/tests/test_yara_scan.py`

**Interfaces:** `compile_rules(rules_dir)->yara.Rules`; `scan_bytes(data, rules)->list[str]`.

- [ ] Steps: test scanning bytes containing a marker string matches a bundled rule → implement compile+scan → pass → commit `feat: M2 YARA scanning`.

### Task 5: M2 — Androguard adapter

**Files:** Create `backend/drishti/static/androguard_adapter.py`; Create `backend/tests/test_adapter_smoke.py`.

**Interfaces:** `ParsedApk{package,permissions,activities,services,receivers,providers,exported,intent_filters,strings,cert}`; `parse_apk(path)->ParsedApk`.

- [ ] Steps: unit-test that `parse_apk` raises a clear error on a non-APK path (real-APK integration test added in the samples plan) → implement adapter wrapping `androguard.core.apk.APK` → pass → commit `feat: M2 Androguard adapter`.

### Task 6: M2 — analyzer orchestration

**Files:** Create `backend/drishti/static/analyzer.py`; Create `backend/tests/test_analyzer.py`.

**Interfaces:** `StaticResult{package,permissions,combos,iocs,cert,yara_hits,exported,mitre}`;
`analyze_parsed(parsed, bundle, led, timestamp, yara_hits=None)->StaticResult` (pure over a `ParsedApk`, so testable without an APK; appends `manifest`/`api_sink`/`ioc`/`cert` nodes).

- [ ] Steps: test that a synthetic `ParsedApk` with banking-trojan perms yields combos, MITRE ids, and ledger nodes → implement → pass → commit `feat: M2 static analyzer orchestration`.

## Self-Review
- M1 hashing+intel §4.1 → Task 1. Permission combos §4.2 → Task 2. IOC → Task 2. Cert → Task 3. YARA → Task 4. Androguard parse → Task 5. Orchestration+MITRE Table 6 → Task 6. Real-APK integration → deferred to samples plan (documented).
