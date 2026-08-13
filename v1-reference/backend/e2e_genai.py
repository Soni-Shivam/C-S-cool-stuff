#!/usr/bin/env python3
"""End-to-end M1->M7 execution with LIVE Gemini, printing every stage's real output.

Run from backend/ with the venv active and backend/.env populated.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
load_dotenv("backend/.env")
load_dotenv(".env")

from drishti.llm import get_provider          # noqa: E402
from drishti.pipeline.pipeline import run_pipeline  # noqa: E402
from drishti.reporting.report import build_android_report  # noqa: E402

APK = sys.argv[1] if len(sys.argv) > 1 else "samples/fdroid.apk"
MODE = sys.argv[2] if len(sys.argv) > 2 else "absent"
OBS = sys.argv[3] if len(sys.argv) > 3 else None

ts = datetime.now(timezone.utc).isoformat()
provider = get_provider()
print("=" * 78)
print(f"PROVIDER      : {provider.name}")
print(f"GEMINI_MODEL  : {os.environ.get('GEMINI_MODEL', '(unset)')}")
print(f"GEMINI_KEY set: {bool(os.environ.get('GEMINI_API_KEY'))}")
print(f"APK           : {APK}")
print(f"DYNAMIC MODE  : {MODE}")
print("=" * 78)

result = run_pipeline(APK, timestamp=ts, provider=provider,
                     dynamic_mode=MODE, observations=OBS)
v = result.verdict

print("\n--- M1 INGEST ---")
print(f"  sha256      : {v.sha256}")
print(f"  intel hit   : {result.static.get('intel_hit', 'n/a')}")

print("\n--- M2 STATIC ---")
s = result.static
print(f"  permissions      : {len(s.get('permissions', []))}")
print(f"  combos           : {[c.get('label') for c in s.get('combos',[])]}")
print(f"  signature severity G = {s.get('signature_severity')}")
print(f"  MITRE (static)   : {s.get('mitre')}")
print(f"  IOCs             : {len(s.get('iocs', []))}")
print(f"  yara hits        : {s.get('yara_hits')}")

print("\n--- M5 ML ---")
m = result.ml
print(f"  P_cal        : {m.get('p_cal')}")
print(f"  label        : {m.get('label')}")
print(f"  model version: {m.get('model_version')}")

print("\n--- M3 DYNAMIC ---")
d = result.dynamic
print(f"  status    : {d.get('status')}")
print(f"  b_dynamic : {d.get('b_dynamic')}")
print(f"  behaviours: {len(d.get('behaviors', []) or [])}")
for b in (d.get("behaviors") or [])[:8]:
    print(f"    - {b}")

print("\n--- M4 GENAI (live) ---")
print(f"  provider            : {v.provider}")
print(f"  verifier passed     : {v.verified}")
print(f"  behavioral risk B   : (folded into score)")
print(f"  impersonated_target : {v.impersonated_target}")
print(f"  victim_profile      : {json.dumps(v.victim_profile)}")
print(f"  attack_techniques   : {v.attack_techniques}")
print(f"  evidence_refs       : {len(v.evidence_refs)} -> {v.evidence_refs[:4]}")
print(f"  summary             :\n      {v.summary}")

print("\n--- M6 SCORING ---")
print(f"  threat_score : {v.threat_score}/100")
print(f"  severity     : {v.severity_band}")
print(f"  confidence   : {v.confidence} ({v.confidence_label})")

print("\n--- LEDGER ---")
print(f"  nodes: {len(result.ledger)}")
types = {}
for n in result.ledger:
    types[n["type"]] = types.get(n["type"], 0) + 1
for t, c in sorted(types.items()):
    print(f"    {t:22s} {c}")
from drishti.ledger import verify_ledger
from drishti.ledger.signing import verify_signature
sig = result.ledger_signature
print(f"  signature    : {sig.get('signature','')[:32]}...")
print(f"  pubkey       : {sig.get('pubkey','')[:32]}...")
try:
    print(f"  hash chain   : {verify_ledger(result.ledger)}")
except Exception as e:
    print(f"  hash chain   : (verify_ledger: {e})")

print("\n--- M7 ANDROID REPORT ---")
report = build_android_report(result, analysis_id="e2e-live-1", gemini_live=True)
rd = report.model_dump()
print(f"  verdict headline : {rd.get('headline')}")
print(f"  recommendation   : {rd.get('recommendation')}")
print(f"  provenance       : {json.dumps(rd.get('provenance'))}")
print(f"  confidence       : {json.dumps(rd.get('confidence'))}")
print(f"  capabilities ({len(rd.get('capabilities', []))}):")
for c in rd.get("capabilities", [])[:8]:
    print(f"    - {c.get('statement')}")
    print(f"      refs={c.get('evidence')}")
print(f"  potential consequences ({len(rd.get('potential_consequences', []))}):")
for c in rd.get("potential_consequences", [])[:8]:
    print(f"    - {c if isinstance(c, str) else c.get('statement')}")
print(f"  indicators: {len(rd.get('indicators', []))}")

out = Path("/tmp/drishti_e2e_report.json")
out.write_text(json.dumps({"verdict": v.model_dump(), "report": rd,
                           "ledger": result.ledger}, default=str, indent=2))
print(f"\nfull artifact -> {out}")
