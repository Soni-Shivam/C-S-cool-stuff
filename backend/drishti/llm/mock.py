"""Offline provider. Deterministic, no network. It is a genuine (if simple)
heuristic reasoner: it reads the same embedded evidence JSON a real model would,
so the offline demo and tests produce coherent, grounded verdicts."""
import json
import re

from drishti.llm.provider import LLMProvider

_JSON_BLOCK = re.compile(r"<<EVIDENCE_JSON>>(.*?)<<END_EVIDENCE_JSON>>", re.DOTALL)


def _extract_evidence(user_data: str) -> dict:
    m = _JSON_BLOCK.search(user_data)
    if not m:
        return {}
    try:
        return json.loads(m.group(1).strip())
    except json.JSONDecodeError:
        return {}


class MockProvider(LLMProvider):
    name = "mock"
    live = False

    def generate(self, system: str, user_data: str) -> str:
        ev = _extract_evidence(user_data)
        return (f"[offline heuristic] {len(ev.get('permission_combos', []))} high-risk "
                f"capabilities; set GEMINI_API_KEY for live Gemini reasoning.")

    def generate_json(self, system: str, user_data: str, schema: dict) -> dict:
        ev = _extract_evidence(user_data)
        combos = ev.get("permission_combos", [])
        p_cal = float(ev.get("p_cal", 0.0))
        node_ids = ev.get("evidence_node_ids", [])
        iocs = ev.get("iocs", {}) or {}
        techniques = sorted({m for c in combos for m in c.get("mitre", [])})

        b = min(1.0, 0.28 * len(combos) + 0.45 * p_cal + (0.2 if iocs.get("ips") else 0.0))
        tactic = "credential / OTP theft" if combos else "no high-risk capability observed"
        return {
            "summary": (f"Offline heuristic verdict: {len(combos)} high-risk capability(ies) "
                        f"detected, calibrated ML P_cal={p_cal:.2f}."),
            "behavioral_risk": round(b, 3),
            "impersonated_target": ev.get("impersonated_target"),
            "victim_profile": {
                "language": "unknown",
                "tactic": tactic,
                "segment": "mobile banking users",
            },
            "attack_techniques": techniques,
            "adversarial_elicitation_deployed": [],
            "evidence_refs": node_ids,
        }
