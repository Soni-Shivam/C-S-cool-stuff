def verify_claim(claim_refs, led) -> bool:
    if not claim_refs:
        return False
    existing = {n.id for n in led.nodes}
    return all(ref in existing for ref in claim_refs)


def filter_verified_claims(claims, led):
    return [c for c in claims if verify_claim(c.get("evidence_refs", []), led)]
