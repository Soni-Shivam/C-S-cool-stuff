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
