# SECURITY INVARIANT:
# pop_key is domain-separated via HKDF and MUST NOT be reused for encryption

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass, field
from typing import Dict

POP_WINDOW_SECONDS = 60
NONCE_TTL_SECONDS = POP_WINDOW_SECONDS + 30

def b64e(b: bytes) -> str:
    # Encode bytes to base64 ASCII for header-safe transport.
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    # Decode base64 ASCII strings back into raw bytes.
    return base64.b64decode(s.encode("ascii"))

# --- HKDF (SHA-256), minimal implementation ---
def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # HKDF extract step to derive a pseudorandom key from input keying material.
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    # HKDF expand step to derive a fixed-length output key.
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]

def derive_pop_key(session_key: bytes) -> bytes:
    # Derive a PoP-only MAC key from the shared session key.
    # Domain separation: this key is ONLY for PoP MACs (not for anything else).
    prk = hkdf_extract(b"opaque-pop-salt-v1", session_key)
    return hkdf_expand(prk, b"OPAQUE-POP-MAC-v1", 32)

# --- Canonicalization ---
def canonical_request(method: str, path: str, body: bytes, ts: str, nonce: str) -> bytes:
    # Canonicalize request fields for deterministic MAC computation.
    body_hash_hex = hashlib.sha256(body).hexdigest()
    return f"{method}\n{path}\n{body_hash_hex}\n{ts}\n{nonce}".encode("utf-8")

@dataclass
class Session:
    username: str
    pop_key: bytes                  # derived MAC key ONLY
    exp: int                        # unix seconds expiry
    nonces: Dict[str, int] = field(default_factory=dict)  # nonce -> first_seen_ts

def evict_old_nonces(sess: Session, now: int, ttl_seconds: int) -> None:
    # Drop old nonces so the replay cache doesn't grow unbounded.
    # remove nonces older than ttl_seconds
    cutoff = now - ttl_seconds
    # dict comp is simplest and fast enough for prototype
    sess.nonces = {n: t for (n, t) in sess.nonces.items() if t >= cutoff}

def verify_pop(
    sess: Session,
    method: str,
    path: str,
    body: bytes,
    ts: str,
    nonce: str,
    pop_b64: str,
    window_seconds: int = POP_WINDOW_SECONDS,
) -> None:
    # Verify PoP MAC + freshness + replay protection for a request.
    now = int(time.time())

    # Expiry check (defense in depth; app.py also checks)
    if sess.exp < now:
        raise ValueError("expired session")

    ts_i = int(ts)
    if abs(now - ts_i) > window_seconds:
        raise ValueError("stale request")

    # Evict old nonces before checking replay
    # TTL should be >= window_seconds (so replays inside the window are detected)
    evict_old_nonces(sess, now, ttl_seconds=NONCE_TTL_SECONDS)

    if nonce in sess.nonces:
        raise ValueError("replay detected")
    sess.nonces[nonce] = now

    msg = canonical_request(method, path, body, ts, nonce)
    expected = hmac.new(sess.pop_key, msg, hashlib.sha256).digest()
    got = b64d(pop_b64)

    if not hmac.compare_digest(expected, got):
        raise ValueError("bad proof")
