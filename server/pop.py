"""Shared experimental HMAC-PoP v2 encoding. This is not OAuth DPoP.
Replay state requires one shared Session per session in a single process.
"""
import base64
import hashlib
import hmac
import re
import struct
import threading
from dataclasses import dataclass, field

WINDOW = 60
LABEL = b'OPAQUE-HTTP-POP-v2'

def frame(*parts: bytes) -> bytes:
    return b''.join(struct.pack('!I', len(p)) + p for p in parts)

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    if not 1 <= length <= 255 * 32:
        raise ValueError('HKDF length')
    prk = hmac.digest(salt, ikm, 'sha256')
    out = last = b''
    for counter in range(1, (length + 31) // 32 + 1):
        last = hmac.digest(prk, last + info + bytes([counter]), 'sha256')
        out += last
    return out[:length]

def derive_key(session_key: bytes, origin: str, sid: str, subject: str) -> bytes:
    # origin and subject come from authenticated server-side session context.
    return hkdf(session_key, b'opaque-pop-salt-v2',
                frame(LABEL, origin.encode('ascii'), sid.encode('ascii'), subject.encode('utf8')))

@dataclass
class Session:
    sid: str
    origin: str
    key: bytes
    exp: int
    username: str = ""
    revoked: bool = False
    last_seen: int = 0
    capacity: int = 4096
    nonces: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.Lock, repr=False)

def canonical(sid: str, origin: str, method: str, target: str, content_type: str,
              body: bytes, ts: str, nonce: str) -> bytes:
    if len(method) > 16 or not re.fullmatch(r'[A-Z]+', method):
        raise ValueError('method encoding')
    if len(target) > 4096 or not target.startswith('/') or target.startswith('//') or '#' in target:
        raise ValueError('target encoding')
    if any(ord(c) < 33 or ord(c) > 126 for c in target):
        raise ValueError('target encoding')
    if not re.fullmatch(r'(0|[1-9][0-9]{0,19})', ts):
        raise ValueError('timestamp encoding')
    if not re.fullmatch(r'[0-9a-f]{32}', nonce):
        raise ValueError('nonce encoding')
    if len(content_type) > 128 or any(ord(c) < 32 or ord(c) > 126 for c in content_type):
        raise ValueError('content type encoding')
    return frame(LABEL, sid.encode('ascii'), origin.encode('ascii'),
                 method.encode('ascii'), target.encode('ascii'),
                 content_type.encode('ascii'), hashlib.sha256(body).digest(),
                 ts.encode('ascii'), nonce.encode('ascii'))

def sign(sess: Session, method: str, target: str, content_type: str,
         body: bytes, ts: str, nonce: str) -> str:
    msg = canonical(sess.sid, sess.origin, method, target, content_type, body, ts, nonce)
    return base64.b64encode(hmac.digest(sess.key, msg, 'sha256')).decode('ascii')

def verify(sess: Session, method: str, target: str, content_type: str,
           body: bytes, ts: str, nonce: str, proof: str, *, now: int) -> None:
    msg = canonical(sess.sid, sess.origin, method, target, content_type, body, ts, nonce)
    if len(proof) != 44:
        raise ValueError('proof encoding')
    try:
        supplied = base64.b64decode(proof, validate=True)
    except (ValueError, UnicodeError) as e:
        raise ValueError('proof encoding') from e
    if len(supplied) != 32 or base64.b64encode(supplied).decode('ascii') != proof:
        raise ValueError('proof encoding')
    expected = hmac.digest(sess.key, msg, 'sha256')
    if not hmac.compare_digest(expected, supplied):
        raise ValueError('bad proof')
    # One critical section implements check-and-insert for this process.
    with sess.lock:
        if sess.revoked or now < sess.last_seen or now >= sess.exp:
            raise ValueError('expired session')
        sess.last_seen = now
        timestamp = int(ts)
        if abs(now - timestamp) > WINDOW:
            raise ValueError('stale request')
        # Inclusive freshness boundary requires retaining expiry == now.
        sess.nonces = {n: until for n, until in sess.nonces.items() if until >= now}
        if nonce in sess.nonces:
            raise ValueError('replay')
        if len(sess.nonces) >= sess.capacity:
            raise ValueError('cache capacity')
        sess.nonces[nonce] = timestamp + WINDOW
