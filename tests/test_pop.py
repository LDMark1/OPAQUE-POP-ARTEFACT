from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import pytest
from server.pop import Session, derive_key, hkdf, sign, verify


def session(**kwargs):
    return Session('s' * 43, 'https://localhost:8000', b'k' * 32, 3000, **kwargs)


def call(s, *, ts='1000', nonce='ab' * 16, **changes):
    args = dict(method='POST', target='/api/transfer?a=1', content_type='application/json',
                body=b'{"amount":1}', ts=ts, nonce=nonce)
    args.update(changes)
    return args, sign(s, **args)


def test_hkdf_rfc5869():
    assert hkdf(bytes.fromhex('0b' * 22), bytes.fromhex('000102030405060708090a0b0c'),
                bytes.fromhex('f0f1f2f3f4f5f6f7f8f9'), 42).hex() == (
                    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
                    '34007208d5b887185865')


def test_bad_mac_does_not_consume_nonce():
    s = session()
    args, good = call(s)
    _, bad = call(replace(s, key=b'x' * 32))
    with pytest.raises(ValueError):
        verify(s, **args, proof=bad, now=1000)
    assert not s.nonces
    verify(s, **args, proof=good, now=1000)
    with pytest.raises(ValueError, match='replay'):
        verify(s, **args, proof=good, now=1000)


def test_future_timestamp_retained_through_inclusive_boundary():
    s = session()
    args, proof = call(s, ts='1060')
    verify(s, **args, proof=proof, now=1000)
    for now in (1091, 1120):
        with pytest.raises(ValueError, match='replay'):
            verify(s, **args, proof=proof, now=now)
    with pytest.raises(ValueError, match='stale'):
        verify(s, **args, proof=proof, now=1121)


@pytest.mark.parametrize('field,value', [('method', 'GET'), ('target', '/api/transfer?a=2'),
    ('content_type', 'text/plain'), ('body', b'changed'), ('ts', '1001'), ('nonce', 'cd' * 16)])
def test_tampering(field, value):
    s = session()
    args, proof = call(s)
    args[field] = value
    with pytest.raises(ValueError):
        verify(s, **args, proof=proof, now=1000)
    assert not s.nonces


@pytest.mark.parametrize('field,value', [('sid', 'z' * 43), ('origin', 'https://other.example')])
def test_context_binding(field, value):
    s = session()
    args, proof = call(s)
    with pytest.raises(ValueError):
        verify(replace(s, **{field: value}), **args, proof=proof, now=1000)
    assert derive_key(b'k', 'https://a', 's', 'u') != derive_key(b'k', 'https://b', 's', 'u')


@pytest.mark.parametrize('proof', ['!', 'A' * 44, 'é' * 44])
def test_strict_base64(proof):
    s = session()
    args, _ = call(s)
    with pytest.raises(ValueError):
        verify(s, **args, proof=proof, now=1000)


def test_cache_capacity_and_expiration():
    s = session(capacity=1)
    args, proof = call(s)
    verify(s, **args, proof=proof, now=1000)
    other, proof2 = call(s, nonce='cd' * 16, ts='1060')
    with pytest.raises(ValueError, match='capacity'):
        verify(s, **other, proof=proof2, now=1060)
    verify(s, **other, proof=proof2, now=1061)


def test_concurrent_duplicates():
    s = session()
    args, proof = call(s)
    def attempt(_):
        try:
            verify(s, **args, proof=proof, now=1000)
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(attempt, range(32))) == 1


def test_expiry_revocation_and_clock_rollback():
    for s, now in [(session(), 3000), (session(revoked=True), 1000), (session(last_seen=1001), 1000)]:
        args, proof = call(s)
        with pytest.raises(ValueError):
            verify(s, **args, proof=proof, now=now)


def test_replay_grid():
    # Every initially admissible offset, then every delay through expiry.
    for offset in range(-60, 61):
        for delay in range(122):
            s = session()
            args, proof = call(s, ts=str(1000 + offset))
            verify(s, **args, proof=proof, now=1000)
            with pytest.raises(ValueError):
                verify(s, **args, proof=proof, now=1000 + delay)
