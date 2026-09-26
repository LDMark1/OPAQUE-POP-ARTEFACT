"""Run from the repository root: python -m client.client_demo."""
import os
from pathlib import Path
import secrets
import ssl
import time

import httpx
import opaque_rs
from server.pop import Session, derive_key, sign

SERVER = os.getenv('SERVER_URL', 'https://localhost:8000').rstrip('/')


def tls_verify_config():
    ca = os.getenv('TLS_CA_BUNDLE', str(Path(__file__).resolve().parents[1] / 'certs/localhost.crt'))
    return ssl.create_default_context(cafile=ca)


def register(client, username, password):
    state, request = opaque_rs.client_registration_start(password)
    response = client.post('/register/start', json={'username': username, 'reg_request_hex': bytes(request).hex()})
    response.raise_for_status()
    upload, _ = opaque_rs.client_registration_finish(state, password, bytes.fromhex(response.json()['reg_response_hex']))
    result = client.post('/register/finish', json={
        'registration_id': response.json()['registration_id'], 'reg_upload_hex': bytes(upload).hex()})
    result.raise_for_status()


def login(client, username, password):
    state, request = opaque_rs.client_login_start(password)
    response = client.post('/login/start', json={'username': username, 'cred_request_hex': bytes(request).hex()})
    response.raise_for_status()
    final, key, _ = opaque_rs.client_login_finish(state, password, bytes.fromhex(response.json()['cred_response_hex']))
    result = client.post('/login/finish', json={'login_id': response.json()['login_id'], 'cred_final_hex': bytes(final).hex()})
    result.raise_for_status()
    data = result.json()
    origin = str(client.base_url).rstrip('/')
    if data['origin'] != origin:
        raise ValueError('unexpected server origin')
    return Session(data['session_id'], origin, derive_key(bytes(key), origin, data['session_id'], username),
                   data['expires_at'], username=username)


def signed_request(client, session, path, *, payload=None, now=None, nonce=None):
    request = client.build_request('POST', path, json=payload) if payload is not None else client.build_request('POST', path)
    body = request.read()
    timestamp = str(int(time.time()) if now is None else now)
    nonce = nonce or secrets.token_hex(16)
    target = request.url.raw_path.decode('ascii')  # includes exact query octets
    proof = sign(session, request.method, target, request.headers.get('content-type', ''), body, timestamp, nonce)
    request.headers.update({'Authorization': f'Bearer {session.sid}', 'X-TS': timestamp,
                            'X-NONCE': nonce, 'X-POP': proof})
    return request


def main():
    if not SERVER.startswith('https://'):
        raise ValueError('HTTPS is required')
    # Unique demo identity so repeated runs never overwrite an existing account.
    username = 'demo-' + secrets.token_hex(8)
    password = secrets.token_bytes(32)
    with httpx.Client(base_url=SERVER, verify=tls_verify_config(), trust_env=False) as client:
        register(client, username, password)
        session = login(client, username, password)
        print('Registration and OPAQUE login succeeded (secret values are not logged).')
        request = signed_request(client, session, '/api/transfer?demo=1', payload={'amount': 50, 'to': 'bob'})
        ok = client.send(request)
        ok.raise_for_status()
        replay = client.send(request)
        assert replay.status_code == 401
        stolen = client.post('/api/transfer', json={'amount': 50, 'to': 'bob'},
                             headers={'Authorization': f'Bearer {session.sid}'})
        assert stolen.status_code == 401
        client.send(signed_request(client, session, '/session/logout')).raise_for_status()
        print('Protected call accepted; replay and stolen bearer rejected; logout succeeded.')


if __name__ == '__main__':
    main()
