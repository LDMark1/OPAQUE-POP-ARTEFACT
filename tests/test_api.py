from concurrent.futures import ThreadPoolExecutor
import secrets
import pytest
from fastapi.testclient import TestClient
import opaque_rs
from server.app import create_app
from client.client_demo import login, register, signed_request

ORIGIN = 'https://localhost:8000'
PASSWORD = b'correct horse battery staple'


@pytest.fixture
def env(tmp_path):
    now = [1000]
    app = create_app(state_dir=tmp_path / 'state', clock=lambda: now[0])
    with TestClient(app, base_url=ORIGIN) as client:
        register(client, 'alice', PASSWORD)
        yield app, client, now


def start_login(client, password=PASSWORD):
    local, request = opaque_rs.client_login_start(password)
    result = client.post('/login/start', json={'username': 'alice', 'cred_request_hex': bytes(request).hex()})
    assert result.status_code == 200
    data = result.json()
    assert set(data) == {'login_id', 'cred_response_hex'}
    return local, data


def finish_body(local, data):
    final, _, _ = opaque_rs.client_login_finish(local, PASSWORD, bytes.fromhex(data['cred_response_hex']))
    return {'login_id': data['login_id'], 'cred_final_hex': bytes(final).hex()}


def test_full_login_tampering_replay_logout(env):
    app, client, now = env
    sess = login(client, 'alice', PASSWORD)
    request = signed_request(client, sess, '/api/transfer?q=1', payload={'amount': 5, 'to': 'bob'}, now=now[0])
    good = client.send(request)
    assert good.status_code == 200 and good.json()['user'] == 'alice'
    assert client.send(request).status_code == 401
    changed = signed_request(client, sess, '/api/transfer?q=1', payload={'amount': 5, 'to': 'bob'}, now=now[0])
    changed.url = changed.url.copy_with(query=b'q=2')
    assert client.send(changed).status_code == 401
    assert client.post('/api/transfer', json={'amount': 5, 'to': 'bob'},
                       headers={'Authorization': f'Bearer {sess.sid}'}).status_code == 401
    assert client.send(signed_request(client, sess, '/session/logout', now=now[0])).status_code == 200
    assert client.send(signed_request(client, sess, '/api/transfer', payload={'amount': 1, 'to': 'bob'}, now=now[0])).status_code == 401


def test_wrong_password_and_invalid_final(env):
    _, client, _ = env
    local, data = start_login(client, b'incorrect')
    with pytest.raises(ValueError):
        opaque_rs.client_login_finish(local, b'incorrect', bytes.fromhex(data['cred_response_hex']))
    local, data = start_login(client)
    body = finish_body(local, data)
    bad = dict(body, cred_final_hex='00' * 64)
    assert client.post('/login/finish', json=bad).status_code == 401
    assert client.post('/login/finish', json=body).status_code == 401


def test_identity_substitution_and_private_state_rejected(env):
    _, client, _ = env
    local, data = start_login(client)
    body = finish_body(local, data)
    for extra in ({'username': 'victim'}, {'server_state_hex': '00' * 128}):
        assert client.post('/login/finish', json={**body, **extra}).status_code == 422
    assert client.post('/login/finish', json=body).status_code == 200
    assert client.post('/login/finish', json=body).status_code == 401


def test_fabricated_expired_and_concurrent_handles(env):
    _, client, now = env
    local, data = start_login(client)
    body = finish_body(local, data)
    assert client.post('/login/finish', json=dict(body, login_id=secrets.token_urlsafe(32))).status_code == 401
    now[0] += 60
    assert client.post('/login/finish', json=body).status_code == 401
    local, data = start_login(client)
    body = finish_body(local, data)
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: client.post('/login/finish', json=body).status_code, range(8)))
    assert statuses.count(200) == 1 and statuses.count(401) == 7


def test_registration_race_cannot_overwrite(env):
    _, client, _ = env
    local, request = opaque_rs.client_registration_start(PASSWORD)
    def start(username):
        return client.post('/register/start', json={'username': username, 'reg_request_hex': bytes(request).hex()})
    assert start('alice').status_code == 409
    first, second = start('bob').json(), start('bob').json()
    def finish(data):
        upload, _ = opaque_rs.client_registration_finish(local, PASSWORD, bytes.fromhex(data['reg_response_hex']))
        return client.post('/register/finish', json={'registration_id': data['registration_id'], 'reg_upload_hex': bytes(upload).hex()})
    assert finish(first).status_code == 200
    assert finish(second).status_code == 409
    login(client, 'alice', PASSWORD)
    login(client, 'bob', PASSWORD)


@pytest.mark.parametrize('value', ['zz', '0', '00 ' * 2, 'a' * 8194])
def test_malformed_inputs(env, value):
    _, client, _ = env
    assert client.post('/login/start', json={'username': 'alice', 'cred_request_hex': value}).status_code == 422


def test_body_authority_tls_bounds(env):
    _, client, _ = env
    assert client.post('/login/start', content=b'x' * 16385).status_code == 413
    assert client.post('/login/start', json={}, headers={'host': 'evil.example'}).status_code == 400
    assert client.post('http://localhost:8000/login/start', json={}).status_code == 400
    assert client.post('/login/start', json={}, headers=[('x-ts', '1'), ('x-ts', '2')]).status_code == 400


def test_expiry_and_delayed_replay(env):
    _, client, now = env
    sess = login(client, 'alice', PASSWORD)
    req = signed_request(client, sess, '/api/transfer', payload={'amount': 1, 'to': 'bob'}, now=1060)
    assert client.send(req).status_code == 200
    now[0] = 1091
    assert client.send(req).status_code == 401
    now[0] = sess.exp
    assert client.send(signed_request(client, sess, '/api/transfer', payload={'amount': 1, 'to': 'bob'}, now=now[0])).status_code == 401


def test_restart_and_single_worker(tmp_path):
    directory = tmp_path / 'state'
    first = create_app(state_dir=directory)
    with TestClient(first, base_url=ORIGIN) as client:
        register(client, 'alice', PASSWORD)
        sess = login(client, 'alice', PASSWORD)
        setup = first.state.runtime.store.setup
        with pytest.raises(RuntimeError, match='one worker'):
            with TestClient(create_app(state_dir=directory), base_url=ORIGIN):
                pass
    second = create_app(state_dir=directory)
    with TestClient(second, base_url=ORIGIN) as client:
        assert second.state.runtime.store.setup == setup
        assert client.send(signed_request(client, sess, '/api/transfer', payload={'amount': 1, 'to': 'bob'})).status_code == 401
        login(client, 'alice', PASSWORD)


def test_bearer_baseline_without_pop_headers(tmp_path):
    with TestClient(create_app(state_dir=tmp_path / 'state', require_pop=False), base_url=ORIGIN) as client:
        register(client, 'alice', PASSWORD)
        sess = login(client, 'alice', PASSWORD)
        assert client.post('/api/transfer', json={'amount': 1, 'to': 'bob'},
                           headers={'Authorization': f'Bearer {sess.sid}'}).status_code == 200


def test_rate_limit(env):
    app, client, _ = env
    app.state.runtime.rate_count = 120
    assert client.post('/login/start', json={'username': 'alice', 'cred_request_hex': '00'}).status_code == 429
