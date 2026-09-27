"""Real TLS socket + compiled Rust OPAQUE integration, no cryptographic mocks."""
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time

import httpx
from client.client_demo import register, login, signed_request


def test_real_https(tmp_path):
    cert, key = tmp_path / 'localhost.crt', tmp_path / 'localhost.key'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '1',
                    '-nodes', '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
                   check=True, capture_output=True)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    origin = f'https://localhost:{port}'
    env = {**os.environ, 'OPAQUE_ORIGIN': origin, 'OPAQUE_STATE_DIR': str(tmp_path / 'state')}
    process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'server.app:app', '--host', '127.0.0.1',
                                '--port', str(port), '--workers', '1', '--no-proxy-headers',
                                '--ssl-keyfile', str(key), '--ssl-certfile', str(cert)],
                               env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        with httpx.Client(base_url=origin, verify=ssl.create_default_context(cafile=str(cert)),
                          trust_env=False, timeout=2) as client:
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError(process.stderr.read().decode())
                try:
                    if client.get('/docs').status_code == 200:
                        break
                except httpx.TransportError:
                    pass
                time.sleep(0.05)
            else:
                raise AssertionError('TLS server failed to start')
            register(client, 'tls-user', b'tls-test-password')
            session = login(client, 'tls-user', b'tls-test-password')
            request = signed_request(client, session, '/api/transfer?q=%2F&x=1&x=2',
                                     payload={'amount': 3, 'to': 'bob'})
            assert client.send(request).status_code == 200
            assert client.send(request).status_code == 401
            changed = signed_request(client, session, '/api/transfer?q=%2F', payload={'amount': 3, 'to': 'bob'})
            changed.url = changed.url.copy_with(query=b'q=/')
            assert client.send(changed).status_code == 401
            assert client.send(signed_request(client, session, '/session/logout')).status_code == 200
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        process.stderr.close()
