"""Single-process research API. TLS and a private, persistent state directory required."""
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
import os
import re
import secrets
import threading
import time
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.responses import JSONResponse
import opaque_rs
from .pop import Session, derive_key, verify
from .storage import Store

MAX_BODY = 16384
PENDING_TTL = 60
MAX_PENDING = 1024
MAX_SESSIONS = 1024


def validate_origin(origin):
    parsed = urlsplit(origin)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.path or parsed.query or parsed.fragment or
            not origin.isascii() or len(origin) > 255):
        raise ValueError('OPAQUE_ORIGIN must be an HTTPS origin without a trailing slash')
    return origin


@dataclass
class Runtime:
    store: Store
    origin: str
    require_pop: bool
    clock: object
    pending: dict = field(default_factory=dict)
    sessions: dict = field(default_factory=dict)
    lock: object = field(default_factory=threading.RLock)
    rate_epoch: float = 0
    rate_count: int = 0

    def reap(self, now):
        self.pending = {k: v for k, v in self.pending.items() if v[3] > now}
        self.sessions = {k: v for k, v in self.sessions.items() if v.exp > now and not v.revoked}

    def reserve(self, kind, username, private_state=None):
        with self.lock:
            now = int(self.clock())
            self.reap(now)
            if len(self.pending) >= MAX_PENDING:
                raise HTTPException(503, 'pending authentication capacity reached')
            handle = secrets.token_urlsafe(32)
            self.pending[handle] = (kind, username, private_state, now + PENDING_TTL)
            return handle

    def consume(self, handle, kind):
        with self.lock:
            item = self.pending.pop(handle, None)
            if item is None or item[0] != kind or int(self.clock()) >= item[3]:
                raise HTTPException(401, 'invalid or expired authentication handle')
            return item[1], item[2]

    def limit_auth(self):
        # Global bound prevents attacker-chosen usernames/IPs growing a rate map.
        # Put per-account/IP throttling at the trusted edge for a real deployment.
        with self.lock:
            now = time.monotonic()
            if now - self.rate_epoch >= 60:
                self.rate_epoch, self.rate_count = now, 0
            if self.rate_count >= 120:
                raise HTTPException(429, 'authentication rate limit', headers={'Retry-After': '60'})
            self.rate_count += 1


class Input(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


Username = Annotated[str, Field(min_length=1, max_length=254, pattern=r'^[^\s\x00-\x1f\x7f]+$')]
Hex = Annotated[str, Field(min_length=2, max_length=8192, pattern=r'^(?:[0-9a-fA-F]{2})+$')]
Handle = Annotated[str, Field(min_length=43, max_length=43, pattern=r'^[A-Za-z0-9_-]+$')]


class RegStartIn(Input):
    username: Username
    reg_request_hex: Hex


class RegFinishIn(Input):
    registration_id: Handle
    reg_upload_hex: Hex


class LoginStartIn(Input):
    username: Username
    cred_request_hex: Hex


class LoginFinishIn(Input):
    login_id: Handle
    cred_final_hex: Hex


class ProtectedIn(Input):
    amount: Annotated[int, Field(gt=0, le=1_000_000)]
    to: Username


def create_app(*, state_dir=None, origin=None, require_pop=True, clock=time.time):
    origin = validate_origin(origin or os.getenv('OPAQUE_ORIGIN', 'https://localhost:8000'))

    @asynccontextmanager
    async def lifespan(app):
        store = Store(state_dir or os.getenv('OPAQUE_STATE_DIR', '.state'), opaque_rs.server_setup_new)
        app.state.runtime = Runtime(store, origin, require_pop, clock)
        try:
            yield
        finally:
            app.state.runtime.pending.clear()
            app.state.runtime.sessions.clear()
            store.close()

    app = FastAPI(lifespan=lifespan)

    @app.middleware('http')
    async def boundary(req, call_next):
        # Never trust forwarded headers. Run uvicorn with --no-proxy-headers.
        expected_host = urlsplit(origin).netloc
        if req.url.scheme != 'https' or req.headers.get('host') != expected_host:
            return JSONResponse({'detail': 'HTTPS and configured authority required'}, status_code=400)
        for name in ('authorization', 'x-ts', 'x-nonce', 'x-pop', 'content-type', 'host'):
            values = req.headers.getlist(name)
            if len(values) > 1 or any(len(v) > 4096 for v in values):
                return JSONResponse({'detail': 'invalid request headers'}, status_code=400)
        if req.headers.get('content-encoding') or req.headers.get('x-http-method-override'):
            return JSONResponse({'detail': 'unsupported request encoding/override'}, status_code=400)
        raw = bytearray()
        async for chunk in req.stream():
            raw.extend(chunk)
            if len(raw) > MAX_BODY:
                return JSONResponse({'detail': 'request too large'}, status_code=413)
        req._body = bytes(raw)  # Starlette cached Request body, replayed to the route.
        response = await call_next(req)
        response.headers['Cache-Control'] = 'no-store'
        return response

    def rt(req):
        return req.app.state.runtime

    @app.post('/register/start')
    def register_start(body: RegStartIn, req: Request):
        state = rt(req)
        state.limit_auth()
        if state.store.get(body.username) is not None:
            raise HTTPException(409, 'account already registered')
        try:
            response = bytes(opaque_rs.server_registration_start(
                state.store.setup, bytes.fromhex(body.reg_request_hex), body.username.encode()))
        except ValueError:
            raise HTTPException(400, 'invalid registration message') from None
        handle = state.reserve('registration', body.username)
        return {'registration_id': handle, 'reg_response_hex': response.hex()}

    @app.post('/register/finish')
    def register_finish(body: RegFinishIn, req: Request):
        state = rt(req)
        state.limit_auth()
        username, _ = state.consume(body.registration_id, 'registration')
        try:
            password_file = opaque_rs.server_registration_finish(bytes.fromhex(body.reg_upload_hex))
        except ValueError:
            raise HTTPException(400, 'invalid registration message') from None
        if not state.store.register(username, password_file):
            raise HTTPException(409, 'account already registered')
        return {'ok': True}

    @app.post('/login/start')
    def login_start(body: LoginStartIn, req: Request):
        state = rt(req)
        state.limit_auth()
        password_file = state.store.get(body.username)
        if password_file is None:
            raise HTTPException(401, 'authentication failed')
        try:
            private_state, response = opaque_rs.server_login_start(
                state.store.setup, password_file, bytes.fromhex(body.cred_request_hex), body.username.encode())
        except ValueError:
            raise HTTPException(400, 'invalid login message') from None
        handle = state.reserve('login', body.username, bytes(private_state))
        return {'login_id': handle, 'cred_response_hex': bytes(response).hex()}

    @app.post('/login/finish')
    def login_finish(body: LoginFinishIn, req: Request):
        state = rt(req)
        state.limit_auth()
        username, private_state = state.consume(body.login_id, 'login')
        try:
            session_key = bytes(opaque_rs.server_login_finish(private_state, bytes.fromhex(body.cred_final_hex)))
        except ValueError:
            raise HTTPException(401, 'authentication failed') from None
        sid = secrets.token_urlsafe(32)
        with state.lock:
            now = int(state.clock())
            state.reap(now)
            if len(state.sessions) >= MAX_SESSIONS:
                raise HTTPException(503, 'session capacity reached')
            state.sessions[sid] = Session(sid, origin, derive_key(session_key, origin, sid, username),
                                          now + 3600, username=username)
        return {'session_id': sid, 'expires_at': now + 3600, 'origin': origin}

    async def authenticate(req):
        state = rt(req)
        authorization = req.headers.get('authorization', '')
        if not re.fullmatch(r'Bearer [A-Za-z0-9_-]{43}', authorization):
            raise HTTPException(401, 'invalid authorization')
        sid = authorization[7:]
        with state.lock:
            state.reap(int(state.clock()))
            session = state.sessions.get(sid)
        if session is None:
            raise HTTPException(401, 'invalid or expired session')
        if state.require_pop:
            try:
                raw_path = req.scope['raw_path']
                query = req.scope.get('query_string', b'')
                target = (raw_path + (b'?' + query if query else b'')).decode('ascii')
                verify(session, req.method, target, req.headers.get('content-type', ''), await req.body(),
                       req.headers.get('x-ts', ''), req.headers.get('x-nonce', ''),
                       req.headers.get('x-pop', ''), now=int(state.clock()))
            except (ValueError, UnicodeError):
                raise HTTPException(401, 'invalid request proof') from None
        else:
            with session.lock:
                if session.revoked or int(state.clock()) >= session.exp:
                    raise HTTPException(401, 'invalid or expired session')
        return session

    @app.post('/api/transfer')
    async def transfer(req: Request, body: ProtectedIn):
        session = await authenticate(req)
        # Simulation only; there is no financial side effect.
        return {'ok': True, 'user': session.username, 'transferred': body.amount, 'to': body.to}

    @app.post('/session/logout')
    async def logout(req: Request):
        session = await authenticate(req)
        with session.lock:
            session.revoked = True
            session.nonces.clear()
        with rt(req).lock:
            rt(req).sessions.pop(session.sid, None)
        return {'ok': True}

    return app


app = create_app()
