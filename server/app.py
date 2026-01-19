# SECURITY INVARIANT:
# - server never stores password hashes
# - server never stores raw OPAQUE session keys
# - server stores only derived PoP MAC keys

import secrets
import time
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

import opaque_rs
from .pop import Session, derive_pop_key, verify_pop

app = FastAPI()

USERS: dict[str, dict] = {}      # username -> {"password_file": bytes}
SESSIONS: dict[str, Session] = {}  # session_id -> Session

SERVER_SETUP = opaque_rs.server_setup_new()
# REQUIRE_POP = False # Stolen token works
REQUIRE_POP = True # Stolen token fails

def server_id_for(username: str) -> bytes:
    # Derive a stable server-side identifier for OPAQUE flows.
    # stable identifier used across register+login
    return username.encode("utf-8")

# -------- Registration --------

class RegStartIn(BaseModel):
    username: str
    reg_request_hex: str

class RegStartOut(BaseModel):
    reg_response_hex: str

@app.post("/register/start", response_model=RegStartOut)
def register_start(body: RegStartIn):
    # Start OPAQUE registration by generating the server's response.
    reg_request = bytes.fromhex(body.reg_request_hex)
    reg_response = opaque_rs.server_registration_start(
        SERVER_SETUP,
        reg_request,
        server_id_for(body.username),
    )
    return {"reg_response_hex": reg_response.hex()}

class RegFinishIn(BaseModel):
    username: str
    reg_upload_hex: str

@app.post("/register/finish")
def register_finish(body: RegFinishIn):
    # Complete registration and persist the password file for the user.
    reg_upload = bytes.fromhex(body.reg_upload_hex)
    password_file = opaque_rs.server_registration_finish(reg_upload)
    USERS[body.username] = {"password_file": password_file}
    return {"ok": True}

# -------- Login --------

class LoginStartIn(BaseModel):
    username: str
    cred_request_hex: str

class LoginStartOut(BaseModel):
    server_state_hex: str
    cred_response_hex: str

@app.post("/login/start", response_model=LoginStartOut)
def login_start(body: LoginStartIn):
    # Start OPAQUE login by producing the server state + response.
    if body.username not in USERS:
        raise HTTPException(404, "unknown user")

    cred_req = bytes.fromhex(body.cred_request_hex)
    password_file = USERS[body.username]["password_file"]

    server_state, cred_resp = opaque_rs.server_login_start(
        SERVER_SETUP,
        password_file,
        cred_req,
        server_id_for(body.username),
    )
    return {"server_state_hex": server_state.hex(), "cred_response_hex": cred_resp.hex()}

class LoginFinishIn(BaseModel):
    username: str
    server_state_hex: str
    cred_final_hex: str

@app.post("/login/finish")
def login_finish(body: LoginFinishIn):
    # Finish OPAQUE login, derive a PoP key, and mint a session id.
    if body.username not in USERS:
        raise HTTPException(404, "unknown user")

    server_state = bytes.fromhex(body.server_state_hex)
    cred_final = bytes.fromhex(body.cred_final_hex)

    # If password wrong, server_login_finish will error; we surface 401.
    try:
        server_session_key = opaque_rs.server_login_finish(server_state, cred_final)
    except Exception:
        raise HTTPException(401, "authentication failed")

    pop_key = derive_pop_key(server_session_key)  # store only a derived MAC key

    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = Session(
        username=body.username,
        pop_key=pop_key,
        exp=int(time.time()) + 3600,
    )

    return {"session_id": session_id}

# -------- Protected endpoint (PoP) --------

class ProtectedIn(BaseModel):
    amount: int
    to: str

@app.post("/api/transfer")
async def transfer(req: Request, body: ProtectedIn):
    # Validate bearer session + PoP proof and execute the protected action.
    auth = req.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "missing bearer session id")
    session_id = auth.split(" ", 1)[1].strip()

    sess = SESSIONS.get(session_id)
    if not sess or sess.exp < int(time.time()):
        raise HTTPException(401, "invalid/expired session")

    ts = req.headers.get("x-ts")
    nonce = req.headers.get("x-nonce")
    pop = req.headers.get("x-pop")
    if not (ts and nonce and pop):
        raise HTTPException(401, "missing PoP headers (x-ts, x-nonce, x-pop)")

    raw_body = await req.body()

    try:
        if REQUIRE_POP:
            verify_pop(sess, req.method, req.url.path, raw_body, ts, nonce, pop)
    except ValueError as e:
        raise HTTPException(401, str(e))

    return {"ok": True, "user": sess.username, "transferred": body.amount, "to": body.to}
