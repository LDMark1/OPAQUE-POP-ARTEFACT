# Opaque PoP Artefact - Architecture

This project is a minimal end-to-end prototype that combines OPAQUE password-authenticated key exchange with a proof-of-possession (PoP) MAC on protected API calls. The goal is to avoid storing password hashes and to prevent replay and stolen-token abuse.

## Components

1) Client demo (`client/client_demo.py`)
   - Orchestrates registration and login via OPAQUE.
   - Derives a PoP MAC key from the OPAQUE session key and signs protected requests.
   - Includes replay and stolen-token attack demonstrations.

2) API server (`server/app.py`)
   - FastAPI service exposing `/register/*`, `/login/*`, and a protected `/api/transfer`.
   - Stores only OPAQUE password files and derived PoP MAC keys (no password hashes or raw session keys).
   - Validates PoP headers and enforces replay protection.

3) PoP utilities (`server/pop.py`)
   - Implements HKDF-based key derivation, canonical request hashing, PoP MAC verification, and nonce replay tracking.

4) Rust OPAQUE bindings (`rust_opaque_rs/src/lib.rs`)
   - Uses `opaque-ke` (RFC 9807 instantiation) with Ristretto255 + TripleDH + Argon2.
   - Exposes a Python module (`opaque_rs`) via `pyo3` for registration/login primitives.

## Data Flow

### Registration
1) Client generates an OPAQUE registration request.
2) Server responds with registration data derived from its setup and server ID.
3) Client finishes registration and uploads a password file to the server.
4) Server stores the password file for future logins.

### Login
1) Client generates a login credential request.
2) Server responds and caches a login state.
3) Client finishes login, derives a session key, and sends finalization data.
4) Server verifies the finalization and derives its session key.
5) Server derives a PoP MAC key from the session key and issues a bearer session ID.

### Protected Requests (PoP)
1) Client signs a canonicalized request with the derived PoP key.
2) Client sends `Authorization: Bearer <session_id>` plus `X-TS`, `X-NONCE`, `X-POP`.
3) Server validates freshness, rejects replayed nonces, and verifies the MAC.

## State and Storage

- In-memory `USERS` store: username -> OPAQUE password file.
- In-memory `SESSIONS` store: session ID -> {username, PoP key, expiry, nonce cache}.
- No password hashes and no raw session keys are stored by the server.

## Security Notes

- PoP MACs bind the request body, method, path, timestamp, and nonce.
- Nonce tracking plus a time window mitigates replay.
- Threat model reference: `threatmodel.md`.

## Project Structure

- `client/`: client demo and PoP generation logic.
- `server/`: FastAPI API and PoP verification utilities.
- `rust_opaque_rs/`: Rust OPAQUE implementation exposed to Python.

## Run Steps

1) Build the Rust Python module:
   - `cd rust_opaque_rs`
   - `maturin develop`

2) Install Python dependencies:
   - `pip install -r server/requirements.txt`
   - `pip install httpx`

3) Start the API server (from repo root):
   - `uvicorn server.app:app --reload`

4) Run the client demo (in a second terminal):
   - `python client/client_demo.py`
