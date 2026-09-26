# OPAQUE + HTTP HMAC-PoP research artefact

This prototype combines password-authenticated OPAQUE login with a custom,
shared-secret HMAC proof on each protected HTTP request. **It is not OAuth DPoP
(RFC 9449), a production authentication service, or a new cryptographic protocol.**
The transfer endpoint is a simulation and moves no money.

OPAQUE stores password registration records instead of conventional password
verifiers. It still uses hashes and a password-hardening function. Compromise of
the complete server setup and registration database can permit offline dictionary
attacks; this artefact does not claim to eliminate password guessing.

## Requirements and reproducible setup

Supported/tested target: Linux, Python 3.12, Rust 1.85.1, OpenSSL. The POSIX process
lock intentionally excludes Windows and prevents multiple workers sharing the
same state directory. Use WSL for Windows development.

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --require-hashes -r requirements-dev.txt
# Install Rust with the official rustup installer if it is not already available.
rustup toolchain install 1.85.1 --profile minimal
maturin build --locked --release --manifest-path rust_opaque_rs/Cargo.toml -o dist
python -m pip install --no-deps dist/*.whl
python -m pytest -q
```

`rust-toolchain.toml`, `rust_opaque_rs/Cargo.lock`, and hash-locked Python
requirements record the tested dependency set. `server/requirements.txt` is the
runtime lock; `requirements-dev.txt` also includes the build and test tools.
To intentionally update Python dependencies, edit the `.in` files and run
`uv pip compile <input> --generate-hashes -o <output>` for both locks, then rerun
all tests. Dependency locks do not replace vulnerability monitoring.

## Run over HTTPS

Generate **new local** TLS material; never upload private keys:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout certs/localhost.key -out certs/localhost.crt \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1'
chmod 600 certs/localhost.key
export OPAQUE_ORIGIN=https://localhost:8000
export OPAQUE_STATE_DIR="$PWD/.state"
uvicorn server.app:app --host 127.0.0.1 --port 8000 --workers 1 \
  --no-proxy-headers --ssl-keyfile certs/localhost.key \
  --ssl-certfile certs/localhost.crt
```

In a second terminal, activate the same environment and run from the repo root:

```bash
python -m client.client_demo
```

The demo registers a fresh random identity, logs in, sends an authenticated
request, verifies that replay and a stolen bearer alone fail, and logs out. It
never prints passwords, session IDs, session keys, or export keys. Set
`SERVER_URL` and `TLS_CA_BUNDLE` for a different HTTPS origin and trusted CA file.
Certificate verification cannot be disabled by the demo.

The API rejects HTTP, a Host value different from the configured origin,
duplicate security headers, content encodings, and method overrides. The
configured origin has no trailing slash. Do not enable proxy headers or put an
unreviewed path-rewriting proxy in front of this configuration.

## Protocol v2 and breaking API changes

1. `/register/start` receives `username` and `reg_request_hex`, and returns
   `registration_id` and `reg_response_hex`.
2. `/register/finish` receives only `registration_id` and `reg_upload_hex`.
   The server binds the handle to the original username and uses a unique SQL
   insertion. Existing accounts cannot be overwritten, including concurrent
   registrations. Account recovery/password changes are **not implemented**.
3. `/login/start` receives `username` and `cred_request_hex`, and returns
   `login_id` and `cred_response_hex`. The serialized private OPAQUE state stays
   on the server. The username bytes are the OPAQUE **credential identifier**,
   not a server identity string.
4. `/login/finish` receives only `login_id` and `cred_final_hex`. The server
   atomically consumes the handle before cryptographic verification, including
   failed attempts. Handles expire after 60 seconds. Client-provided usernames
   or private server state are rejected as extra fields.
5. Login returns `session_id`, `expires_at`, and `origin`. Both sides derive a
   PoP key using HKDF-SHA-256, with a context containing the protocol label,
   trusted origin, session ID, and username. Sessions expire after one hour.
6. `/api/transfer` and `/session/logout` require `Authorization: Bearer <sid>`
   and `X-TS`, `X-NONCE`, `X-POP`. Logout revokes the session. A request already
   authenticated concurrently with logout may finish; no transactional
   business operation is implemented here.

Client and server share `server/pop.py`. The MAC input is a sequence of fields,
each prefixed with its unsigned 32-bit big-endian byte length:

- `OPAQUE-HTTP-POP-v2`, session ID, trusted origin;
- uppercase method, exact raw path plus query, exact Content-Type;
- SHA-256 of the transmitted body, canonical decimal timestamp, nonce.

Nonce encoding is 16 random bytes as 32 lowercase hexadecimal characters. The
proof is canonical padded Base64 of a 32-byte HMAC-SHA-256. Reordering query
parameters or changing percent encoding changes the proof. There are no other
application-semantic headers in this prototype; if new endpoints depend on
additional headers, extend and version the signed format before using them.

## Replay, state, and resource bounds

MAC verification precedes replay-cache mutation. One lock covers freshness,
nonce check, and insertion. The timestamp window is inclusive ±60 seconds;
a nonce remains recorded through `timestamp + 60`, inclusive. Live entries
are never evicted to accept new requests. A full cache rejects the request.
Tests include the future-timestamp case that previously allowed delayed replay.
A session also rejects clock rollback below its last verified check; operate
with a trusted, nondecreasing server clock.

Default limits: 16 KiB request body, 4,096 hex-encoded message bytes, 1,024 pending
handles, 1,024 sessions, and 4,096 live nonces per session. A process-wide limit
allows 120 authentication endpoint calls per 60-second period. This is a coarse
resource guard; distributed abuse and per-account/IP policies need a trusted
edge or a coordinated service.

OPAQUE setup and password records persist together in `.state/credentials.sqlite3`.
The state directory must have mode `0700`, and the database `0600`. Back up and
restore them together; never regenerate the server setup independently of user
records. The directory contains private authentication material and must stay
out of version control. Python does not guarantee zeroization of secret objects.

Sessions, replay caches, and pending handshakes stay in memory and are invalidated
on restart. An OS lock rejects another process using the same state directory.
Do not copy the database to multiple instances or deploy this prototype behind
a multiworker/load-balanced setup. A distributed deployment needs coordinated,
atomic session/replay storage and a separately reviewed threat model.

## Tests and publication use

```bash
python -m pytest -q
```

The suite builds on the genuine `opaque_rs` extension, not a cryptographic mock:

- correct/wrong passwords, private-state and identity injection, fabricated,
  expired, reused, and concurrently completed login handles;
- duplicate registration, malformed encodings, body/authority/TLS bounds;
- tampering, stolen bearer, delayed replay, exact expiry, logout, restart;
- RFC 5869 HKDF vector, 32 concurrent duplicate proofs, cache saturation,
  and 14,762 timestamp/delay replay cases;
- a real local HTTPS socket with certificate verification and raw-query binding.

GitHub Actions builds the locked Rust extension and runs the suite. Tests are
regression evidence, **not a security proof** or an independent cryptographic
audit. The account-existence responses permit username enumeration. Signup is
open and does not prove ownership of an email address. Client compromise, XSS,
malicious browser extensions, and theft of both token and PoP key remain outside
this mitigation. TLS remains mandatory.

For a bearer-only experimental baseline, instantiate
`create_app(require_pop=False)` in a separate local test harness; it correctly
does not require PoP headers. The shipped server always enables PoP. Record the
mode, commit, platform, dependency locks, raw measurements, and experiment script
when reporting results. Comparative latency/throughput benchmarks, a browser
client, recovery, and production deployment validation remain future work.
