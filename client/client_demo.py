import base64
import hashlib
import hmac
import secrets
import time

import httpx
import opaque_rs

SERVER = "http://127.0.0.1:8000"

def b64e(b: bytes) -> str:
    # Encode bytes to base64 ASCII for PoP header transport.
    return base64.b64encode(b).decode("ascii")

def canonical_request(method: str, path: str, body_bytes: bytes, ts: str, nonce: str) -> bytes:
    # Canonicalize request fields so client/server MACs match.
    body_hash_hex = hashlib.sha256(body_bytes).hexdigest()
    return f"{method}\n{path}\n{body_hash_hex}\n{ts}\n{nonce}".encode("utf-8")

def make_pop(session_key: bytes, method: str, path: str, body_bytes: bytes, ts: str, nonce: str) -> str:
    # Compute a PoP MAC over the canonical request.
    msg = canonical_request(method, path, body_bytes, ts, nonce)
    mac = hmac.new(session_key, msg, hashlib.sha256).digest()
    return b64e(mac)

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    # HKDF extract step to derive a pseudorandom key.
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    # HKDF expand step to produce a fixed-length key.
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]

def derive_pop_key(session_key: bytes) -> bytes:
    # Derive a PoP-only MAC key from the OPAQUE session key.
    prk = hkdf_extract(b"opaque-pop-salt-v1", session_key)
    return hkdf_expand(prk, b"OPAQUE-POP-MAC-v1", 32)

def main():
    # End-to-end demo: register, login, and call a PoP-protected endpoint.
    username = "alice@example.com"
    password = b"correct horse battery staple"

    with httpx.Client() as c:
        # -----------------------
        # REGISTRATION (real OPAQUE)
        # -----------------------
        client_state, reg_request = opaque_rs.client_registration_start(password)

        r1 = c.post(f"{SERVER}/register/start", json={
            "username": username,
            "reg_request_hex": reg_request.hex(),
        })
        r1.raise_for_status()
        reg_response = bytes.fromhex(r1.json()["reg_response_hex"])

        reg_upload, export_key_reg = opaque_rs.client_registration_finish(
            client_state, password, reg_response
        )

        r2 = c.post(f"{SERVER}/register/finish", json={
            "username": username,
            "reg_upload_hex": reg_upload.hex(),
        })
        r2.raise_for_status()

        print("[+] Registered")
        print("    export_key(reg) =", export_key_reg.hex())

        # -----------------------
        # LOGIN (real OPAQUE)
        # -----------------------
        login_state, cred_req = opaque_rs.client_login_start(password)

        l1 = c.post(f"{SERVER}/login/start", json={
            "username": username,
            "cred_request_hex": cred_req.hex(),
        })
        l1.raise_for_status()
        server_state = bytes.fromhex(l1.json()["server_state_hex"])
        cred_resp = bytes.fromhex(l1.json()["cred_response_hex"])

        cred_final, client_session_key, export_key_login = opaque_rs.client_login_finish(
            login_state, password, cred_resp
        )

        l2 = c.post(f"{SERVER}/login/finish", json={
            "username": username,
            "server_state_hex": server_state.hex(),
            "cred_final_hex": cred_final.hex(),
        })
        l2.raise_for_status()
        session_id = l2.json()["session_id"]

        print("[+] Logged in")
        print("    session_id =", session_id)
        print("    export_key(login) =", export_key_login.hex())
        print("    session_key(client) =", client_session_key.hex()[:32] + "...")

        # -----------------------
        # PROTECTED REQUEST with PoP
        # -----------------------
        path = "/api/transfer"
        method = "POST"
        body = {"amount": 50, "to": "bob@example.com"}

        # Ensure body_bytes exactly matches what is sent
        req = httpx.Request(method, f"{SERVER}{path}", json=body)
        body_bytes = req.read()

        ts = str(int(time.time()))
        nonce = secrets.token_urlsafe(16)
        pop_key = derive_pop_key(client_session_key)
        pop = make_pop(pop_key, method, path, body_bytes, ts, nonce)


        req.headers.update({
            "Authorization": f"Bearer {session_id}",
            "X-TS": ts,
            "X-NONCE": nonce,
            "X-POP": pop,
        })

        ok = c.send(req)
        ok.raise_for_status()
        print("[+] Protected call OK:", ok.json())

         # -----------------------
        # REPLAY DEMO: resend exact same request + same headers (ts/nonce/pop)
        # -----------------------
        replay_req = httpx.Request(method, f"{SERVER}{path}", json=body)
        replay_req.read()  # ensure body is finalized
        replay_req.headers.update(req.headers)  # reuse identical PoP headers
        replay = c.send(replay_req)
        print("[+] Replay attempt status:", replay.status_code)
        print("    body:", replay.text)

        # -----------------------
        # ATTACK DEMO: stolen bearer token only (no session_key)
        # -----------------------
        attacker_key = b"\x00" * 32  # wrong key, attacker only has token
        req2 = httpx.Request(method, f"{SERVER}{path}", json=body)
        body_bytes2 = req2.read()
        
        ts2 = str(int(time.time()))
        nonce2 = secrets.token_urlsafe(16)
        pop2 = make_pop(attacker_key, method, path, body_bytes2, ts2, nonce2)

        req2.headers.update({
            "Authorization": f"Bearer {session_id}",  # stolen token
            "X-TS": ts2,
            "X-NONCE": nonce2,
            "X-POP": pop2,
        })

        bad = c.send(req2)
        print("[+] Stolen-token attempt status:", bad.status_code)
        print("    body:", bad.text)

if __name__ == "__main__":
    main()
