import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from client.crypto import (
    decrypt_with, encrypt_for, gen_keys,
    pub_bytes, sign_blob, verify_blob,
)

BASE = "http://127.0.0.1:8765"


def login(email, sk_sign):
    ch = requests.post(f"{BASE}/auth/challenge", json={"email": email}).json()
    sig = sk_sign.sign(bytes.fromhex(ch["nonce"]))
    out = requests.post(f"{BASE}/auth/verify", json={
        "challenge_id": ch["challenge_id"],
        "signature": sig.hex(),
    }).json()
    return {"Authorization": f"Bearer {out['token']}"}


def register(email):
    sk_sign, sk_enc = gen_keys()
    r = requests.post(f"{BASE}/register", json={
        "email": email,
        "pk_sign": pub_bytes(sk_sign).hex(),
        "pk_enc": pub_bytes(sk_enc).hex(),
    })
    assert r.status_code == 200, r.text
    return sk_sign, sk_enc


def main():
    print("registering alice and bob")
    a_sign, a_enc = register("alice@example.com")
    b_sign, b_enc = register("bob@example.com")

    print("alice logs in")
    a_hdr = login("alice@example.com", a_sign)

    bob_keys = requests.get(f"{BASE}/users/bob@example.com/keys", headers=a_hdr).json()
    bob_pk_enc = bytes.fromhex(bob_keys["pk_enc"])

    plaintext = b"the meeting is at noon\n"
    filename = "note.txt"
    aad = f"alice@example.com|bob@example.com|{filename}".encode()

    epk, nonce, ct = encrypt_for(bob_pk_enc, plaintext, aad)
    sig = sign_blob(a_sign, ct, epk, nonce, aad)

    r = requests.post(f"{BASE}/files",
                      headers=a_hdr,
                      data={
                          "recipient": "bob@example.com",
                          "filename": filename,
                          "epk": epk.hex(),
                          "nonce": nonce.hex(),
                          "signature": sig.hex(),
                      },
                      files={"blob": ("ct.bin", ct, "application/octet-stream")})
    assert r.status_code == 200, r.text
    fid = r.json()["file_id"]
    print(f"uploaded, file id {fid}")

    b_hdr = login("bob@example.com", b_sign)
    inbox = requests.get(f"{BASE}/files", headers=b_hdr).json()
    assert any(row["id"] == fid for row in inbox)

    meta = requests.get(f"{BASE}/files/{fid}/meta", headers=b_hdr).json()
    blob = requests.get(f"{BASE}/files/{fid}/blob", headers=b_hdr).content

    epk2 = bytes.fromhex(meta["epk"])
    n2 = bytes.fromhex(meta["nonce"])
    s2 = bytes.fromhex(meta["signature"])
    aad2 = f"alice@example.com|bob@example.com|{meta['filename']}".encode()

    verify_blob(pub_bytes(a_sign), s2, blob, epk2, n2, aad2)

    pt = decrypt_with(b_enc, epk2, n2, blob, aad2)
    assert pt == plaintext
    print(f"recovered: {pt!r}")

    tampered = bytearray(blob)
    tampered[0] ^= 0x01
    try:
        verify_blob(pub_bytes(a_sign), s2, bytes(tampered), epk2, n2, aad2)
    except Exception as e:
        print(f"signature rejected on tamper: {type(e).__name__}")
    else:
        raise SystemExit("FAIL: tampered ciphertext should not verify")

    c_sign, _ = register("eve@example.com")
    e_hdr = login("eve@example.com", c_sign)
    r = requests.get(f"{BASE}/files/{fid}/meta", headers=e_hdr)
    assert r.status_code == 403
    print("server returned 403 for non-recipient")

    print("all checks passed")


if __name__ == "__main__":
    main()