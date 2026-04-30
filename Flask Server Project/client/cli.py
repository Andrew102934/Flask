import getpass
import os
from pathlib import Path

import requests
import typer

from .crypto import (
    decrypt_with, encrypt_for, gen_keys,
    load_keystore, pub_bytes, save_keystore,
    sign_blob, verify_blob,
)

SERVER = os.environ.get("FILEDROP_SERVER", "http://127.0.0.1:8000").rstrip("/")
KEYSTORE = Path(os.environ.get("FILEDROP_KEYSTORE", Path.home() / ".filedrop" / "keystore.json"))
TOKEN = KEYSTORE.with_suffix(".token")

cli = typer.Typer(add_completion=False, help="FileDrop client")


def _die(msg, code=1):
    typer.echo(msg, err=True)
    raise typer.Exit(code)


def _read_passphrase(confirm=False):
    pw = getpass.getpass("Passphrase: ")
    if confirm and getpass.getpass("Confirm: ") != pw:
        _die("passphrases don't match")
    return pw


def _bearer():
    if not TOKEN.exists():
        _die("not logged in, run login first")
    return {"Authorization": f"Bearer {TOKEN.read_text().strip()}"}


def _api(method, path, **kwargs):
    r = requests.request(method, f"{SERVER}{path}", **kwargs)
    if r.status_code >= 400:
        try:
            detail = r.json().get("detail", r.text)
        except ValueError:
            detail = r.text
        _die(f"{method} {path}: {r.status_code} {detail}")
    return r


@cli.command()
def register(email: str):
    if KEYSTORE.exists():
        _die(f"keystore already exists at {KEYSTORE}, remove it first")

    pw = _read_passphrase(confirm=True)
    sk_sign, sk_enc = gen_keys()

    _api("POST", "/register", json={
        "email": email,
        "pk_sign": pub_bytes(sk_sign).hex(),
        "pk_enc": pub_bytes(sk_enc).hex(),
    })

    save_keystore(KEYSTORE, email, sk_sign, sk_enc, pw)
    typer.echo(f"registered {email}, keystore at {KEYSTORE}")


@cli.command()
def login():
    if not KEYSTORE.exists():
        _die("no keystore, run register first")

    pw = _read_passphrase()
    email, sk_sign, _ = load_keystore(KEYSTORE, pw)

    ch = _api("POST", "/auth/challenge", json={"email": email}).json()
    nonce = bytes.fromhex(ch["nonce"])
    sig = sk_sign.sign(nonce)

    out = _api("POST", "/auth/verify", json={
        "challenge_id": ch["challenge_id"],
        "signature": sig.hex(),
    }).json()

    TOKEN.parent.mkdir(parents=True, exist_ok=True)
    TOKEN.write_text(out["token"])
    typer.echo(f"logged in as {email}")


@cli.command()
def send(recipient: str, path: Path):
    if not path.is_file():
        _die(f"not a file: {path}")

    pw = _read_passphrase()
    sender, sk_sign, _ = load_keystore(KEYSTORE, pw)
    headers = _bearer()

    keys = _api("GET", f"/users/{recipient}/keys", headers=headers).json()
    rcpt_pk_enc = bytes.fromhex(keys["pk_enc"])

    plaintext = path.read_bytes()
    filename = path.name
    aad = f"{sender}|{recipient}|{filename}".encode()

    epk, nonce, ct = encrypt_for(rcpt_pk_enc, plaintext, aad)
    sig = sign_blob(sk_sign, ct, epk, nonce, aad)

    r = _api("POST", "/files",
             headers=headers,
             data={
                 "recipient": recipient,
                 "filename": filename,
                 "epk": epk.hex(),
                 "nonce": nonce.hex(),
                 "signature": sig.hex(),
             },
             files={"blob": ("ct.bin", ct, "application/octet-stream")})
    typer.echo(f"uploaded, file id {r.json()['file_id']}")


@cli.command("list")
def list_inbox():
    rows = _api("GET", "/files", headers=_bearer()).json()
    if not rows:
        typer.echo("inbox is empty")
        return
    for row in rows:
        typer.echo(f"{row['id']}  {row['sender']}  {row['filename']}")


@cli.command()
def fetch(file_id: str, out: Path):
    pw = _read_passphrase()
    me, _, sk_enc = load_keystore(KEYSTORE, pw)
    headers = _bearer()

    meta = _api("GET", f"/files/{file_id}/meta", headers=headers).json()
    blob = _api("GET", f"/files/{file_id}/blob", headers=headers).content

    sender = meta["sender"]
    filename = meta["filename"]
    epk = bytes.fromhex(meta["epk"])
    nonce = bytes.fromhex(meta["nonce"])
    signature = bytes.fromhex(meta["signature"])

    sender_keys = _api("GET", f"/users/{sender}/keys", headers=headers).json()
    sender_pk_sign = bytes.fromhex(sender_keys["pk_sign"])

    aad = f"{sender}|{me}|{filename}".encode()

    try:
        verify_blob(sender_pk_sign, signature, blob, epk, nonce, aad)
    except Exception:
        _die(f"signature check failed, refusing to decrypt {filename}", code=2)

    plaintext = decrypt_with(sk_enc, epk, nonce, blob, aad)
    out.write_bytes(plaintext)
    typer.echo(f"verified signature from {sender}, wrote {len(plaintext)} bytes to {out}")


if __name__ == "__main__":
    cli()