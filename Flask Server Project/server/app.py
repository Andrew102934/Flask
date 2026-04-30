import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, EmailStr
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .db import db, init_db

BLOB_DIR = Path(__file__).resolve().parent.parent / "blobs"
BLOB_DIR.mkdir(exist_ok=True)

CHALLENGE_TTL = 60
TOKEN_TTL = 3600
KEY_LEN = 32


@asynccontextmanager
async def lifespan(_app):
    init_db()
    yield


app = FastAPI(title="FileDrop", version="0.1", lifespan=lifespan)


class RegisterReq(BaseModel):
    email: EmailStr
    pk_sign: str
    pk_enc: str


@app.post("/register")
def register(req: RegisterReq):
    pk_sign = bytes.fromhex(req.pk_sign)
    pk_enc = bytes.fromhex(req.pk_enc)
    if len(pk_sign) != KEY_LEN or len(pk_enc) != KEY_LEN:
        raise HTTPException(400, "bad key length")

    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email = ?", (req.email,)).fetchone():
            raise HTTPException(409, "user already registered")
        conn.execute(
            "INSERT INTO users (email, pk_sign, pk_enc, created_at) VALUES (?, ?, ?, ?)",
            (req.email, pk_sign, pk_enc, int(time.time())),
        )
    return {"status": "registered", "email": req.email}


class ChallengeReq(BaseModel):
    email: EmailStr


@app.post("/auth/challenge")
def challenge(req: ChallengeReq):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE email = ?", (req.email,)).fetchone():
            raise HTTPException(404, "no such user")
        cid = secrets.token_hex(16)
        nonce = secrets.token_bytes(32)
        conn.execute(
            "INSERT INTO challenges (id, email, nonce, expires_at) VALUES (?, ?, ?, ?)",
            (cid, req.email, nonce, int(time.time()) + CHALLENGE_TTL),
        )
    return {"challenge_id": cid, "nonce": nonce.hex()}


class VerifyReq(BaseModel):
    challenge_id: str
    signature: str


@app.post("/auth/verify")
def verify(req: VerifyReq):
    now = int(time.time())
    with db() as conn:
        ch = conn.execute(
            "SELECT email, nonce, expires_at FROM challenges WHERE id = ?",
            (req.challenge_id,),
        ).fetchone()
        if not ch or ch["expires_at"] < now:
            raise HTTPException(400, "challenge invalid or expired")

        user = conn.execute(
            "SELECT pk_sign FROM users WHERE email = ?", (ch["email"],)
        ).fetchone()
        try:
            Ed25519PublicKey.from_public_bytes(user["pk_sign"]).verify(
                bytes.fromhex(req.signature), ch["nonce"]
            )
        except InvalidSignature:
            raise HTTPException(401, "bad signature")

        token = secrets.token_urlsafe(32)
        conn.execute(
            "INSERT INTO tokens (token, email, expires_at) VALUES (?, ?, ?)",
            (token, ch["email"], now + TOKEN_TTL),
        )
        conn.execute("DELETE FROM challenges WHERE id = ?", (req.challenge_id,))

    return {"token": token, "expires_in": TOKEN_TTL}


def whoami(authorization):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing token")
    token = authorization[len("Bearer "):]
    with db() as conn:
        row = conn.execute(
            "SELECT email, expires_at FROM tokens WHERE token = ?", (token,)
        ).fetchone()
    if not row or row["expires_at"] < int(time.time()):
        raise HTTPException(401, "invalid or expired token")
    return row["email"]


@app.get("/users/{email}/keys")
def get_keys(email: str, authorization: Optional[str] = Header(default=None)):
    whoami(authorization)
    with db() as conn:
        row = conn.execute(
            "SELECT pk_sign, pk_enc FROM users WHERE email = ?", (email,)
        ).fetchone()
    if not row:
        raise HTTPException(404, "no such user")
    return {"pk_sign": row["pk_sign"].hex(), "pk_enc": row["pk_enc"].hex()}


@app.post("/files")
async def upload(
    recipient: str = Form(...),
    filename: str = Form(...),
    epk: str = Form(...),
    nonce: str = Form(...),
    signature: str = Form(...),
    blob: UploadFile = File(...),
    authorization: Optional[str] = Header(default=None),
):
    sender = whoami(authorization)
    with db() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE email = ?", (recipient,)).fetchone():
            raise HTTPException(404, "recipient not registered")

        fid = secrets.token_hex(16)
        path = BLOB_DIR / fid
        with open(path, "wb") as f:
            while chunk := await blob.read(1 << 20):
                f.write(chunk)

        conn.execute(
            """INSERT INTO files
               (id, sender, recipient, filename, epk, nonce, signature, blob_path, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (fid, sender, recipient, filename,
             bytes.fromhex(epk), bytes.fromhex(nonce), bytes.fromhex(signature),
             str(path), int(time.time())),
        )
    return {"file_id": fid}


@app.get("/files")
def list_inbox(authorization: Optional[str] = Header(default=None)):
    me = whoami(authorization)
    with db() as conn:
        rows = conn.execute(
            """SELECT id, sender, filename, created_at
               FROM files WHERE recipient = ? ORDER BY created_at DESC""",
            (me,),
        ).fetchall()
    return [dict(r) for r in rows]


def _load_file(fid, me):
    with db() as conn:
        row = conn.execute(
            """SELECT sender, recipient, filename, epk, nonce, signature, blob_path
               FROM files WHERE id = ?""",
            (fid,),
        ).fetchone()
    if not row:
        raise HTTPException(404, "no such file")
    if row["recipient"] != me:
        raise HTTPException(403, "not the recipient")
    return row


@app.get("/files/{fid}/meta")
def file_meta(fid: str, authorization: Optional[str] = Header(default=None)):
    me = whoami(authorization)
    row = _load_file(fid, me)
    return {
        "sender": row["sender"],
        "filename": row["filename"],
        "epk": row["epk"].hex(),
        "nonce": row["nonce"].hex(),
        "signature": row["signature"].hex(),
    }


@app.get("/files/{fid}/blob")
def file_blob(fid: str, authorization: Optional[str] = Header(default=None)):
    me = whoami(authorization)
    row = _load_file(fid, me)
    with open(row["blob_path"], "rb") as f:
        return Response(content=f.read(), media_type="application/octet-stream")