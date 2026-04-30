import json
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

RAW_PUB = serialization.PublicFormat.Raw
RAW_PRIV = serialization.PrivateFormat.Raw
RAW_ENC = serialization.Encoding.Raw
NO_ENC = serialization.NoEncryption()
HKDF_INFO = b"filedrop-v1-dek"


def gen_keys():
    return Ed25519PrivateKey.generate(), X25519PrivateKey.generate()


def pub_bytes(sk):
    return sk.public_key().public_bytes(RAW_ENC, RAW_PUB)


def priv_bytes(sk):
    return sk.private_bytes(RAW_ENC, RAW_PRIV, NO_ENC)


def _derive_key(shared, salt):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HKDF_INFO).derive(shared)


def encrypt_for(recipient_pk_enc, plaintext, aad):
    esk = X25519PrivateKey.generate()
    epk = esk.public_key().public_bytes(RAW_ENC, RAW_PUB)
    rcpt = X25519PublicKey.from_public_bytes(recipient_pk_enc)
    shared = esk.exchange(rcpt)
    dek = _derive_key(shared, epk + recipient_pk_enc)
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return epk, nonce, ct


def decrypt_with(my_sk_enc, epk, nonce, ct, aad):
    epk_pub = X25519PublicKey.from_public_bytes(epk)
    shared = my_sk_enc.exchange(epk_pub)
    my_pk = my_sk_enc.public_key().public_bytes(RAW_ENC, RAW_PUB)
    dek = _derive_key(shared, epk + my_pk)
    return AESGCM(dek).decrypt(nonce, ct, aad)


def _digest(*parts):
    h = hashes.Hash(hashes.SHA256())
    for p in parts:
        h.update(len(p).to_bytes(4, "big"))
        h.update(p)
    return h.finalize()


def sign_blob(sk, *parts):
    return sk.sign(_digest(*parts))


def verify_blob(pk_bytes, signature, *parts):
    Ed25519PublicKey.from_public_bytes(pk_bytes).verify(signature, _digest(*parts))


SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


def _kdf(passphrase, salt):
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(passphrase.encode())


def save_keystore(path, email, sk_sign, sk_enc, passphrase):
    salt = os.urandom(16)
    key = _kdf(passphrase, salt)
    nonce = os.urandom(12)
    inner = json.dumps({
        "sk_sign": priv_bytes(sk_sign).hex(),
        "sk_enc": priv_bytes(sk_enc).hex(),
    }).encode()
    blob = AESGCM(key).encrypt(nonce, inner, email.encode())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "email": email,
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "blob": blob.hex(),
    }, indent=2))


def load_keystore(path, passphrase):
    data = json.loads(path.read_text())
    salt = bytes.fromhex(data["salt"])
    key = _kdf(passphrase, salt)
    inner_bytes = AESGCM(key).decrypt(
        bytes.fromhex(data["nonce"]),
        bytes.fromhex(data["blob"]),
        data["email"].encode(),
    )
    inner = json.loads(inner_bytes)
    return (
        data["email"],
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(inner["sk_sign"])),
        X25519PrivateKey.from_private_bytes(bytes.fromhex(inner["sk_enc"])),
    )