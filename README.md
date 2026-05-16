# Flask
Part 1:

Hi, I'm Andrew. This is my final project for CPSC 352, Cryptography. I built a system called FileDrop, it's a secure file exchange service where two users can send file through a central server, but the server never sees the plaintext, the symmetric keys, or anyone's private keys. All the cryptography happens on the client side. 

The project meets the two requirements from the assignment, confidentiality, meaning only the intended recipient can read the file, and a digital signature, meaning the recipient can verify who sent it and that it wasn't tampered with. 


Part 2:

The codebase is split into a server and a client. The server is a small FastAPI web service backed by SQLite. The client is a command line tool. For Cryptography I used pyca/cryptography, the standard audited Python library, so I'm following the standard practise rather than implementing it from scratch on my own.

Each user has two static keypair, an Ed25519 keypair for digital signatures, and an X25519 keypair for ECDH key segment. File encryption uses AES-256-GCM. Keys are derived using HKDF-SHA256. The local keystore on disk is encrypted with a key derived from a passphrase using scrypt, which is a slow and memory-hard function that can resist brute force.


Part 3:

I have three terminals open, one for server, one for Alice, and one for Bob

Server Terminal

I will start from a clean state and I will remove any files I had from previous runs.

Remove-Item filedrop.db, alice.json, alice.token, bob.json, bob.token, note.txt, got.txt -ErrorAction SilentlyContinue

Remove-Item -Recurse -Force blobs -ErrorAction SilentlyContinue

New-Item -ItemType Directory blobs | Out-Null

I start the server on port 8765

python -m uvicorn server.app:app --host 127.0.0.1 --port 8765

Alice Terminal

$env:FILEDROP_SERVER = "http://127.0.0.1:8765"
$env:FILEDROP_KEYSTORE = "$PWD\alice.json"

Alice registers. Her client generates her two keypairs locally, sends only the public halves to the server, and stores the private halves in an encrypted keystore on her own disk. She enters a passphrase, which is what protects the keystore

python -m client.cli register alice@example.com


We will choose the passphrase to be "alice"

Now Alice logs in. This is where it's interesting, as there are no passwords sent over the network. The server generates 32 random bytes, sends them to Alice as a challenge, and Alice signs them with her Ed25519 private key. The server verifies the signature using the public key it has on file. If it checks out, Alice has prove she possess the private key, without ever transmitting it. 

python -m client.cli login

Bob Terminal 

Bob does the same, register, login. Different keystore, different passphrase, and completely separate identity. 

$env:FILEDROP_SERVER = "http://127.0.0.1:8765"
$env:FILEDROP_KEYSTORE = "$PWD\bob.json"
python -m client.cli register bob@example.com
Passphrase: "bob"
python -m client.cli login

Go back to Alice's terminal.

Now we will move on to the actual file send. Alice write a quick message and sends it to Bob.

"the meeting is at noon" | Out-File -Encoding ascii note.txt python -m client.cli send bob@example.com .\note.txt

Passphrase: Alice


What's happening here is that Alice's client fetches Bob's encryption public key from the server. Then it generates a fresh ephemeral X25519 keypair just for this one file. It runs ECDH between her ephemeral private key and Bob's static encryption key, which produces a shared secret only the two of them can compute. That shared secret goes through HKDF to derive a 32-byte AES key. The file is then encrypted with AES-256-GCM

The ephemeral public key travels with the ciphertext so Bob can reproduce the same shared secret. Because the ephemeral private key is discarded immediately after use, this gives us forward secrecy, even if Bob's long term private key were stolen years from now, this file would still stay confidential.

The encryption also includes additional authenticated data, which binds the ciphertext to the sender, the recipient, and the filename. Tampering with any of those values will cause the decryption to fail. Then, Alice signs the whole bundle with her Ed25519 key.

Switch to Bob's terminal

Bob checks his inbox, fetches the file, and reads it.

python -m client.cli list
python -m client.cli fetch <FILE_ID> .\got.txt
Passphrase: "bob
Get-Content .\got.txt

So now you see that Bob can actually read the file that Alice sent him.


---- Tampering Demo

Now we will move on to the tamper detection, I will flip a single byte inside the stored ciphertext
Get-Content -Encoding Byte -TotalCount 80 .\blobs\<FILE_ID>

$blob = ".\blobs\<FILE_ID>"
$bytes = [System.IO.File]::ReadAllBytes($blob)
$bytes[0] = $bytes[0] -bxor 0x01
[System.IO.File]::WriteAllBytes($blob, $bytes)

Now Bob tries to fetch the same file again

python -m client.cli fetch <SAME_FILE_ID> .\tampered.txt

We see the message signature check failed, refusing to decrypt note.txt. 

The client immediately reports that the signature check failed and refused to even attempt decryption. No output file is written. That's the digitial signature property, Bob can detect tampering before he ever sees the modified bytes

--- Access Control Demo

Next we will move on to the access control demo. Even though the cryptography prevents the server from reading files, the server also enforces who can download what. If Alice (who isn't the intended recipient) tries to fetch Bob's file.

Run this command in Alice's terminal:

python -m client.cli fetch <SAME_FILE_ID> .\stolen.txt
Passphrase: "alice"

The server returns 403 with not the recipient error message. Alice can't read what was sent to Bob even though she's the one who sent it.

--- Recapping

To recap, the server can store ciphertexts and public keys, but it can't read files because the symmetric keys never leaves the clients and are derives per-file from ephemeral key exchange. It can't tamper undetected because every file is signed. It can't impersonate users at login, because authentication requires possession of the private key, not just a password.

--- Closing

The implementation is in all of these files here, it's around 500 lines of Python. The crypto module itself is about 150 lines. I used pyca/cryptography for primitives, FastAPI and SQLite on the server, and Typer for the CLI. The biggest design choice was using ephemeral ECDH for forward secrecy rather than wrapping a symmetric key with the recipient's static RSA. Thanks for watching. 
