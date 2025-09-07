# securefs-go

**A small, local, end-to-end encrypted file store with sharing** — written in Go.
Inspired by UC Berkeley CS161 (Project 2) objectives; implemented from scratch for easy cloning and running.

> ⚠️ Learning project — **not production crypto**.

## Features
- 🔐 Password-derived master keys (no plaintext secrets at rest)
- 📄 Store / load / append files (per-file keys, AES-GCM chunks)
- 🤝 Link-style sharing via signed capability codes (HMAC)
- 🔄 Revocation via key rotation (re-encrypts chunks)
- 🧪 Deep tests: multi-session, sharing, tamper, revoke, persistence

## Quick Start
```bash
git clone https://github.com/yourname/securefs-go
cd securefs-go

# Run tests
make test

# Try the CLI (uses .securefs.json in the current dir)
go run ./cmd/securefs signup  --user alice --pass secret
go run ./cmd/securefs put     --user alice --pass secret --name notes.txt --data "hello"
code=$(go run ./cmd/securefs share --user alice --pass secret --name notes.txt)
go run ./cmd/securefs signup  --user bob   --pass hunter2
go run ./cmd/securefs accept  --user bob   --pass hunter2 --as notes_copy.txt --code "$code"
go run ./cmd/securefs append  --user bob   --pass hunter2 --name notes_copy.txt --data " world"
go run ./cmd/securefs get     --user alice --pass secret --name notes.txt   # -> hello world
go run ./cmd/securefs revoke  --user alice --pass secret --name notes.txt
```

## Design

### Persistence model
- A single JSON store (`.securefs.json`) holds **Users**, **Files**, **Chunks**, and a 32-byte random **Store Secret**.
- In-memory state is protected by an RW mutex; all mutating ops persist by serializing the Store and writing with `os.WriteFile(..., 0600)`. (Simple, not crash-safe journaling.)

### Identity & bootstrap
- **Signup**: generate 16-byte salt; derive a **master key MK** = `deriveKey(password, salt, "master", 32)`.
- The user’s private record (`userPrivate`) contains a **FileIndex** (`filename → fileRootUUID`), serialized as JSON and encrypted under MK (AES-GCM). The public user record stores `{ Username, Salt, EncUser }`.
- **Login**: recompute MK and decrypt `EncUser`; wrong password → decrypt fails.

### Key derivation & symmetric crypto
- `deriveKey(password, salt, info, length)` is an **HMAC-SHA256–based KDF (HKDF-ish)** used for demo purposes (not memory-hard like Argon2).
- AEAD is **AES-GCM** with a 12-byte random nonce. Ciphertext layout: `[nonce || gcm(ciphertext)]`. Integrity is enforced by the GCM tag; tampering yields decryption errors.

### File layout & chunking
- Each file has a symmetric **file key Kf**. On first `StoreFile`, Kf = `deriveKey(MK, []byte(filename), "file-key", 32)` and is stored in the file record.
- Content is stored as an **ordered list of chunks**: for each write/append, generate a random UUID for the chunk, encrypt `symEnc(Kf, data)`, and append the chunk UUID to the file record’s list.
- `LoadFile` streams chunks in order and AEAD-decrypts with Kf, concatenating plaintexts.

### Sharing model (capability codes)
- `CreateShare(name)` returns a **capability code**: JSON containing `{ File: <uuid>, Key: <Kf> }`, then **HMAC-signed** with the Store Secret over the message `("share|" || File || Key)`. The whole JSON is base64url-encoded.
- `AcceptShare(saveAs, code)` verifies the HMAC; if valid, it binds `saveAs → File` in the recipient’s FileIndex and ensures the file record’s key is Kf from the capability.
- Tampering with the code breaks verification; dangling capabilities (deleted File UUID) fail on accept.

### Revocation semantics (demo-oriented)
- `Revoke(name)` **rotates Kf** and **re-encrypts all chunks** under the new key (O(#chunks)). The design illustrates key rotation mechanics.
- **Note:** This implementation does **not** implement per-recipient capabilities; collaborators reading via the shared file record still see updated state. For strict revocation (collaborator loses access), you’d maintain **per-recipient wrapped keys** (or a share-graph root), rotate the root, and only reissue to authorized recipients.

### Concurrency & multi-session behavior
- A `Client` caches its decrypted `userPrivate`. Another session’s new filename bindings (e.g., after a share accept) won’t be visible until you **login/refresh** again; tests reflect this by re-logging.

### Security properties & scope
- AEAD provides **confidentiality + integrity** for file data; HMAC provides **authenticity** for share codes.
- KDF is **not memory-hard** and thus not ideal against offline dictionary attacks; acceptable for an educational demo.
- No attempt at **forward secrecy**, server-side trust minimization, or tamper-evident store persistence. Keys and metadata live in a single trusted store.

### Complexity & limits
- `LoadFile` is O(#chunks); `Revoke` is O(total bytes) due to re-encryption.
- No large-file streaming API, no journaling/rollback, no key escrow or user-to-user PKI.
- Clean separation between **library** (`pkg/securefs`) and **CLI** (`cmd/securefs`) enables swapping the persistence layer or exposing an HTTP API later.

