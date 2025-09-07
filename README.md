# securefs-go

**A tiny, local, end‑to‑end encrypted file store with sharing** — written in Go for quick demos and portfolio use.  
Inspired by the goals of UC Berkeley CS161 Project 2 (client API), but implemented from scratch for easy cloning and running.

> ⚠️ This is a learning project, **not production crypto**.

## Features
- 🔐 Password-derived keys per user (no plaintext secrets at rest)
- 📄 Store / load / append files (chunked, AES‑GCM)
- 🤝 Link‑style sharing via short codes (HMAC protected)
- 🔄 Revocation by key rotation (re‑encrypts content)
- 🧪 `go test` covers the happy path

## Quick Start
```bash
git clone https://github.com/yourname/securefs-go
cd securefs-go

# Run tests
make test

# Try the CLI (uses .securefs.json in the current dir)
go run ./cmd/securefs signup    --user alice --pass secret
go run ./cmd/securefs login     --user alice --pass secret
go run ./cmd/securefs put       --user alice --pass secret --name notes.txt --data "hello"
go run ./cmd/securefs get       --user alice --pass secret --name notes.txt
code=$(go run ./cmd/securefs share --user alice --pass secret --name notes.txt)
echo "share code: $code"
go run ./cmd/securefs accept    --user bob   --pass hunter2 --as notes_copy.txt --code "$code"
go run ./cmd/securefs append    --user bob   --pass hunter2 --name notes_copy.txt --data " world"
go run ./cmd/securefs get       --user alice --pass secret --name notes.txt
go run ./cmd/securefs revoke    --user alice --pass secret --name notes.txt
```

## Design (short)
- A single JSON file persists: users, files, chunks, and a random store secret.
- `deriveKey(password, salt, info)` – HMAC‑SHA256‑based KDF (HKDF‑ish).  
- `symEnc/symDec` – AES‑GCM with a random 12‑byte nonce (prepended).
- Files are stored as a list of encrypted chunks under random IDs.
- Sharing produces a signed code containing the file root ID and file key. Accepting imports that capability under a chosen filename.
- Revocation rotates the file key and re‑encrypts all chunks (simple but clear).

## Attribution
This project is *inspired by* the **CS161 Project 2** client API objectives. The original course spec and userlib are © UC Berkeley CS161 staff. This repo is an independent, from‑scratch re‑implementation for educational/portfolio purposes.
