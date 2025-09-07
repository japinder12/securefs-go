package securefs

import (
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"
)

// ---- helpers ----

func newTempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "store.json")
	s, err := OpenStore(p)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s
}

func mustLogin(t *testing.T, s *Store, user, pass string) *Client {
	t.Helper()
	c, err := Login(s, user, pass)
	if err != nil {
		t.Fatalf("Login(%s): %v", user, err)
	}
	return c
}

// ==========================
// Happy path & basic auth
// ==========================

func TestSignupLogin_BasicAndWrongPassword(t *testing.T) {
	s := newTempStore(t)

	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatalf("Signup(alice): %v", err)
	}

	// good login
	if _, err := Login(s, "alice", "wonder"); err != nil {
		t.Fatalf("Login(alice, correct): %v", err)
	}

	// wrong password
	if _, err := Login(s, "alice", "wrong"); err == nil {
		t.Fatalf("expected wrong-password to fail, got nil")
	}

	// duplicate username
	if err := Signup(s, "alice", "another"); err == nil {
		t.Fatalf("expected duplicate username to fail, got nil")
	}
}

func TestStoreLoadAppend_SingleUser(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")

	if err := alice.StoreFile("notes.txt", []byte("Bitcoin is Nick's favorite ")); err != nil {
		t.Fatal(err)
	}
	if err := alice.AppendFile("notes.txt", []byte("digital ")); err != nil {
		t.Fatal(err)
	}
	if err := alice.AppendFile("notes.txt", []byte("cryptocurrency!")); err != nil {
		t.Fatal(err)
	}

	got, err := alice.LoadFile("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := "Bitcoin is Nick's favorite digital cryptocurrency!"
	if string(got) != want {
		t.Fatalf("content mismatch:\n want: %q\n  got: %q", want, string(got))
	}
}

// ==========================
// Multi-session / consistency
// ==========================

func TestMultiSession_Consistency(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	phone := mustLogin(t, s, "alice", "wonder")
	laptop := mustLogin(t, s, "alice", "wonder")

	// Phone creates file
	if err := phone.StoreFile("joint.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}

	// Re-login on laptop to refresh its user record (new filename mapping)
	laptop = mustLogin(t, s, "alice", "wonder")

	// Laptop appends
	if err := laptop.AppendFile("joint.txt", []byte(" world")); err != nil {
		t.Fatal(err)
	}

	a, err := phone.LoadFile("joint.txt")
	if err != nil {
		t.Fatal(err)
	}
	b, err := laptop.LoadFile("joint.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != "hello world" || string(b) != "hello world" {
		t.Fatalf("views diverged: phone=%q laptop=%q", string(a), string(b))
	}
}

// ==========================
// Sharing & collaboration
// ==========================

func TestShareAccept_CollaborationAppend(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	if err := Signup(s, "bob", "builder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")
	bob := mustLogin(t, s, "bob", "builder")

	if err := alice.StoreFile("notes.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	code, err := alice.CreateShare("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.AcceptShare("their_copy.txt", code); err != nil {
		t.Fatal(err)
	}
	if err := bob.AppendFile("their_copy.txt", []byte(" world")); err != nil {
		t.Fatal(err)
	}

	got, err := alice.LoadFile("notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(got))
	}
}

func TestShareCode_TamperDetection(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	if err := Signup(s, "bob", "builder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")
	bob := mustLogin(t, s, "bob", "builder")

	if err := alice.StoreFile("doc.txt", []byte("hello")); err != nil {
		t.Fatal(err)
	}
	code, err := alice.CreateShare("doc.txt")
	if err != nil {
		t.Fatal(err)
	}

	// tamper last byte of the base64 payload
	raw, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0xFF
	bad := base64.RawURLEncoding.EncodeToString(raw)

	if err := bob.AcceptShare("doc_copy.txt", bad); err == nil {
		t.Fatalf("expected tampered share code to fail, got nil")
	}
}

func TestShareCode_DanglingShareFails(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	if err := Signup(s, "bob", "builder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")
	bob := mustLogin(t, s, "bob", "builder")

	if err := alice.StoreFile("ghost.txt", []byte("boo")); err != nil {
		t.Fatal(err)
	}
	code, err := alice.CreateShare("ghost.txt")
	if err != nil {
		t.Fatal(err)
	}

	// Decode to find file UUID then delete it to simulate dangling capability
	var sc ShareCode
	b, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &sc); err != nil {
		t.Fatal(err)
	}
	delete(s.Files, sc.File)

	if err := bob.AcceptShare("ghost_copy.txt", code); err == nil {
		t.Fatalf("expected dangling share to fail, got nil")
	}
}

// ==========================
// Revocation semantics
// ==========================

func TestRevoke_KeyRotationAndNewShare(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	if err := Signup(s, "bob", "builder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")
	bob := mustLogin(t, s, "bob", "builder")

	if err := alice.StoreFile("secrets.txt", []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	code1, err := alice.CreateShare("secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := bob.AcceptShare("secrets_copy.txt", code1); err != nil {
		t.Fatal(err)
	}
	if err := bob.AppendFile("secrets_copy.txt", []byte("-beta")); err != nil {
		t.Fatal(err)
	}
	got, _ := alice.LoadFile("secrets.txt")
	if string(got) != "alpha-beta" {
		t.Fatalf("pre-revoke content mismatch, got %q", string(got))
	}

	// Revoke (rotate key + re-encrypt)
	if err := alice.Revoke("secrets.txt"); err != nil {
		t.Fatal(err)
	}

	// Owner still reads
	got, err = alice.LoadFile("secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "alpha-beta" {
		t.Fatalf("post-revoke content mismatch, got %q", string(got))
	}

	// New share after revoke should embed a different key than old code.
	var sc1, sc2 ShareCode
	if b1, err := base64.RawURLEncoding.DecodeString(code1); err == nil {
		_ = json.Unmarshal(b1, &sc1)
	}
	code2, err := alice.CreateShare("secrets.txt")
	if err != nil {
		t.Fatal(err)
	}
	if b2, err := base64.RawURLEncoding.DecodeString(code2); err == nil {
		_ = json.Unmarshal(b2, &sc2)
	}
	if string(sc1.Key) == string(sc2.Key) {
		t.Fatalf("expected rotated file key to differ in new share code")
	}
}

// ==========================
// Integrity: tamper chunks
// ==========================

func TestIntegrity_TamperChunkCausesDecryptFailure(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")

	if err := alice.StoreFile("tamper.txt", []byte("HELLO")); err != nil {
		t.Fatal(err)
	}
	if err := alice.AppendFile("tamper.txt", []byte("_WORLD")); err != nil {
		t.Fatal(err)
	}

	// Find root via user's private index (same package -> allowed).
	root, ok := alice.priv.FileIndex["tamper.txt"]
	if !ok {
		t.Fatalf("file not in index")
	}
	rec := s.Files[root]
	if len(rec.Chunks) == 0 {
		t.Fatalf("no chunks")
	}
	// Flip a byte in the first chunk
	chID := rec.Chunks[0]
	ct := s.Chunks[chID]
	ct[len(ct)/2] ^= 0xA5
	s.Chunks[chID] = ct

	_, err := alice.LoadFile("tamper.txt")
	if err == nil {
		t.Fatalf("expected tampered chunk to fail decryption, got nil")
	}
}

// ==========================
// Persistence
// ==========================

func TestPersistence_SaveAndReopen(t *testing.T) {
	s := newTempStore(t)
	if err := Signup(s, "alice", "wonder"); err != nil {
		t.Fatal(err)
	}
	alice := mustLogin(t, s, "alice", "wonder")

	if err := alice.StoreFile("persist.txt", []byte("state")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Re-open same store file
	s2, err := OpenStore(s.path)
	if err != nil {
		t.Fatalf("OpenStore(reopen): %v", err)
	}
	alice2 := mustLogin(t, s2, "alice", "wonder")

	got, err := alice2.LoadFile("persist.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "state" {
		t.Fatalf("persistence lost, got %q", string(got))
	}
}
