package securefs

import "testing"

func TestHappyPath(t *testing.T) {
	store, err := OpenStore("test_store.json")
	if err != nil { t.Fatal(err) }
	defer func() { _ = store.Save() }()

	if err := Signup(store, "alice", "wonder"); err != nil { t.Fatal(err) }
	if err := Signup(store, "bob", "builder"); err != nil { t.Fatal(err) }

	alice, err := Login(store, "alice", "wonder")
	if err != nil { t.Fatal(err) }
	if err := alice.StoreFile("notes.txt", []byte("hello")); err != nil { t.Fatal(err) }

	code, err := alice.CreateShare("notes.txt")
	if err != nil { t.Fatal(err) }

	bob, err := Login(store, "bob", "builder")
	if err != nil { t.Fatal(err) }
	if err := bob.AcceptShare("notes_copy.txt", code); err != nil { t.Fatal(err) }
	if err := bob.AppendFile("notes_copy.txt", []byte(" world")); err != nil { t.Fatal(err) }

	got, err := alice.LoadFile("notes.txt")
	if err != nil { t.Fatal(err) }
	if string(got) != "hello world" {
		t.Fatalf("expected 'hello world', got %q", string(got))
	}

	// revoke and ensure old content remains, but future shares would rotate key
	if err := alice.Revoke("notes.txt"); err != nil { t.Fatal(err) }
}
