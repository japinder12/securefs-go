package securefs

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Client is a logged-in view for one user.
type Client struct {
	store     *Store
	username  string
	masterKey []byte
	priv      *userPrivate
}

func Signup(store *Store, username, password string) error {
	if username == "" || password == "" {
		return errors.New("empty credentials")
	}
	if _, ok := store.Users[username]; ok {
		return errors.New("user exists")
	}
	salt := RandomBytes(16)
	mk := deriveKey([]byte(password), salt, []byte("master"), 32)

	priv := &userPrivate{FileIndex: map[string]uuid.UUID{}}
	enc := symEnc(mk, must(json.Marshal(priv)))

	rec := &userRecord{
		Username: username,
		Salt:     salt,
		EncUser:  enc,
	}
	return store.withWrite(func() error {
		store.Users[username] = rec
		return nil
	})
}

func Login(store *Store, username, password string) (*Client, error) {
	rec, ok := store.Users[username]
	if !ok {
		return nil, errors.New("no such user")
	}
	mk := deriveKey([]byte(password), rec.Salt, []byte("master"), 32)
	pt, err := symDec(mk, rec.EncUser)
	if err != nil {
		return nil, errors.New("bad password")
	}
	var priv userPrivate
	if err := json.Unmarshal(pt, &priv); err != nil {
		return nil, err
	}
	return &Client{store: store, username: username, masterKey: mk, priv: &priv}, nil
}

func (c *Client) persist() error {
	rec := c.store.Users[c.username]
	rec.EncUser = symEnc(c.masterKey, must(json.Marshal(c.priv)))
	return c.store.Save()
}

func (c *Client) StoreFile(name string, data []byte) error {
	key := deriveKey(c.masterKey, []byte(name), []byte("file-key"), 32)
	root := uuid.New()
	// fresh record
	rec := &fileRecord{Key: key, Chunks: []uuid.UUID{}}
	// write first chunk
	chID := uuid.New()
	c.store.Chunks[chID] = symEnc(key, data)
	rec.Chunks = append(rec.Chunks, chID)
	c.store.Files[root] = rec
	c.priv.FileIndex[name] = root
	return c.persist()
}

func (c *Client) LoadFile(name string) ([]byte, error) {
	root, ok := c.priv.FileIndex[name]
	if !ok { return nil, ErrNotFound }
	rec := c.store.Files[root]
	var out []byte
	for _, id := range rec.Chunks {
		pt, err := symDec(rec.Key, c.store.Chunks[id])
		if err != nil { return nil, err }
		out = append(out, pt...)
	}
	return out, nil
}

func (c *Client) AppendFile(name string, more []byte) error {
	root, ok := c.priv.FileIndex[name]
	if !ok { return ErrNotFound }
	rec := c.store.Files[root]
	chID := uuid.New()
	c.store.Chunks[chID] = symEnc(rec.Key, more)
	rec.Chunks = append(rec.Chunks, chID)
	return c.persist()
}

func (c *Client) CreateShare(name string) (string, error) {
	root, ok := c.priv.FileIndex[name]
	if !ok { return "", ErrNotFound }
	rec := c.store.Files[root]
	code := ShareCode{File: root, Key: rec.Key}
	msg := append([]byte("share|"), append(code.File[:], code.Key...)...)
	code.Mac = hmacSHA256(c.store.Secret, msg)
	b, _ := json.Marshal(code)
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (c *Client) AcceptShare(saveAs, code string) error {
	b, err := base64.RawURLEncoding.DecodeString(code)
	if err != nil { return err }
	var sc ShareCode
	if err := json.Unmarshal(b, &sc); err != nil { return err }
	msg := append([]byte("share|"), append(sc.File[:], sc.Key...)...)
	if !hmacEqual(hmacSHA256(c.store.Secret, msg), sc.Mac) {
		return errors.New("invalid share code")
	}
	rec, ok := c.store.Files[sc.File]
	if !ok { return errors.New("dangling share") }
	// adopt under new name
	c.priv.FileIndex[saveAs] = sc.File
	// ensure local can decrypt (use received key)
	rec.Key = sc.Key
	return c.persist()
}

func (c *Client) Revoke(name string) error {
	root, ok := c.priv.FileIndex[name]
	if !ok { return ErrNotFound }
	rec := c.store.Files[root]
	// rotate key and re-encrypt all chunks
	newKey := deriveKey(c.masterKey, []byte(name), []byte("file-key|rotated|"+uuid.New().String()), 32)
	var newChunks []uuid.UUID
	for _, id := range rec.Chunks {
		pt, err := symDec(rec.Key, c.store.Chunks[id])
		if err != nil { return err }
		newID := uuid.New()
		c.store.Chunks[newID] = symEnc(newKey, pt)
		newChunks = append(newChunks, newID)
		// optionally delete old chunk
		delete(c.store.Chunks, id)
	}
	rec.Key = newKey
	rec.Chunks = newChunks
	return c.persist()
}

// ---- helpers ----
func must[T any](v T, err error) T {
	if err != nil { panic(err) }
	return v
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) { return false }
	var diff byte
	for i := range a { diff |= a[i] ^ b[i] }
	return diff == 0
}

func (c *Client) Debug() {
	fmt.Printf("user=%s files=%v\n", c.username, c.priv.FileIndex)
}
