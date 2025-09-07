package securefs

import "github.com/google/uuid"

type userRecord struct {
	Username string
	Salt     []byte
	EncUser  []byte // encrypted userPrivate with master key
}

type userPrivate struct {
	FileIndex map[string]uuid.UUID // filename -> file root
}

type fileRecord struct {
	Key    []byte      // 32-byte symmetric key
	Chunks []uuid.UUID // ordered list of chunk IDs
}

// ShareCode is a signed capability string containing file root and key.
type ShareCode struct {
	File uuid.UUID
	Key  []byte
	Mac  []byte
}
