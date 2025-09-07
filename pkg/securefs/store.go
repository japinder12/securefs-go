package securefs

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/google/uuid"
)

// Store persists everything in a single JSON file for demo purposes.
type Store struct {
	mu     sync.RWMutex
	path   string
	Secret []byte // random store secret for signing share codes

	Users  map[string]*userRecord
	Files  map[uuid.UUID]*fileRecord
	Chunks map[uuid.UUID][]byte
}

func OpenStore(path string) (*Store, error) {
	s := &Store{
		path:   path,
		Secret: RandomBytes(32),
		Users:  make(map[string]*userRecord),
		Files:  make(map[uuid.UUID]*fileRecord),
		Chunks: make(map[uuid.UUID][]byte),
	}
	// Load if exists
	if _, err := os.Stat(path); err == nil {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, s); err != nil {
			return nil, err
		}
		// Defensive: ensure maps non-nil
		if s.Users == nil { s.Users = make(map[string]*userRecord) }
		if s.Files == nil { s.Files = make(map[uuid.UUID]*fileRecord) }
		if s.Chunks == nil { s.Chunks = make(map[uuid.UUID][]byte) }
		return s, nil
	}
	return s, nil
}

func (s *Store) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil { return err }
	return os.WriteFile(s.path, b, 0o600)
}

func (s *Store) withWrite(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := fn()
	if err != nil { return err }
	// persist
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil { return err }
	return os.WriteFile(s.path, b, 0o600)
}

// Helpers
func copyBytes(b []byte) []byte {
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp
}

var ErrNotFound = errors.New("not found")
