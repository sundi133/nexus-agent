package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store holds the active bundle and persists it so the agent can enforce
// the last known policy while offline or across restarts.
type Store struct {
	mu     sync.RWMutex
	bundle *Bundle
	etag   string
	path   string
}

type persisted struct {
	ETag   string  `json:"etag"`
	Bundle *Bundle `json:"bundle"`
}

// NewStore creates a store backed by file at path. It loads any cached
// bundle; a missing cache is not an error.
func NewStore(path string) (*Store, error) {
	s := &Store{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var p persisted
	if err := json.Unmarshal(b, &p); err != nil {
		// A corrupt cache must not brick the agent; the next sync replaces it.
		return s, nil
	}
	if p.Bundle != nil && p.Bundle.Validate() == nil {
		s.bundle, s.etag = p.Bundle, p.ETag
	}
	return s, nil
}

// Get returns the active bundle (nil if none) and its ETag.
func (s *Store) Get() (*Bundle, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bundle, s.etag
}

// Set validates, activates and persists a bundle.
func (s *Store) Set(b *Bundle, etag string) error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if err := b.Validate(); err != nil {
		return fmt.Errorf("invalid policy bundle: %w", err)
	}
	data, err := json.MarshalIndent(persisted{ETag: etag, Bundle: b}, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path, data, 0o600); err != nil {
		return err
	}
	s.mu.Lock()
	s.bundle, s.etag = b, etag
	s.mu.Unlock()
	return nil
}

// writeFileAtomic writes via temp file + rename so a crash never leaves a
// half-written file behind.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
