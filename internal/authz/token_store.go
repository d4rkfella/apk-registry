package authz

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/d4rkfella/apk-registry/internal/config"
)

var ErrKeyNotFound = errors.New("API key not found")
var ErrKeyNameExists = errors.New("API key name already exists")
var ErrInvalidKeyRequest = errors.New("invalid API key request")

var keyIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
var keyNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type storedKey struct {
	APIKey
	digest [sha256.Size]byte
}

type tokenFileKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Hash        string     `json:"hash"`
	Permissions []string   `json:"permissions"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type TokenStore struct {
	mu       sync.RWMutex
	filename string
	keys     []storedKey
}

func OpenTokenStore(filename string) (_ *TokenStore, retErr error) {
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create API key directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("inspect API key directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("API key directory must be a real directory")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, fmt.Errorf("secure API key directory: %w", err)
	}
	store := &TokenStore{filename: filename}
	fileInfo, err := os.Lstat(filename)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect API key store: %w", err)
	}
	if !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("API key store must be a regular file")
	}
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("open API key store: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close API key store: %w", err))
		}
	}()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat API key store: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("API key store must be a regular file")
	}
	if err := os.Chmod(filename, 0600); err != nil {
		return nil, fmt.Errorf("secure API key store: %w", err)
	}
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	var records []tokenFileKey
	if err := decoder.Decode(&records); err != nil {
		return nil, fmt.Errorf("decode API key store: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("API key store must contain one JSON value")
	}
	names := make(map[string]bool, len(records))
	ids := make(map[string]bool, len(records))
	for _, record := range records {
		hash, err := hex.DecodeString(record.Hash)
		if !keyIDPattern.MatchString(record.ID) || !keyNamePattern.MatchString(record.Name) || err != nil || len(hash) != sha256.Size {
			return nil, errors.New("API key store contains an invalid entry")
		}
		if names[record.Name] || ids[record.ID] || record.CreatedAt.IsZero() {
			return nil, errors.New("API key store contains duplicate or incomplete entries")
		}
		if err := config.ValidateKeyScope(record.Permissions); err != nil {
			return nil, fmt.Errorf("invalid stored API key scope: %w", err)
		}
		names[record.Name], ids[record.ID] = true, true
		var digest [sha256.Size]byte
		copy(digest[:], hash)
		if record.ExpiresAt != nil && record.ExpiresAt.IsZero() {
			return nil, errors.New("API key store contains an invalid expiration")
		}
		apiKey := APIKey{
			ID: record.ID, Name: record.Name, Permissions: record.Permissions, CreatedAt: record.CreatedAt,
			ExpiresAt: record.ExpiresAt,
		}
		if apiKey.ExpiresAt != nil {
			expiresAt := apiKey.ExpiresAt.UTC()
			apiKey.ExpiresAt = &expiresAt
		}
		store.keys = append(store.keys, storedKey{
			APIKey: apiKey,
			digest: digest,
		})
	}
	return store, nil
}

func (s *TokenStore) Create(name string, permissions []string, expiresAt *time.Time) (APIKey, string, error) {
	name = strings.TrimSpace(name)
	if !keyNamePattern.MatchString(name) {
		return APIKey{}, "", fmt.Errorf("%w: name must be 1-64 letters, numbers, dots, underscores, or hyphens", ErrInvalidKeyRequest)
	}
	if err := config.ValidateKeyScope(permissions); err != nil {
		return APIKey{}, "", fmt.Errorf("%w: %v", ErrInvalidKeyRequest, err)
	}
	if expiresAt != nil && !expiresAt.After(time.Now()) {
		return APIKey{}, "", fmt.Errorf("%w: expiration must be in the future", ErrInvalidKeyRequest)
	}
	permissions = uniqueStrings(permissions)
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return APIKey{}, "", fmt.Errorf("generate API key: %w", err)
	}
	rawToken := "apk_" + hex.EncodeToString(secret)
	digest := sha256.Sum256([]byte(rawToken))
	idBytes := make([]byte, 16)
	if _, err := rand.Read(idBytes); err != nil {
		return APIKey{}, "", fmt.Errorf("generate API key ID: %w", err)
	}
	key := APIKey{
		ID: hex.EncodeToString(idBytes), Name: name, Permissions: permissions, CreatedAt: time.Now().UTC(),
	}
	if expiresAt != nil {
		expiresAtUTC := expiresAt.UTC()
		key.ExpiresAt = &expiresAtUTC
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for _, current := range s.keys {
		if current.Name == name {
			return APIKey{}, "", ErrKeyNameExists
		}
	}
	next := append(append([]storedKey(nil), s.keys...), storedKey{APIKey: key, digest: digest})
	if err := s.save(next); err != nil {
		return APIKey{}, "", err
	}
	s.keys = next
	return key, rawToken, nil
}

func (s *TokenStore) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for i, key := range s.keys {
		if key.ID == id {
			index = i
			break
		}
	}
	if index < 0 {
		return ErrKeyNotFound
	}
	next := append([]storedKey(nil), s.keys[:index]...)
	next = append(next, s.keys[index+1:]...)
	if err := s.save(next); err != nil {
		return err
	}
	s.keys = next
	return nil
}

func (s *TokenStore) List() []APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keys := make([]APIKey, 0, len(s.keys))
	for _, key := range s.keys {
		public := key.APIKey
		public.Permissions = append([]string(nil), key.Permissions...)
		if public.ExpiresAt != nil {
			expiresAt := *public.ExpiresAt
			public.ExpiresAt = &expiresAt
		}
		keys = append(keys, public)
	}
	return keys
}

func (s *TokenStore) Authenticate(raw string) (*Identity, error) {
	digest := sha256.Sum256([]byte(raw))
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, key := range s.keys {
		if subtle.ConstantTimeCompare(digest[:], key.digest[:]) == 1 {
			if key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now()) {
				return nil, errors.New("invalid API key")
			}
			return &Identity{
				Name: key.Name, Permissions: key.Permissions,
			}, nil
		}
	}
	return nil, errors.New("invalid API key")
}

func (s *TokenStore) save(keys []storedKey) (retErr error) {
	records := make([]tokenFileKey, 0, len(keys))
	for _, key := range keys {
		records = append(records, tokenFileKey{
			ID: key.ID, Name: key.Name, Hash: hex.EncodeToString(key.digest[:]),
			Permissions: key.Permissions, CreatedAt: key.CreatedAt, ExpiresAt: key.ExpiresAt,
		})
	}
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return fmt.Errorf("encode API key store: %w", err)
	}
	temp, err := os.CreateTemp(filepath.Dir(s.filename), ".api-keys-*")
	if err != nil {
		return fmt.Errorf("create API key store temp file: %w", err)
	}
	tempName := temp.Name()
	closed := false
	defer func() {
		if !closed {
			if err := temp.Close(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close API key store temp file: %w", err))
			}
		}
		if err := os.Remove(tempName); err != nil && !errors.Is(err, os.ErrNotExist) {
			retErr = errors.Join(retErr, fmt.Errorf("remove API key store temp file: %w", err))
		}
	}()
	if err := temp.Chmod(0600); err != nil {
		return fmt.Errorf("secure API key store temp file: %w", err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("write API key store: %w", err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("sync API key store: %w", err)
	}
	if err := temp.Close(); err != nil {
		closed = true
		return fmt.Errorf("close API key store: %w", err)
	}
	closed = true
	if err := os.Rename(tempName, s.filename); err != nil {
		return fmt.Errorf("publish API key store: %w", err)
	}
	return nil
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
