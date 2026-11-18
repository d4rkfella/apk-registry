package authz

import (
	"testing"
	"time"
)

func TestKeyExpirationPersistsAndBlocksAuthentication(t *testing.T) {
	filename := t.TempDir() + "/api-keys.json"
	store, err := OpenTokenStore(filename)
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	key, token, err := store.Create("temporary", []string{"deploy"}, &expiresAt)
	if err != nil {
		t.Fatal(err)
	}
	if key.ExpiresAt == nil || !key.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("created expiration = %v, want %v", key.ExpiresAt, expiresAt)
	}

	reopened, err := OpenTokenStore(filename)
	if err != nil {
		t.Fatal(err)
	}
	keys := reopened.List()
	if len(keys) != 1 || keys[0].ExpiresAt == nil || !keys[0].ExpiresAt.Equal(expiresAt) {
		t.Fatalf("persisted expiration = %v, want %v", keys, expiresAt)
	}
	if _, err := reopened.Authenticate(token); err != nil {
		t.Fatalf("unexpired API key did not authenticate: %v", err)
	}

	expiredAt := time.Now().UTC().Add(-time.Second)
	reopened.mu.Lock()
	reopened.keys[0].ExpiresAt = &expiredAt
	reopened.mu.Unlock()
	if _, err := reopened.Authenticate(token); err == nil {
		t.Fatal("expired API key authenticated")
	}
}

func TestCreateRejectsPastExpiration(t *testing.T) {
	store, err := OpenTokenStore(t.TempDir() + "/api-keys.json")
	if err != nil {
		t.Fatal(err)
	}
	expiresAt := time.Now().UTC().Add(-time.Second)
	if _, _, err := store.Create("expired", []string{"deploy"}, &expiresAt); err == nil {
		t.Fatal("API key creation accepted a past expiration")
	}
}
