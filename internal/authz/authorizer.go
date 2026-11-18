package authz

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"
)

type Identity struct {
	Name        string
	Permissions []string
}

type Authorizer struct {
	usernameHash [sha256.Size]byte
	passwordHash [sha256.Size]byte
	keys         *TokenStore
}

func New(adminUsername, adminPassword string, keys *TokenStore) *Authorizer {
	return &Authorizer{
		usernameHash: sha256.Sum256([]byte(adminUsername)),
		passwordHash: sha256.Sum256([]byte(adminPassword)),
		keys:         keys,
	}
}

func (a *Authorizer) AuthenticateAdmin(username, password string) bool {
	usernameHash := sha256.Sum256([]byte(username))
	passwordHash := sha256.Sum256([]byte(password))
	usernameOK := subtle.ConstantTimeCompare(usernameHash[:], a.usernameHash[:])
	passwordOK := subtle.ConstantTimeCompare(passwordHash[:], a.passwordHash[:])
	return usernameOK&passwordOK == 1
}

func (a *Authorizer) Authenticate(raw string) (*Identity, error) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "apk_") {
		return nil, errors.New("invalid API key")
	}
	return a.keys.Authenticate(raw)
}

func (a *Authorizer) Authorize(identity *Identity, permission string) bool {
	if identity == nil {
		return false
	}
	for _, granted := range identity.Permissions {
		if granted == permission {
			return true
		}
	}
	return false
}
