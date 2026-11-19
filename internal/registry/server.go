package registry

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/d4rkfella/apk-registry/internal/authz"
	"github.com/d4rkfella/apk-registry/internal/config"
)

type Server struct {
	Config     config.Config
	Manager    *Manager
	Authorizer *authz.Authorizer
	Keys       *authz.TokenStore
	Log        *slog.Logger
}

type createAPIKeyRequest struct {
	Name        string     `json:"name"`
	Permissions []string   `json:"permissions"`
	ExpiresAt   *time.Time `json:"expires_at"`
}

type createAPIKeyResponse struct {
	authz.APIKey
	Token string `json:"token"`
}

type rsaJWK struct {
	KeyType  string `json:"kty"`
	KeyID    string `json:"kid"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

func (s *Server) Routes() http.Handler {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /api/v1/admin/tokens", s.listAPIKeys)
	mux.HandleFunc("POST /api/v1/admin/tokens", s.createAPIKey)
	mux.HandleFunc("DELETE /api/v1/admin/tokens/{id}", s.revokeAPIKey)
	mux.HandleFunc("GET /{repo}/apk-configuration", s.apkConfiguration)
	mux.HandleFunc("GET /{repo}/jwks.json", s.jwks)
	mux.HandleFunc("GET /{repo}/{filename}", s.readSigningPublicKey)
	mux.HandleFunc("GET /{repo}/{path...}", s.readPackage)
	mux.HandleFunc("PUT /{repo}/{path...}", s.uploadPackage)
	mux.HandleFunc("DELETE /{repo}/{path...}", s.deletePackage)
	return logging(mux, s.Log)
}

func (s *Server) listAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	jsonResponse(w, http.StatusOK, s.Keys.List())
}

func (s *Server) createAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request createAPIKeyRequest
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid API key request", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "API key request must contain one JSON value", http.StatusBadRequest)
		return
	}
	key, token, err := s.Keys.Create(request.Name, request.Permissions, request.ExpiresAt)
	if errors.Is(err, authz.ErrKeyNameExists) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if errors.Is(err, authz.ErrInvalidKeyRequest) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		s.Log.Error("create API key", "error", err)
		http.Error(w, "could not create API key", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, http.StatusCreated, createAPIKeyResponse{APIKey: key, Token: token})
}

func (s *Server) revokeAPIKey(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if err := s.Keys.Revoke(r.PathValue("id")); errors.Is(err, authz.ErrKeyNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		s.Log.Error("revoke API key", "error", err)
		http.Error(w, "could not revoke API key", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	username, password, ok := r.BasicAuth()
	if !ok || !s.Authorizer.AuthenticateAdmin(username, password) {
		reason := "invalid_credentials"
		if !ok {
			reason = "missing_or_malformed_credentials"
		}
		s.Log.Warn("authentication failed",
			"auth_type", "admin_basic",
			"reason", reason,
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)
		w.Header().Set("WWW-Authenticate", `Basic realm="apk-registry-admin", charset="UTF-8"`)
		http.Error(w, "administrator credentials required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) readPackage(w http.ResponseWriter, r *http.Request) {
	repo, relative := r.PathValue("repo"), r.PathValue("path")
	if !s.requireReadAccess(w, r, repo) {
		return
	}
	file, filename, err := s.Manager.Read(r.Context(), repo, relative)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.NotFound(w, r)
		} else if errors.Is(err, errInvalidPackagePath) {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	defer file.Close()
	switch {
	case strings.HasSuffix(filename, ".apk"):
		w.Header().Set("Content-Type", "application/vnd.alpine.apk")
	case filename == "APKINDEX.tar.gz":
		w.Header().Set("Content-Type", "application/gzip")
	}
	http.ServeContent(w, r, filename, time.Time{}, file)
}

func (s *Server) apkConfiguration(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")
	if !s.requireReadAccess(w, r, repo) {
		return
	}
	if s.Manager.signingKey == nil {
		http.NotFound(w, r)
		return
	}
	jsonResponse(w, http.StatusOK, struct {
		JWKSURI string `json:"jwks_uri"`
	}{JWKSURI: s.publicRepositoryURL(r, repo) + "/jwks.json"})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")
	if !s.requireReadAccess(w, r, repo) {
		return
	}
	if s.Manager.signingKey == nil {
		http.NotFound(w, r)
		return
	}
	key := s.Manager.signingKey
	jsonResponse(w, http.StatusOK, struct {
		Keys []rsaJWK `json:"keys"`
	}{Keys: []rsaJWK{{
		KeyType:  "RSA",
		KeyID:    key.id,
		Modulus:  base64.RawURLEncoding.EncodeToString(key.publicKey.N.Bytes()),
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.publicKey.E)).Bytes()),
	}}})
}

func (s *Server) readSigningPublicKey(w http.ResponseWriter, r *http.Request) {
	repo := r.PathValue("repo")
	if !s.requireReadAccess(w, r, repo) {
		return
	}
	if s.Manager.signingKey == nil || r.PathValue("filename") != s.Manager.signingKey.publicName {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	http.ServeContent(w, r, s.Manager.signingKey.publicName, time.Time{}, bytes.NewReader(s.Manager.signingKey.publicKeyPEM))
}

func (s *Server) publicRepositoryURL(r *http.Request, repo string) string {
	if s.Config.PublicURL != "" {
		return strings.TrimRight(s.Config.PublicURL, "/") + "/" + repo
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if forwardedProto := strings.ToLower(strings.TrimSpace(strings.SplitN(r.Header.Get("X-Forwarded-Proto"), ",", 2)[0])); forwardedProto == "http" || forwardedProto == "https" {
		scheme = forwardedProto
	}
	return (&url.URL{Scheme: scheme, Host: r.Host, Path: "/" + repo}).String()
}

func (s *Server) requireReadAccess(w http.ResponseWriter, r *http.Request, repo string) bool {
	if !s.requireConfiguredRepository(w, r, repo) {
		return false
	}
	if !*s.Config.PublicRead {
		identity, ok := s.authenticate(w, r)
		if !ok {
			return false
		}
		if !s.Authorizer.Authorize(identity, "read") {
			http.Error(w, "read permission denied", http.StatusForbidden)
			return false
		}
	}
	return true
}

func (s *Server) uploadPackage(w http.ResponseWriter, r *http.Request) {
	repo, relative := r.PathValue("repo"), r.PathValue("path")
	if !s.requireConfiguredRepository(w, r, repo) {
		return
	}
	identity, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !s.Authorizer.Authorize(identity, "deploy") {
		http.Error(w, "deploy permission denied", http.StatusForbidden)
		return
	}
	result, err := s.Manager.Upload(r.Context(), repo, relative, s.Authorizer.Authorize(identity, "delete"), r.Body)
	if err != nil {
		s.writeManagerError(w, r, err)
		return
	}
	jsonResponse(w, http.StatusCreated, result)
}

func (s *Server) deletePackage(w http.ResponseWriter, r *http.Request) {
	repo, relative := r.PathValue("repo"), r.PathValue("path")
	if !s.requireConfiguredRepository(w, r, repo) {
		return
	}
	identity, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !s.Authorizer.Authorize(identity, "delete") {
		http.Error(w, "delete permission denied", http.StatusForbidden)
		return
	}
	if err := s.Manager.Delete(r.Context(), repo, relative); err != nil {
		s.writeManagerError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*authz.Identity, bool) {
	raw, err := bearer(r)
	if err != nil {
		s.Log.Warn("authentication failed",
			"auth_type", "api_key",
			"reason", "missing_or_malformed_credentials",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)
		w.Header().Set("WWW-Authenticate", `Basic realm="apk-registry", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return nil, false
	}
	identity, err := s.Authorizer.Authenticate(raw)
	if err != nil {
		s.Log.Warn("authentication failed",
			"auth_type", "api_key",
			"reason", "invalid_credentials",
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)
		w.Header().Set("WWW-Authenticate", `Basic realm="apk-registry", charset="UTF-8"`)
		http.Error(w, "invalid credential", http.StatusUnauthorized)
		return nil, false
	}
	return identity, true
}

func (s *Server) requireConfiguredRepository(w http.ResponseWriter, r *http.Request, repo string) bool {
	if repo != s.Config.Repository {
		http.NotFound(w, r)
		return false
	}
	return true
}

func bearer(r *http.Request) (string, error) {
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
		if token != "" {
			return token, nil
		}
	}
	if strings.HasPrefix(header, "Basic ") {
		raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(header, "Basic ")))
		if err == nil {
			_, token, ok := strings.Cut(string(raw), ":")
			if ok && strings.TrimSpace(token) != "" {
				return strings.TrimSpace(token), nil
			}
		}
	}
	return "", errors.New("missing bearer token")
}

func (s *Server) writeManagerError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errOverwriteDenied):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, errUnsupportedArchitecture):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, errPackageTooLarge):
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
	case errors.Is(err, errInvalidPackagePath):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, errInvalidAPK):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, os.ErrNotExist):
		http.NotFound(w, r)
	default:
		s.Log.Error("package operation failed", "error", err)
		http.Error(w, "package operation failed", http.StatusInternalServerError)
	}
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func logging(next http.Handler, log *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Info("request", "method", r.Method, "path", r.URL.Path, "duration", time.Since(start))
	})
}
