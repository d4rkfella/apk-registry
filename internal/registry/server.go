package registry

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/d4rkfella/apk-registry/internal/authz"
	"github.com/d4rkfella/apk-registry/internal/config"
	"github.com/felixge/httpsnoop"
)

type Server struct {
	Config     config.Config
	Manager    *Manager
	Authorizer *authz.Authorizer
	Keys       *authz.TokenStore
	Log        *slog.Logger
	ready      atomic.Bool
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
	metrics := s.metricsCollector()
	mux := http.NewServeMux()
	register := func(pattern string, handler http.Handler) {
		_, route, _ := strings.Cut(pattern, " ")
		mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if info, ok := r.Context().Value(requestInfoContextKey{}).(*requestInfo); ok {
				info.route = route
			}
			handler.ServeHTTP(w, r)
		}))
	}
	register("GET /healthz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
	}))
	register("GET /readyz", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready.Load() {
			jsonResponse(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "ready"})
	}))
	register("GET /api/v1/admin/tokens", http.HandlerFunc(s.listAPIKeys))
	register("POST /api/v1/admin/tokens", http.HandlerFunc(s.createAPIKey))
	register("DELETE /api/v1/admin/tokens/{id}", http.HandlerFunc(s.revokeAPIKey))
	register("GET /{repo}/apk-configuration", http.HandlerFunc(s.apkConfiguration))
	register("GET /{repo}/jwks.json", http.HandlerFunc(s.jwks))
	register("GET /{repo}/{filename}", http.HandlerFunc(s.readSigningPublicKey))
	register("GET /{repo}/{path...}", http.HandlerFunc(s.readPackage))
	register("PUT /{repo}/{path...}", http.HandlerFunc(s.uploadPackage))
	register("DELETE /{repo}/{path...}", http.HandlerFunc(s.deletePackage))
	return logging(mux, s.Log, metrics)
}

// MetricsHandler serves Prometheus metrics on a dedicated HTTP listener.
func (s *Server) MetricsHandler() http.Handler {
	if s.Log == nil {
		s.Log = slog.Default()
	}
	metrics := s.metricsCollector()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if s.Config.MetricsAuthEnabled {
			identity, ok := s.authenticate(w, r)
			if !ok {
				return
			}
			if !s.Authorizer.Authorize(identity, "metrics") {
				http.Error(w, "metrics permission required", http.StatusForbidden)
				return
			}
		}
		metrics.handler().ServeHTTP(w, r)
	})
	return logging(mux, s.Log, metrics)
}

func (s *Server) metricsCollector() *registryMetrics {
	if s.Manager == nil {
		return newRegistryMetrics()
	}
	if s.Manager.metrics == nil {
		s.Manager.metrics = newRegistryMetrics()
	}
	return s.Manager.metrics
}

// SetReady controls whether the readiness endpoint reports the server ready.
func (s *Server) SetReady(ready bool) {
	s.ready.Store(ready)
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
	switch {
	case strings.HasSuffix(filename, ".apk"):
		w.Header().Set("Content-Type", "application/vnd.alpine.apk")
	case filename == "APKINDEX.tar.gz":
		w.Header().Set("Content-Type", "application/gzip")
	}
	http.ServeContent(w, r, filename, time.Time{}, file)
	if err := file.Close(); err != nil {
		s.Log.Error("close package file", "repository", repo, "filename", filename, "error", err)
	}
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

type requestInfoContextKey struct{}

type requestInfo struct {
	route string
}

func logging(next http.Handler, log *slog.Logger, metrics *registryMetrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		requestID, err := newRequestID()
		if err != nil {
			log.Error("generate request ID", "error", err)
		} else {
			w.Header().Set("X-Request-ID", requestID)
		}
		info := &requestInfo{route: "unmatched"}
		r = r.WithContext(context.WithValue(r.Context(), requestInfoContextKey{}, info))
		result := httpsnoop.CaptureMetrics(next, w, r)
		duration := time.Since(start)
		status := result.Code
		if status == 0 {
			status = http.StatusOK
		}
		if metrics != nil {
			metrics.observeRequest(r.Method, info.route, status, duration)
		}
		attrs := []any{
			"method", r.Method,
			"route", info.route,
			"status", status,
			"duration_ms", float64(duration.Microseconds()) / 1000,
			"response_bytes", result.Written,
		}
		if requestID != "" {
			attrs = append(attrs, "request_id", requestID)
		}
		if status >= http.StatusInternalServerError {
			log.Error("HTTP request failed", attrs...)
		} else {
			log.Info("HTTP request completed", attrs...)
		}
	})
}

func newRequestID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}
