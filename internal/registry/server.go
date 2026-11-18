package registry

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
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
		w.Header().Set("WWW-Authenticate", `Basic realm="apk-registry-admin", charset="UTF-8"`)
		http.Error(w, "administrator credentials required", http.StatusUnauthorized)
		return false
	}
	return true
}

func (s *Server) readPackage(w http.ResponseWriter, r *http.Request) {
	repo, relative := r.PathValue("repo"), r.PathValue("path")
	if !s.requireConfiguredRepository(w, r, repo) {
		return
	}
	if !*s.Config.PublicRead {
		identity, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		if !s.Authorizer.Authorize(identity, "read") {
			http.Error(w, "read permission denied", http.StatusForbidden)
			return
		}
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
	case filename == "Packages.adb":
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	http.ServeContent(w, r, filename, time.Time{}, file)
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
		w.Header().Set("WWW-Authenticate", `Basic realm="apk-registry", charset="UTF-8"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return nil, false
	}
	identity, err := s.Authorizer.Authenticate(raw)
	if err != nil {
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
