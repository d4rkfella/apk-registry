package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/d4rkfella/apk-registry/internal/authz"
	"github.com/d4rkfella/apk-registry/internal/config"
)

func TestAdminScopedKeysAndAutomaticIndexing(t *testing.T) {
	root := t.TempDir()
	indexer := filepath.Join(t.TempDir(), "apk")
	script := "#!/bin/sh\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then\n    shift\n    printf index > \"$1\"\n    exit 0\n  fi\n  shift\ndone\nexit 1\n"
	if err := os.WriteFile(indexer, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	publicRead := true
	cfg := config.Config{
		StorageRoot:   root,
		Repository:    "os",
		IndexFormat:   "v2",
		APKBinary:     indexer,
		MaxUploadSize: 1 << 20,
		AdminUsername: "admin",
		AdminPassword: "a-long-test-password",
		PublicRead:    &publicRead,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := NewManager(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	manager.Start(workerCtx)
	t.Cleanup(cancelWorker)
	keys, err := authz.OpenTokenStore(manager.PrivateStatePath())
	if err != nil {
		t.Fatal(err)
	}
	handler := (&Server{
		Config: cfg, Manager: manager, Authorizer: authz.New(cfg.AdminUsername, cfg.AdminPassword, keys),
		Keys: keys, Log: log,
	}).Routes()
	server := httptest.NewServer(handler)
	defer server.Close()

	response := request(t, server.Client(), http.MethodPost, server.URL+"/api/v1/admin/tokens", "", []byte(`{"name":"ci","permissions":["deploy"]}`))
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated key creation status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	response.Body.Close()
	response = requestAdmin(t, server.Client(), http.MethodPost, server.URL+"/api/v1/admin/tokens", []byte(`{"name":"ci","permissions":["deploy"]}`), false)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid admin credentials status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	response.Body.Close()

	deployKey := createKey(t, server.Client(), server.URL, "ci", []string{"deploy"})
	maintainerKey := createKey(t, server.Client(), server.URL, "manual", []string{"read", "deploy", "delete"})
	if deployKey.Token == "" || maintainerKey.Token == "" || deployKey.ID == maintainerKey.ID {
		t.Fatal("admin API did not create distinct one-time API keys")
	}
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	expiringKey := createKeyWithExpiration(t, server.Client(), server.URL, "short-lived", []string{"deploy"}, expiresAt)
	if expiringKey.ExpiresAt == nil || !expiringKey.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("API key expiration = %v, want %v", expiringKey.ExpiresAt, expiresAt)
	}
	expiredRequest, err := json.Marshal(map[string]any{
		"name": "already-expired", "permissions": []string{"deploy"},
		"expires_at": time.Now().UTC().Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	response = requestAdmin(t, server.Client(), http.MethodPost, server.URL+"/api/v1/admin/tokens", expiredRequest, true)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("past API key expiration status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	response.Body.Close()
	list := requestAdmin(t, server.Client(), http.MethodGet, server.URL+"/api/v1/admin/tokens", nil, true)
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list API keys status = %d, want %d", list.StatusCode, http.StatusOK)
	}
	listBody, err := io.ReadAll(list.Body)
	list.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(listBody, []byte(deployKey.Token)) || bytes.Contains(listBody, []byte(maintainerKey.Token)) {
		t.Fatal("list API keys exposed a plaintext token")
	}
	storeInfo, err := os.Stat(manager.PrivateStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if storeInfo.Mode().Perm() != 0600 {
		t.Fatalf("API key store permissions = %04o, want 0600", storeInfo.Mode().Perm())
	}

	reopened, err := authz.OpenTokenStore(manager.PrivateStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Authenticate(deployKey.Token); err != nil {
		t.Fatalf("persisted API key did not authenticate after reopening store: %v", err)
	}

	const packageURL = "/os/x86_64/foo-1.0-r0.apk"
	body := testAPK(t, "foo", "1.0-r0", "x86_64")
	response = request(t, server.Client(), http.MethodPut, server.URL+"/other/x86_64/foo-1.0-r0.apk", deployKey.Token, body)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("non-configured repository status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	response.Body.Close()
	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, "", body)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	response.Body.Close()
	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, deployKey.Token, body)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("new upload status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	response.Body.Close()
	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	waitFor(t, "package index generation", func() bool {
		_, err := os.Stat(indexPath)
		return err == nil
	})
	privateFile := filepath.Join(filepath.Dir(indexPath), ".internal-private")
	if err := os.WriteFile(privateFile, body, 0600); err != nil {
		t.Fatal(err)
	}
	response = request(t, server.Client(), http.MethodGet, server.URL+"/os/x86_64/.internal-private", "", nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("download of a non-package file status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	response.Body.Close()
	if err := os.Remove(privateFile); err != nil {
		t.Fatal(err)
	}

	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public download status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	readBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(readBody, body) {
		t.Fatalf("downloaded APK differs from uploaded APK: %v", err)
	}

	publicRead = false
	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, "", nil)
	challenge := response.Header.Get("WWW-Authenticate")
	if response.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(challenge, "Basic ") {
		t.Fatalf("private download without credentials status/challenge = %d/%q, want 401 and a Basic challenge", response.StatusCode, challenge)
	}
	response.Body.Close()
	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, deployKey.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("private download without read scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	response.Body.Close()
	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, maintainerKey.Token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("private download with read scope status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	response.Body.Close()
	response = requestBasicToken(t, server.Client(), server.URL+packageURL, maintainerKey.Token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("private download with Basic API-key credentials status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	response.Body.Close()
	publicRead = true

	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, deployKey.Token, body)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("overwrite without delete scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	response.Body.Close()
	response = request(t, server.Client(), http.MethodDelete, server.URL+packageURL, deployKey.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	response.Body.Close()

	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, maintainerKey.Token, body)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("overwrite with delete scope status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	response.Body.Close()
	response = request(t, server.Client(), http.MethodDelete, server.URL+packageURL, maintainerKey.Token, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete with scope status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	response.Body.Close()
	waitFor(t, "empty package index removal", func() bool {
		_, err := os.Stat(indexPath)
		return os.IsNotExist(err)
	})

	response = requestAdmin(t, server.Client(), http.MethodDelete, server.URL+"/api/v1/admin/tokens/"+deployKey.ID, nil, true)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke API key status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	response.Body.Close()
	if _, err := keys.Authenticate(deployKey.Token); err == nil {
		t.Fatal("revoked API key still authenticated")
	}
}

func TestIndexingDoesNotBlockConcurrentUploadsAndPublishesLatestSnapshot(t *testing.T) {
	root := t.TempDir()
	indexer := filepath.Join(t.TempDir(), "apk")
	startedPath := filepath.Join(t.TempDir(), "index-started")
	releasePath := filepath.Join(t.TempDir(), "release-index")
	script := fmt.Sprintf("#!/bin/sh\nargs=\"$*\"\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then\n    shift\n    output=\"$1\"\n  fi\n  shift\ndone\nif [ ! -e %q ]; then\n  : > %q\n  while [ ! -e %q ]; do sleep 0.01; done\nfi\nprintf '%%s\\\\n' \"$args\" > \"$output\"\n", startedPath, startedPath, releasePath)
	if err := os.WriteFile(indexer, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		StorageRoot: root, Repository: "os",
		IndexFormat: "v2", APKBinary: indexer, MaxUploadSize: 1 << 20,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := NewManager(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	manager.Start(workerCtx)
	t.Cleanup(cancelWorker)
	t.Cleanup(func() { _ = os.WriteFile(releasePath, nil, 0600) })

	bodies := map[string][]byte{
		"foo": testAPK(t, "foo", "1.0-r0", "x86_64"),
		"bar": testAPK(t, "bar", "1.0-r0", "x86_64"),
		"baz": testAPK(t, "baz", "1.0-r0", "x86_64"),
	}
	upload := func(name string) error {
		relative := "x86_64/" + name + "-1.0-r0.apk"
		_, err := manager.Upload(context.Background(), "os", relative, false, bytes.NewReader(bodies[name]))
		return err
	}
	if err := upload("foo"); err != nil {
		t.Fatalf("initial upload: %v", err)
	}
	waitFor(t, "indexer start", func() bool {
		_, err := os.Stat(startedPath)
		return err == nil
	})

	results := make(chan error, 2)
	go func() { results <- upload("bar") }()
	go func() { results <- upload("baz") }()
	for range 2 {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent upload: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("upload waited for index generation to finish")
		}
	}

	if err := os.WriteFile(releasePath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	waitFor(t, "latest index snapshot", func() bool {
		index, err := os.ReadFile(indexPath)
		return err == nil &&
			strings.Contains(string(index), "foo-1.0-r0.apk") &&
			strings.Contains(string(index), "bar-1.0-r0.apk") &&
			strings.Contains(string(index), "baz-1.0-r0.apk")
	})
}

func TestV2NewPackageMergesIntoCurrentIndex(t *testing.T) {
	root := t.TempDir()
	indexer := filepath.Join(t.TempDir(), "apk")
	script := "#!/bin/sh\nargs=\"$*\"\noutput=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then\n    shift\n    output=\"$1\"\n  fi\n  shift\ndone\nprintf '%s\\n' \"$args\" > \"$output\"\n"
	if err := os.WriteFile(indexer, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		StorageRoot: root, Repository: "os",
		IndexFormat: "v2", APKBinary: indexer, MaxUploadSize: 1 << 20,
	}
	manager, err := NewManager(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go manager.runIndexWorker(ctx)
	t.Cleanup(cancel)

	upload := func(name string) {
		t.Helper()
		relative := "x86_64/" + name + "-1.0-r0.apk"
		_, err := manager.Upload(ctx, "os", relative, false, bytes.NewReader(testAPK(t, name, "1.0-r0", "x86_64")))
		if err != nil {
			t.Fatalf("upload %s: %v", name, err)
		}
	}
	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	upload("foo")
	waitFor(t, "initial full index", func() bool {
		index, err := os.ReadFile(indexPath)
		return err == nil && !strings.Contains(string(index), "--merge") && strings.Contains(string(index), "foo-1.0-r0.apk")
	})
	upload("bar")
	waitFor(t, "incremental index merge", func() bool {
		index, err := os.ReadFile(indexPath)
		return err == nil &&
			strings.Contains(string(index), "--merge --index "+indexPath) &&
			strings.Contains(string(index), "bar-1.0-r0.apk")
	})
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(index), "foo-1.0-r0.apk") {
		t.Fatal("incremental merge unnecessarily included previously indexed package files")
	}
}

type createdKey struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func createKey(t *testing.T, client *http.Client, baseURL, name string, permissions []string) createdKey {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "permissions": permissions})
	if err != nil {
		t.Fatal(err)
	}
	response := requestAdmin(t, client, http.MethodPost, baseURL+"/api/v1/admin/tokens", body, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		responseBody, _ := io.ReadAll(response.Body)
		t.Fatalf("create API key status = %d, want %d: %s", response.StatusCode, http.StatusCreated, responseBody)
	}
	var key createdKey
	if err := json.NewDecoder(response.Body).Decode(&key); err != nil {
		t.Fatal(err)
	}
	return key
}

func createKeyWithExpiration(t *testing.T, client *http.Client, baseURL, name string, permissions []string, expiresAt time.Time) createdKey {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name": name, "permissions": permissions, "expires_at": expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := requestAdmin(t, client, http.MethodPost, baseURL+"/api/v1/admin/tokens", body, true)
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		responseBody, _ := io.ReadAll(response.Body)
		t.Fatalf("create expiring API key status = %d, want %d: %s", response.StatusCode, http.StatusCreated, responseBody)
	}
	var key createdKey
	if err := json.NewDecoder(response.Body).Decode(&key); err != nil {
		t.Fatal(err)
	}
	return key
}

func request(t *testing.T, client *http.Client, method, url, token string, body []byte) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requestBasicToken(t *testing.T, client *http.Client, url, token string) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth("token", token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func requestAdmin(t *testing.T, client *http.Client, method, url string, body []byte, valid bool) *http.Response {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if valid {
		request.SetBasicAuth("admin", "a-long-test-password")
	} else {
		request.SetBasicAuth("admin", "wrong-password")
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func testAPK(t *testing.T, name, version, arch string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
	info := []byte("pkgname = " + name + "\npkgver = " + version + "\narch = " + arch + "\n")
	if err := archive.WriteHeader(&tar.Header{Name: ".PKGINFO", Mode: 0644, Size: int64(len(info))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(info); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}
