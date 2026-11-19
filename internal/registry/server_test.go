package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	apkoapk "chainguard.dev/apko/pkg/apk/apk"
	"github.com/d4rkfella/apk-registry/internal/authz"
	"github.com/d4rkfella/apk-registry/internal/config"
)

func TestAdminScopedKeysAndAutomaticIndexing(t *testing.T) {
	root := t.TempDir()
	publicRead := true
	cfg := config.Config{
		StorageRoot:   root,
		Repository:    "os",
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
	startedPath := filepath.Join(t.TempDir(), "index-started")
	releasePath := filepath.Join(t.TempDir(), "release-index")
	cfg := config.Config{
		StorageRoot: root, Repository: "os",
		MaxUploadSize: 1 << 20,
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := NewManager(cfg, log)
	if err != nil {
		t.Fatal(err)
	}
	manager.indexer = indexerFunc(func(_ context.Context, packageDir, _, output, _ string) error {
		if _, err := os.Stat(startedPath); os.IsNotExist(err) {
			if err := os.WriteFile(startedPath, nil, 0600); err != nil {
				return err
			}
			for {
				if _, err := os.Stat(releasePath); err == nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		files, err := filepath.Glob(filepath.Join(packageDir, "*.apk"))
		if err != nil {
			return err
		}
		var entries strings.Builder
		for _, file := range files {
			fmt.Fprintln(&entries, filepath.Base(file))
		}
		return os.WriteFile(output, []byte(entries.String()), 0600)
	})
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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(t.TempDir(), "registry.rsa")
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(privateKeyPath, privatePEM, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		StorageRoot: root, Repository: "os",
		MaxUploadSize: 1 << 20,
		SigningKey:    privateKeyPath,
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
		index, err := readAPKIndex(indexPath)
		return err == nil && strings.Contains(index, "P:foo\n") && strings.Contains(index, "V:1.0-r0\n")
	})
	upload("bar")
	waitFor(t, "incremental index merge", func() bool {
		index, err := readAPKIndex(indexPath)
		return err == nil &&
			strings.Contains(index, "P:foo\n") &&
			strings.Contains(index, "P:bar\n")
	})
	upload("baz")
	waitFor(t, "cached incremental index merge", func() bool {
		index, err := readAPKIndex(indexPath)
		return err == nil &&
			strings.Contains(index, "P:foo\n") &&
			strings.Contains(index, "P:bar\n") &&
			strings.Contains(index, "P:baz\n")
	})
	indexFile, err := os.Open(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	signedIndex, indexErr := apkoapk.IndexFromArchive(indexFile)
	closeErr := indexFile.Close()
	if indexErr != nil {
		t.Fatalf("read cached signed APKINDEX: %v", indexErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if len(signedIndex.Signature) == 0 {
		t.Fatal("cached incremental index is not signed")
	}
	changedTime := time.Now().Add(time.Second)
	if err := os.Chtimes(indexPath, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	upload("qux")
	waitFor(t, "index reload after external file change", func() bool {
		index, err := readAPKIndex(indexPath)
		return err == nil &&
			strings.Contains(index, "P:foo\n") &&
			strings.Contains(index, "P:bar\n") &&
			strings.Contains(index, "P:baz\n") &&
			strings.Contains(index, "P:qux\n")
	})
	if err := manager.Delete(ctx, "os", "x86_64/bar-1.0-r0.apk"); err != nil {
		t.Fatalf("delete indexed package: %v", err)
	}
	waitFor(t, "full rebuild after deletion", func() bool {
		index, err := readAPKIndex(indexPath)
		return err == nil &&
			strings.Contains(index, "P:foo\n") &&
			!strings.Contains(index, "P:bar\n") &&
			strings.Contains(index, "P:baz\n") &&
			strings.Contains(index, "P:qux\n")
	})
	index, err := readAPKIndex(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(index, "P:foo\n") || strings.Contains(index, "P:bar\n") ||
		!strings.Contains(index, "P:baz\n") || !strings.Contains(index, "P:qux\n") {
		t.Fatal("index merge or full rebuild did not preserve the expected package records")
	}
}

func TestEmptyRepositoryIndexIsServedAndFirstPackageMerges(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		StorageRoot: root, Repository: "os",
		MaxUploadSize: 1 << 20,
	}
	manager, err := NewManager(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go manager.runIndexWorker(ctx)
	t.Cleanup(cancel)

	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	file, name, err := manager.Read(ctx, "os", "x86_64/APKINDEX.tar.gz")
	if err != nil {
		t.Fatalf("read empty repository index: %v", err)
	}
	file.Close()
	if name != "APKINDEX.tar.gz" {
		t.Fatalf("index filename = %q, want APKINDEX.tar.gz", name)
	}
	index, err := readAPKIndex(indexPath)
	if err != nil {
		t.Fatalf("read generated empty index: %v", err)
	}
	if strings.TrimSpace(index) != "" {
		t.Fatalf("new repository index contains package records: %q", index)
	}

	published, err := manager.buildAndPublishIndex(ctx, indexNamespace{arch: "x86_64"}, indexWork{full: true})
	if err != nil || !published {
		t.Fatalf("startup recovery of empty index = %v, %v; want published, nil", published, err)
	}
	if _, err := os.Stat(indexPath); err != nil {
		t.Fatalf("startup recovery removed the empty index: %v", err)
	}

	_, err = manager.Upload(
		ctx,
		"os",
		"x86_64/foo-1.0-r0.apk",
		false,
		bytes.NewReader(testAPK(t, "foo", "1.0-r0", "x86_64")),
	)
	if err != nil {
		t.Fatalf("upload first package to empty repository: %v", err)
	}
	waitFor(t, "first package merge into empty index", func() bool {
		index, err := readAPKIndex(indexPath)
		return err == nil && strings.Contains(index, "P:foo\n")
	})
}

func TestSigningKeyIsDiscoverableAndServedAtRepositoryRoot(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyPath := filepath.Join(t.TempDir(), "registry.rsa")
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(privateKeyPath, privatePEM, 0600); err != nil {
		t.Fatal(err)
	}

	publicRead := true
	cfg := config.Config{
		StorageRoot: t.TempDir(), Repository: "os", MaxUploadSize: 1 << 20,
		PublicRead: &publicRead, PublicURL: "https://packages.example.com",
		SigningKey: privateKeyPath,
	}
	manager, err := NewManager(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&Server{Config: cfg, Manager: manager}).Routes())
	defer server.Close()

	response := request(t, server.Client(), http.MethodGet, server.URL+"/os/apk-configuration", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("apk-configuration status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var discovery struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(response.Body).Decode(&discovery); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if discovery.JWKSURI != "https://packages.example.com/os/jwks.json" {
		t.Fatalf("jwks_uri = %q, want configured public URL", discovery.JWKSURI)
	}

	response = request(t, server.Client(), http.MethodGet, server.URL+"/os/jwks.json", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JWKS status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	var jwks struct {
		Keys []struct {
			KeyType  string `json:"kty"`
			KeyID    string `json:"kid"`
			Modulus  string `json:"n"`
			Exponent string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		response.Body.Close()
		t.Fatal(err)
	}
	response.Body.Close()
	if len(jwks.Keys) != 1 || jwks.Keys[0].KeyType != "RSA" ||
		jwks.Keys[0].KeyID != "registry" || jwks.Keys[0].Modulus == "" ||
		jwks.Keys[0].Exponent != "AQAB" {
		t.Fatalf("unexpected JWKS response: %+v", jwks)
	}

	response = request(t, server.Client(), http.MethodGet, server.URL+"/os/registry.rsa.pub", "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public key status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	publicPEM, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	publicBlock, _ := pem.Decode(publicPEM)
	if publicBlock == nil {
		t.Fatal("served public key is not PEM encoded")
	}
	parsedPublic, err := x509.ParsePKIXPublicKey(publicBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	servedKey, ok := parsedPublic.(*rsa.PublicKey)
	if !ok || servedKey.N.Cmp(privateKey.N) != 0 {
		t.Fatal("served public key does not match the configured private key")
	}
}

func TestUploadRejectsUnsupportedArchitecture(t *testing.T) {
	manager, err := NewManager(config.Config{
		StorageRoot: t.TempDir(), Repository: "os", MaxUploadSize: 1 << 20,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.Upload(
		context.Background(),
		"os",
		"sparc64/package-1.0-r0.apk",
		false,
		bytes.NewReader(testAPK(t, "package", "1.0-r0", "sparc64")),
	)
	if !errors.Is(err, errUnsupportedArchitecture) {
		t.Fatalf("upload error = %v, want unsupported architecture", err)
	}
}

func TestUploadRejectsAPKMetadataThatApkoCannotIndex(t *testing.T) {
	manager, err := NewManager(config.Config{
		StorageRoot: t.TempDir(), Repository: "os", MaxUploadSize: 1 << 20,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	info := []byte("pkgname = package\npkgver = 1.0-r0\narch = x86_64\npkgdesc = `first line\nsecond line`\n")
	_, err = manager.Upload(
		context.Background(),
		"os",
		"x86_64/package-1.0-r0.apk",
		false,
		bytes.NewReader(testAPKWithInfo(t, info)),
	)
	if !errors.Is(err, errInvalidAPK) {
		t.Fatalf("upload error = %v, want invalid APK metadata", err)
	}
}

func TestFailedAuthenticationIsLoggedWithoutCredentials(t *testing.T) {
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logOutput, nil))
	keys, err := authz.OpenTokenStore(filepath.Join(t.TempDir(), "api-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Authorizer: authz.New("admin", "expected-admin-password", keys),
		Keys:       keys,
		Log:        logger,
	}

	adminRequest := httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens", nil)
	if server.requireAdmin(httptest.NewRecorder(), adminRequest) {
		t.Fatal("missing admin credentials were accepted")
	}
	adminRequest = httptest.NewRequest(http.MethodGet, "/api/v1/admin/tokens", nil)
	adminRequest.SetBasicAuth("admin", "do-not-log-admin-password")
	if server.requireAdmin(httptest.NewRecorder(), adminRequest) {
		t.Fatal("invalid admin credentials were accepted")
	}

	apiKeyRequest := httptest.NewRequest(http.MethodPut, "/os/x86_64/package.apk", nil)
	apiKeyRequest.Header.Set("Authorization", "Bearer apk_do-not-log-api-key")
	if _, ok := server.authenticate(httptest.NewRecorder(), apiKeyRequest); ok {
		t.Fatal("invalid API key was accepted")
	}

	logs := logOutput.String()
	for _, expected := range []string{
		"authentication failed",
		"auth_type=admin_basic",
		"auth_type=api_key",
		"reason=missing_or_malformed_credentials",
		"reason=invalid_credentials",
	} {
		if !strings.Contains(logs, expected) {
			t.Errorf("authentication logs do not contain %q: %s", expected, logs)
		}
	}
	for _, secret := range []string{"do-not-log-admin-password", "apk_do-not-log-api-key"} {
		if strings.Contains(logs, secret) {
			t.Errorf("authentication logs exposed credential %q", secret)
		}
	}
}

type createdKey struct {
	ID        string     `json:"id"`
	Token     string     `json:"token"`
	ExpiresAt *time.Time `json:"expires_at"`
}

type indexerFunc func(context.Context, string, string, string, string) error

func (f indexerFunc) BuildV2Merge(ctx context.Context, packageDir, existing, output, arch string) error {
	return f(ctx, packageDir, existing, output, arch)
}

func readAPKIndex(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer gz.Close()

	tarReader := tar.NewReader(gz)
	for {
		header, err := tarReader.Next()
		if err != nil {
			return "", err
		}
		if header.Name == "APKINDEX" {
			data, err := io.ReadAll(tarReader)
			return string(data), err
		}
	}
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
	return testAPKWithInfo(t, []byte("pkgname = "+name+"\npkgver = "+version+"\narch = "+arch+"\n"))
}

func testAPKWithInfo(t *testing.T, info []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	compressed := gzip.NewWriter(&buffer)
	archive := tar.NewWriter(compressed)
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
