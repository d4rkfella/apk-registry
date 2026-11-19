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
	"sync/atomic"
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
	t.Cleanup(func() {
		cancelWorker()
		manager.Wait()
	})
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
	closeResponseBody(t, response.Body)
	response = requestAdmin(t, server.Client(), http.MethodPost, server.URL+"/api/v1/admin/tokens", []byte(`{"name":"ci","permissions":["deploy"]}`), false)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("invalid admin credentials status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	closeResponseBody(t, response.Body)

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
	closeResponseBody(t, response.Body)
	list := requestAdmin(t, server.Client(), http.MethodGet, server.URL+"/api/v1/admin/tokens", nil, true)
	if list.StatusCode != http.StatusOK {
		t.Fatalf("list API keys status = %d, want %d", list.StatusCode, http.StatusOK)
	}
	listBody, err := io.ReadAll(list.Body)
	closeResponseBody(t, list.Body)
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
	closeResponseBody(t, response.Body)
	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, "", body)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}
	closeResponseBody(t, response.Body)
	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, deployKey.Token, body)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("new upload status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	closeResponseBody(t, response.Body)
	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	waitFor(t, "package index generation", func() bool {
		_, err := os.Stat(indexPath)
		return err == nil
	})
	indexURL := server.URL + "/os/x86_64/APKINDEX.tar.gz"
	response = request(t, server.Client(), http.MethodGet, indexURL, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("index download status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	lastModified := response.Header.Get("Last-Modified")
	if lastModified == "" {
		t.Fatal("index response has no Last-Modified header")
	}
	etag := response.Header.Get("ETag")
	if etag == "" {
		t.Fatal("index response has no ETag")
	}
	closeResponseBody(t, response.Body)
	headRequest, err := http.NewRequest(http.MethodHead, indexURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = server.Client().Do(headRequest)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusOK || response.Header.Get("ETag") != etag {
		t.Fatalf("index HEAD status/ETag = %d/%q, want %d/%q", response.StatusCode, response.Header.Get("ETag"), http.StatusOK, etag)
	}

	conditionalRequest, err := http.NewRequest(http.MethodGet, indexURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	conditionalRequest.Header.Set("If-None-Match", etag)
	response, err = server.Client().Do(conditionalRequest)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional index request status = %d, want %d", response.StatusCode, http.StatusNotModified)
	}
	conditionalRequest, err = http.NewRequest(http.MethodGet, indexURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	conditionalRequest.Header.Set("If-Modified-Since", lastModified)
	response, err = server.Client().Do(conditionalRequest)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional index request status = %d, want %d", response.StatusCode, http.StatusNotModified)
	}

	privateFile := filepath.Join(filepath.Dir(indexPath), ".internal-private")
	if err := os.WriteFile(privateFile, body, 0600); err != nil {
		t.Fatal(err)
	}
	response = request(t, server.Client(), http.MethodGet, server.URL+"/os/x86_64/.internal-private", "", nil)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("download of a non-package file status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
	closeResponseBody(t, response.Body)
	if err := os.Remove(privateFile); err != nil {
		t.Fatal(err)
	}

	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, "", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("public download status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	readBody, err := io.ReadAll(response.Body)
	closeResponseBody(t, response.Body)
	if err != nil || !bytes.Equal(readBody, body) {
		t.Fatalf("downloaded APK differs from uploaded APK: %v", err)
	}

	publicRead = false
	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, "", nil)
	challenge := response.Header.Get("WWW-Authenticate")
	if response.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(challenge, "Basic ") {
		t.Fatalf("private download without credentials status/challenge = %d/%q, want 401 and a Basic challenge", response.StatusCode, challenge)
	}
	closeResponseBody(t, response.Body)
	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, deployKey.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("private download without read scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	closeResponseBody(t, response.Body)
	response = request(t, server.Client(), http.MethodGet, server.URL+packageURL, maintainerKey.Token, nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("private download with read scope status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	closeResponseBody(t, response.Body)
	response = requestBasicToken(t, server.Client(), server.URL+packageURL, maintainerKey.Token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("private download with Basic API-key credentials status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	closeResponseBody(t, response.Body)
	publicRead = true

	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, deployKey.Token, body)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("overwrite without delete scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	closeResponseBody(t, response.Body)
	response = request(t, server.Client(), http.MethodDelete, server.URL+packageURL, deployKey.Token, nil)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without scope status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
	closeResponseBody(t, response.Body)

	response = request(t, server.Client(), http.MethodPut, server.URL+packageURL, maintainerKey.Token, body)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("overwrite with delete scope status = %d, want %d", response.StatusCode, http.StatusCreated)
	}
	closeResponseBody(t, response.Body)
	response = request(t, server.Client(), http.MethodDelete, server.URL+packageURL, maintainerKey.Token, nil)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("delete with scope status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	closeResponseBody(t, response.Body)
	waitFor(t, "empty package index removal", func() bool {
		_, err := os.Stat(indexPath)
		return os.IsNotExist(err)
	})

	response = requestAdmin(t, server.Client(), http.MethodDelete, server.URL+"/api/v1/admin/tokens/"+deployKey.ID, nil, true)
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke API key status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	closeResponseBody(t, response.Body)
	if _, err := keys.Authenticate(deployKey.Token); err == nil {
		t.Fatal("revoked API key still authenticated")
	}
}

func TestApkoCachesIndexUsingETag(t *testing.T) {
	root := t.TempDir()
	publicRead := true
	cfg := config.Config{
		StorageRoot: root, Repository: "os", PublicRead: &publicRead,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager, err := NewManager(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	file, _, err := manager.Read(context.Background(), "os", "x86_64/APKINDEX.tar.gz")
	if err != nil {
		t.Fatalf("create empty index: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	var headRequests, getRequests atomic.Int64
	routes := (&Server{Config: cfg, Manager: manager, Log: logger}).Routes()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/os/x86_64/APKINDEX.tar.gz" {
			switch r.Method {
			case http.MethodHead:
				headRequests.Add(1)
			case http.MethodGet:
				getRequests.Add(1)
			}
		}
		routes.ServeHTTP(w, r)
	})
	server := httptest.NewServer(handler)
	defer server.Close()

	repositoryURL := server.URL + "/os"
	getIndexes := func() {
		t.Helper()
		indexes, err := apkoapk.GetRepositoryIndexes(
			context.Background(), []string{repositoryURL}, nil, "x86_64",
			apkoapk.WithIgnoreSignatures(true),
			apkoapk.WithHTTPClient(server.Client()),
		)
		if err != nil {
			t.Fatalf("apko fetch repository index: %v", err)
		}
		if len(indexes) != 1 {
			t.Fatalf("apko returned %d indexes, want 1", len(indexes))
		}
	}

	getIndexes()
	getIndexes()
	if got := getRequests.Load(); got != 1 {
		t.Fatalf("apko made %d index GET requests for an unchanged index, want 1", got)
	}
	if got := headRequests.Load(); got != 2 {
		t.Fatalf("apko made %d index HEAD requests, want 2", got)
	}

	changedArchive, err := apkoapk.ArchiveFromIndex(&apkoapk.APKIndex{Description: "changed index"})
	if err != nil {
		t.Fatalf("create changed index archive: %v", err)
	}
	changedIndex, err := io.ReadAll(changedArchive)
	if err != nil {
		t.Fatalf("read changed index archive: %v", err)
	}
	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	if err := os.WriteFile(indexPath, changedIndex, 0644); err != nil {
		t.Fatalf("replace index: %v", err)
	}

	getIndexes()
	if got := getRequests.Load(); got != 2 {
		t.Fatalf("apko made %d index GET requests after the index changed, want 2", got)
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
	t.Cleanup(func() {
		cancelWorker()
		manager.Wait()
	})
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
	if err := file.Close(); err != nil {
		t.Fatalf("close generated empty index: %v", err)
	}
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

func TestStartupRecoverySignsExistingEmptyIndex(t *testing.T) {
	root := t.TempDir()
	cfg := config.Config{
		StorageRoot: root, Repository: "os",
		MaxUploadSize: 1 << 20,
	}
	unsignedManager, err := NewManager(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	indexPath := filepath.Join(root, "os", "x86_64", "APKINDEX.tar.gz")
	file, _, err := unsignedManager.Read(ctx, "os", "x86_64/APKINDEX.tar.gz")
	if err != nil {
		t.Fatalf("create existing empty index: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close existing empty index: %v", err)
	}

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
	cfg.SigningKey = privateKeyPath
	signedManager, err := NewManager(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	published, err := signedManager.buildAndPublishIndex(ctx, indexNamespace{arch: "x86_64"}, indexWork{full: true})
	if err != nil || !published {
		t.Fatalf("startup recovery of empty index = %v, %v; want published, nil", published, err)
	}
	indexFile, err := os.Open(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	index, indexErr := apkoapk.IndexFromArchive(indexFile)
	closeErr := indexFile.Close()
	if indexErr != nil {
		t.Fatalf("read signed empty APKINDEX: %v", indexErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if len(index.Packages) != 0 {
		t.Fatalf("recovered empty index contains %d packages, want 0", len(index.Packages))
	}
	if len(index.Signature) == 0 {
		t.Fatal("startup recovery did not sign the existing empty index")
	}
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
		closeResponseBody(t, response.Body)
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
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
		closeResponseBody(t, response.Body)
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
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
	closeResponseBody(t, response.Body)
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

func TestRequestLoggingAndMetrics(t *testing.T) {
	var logOutput bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
	cfg := config.Config{
		StorageRoot: t.TempDir(), Repository: "os", MaxUploadSize: 1 << 20,
		AdminUsername: "metrics-admin", AdminPassword: "metrics-admin-password",
		MetricsAuthEnabled: true,
	}
	manager, err := NewManager(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := authz.OpenTokenStore(manager.PrivateStatePath())
	if err != nil {
		t.Fatal(err)
	}
	app := &Server{
		Config: cfg, Manager: manager,
		Authorizer: authz.New(cfg.AdminUsername, cfg.AdminPassword, keys),
		Keys:       keys,
		Log:        logger,
	}
	server := httptest.NewServer(app.Routes())
	defer server.Close()
	metricsServer := httptest.NewServer(app.MetricsHandler())
	defer metricsServer.Close()

	response, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if response.Header.Get("X-Request-ID") == "" {
		t.Fatal("health response has no request ID")
	}
	var requestLog map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logOutput.Bytes()), &requestLog); err != nil {
		t.Fatalf("decode request log: %v", err)
	}
	if requestLog["msg"] != "HTTP request completed" ||
		requestLog["route"] != "/healthz" ||
		requestLog["path"] != "/healthz" ||
		requestLog["status"] != float64(http.StatusOK) ||
		requestLog["request_id"] != response.Header.Get("X-Request-ID") {
		t.Fatalf("request log is missing expected fields: %v", requestLog)
	}

	response, err = server.Client().Get(server.URL + "/no-such-route?secret=query-value")
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}
	if !strings.Contains(logOutput.String(), `"path":"/no-such-route"`) {
		t.Fatal("request log does not include the concrete path for an unmatched route")
	}
	if strings.Contains(logOutput.String(), "query-value") {
		t.Fatal("request log includes a query string")
	}

	response, err = server.Client().Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("application listener /metrics status = %d, want %d", response.StatusCode, http.StatusNotFound)
	}

	response, err = server.Client().Get(metricsServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}

	_, metricsToken, err := keys.Create("prometheus", []string{"metrics"}, nil)
	if err != nil {
		t.Fatalf("create metrics-only API key: %v", err)
	}
	_, deployToken, err := keys.Create("deployer", []string{"deploy"}, nil)
	if err != nil {
		t.Fatalf("create deploy-only API key: %v", err)
	}

	request, err := http.NewRequest(http.MethodGet, metricsServer.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+metricsToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	metrics, readErr := io.ReadAll(response.Body)
	closeResponseBody(t, response.Body)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if !bytes.Contains(metrics, []byte(`apk_registry_http_requests_total{method="GET",route="/healthz",status="200"} 1`)) {
		t.Fatalf("metrics do not include the health request: %s", metrics)
	}
	if !strings.Contains(logOutput.String(), `"route":"/metrics"`) {
		t.Fatal("metrics listener request log does not include the /metrics route")
	}

	request, err = http.NewRequest(http.MethodGet, metricsServer.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+deployToken)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("deploy-only metrics status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}

	request, err = http.NewRequest(http.MethodGet, metricsServer.URL+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.SetBasicAuth(cfg.AdminUsername, cfg.AdminPassword)
	response, err = server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin Basic credentials metrics status = %d, want %d", response.StatusCode, http.StatusUnauthorized)
	}

	app.Config.MetricsAuthEnabled = false
	response, err = server.Client().Get(metricsServer.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	closeResponseBody(t, response.Body)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status with auth disabled = %d, want %d", response.StatusCode, http.StatusOK)
	}
}

func TestReadinessEndpointTracksShutdownState(t *testing.T) {
	server := &Server{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	handler := server.Routes()

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("initial readiness status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	server.SetReady(true)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ready status = %d, want %d", response.Code, http.StatusOK)
	}

	server.SetReady(false)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("shutdown readiness status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("liveness status = %d, want %d while unready", response.Code, http.StatusOK)
	}
}

func TestManagerWaitStopsStartedWorkers(t *testing.T) {
	manager, err := NewManager(config.Config{
		StorageRoot: t.TempDir(), Repository: "os", MaxUploadSize: 1 << 20,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	manager.Start(ctx)
	cancel()

	done := make(chan struct{})
	go func() {
		manager.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("manager workers did not stop after context cancellation")
	}
}

func TestIndexBuildMetrics(t *testing.T) {
	root := t.TempDir()
	packageDir := filepath.Join(root, "os", "x86_64")
	if err := os.MkdirAll(packageDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "foo.apk"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{
		root:      root,
		repo:      "os",
		indexName: "APKINDEX.tar.gz",
		indexer: indexerFunc(func(_ context.Context, _, _, output, _ string) error {
			return os.WriteFile(output, []byte("index"), 0644)
		}),
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:  newRegistryMetrics(),
		states:   make(map[indexNamespace]*namespaceState),
		pending:  make(map[indexNamespace]indexWork),
		retrying: make(map[indexNamespace]indexRetry),
		wake:     make(chan struct{}, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		manager.runIndexWorker(ctx)
		close(done)
	}()
	manager.enqueueIndex(indexNamespace{arch: "x86_64"})
	metricHandler := manager.metrics.handler()
	waitFor(t, "successful index build metric", func() bool {
		recorder := httptest.NewRecorder()
		metricHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return bytes.Contains(recorder.Body.Bytes(), []byte(`apk_registry_index_builds_total{architecture="x86_64",outcome="success"} 1`))
	})
	cancel()
	<-done

	recorder := httptest.NewRecorder()
	metricHandler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !bytes.Contains(recorder.Body.Bytes(), []byte(`apk_registry_index_builds_total{architecture="x86_64",outcome="success"} 1`)) {
		t.Fatalf("metrics do not include the successful index build: %s", recorder.Body.String())
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

func TestUploadEnforcesSizeLimitAndRemovesPartialFile(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(config.Config{
		StorageRoot: root, Repository: "os", MaxUploadSize: 16,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.Upload(
		context.Background(),
		"os",
		"x86_64/package-1.0-r0.apk",
		false,
		bytes.NewReader(bytes.Repeat([]byte("x"), 17)),
	)
	if !errors.Is(err, errPackageTooLarge) {
		t.Fatalf("oversized upload error = %v, want package-too-large", err)
	}

	packageDir := filepath.Join(root, "os", "x86_64")
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("oversized upload left files in package directory: %v", entries)
	}
}

func TestUploadRejectsUnsafePathsAndSymlinkedDirectories(t *testing.T) {
	root := t.TempDir()
	manager, err := NewManager(config.Config{
		StorageRoot: root, Repository: "os", MaxUploadSize: 1 << 20,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}

	_, err = manager.Upload(
		context.Background(),
		"os",
		"../escape-1.0-r0.apk",
		false,
		bytes.NewReader(testAPK(t, "escape", "1.0-r0", "x86_64")),
	)
	if !errors.Is(err, errInvalidPackagePath) {
		t.Fatalf("traversal upload error = %v, want invalid package path", err)
	}

	repositoryDir := filepath.Join(root, "os")
	if err := os.MkdirAll(repositoryDir, 0755); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()
	if err := os.Symlink(outsideDir, filepath.Join(repositoryDir, "x86_64")); err != nil {
		t.Skipf("create symlink for path-safety test: %v", err)
	}
	_, err = manager.Upload(
		context.Background(),
		"os",
		"x86_64/package-1.0-r0.apk",
		false,
		bytes.NewReader(testAPK(t, "package", "1.0-r0", "x86_64")),
	)
	if err == nil || !strings.Contains(err.Error(), "symbolic links are not allowed") {
		t.Fatalf("upload through a symlinked package directory error = %v, want symlink rejection", err)
	}
	entries, err := os.ReadDir(outsideDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("symlinked upload wrote outside the storage root: %v", entries)
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

func readAPKIndex(filename string) (_ string, retErr error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close APK index file: %w", err))
		}
	}()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := gz.Close(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close APK index gzip reader: %w", err))
		}
	}()

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

func closeResponseBody(t *testing.T, body io.Closer) {
	t.Helper()
	if err := body.Close(); err != nil {
		t.Errorf("close HTTP response body: %v", err)
	}
}

func createKey(t *testing.T, client *http.Client, baseURL, name string, permissions []string) createdKey {
	t.Helper()
	body, err := json.Marshal(map[string]any{"name": name, "permissions": permissions})
	if err != nil {
		t.Fatal(err)
	}
	response := requestAdmin(t, client, http.MethodPost, baseURL+"/api/v1/admin/tokens", body, true)
	defer closeResponseBody(t, response.Body)
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
	defer closeResponseBody(t, response.Body)
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
