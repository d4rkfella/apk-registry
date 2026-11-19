package config

import (
	"strings"
	"testing"
)

func TestLoadUsesEnvironmentAndDefaults(t *testing.T) {
	t.Setenv("REGISTRY_ADMIN_USERNAME", "admin")
	t.Setenv("REGISTRY_ADMIN_PASSWORD", "long-enough-test-password")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("STORAGE_ROOT", t.TempDir())
	t.Setenv("REGISTRY_REPOSITORY", "")
	t.Setenv("REGISTRY_PUBLIC_URL", "https://packages.example.com")
	t.Setenv("REGISTRY_PUBLIC_READ", "false")
	t.Setenv("APK_INDEX_FORMAT", "v2")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MaxUploadSize <= 0 {
		t.Fatalf("defaults were not applied: %+v", cfg)
	}
	if cfg.Repository != "os" {
		t.Fatalf("default repository = %q, want os", cfg.Repository)
	}
	if cfg.PublicURL != "https://packages.example.com" {
		t.Fatalf("public URL = %q, want https://packages.example.com", cfg.PublicURL)
	}
	if cfg.PublicRead == nil || *cfg.PublicRead {
		t.Fatal("REGISTRY_PUBLIC_READ=false was not applied")
	}
}

func TestLoadRejectsRemovedIndexFormat(t *testing.T) {
	t.Setenv("REGISTRY_ADMIN_USERNAME", "admin")
	t.Setenv("REGISTRY_ADMIN_PASSWORD", "long-enough-test-password")
	t.Setenv("APK_INDEX_FORMAT", "v3")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "APKINDEX.tar.gz") {
		t.Fatalf("Load() error = %v, want removed index format error", err)
	}
}

func TestValidateRequiresAdminCredentials(t *testing.T) {
	cfg := Config{
		ListenAddr:    ":8080",
		StorageRoot:   t.TempDir(),
		Repository:    "packages",
		MaxUploadSize: 1024,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "REGISTRY_ADMIN_USERNAME") {
		t.Fatalf("Validate() error = %v, want missing admin credentials", err)
	}
}

func TestValidateSigningKeyNameAndPublicURL(t *testing.T) {
	cfg := Config{
		ListenAddr:    ":8080",
		StorageRoot:   t.TempDir(),
		Repository:    "os",
		MaxUploadSize: 1024,
		AdminUsername: "admin",
		AdminPassword: "long-enough-test-password",
		SigningKey:    "/keys/registry.pem",
		PublicURL:     "https://packages.example.com",
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "ending in .rsa") {
		t.Fatalf("Validate() error = %v, want signing key filename error", err)
	}

	cfg.SigningKey = "/keys/registry.rsa"
	cfg.PublicURL = "https://user:pass@packages.example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "REGISTRY_PUBLIC_URL") {
		t.Fatalf("Validate() error = %v, want public URL error", err)
	}
}
