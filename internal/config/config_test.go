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
	t.Setenv("REGISTRY_PUBLIC_READ", "false")
	t.Setenv("APK_INDEX_FORMAT", "v3")

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
	if cfg.IndexFormat != "v3" {
		t.Fatalf("index format = %q, want v3", cfg.IndexFormat)
	}
	if cfg.PublicRead == nil || *cfg.PublicRead {
		t.Fatal("REGISTRY_PUBLIC_READ=false was not applied")
	}
}

func TestValidateRequiresAdminCredentials(t *testing.T) {
	cfg := Config{
		ListenAddr:    ":8080",
		StorageRoot:   t.TempDir(),
		Repository:    "packages",
		IndexFormat:   "v2",
		APKBinary:     "apk",
		MaxUploadSize: 1024,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "REGISTRY_ADMIN_USERNAME") {
		t.Fatalf("Validate() error = %v, want missing admin credentials", err)
	}
}
