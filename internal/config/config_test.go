package config

import (
	"strings"
	"testing"
)

func TestLoadUsesEnvironmentAndDefaults(t *testing.T) {
	t.Setenv("APK_REGISTRY_ADMIN_USERNAME", "admin")
	t.Setenv("APK_REGISTRY_ADMIN_PASSWORD", "long-enough-test-password")
	t.Setenv("APK_REGISTRY_LISTEN_ADDR", "")
	t.Setenv("APK_REGISTRY_STORAGE_ROOT", t.TempDir())
	t.Setenv("APK_REGISTRY_REPOSITORY", "")
	t.Setenv("APK_REGISTRY_PUBLIC_URL", "https://packages.example.com")
	t.Setenv("APK_REGISTRY_PUBLIC_READ", "false")
	t.Setenv("APK_REGISTRY_METRICS_ENABLED", "")
	t.Setenv("APK_REGISTRY_METRICS_HOST", "")
	t.Setenv("APK_REGISTRY_METRICS_PORT", "")
	t.Setenv("APK_REGISTRY_METRICS_AUTH_ENABLED", "")

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
		t.Fatal("APK_REGISTRY_PUBLIC_READ=false was not applied")
	}
	if !cfg.MetricsEnabled || cfg.MetricsHost != "0.0.0.0" || cfg.MetricsPort != 9094 || !cfg.MetricsAuthEnabled {
		t.Fatalf("metrics defaults were not applied: enabled=%v host=%q port=%d auth=%v",
			cfg.MetricsEnabled, cfg.MetricsHost, cfg.MetricsPort, cfg.MetricsAuthEnabled)
	}
}

func TestLoadUsesPrefixedEnvironment(t *testing.T) {
	storageRoot := t.TempDir()
	t.Setenv("APK_REGISTRY_LISTEN_ADDR", ":9090")
	t.Setenv("APK_REGISTRY_STORAGE_ROOT", storageRoot)
	t.Setenv("APK_REGISTRY_REPOSITORY", "packages")
	t.Setenv("APK_REGISTRY_ADMIN_USERNAME", "prefixed-admin")
	t.Setenv("APK_REGISTRY_ADMIN_PASSWORD", "prefixed-long-enough-password")
	t.Setenv("APK_REGISTRY_PUBLIC_URL", "https://new.example.com")
	t.Setenv("APK_REGISTRY_PUBLIC_READ", "false")
	t.Setenv("APK_REGISTRY_MAX_UPLOAD_SIZE", "2048")
	t.Setenv("APK_REGISTRY_METRICS_ENABLED", "false")
	t.Setenv("APK_REGISTRY_METRICS_HOST", "127.0.0.1")
	t.Setenv("APK_REGISTRY_METRICS_PORT", "9123")
	t.Setenv("APK_REGISTRY_METRICS_AUTH_ENABLED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":9090" || cfg.StorageRoot != storageRoot || cfg.Repository != "packages" {
		t.Fatalf("prefixed values were not applied: %+v", cfg)
	}
	if cfg.AdminUsername != "prefixed-admin" || cfg.AdminPassword != "prefixed-long-enough-password" {
		t.Fatalf("prefixed admin credentials were not applied: %+v", cfg)
	}
	if cfg.PublicURL != "https://new.example.com" || cfg.PublicRead == nil || *cfg.PublicRead {
		t.Fatalf("prefixed public settings were not applied: %+v", cfg)
	}
	if cfg.MaxUploadSize != 2048 {
		t.Fatalf("max upload size = %d, want 2048", cfg.MaxUploadSize)
	}
	if cfg.MetricsEnabled || cfg.MetricsHost != "127.0.0.1" || cfg.MetricsPort != 9123 || cfg.MetricsAuthEnabled {
		t.Fatalf("metrics environment was not applied: enabled=%v host=%q port=%d auth=%v",
			cfg.MetricsEnabled, cfg.MetricsHost, cfg.MetricsPort, cfg.MetricsAuthEnabled)
	}
}

func TestValidateMetricsListener(t *testing.T) {
	cfg := Config{
		ListenAddr: ":8080", StorageRoot: t.TempDir(), Repository: "os",
		MaxUploadSize: 1024, AdminUsername: "admin", AdminPassword: "long-enough-test-password",
		MetricsEnabled: true, MetricsHost: "0.0.0.0", MetricsPort: 9094,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid metrics listener config: %v", err)
	}
	cfg.MetricsPort = 65536
	if err := cfg.Validate(); err == nil {
		t.Fatal("Validate() accepted metrics port above 65535")
	}
}

func TestValidateRequiresAdminCredentials(t *testing.T) {
	cfg := Config{
		ListenAddr:    ":8080",
		StorageRoot:   t.TempDir(),
		Repository:    "packages",
		MaxUploadSize: 1024,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "APK_REGISTRY_ADMIN_USERNAME") {
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

	cfg.MetricsEnabled = false
	cfg.SigningKey = "/keys/registry.rsa"
	cfg.PublicURL = "https://user:pass@packages.example.com"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "APK_REGISTRY_PUBLIC_URL") {
		t.Fatalf("Validate() error = %v, want public URL error", err)
	}
}
