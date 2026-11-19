package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/d4rkfella/apk-registry/internal/repository"
)

type Config struct {
	ListenAddr    string
	StorageRoot   string
	Repository    string
	PublicRead    *bool
	PublicURL     string
	SigningKey    string
	MaxUploadSize int64
	AdminUsername string
	AdminPassword string
}

func Load() (Config, error) {
	cfg := Config{
		ListenAddr:    ":8080",
		StorageRoot:   "./data",
		Repository:    "os",
		MaxUploadSize: 1 << 30,
	}
	cfg.ListenAddr = env("APK_REGISTRY_LISTEN_ADDR", cfg.ListenAddr)
	cfg.StorageRoot = env("APK_REGISTRY_STORAGE_ROOT", cfg.StorageRoot)
	cfg.Repository = env("APK_REGISTRY_REPOSITORY", cfg.Repository)
	cfg.PublicURL = os.Getenv("APK_REGISTRY_PUBLIC_URL")
	cfg.SigningKey = os.Getenv("APK_REGISTRY_INDEX_SIGNING_KEY")
	cfg.AdminUsername = os.Getenv("APK_REGISTRY_ADMIN_USERNAME")
	cfg.AdminPassword = os.Getenv("APK_REGISTRY_ADMIN_PASSWORD")
	if format := os.Getenv("APK_REGISTRY_INDEX_FORMAT"); format != "" && format != "v2" {
		return Config{}, fmt.Errorf("APK_REGISTRY_INDEX_FORMAT=%q is unsupported; the registry always serves APKINDEX.tar.gz", format)
	}
	if raw := os.Getenv("APK_REGISTRY_MAX_UPLOAD_SIZE"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("parse APK_REGISTRY_MAX_UPLOAD_SIZE: %w", err)
		}
		cfg.MaxUploadSize = size
	}
	if raw := os.Getenv("APK_REGISTRY_PUBLIC_READ"); raw != "" {
		public, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse APK_REGISTRY_PUBLIC_READ: %w", err)
		}
		cfg.PublicRead = &public
	}
	if cfg.PublicRead == nil {
		public := true
		cfg.PublicRead = &public
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.ListenAddr == "" || c.StorageRoot == "" || c.Repository == "" {
		return errors.New("listen_addr, storage_root, and repository are required")
	}
	if c.AdminUsername == "" || len(c.AdminUsername) > 128 || strings.ContainsAny(c.AdminUsername, ":\r\n") {
		return errors.New("APK_REGISTRY_ADMIN_USERNAME must be 1-128 characters and cannot contain colons or newlines")
	}
	if len(c.AdminPassword) < 16 {
		return errors.New("APK_REGISTRY_ADMIN_PASSWORD must be at least 16 characters")
	}
	if c.MaxUploadSize <= 0 {
		return errors.New("max_upload_size must be positive")
	}
	if !repository.ValidSegment(c.Repository) {
		return errors.New("repository must be a valid path segment")
	}
	if c.PublicURL != "" {
		publicURL, err := url.Parse(c.PublicURL)
		if err != nil || (publicURL.Scheme != "http" && publicURL.Scheme != "https") ||
			publicURL.Host == "" || publicURL.User != nil ||
			(publicURL.Path != "" && publicURL.Path != "/") ||
			publicURL.RawQuery != "" || publicURL.Fragment != "" {
			return errors.New("APK_REGISTRY_PUBLIC_URL must be an HTTP(S) origin without credentials, path, query, or fragment")
		}
	}
	if c.SigningKey != "" && !strings.HasSuffix(filepath.Base(c.SigningKey), ".rsa") {
		return errors.New("APK_REGISTRY_INDEX_SIGNING_KEY must name a PEM RSA key ending in .rsa")
	}
	return nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func ValidateKeyScope(permissions []string) error {
	if len(permissions) == 0 {
		return errors.New("permissions are required")
	}
	for _, permission := range permissions {
		if permission != "read" && permission != "deploy" && permission != "delete" {
			return fmt.Errorf("unknown permission %q", permission)
		}
	}
	return nil
}
