package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/d4rkfella/apk-registry/internal/repository"
)

type Config struct {
	ListenAddr    string
	StorageRoot   string
	Repository    string
	PublicRead    *bool
	IndexFormat   string
	APKBinary     string
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
		IndexFormat:   "v2",
		APKBinary:     "apk",
		MaxUploadSize: 1 << 30,
	}
	cfg.ListenAddr = env("LISTEN_ADDR", cfg.ListenAddr)
	cfg.StorageRoot = env("STORAGE_ROOT", cfg.StorageRoot)
	cfg.Repository = env("REGISTRY_REPOSITORY", cfg.Repository)
	cfg.IndexFormat = env("APK_INDEX_FORMAT", cfg.IndexFormat)
	cfg.APKBinary = env("APK_BINARY", cfg.APKBinary)
	cfg.SigningKey = os.Getenv("APK_INDEX_SIGNING_KEY")
	cfg.AdminUsername = os.Getenv("REGISTRY_ADMIN_USERNAME")
	cfg.AdminPassword = os.Getenv("REGISTRY_ADMIN_PASSWORD")
	if raw := os.Getenv("MAX_UPLOAD_SIZE"); raw != "" {
		size, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return Config{}, fmt.Errorf("parse MAX_UPLOAD_SIZE: %w", err)
		}
		cfg.MaxUploadSize = size
	}
	if raw := os.Getenv("REGISTRY_PUBLIC_READ"); raw != "" {
		public, err := strconv.ParseBool(raw)
		if err != nil {
			return Config{}, fmt.Errorf("parse REGISTRY_PUBLIC_READ: %w", err)
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
	if c.ListenAddr == "" || c.StorageRoot == "" || c.Repository == "" || c.APKBinary == "" {
		return errors.New("listen_addr, storage_root, repository, and apk_binary are required")
	}
	if c.AdminUsername == "" || len(c.AdminUsername) > 128 || strings.ContainsAny(c.AdminUsername, ":\r\n") {
		return errors.New("REGISTRY_ADMIN_USERNAME must be 1-128 characters and cannot contain colons or newlines")
	}
	if len(c.AdminPassword) < 16 {
		return errors.New("REGISTRY_ADMIN_PASSWORD must be at least 16 characters")
	}
	if c.MaxUploadSize <= 0 {
		return errors.New("max_upload_size must be positive")
	}
	if !repository.ValidSegment(c.Repository) {
		return errors.New("repository must be a valid path segment")
	}
	if c.IndexFormat != "v2" && c.IndexFormat != "v3" {
		return fmt.Errorf("unsupported index_format %q", c.IndexFormat)
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
