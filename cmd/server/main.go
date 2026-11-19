package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/d4rkfella/apk-registry/internal/authz"
	"github.com/d4rkfella/apk-registry/internal/config"
	"github.com/d4rkfella/apk-registry/internal/registry"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load()
	if err != nil {
		log.Error("load configuration", "error", err)
		os.Exit(1)
	}
	manager, err := registry.NewManager(cfg, log)
	if err != nil {
		log.Error("initialize package storage", "error", err)
		os.Exit(1)
	}
	manager.Start(context.Background())
	keys, err := authz.OpenTokenStore(manager.PrivateStatePath())
	if err != nil {
		log.Error("initialize API key store", "error", err)
		os.Exit(1)
	}
	app := &registry.Server{
		Config:     cfg,
		Manager:    manager,
		Authorizer: authz.New(cfg.AdminUsername, cfg.AdminPassword, keys),
		Keys:       keys,
		Log:        log,
	}
	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           app.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Info("starting", "listen", cfg.ListenAddr, "storage", cfg.StorageRoot)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("server", "error", err)
		os.Exit(1)
	}
}
