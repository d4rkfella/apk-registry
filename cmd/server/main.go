package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/d4rkfella/apk-registry/internal/authz"
	"github.com/d4rkfella/apk-registry/internal/config"
	"github.com/d4rkfella/apk-registry/internal/registry"
)

const serverShutdownTimeout = 20 * time.Second

func main() {
	log := newJSONLogger(os.Stdout)
	if err := run(log); err != nil {
		log.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func newJSONLogger(output io.Writer) *slog.Logger {
	logger := slog.New(slog.NewJSONHandler(output, nil))
	slog.SetDefault(logger)
	return logger
}

func run(log *slog.Logger) error {
	signalCtx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}
	manager, err := registry.NewManager(cfg, log)
	if err != nil {
		return fmt.Errorf("initialize package storage: %w", err)
	}
	workerCtx, cancelWorker := context.WithCancel(context.Background())
	manager.Start(workerCtx)
	defer func() {
		cancelWorker()
		manager.Wait()
	}()

	keys, err := authz.OpenTokenStore(manager.PrivateStatePath())
	if err != nil {
		return fmt.Errorf("initialize API key store: %w", err)
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
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.ListenAddr, err)
	}

	var metricsServer *http.Server
	var metricsListener net.Listener
	metricsAddr := net.JoinHostPort(cfg.MetricsHost, strconv.Itoa(cfg.MetricsPort))
	if cfg.MetricsEnabled {
		metricsListener, err = net.Listen("tcp", metricsAddr)
		if err != nil {
			if closeErr := listener.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("close application listener: %w", closeErr))
			}
			return fmt.Errorf("listen for metrics on %s: %w", metricsAddr, err)
		}
		metricsServer = &http.Server{
			Addr:              metricsAddr,
			Handler:           app.MetricsHandler(),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	type serverResult struct {
		name string
		err  error
	}
	serverErrors := make(chan serverResult, 2)
	go func() {
		serverErrors <- serverResult{name: "application", err: server.Serve(listener)}
	}()
	if metricsServer != nil {
		go func() {
			serverErrors <- serverResult{name: "metrics", err: metricsServer.Serve(metricsListener)}
		}()
	}
	app.SetReady(true)
	log.Info("HTTP server listening", "address", cfg.ListenAddr, "storage", cfg.StorageRoot)
	if metricsServer != nil {
		log.Info("metrics server listening", "address", metricsAddr, "authentication_enabled", cfg.MetricsAuthEnabled)
	}

	var serveErr error
	select {
	case <-signalCtx.Done():
		log.Info("shutdown signal received")
	case result := <-serverErrors:
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			serveErr = fmt.Errorf("%s server: %w", result.name, result.err)
		}
	}

	stopSignals()
	app.SetReady(false)
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), serverShutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	if metricsServer != nil {
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("shut down metrics server: %w", err))
		}
	}
	cancelShutdown()
	if shutdownErr != nil {
		log.Error("graceful HTTP shutdown failed; closing active connections", "error", shutdownErr)
		if err := server.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("force-close HTTP server", "error", err)
		}
		if metricsServer != nil {
			if err := metricsServer.Close(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("force-close metrics server", "error", err)
			}
		}
	}

	cancelWorker()
	manager.Wait()
	log.Info("server shutdown complete")

	if serveErr != nil {
		return fmt.Errorf("serve HTTP: %w", serveErr)
	}
	if shutdownErr != nil {
		return fmt.Errorf("shut down HTTP server: %w", shutdownErr)
	}
	return nil
}
