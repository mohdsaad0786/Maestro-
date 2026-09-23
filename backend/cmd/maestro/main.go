package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mohdsaad0786/maestro/backend/internal/api"
	"github.com/mohdsaad0786/maestro/backend/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if len(os.Getenv("MAESTRO_API_TOKEN")) < 32 {
		slog.Error("MAESTRO_API_TOKEN must have at least 32 characters")
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	database := os.Getenv("MAESTRO_DATABASE_URL")
	if database == "" {
		database = "file:maestro.db?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	}
	connection, err := store.Open(ctx, database)
	if err != nil {
		slog.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer connection.Close()
	address := os.Getenv("MAESTRO_LISTEN")
	if address == "" {
		address = "127.0.0.1:8080"
	}
	server := &http.Server{Addr: address, Handler: (&api.Server{Store: connection, Token: os.Getenv("MAESTRO_API_TOKEN")}).Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 190 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("server shutdown", "error", err)
		}
	}()
	slog.Info("listening", "address", address)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("http server", "error", err)
		os.Exit(1)
	}
}
