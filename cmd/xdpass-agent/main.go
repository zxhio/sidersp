package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"sidersp/internal/agent/api"
	"sidersp/internal/agent/service"
)

const (
	defaultListenAddr = "127.0.0.1:18081"
	listenAddrEnv     = "XDPASS_AGENT_LISTEN_ADDR"
	shutdownTimeout   = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, listenAddrFromEnv()); err != nil {
		logrus.WithError(err).Fatal("Fail to run agent")
	}
}

func listenAddrFromEnv() string {
	addr := strings.TrimSpace(os.Getenv(listenAddrEnv))
	if addr == "" {
		return defaultListenAddr
	}
	return addr
}

func run(ctx context.Context, listenAddr string) error {
	runtime := service.NewInMemoryRuntime()
	statusService := service.NewStatusServiceWithRuntime(runtime.RuntimeDeps())
	rulesetService := service.NewRulesetService(runtime)
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: api.NewRouter(statusService, rulesetService),
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	logrus.WithField("listen_addr", listenAddr).Info("Started agent server")

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		return nil
	case err := <-errCh:
		if err == nil {
			return nil
		}
		return fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
}
