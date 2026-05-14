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
	"sidersp/internal/agent/runtime"
)

const (
	defaultListenAddr     = "127.0.0.1:18081"
	listenAddrEnv         = "XDPASS_AGENT_LISTEN_ADDR"
	runtimeModeEnv        = "XDPASS_AGENT_RUNTIME_MODE"
	dataplaneInterfaceEnv = "XDPASS_AGENT_DATAPLANE_INTERFACE"
	shutdownTimeout       = 5 * time.Second
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, listenAddrFromEnv(), runtimeOptionsFromEnv()); err != nil {
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

func runtimeOptionsFromEnv() runtime.Options {
	options := runtime.DefaultOptions()
	if mode := strings.TrimSpace(os.Getenv(runtimeModeEnv)); mode != "" {
		options.Mode = runtime.Mode(mode)
	}
	options.Dataplane.Interface = strings.TrimSpace(os.Getenv(dataplaneInterfaceEnv))
	return options
}

func run(ctx context.Context, listenAddr string, runtimeOptions runtime.Options) error {
	composition, err := runtime.NewComposition(runtimeOptions)
	if err != nil {
		return err
	}
	defer func() {
		if err := composition.Close(); err != nil {
			logrus.WithError(err).Error("Fail to close agent runtime")
		}
	}()

	services := composition.Services
	srv := &http.Server{
		Addr:    listenAddr,
		Handler: api.NewRouter(services.Status, services.Ruleset, services.Attachments, services.Response, services.Dispatch, services.Stats, services.Events),
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
