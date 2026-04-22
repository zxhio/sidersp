package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
	"sidersp/internal/console"
	"sidersp/internal/controlplane"
	"sidersp/internal/dataplane"
	"sidersp/internal/response"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to config file")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	go func() {
		sig := <-sigCh
		logrus.WithField("signal", sig.String()).Info("Stopped service")
		cancel()
	}()

	cfg, err := config.Load(*configPath)
	if err != nil {
		logrus.WithError(err).WithField("config_path", *configPath).Fatal("Fail to load config")
	}

	dp, err := dataplane.Open(dataplane.Options{
		Interface:  cfg.Dataplane.Interface,
		AttachMode: cfg.Dataplane.AttachMode,
	})
	if err != nil {
		logrus.WithError(err).Fatal("Fail to open dataplane")
	}
	defer func() {
		if err := dp.Close(); err != nil {
			logrus.WithError(err).WithField("interface", cfg.Dataplane.Interface).Error("Fail to close dataplane")
		}
	}()

	cp := controlplane.NewRuntime(cfg, dp, dp, dp)
	consoleServer := console.NewServer(cfg.Console.ListenAddr, cp)
	responseRuntime, err := buildResponseRuntime(cfg, dp)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to build response runtime")
	}
	logrus.WithFields(logrus.Fields{
		"config_path": *configPath,
		"interface":   cfg.Dataplane.Interface,
	}).Info("Started service")

	errCh := make(chan error, 3)

	go func() {
		if err := cp.Run(ctx); err != nil {
			errCh <- fmt.Errorf("run controlplane: %w", err)
			cancel()
		}
	}()

	go func() {
		if err := consoleServer.Run(ctx); err != nil {
			errCh <- fmt.Errorf("run console: %w", err)
			cancel()
		}
	}()

	if responseRuntime != nil {
		go func() {
			if err := responseRuntime.Run(ctx); err != nil {
				errCh <- fmt.Errorf("run response runtime: %w", err)
				cancel()
			}
		}()
	}

	select {
	case err := <-errCh:
		logrus.WithError(err).Fatal("Fail to run service")
	case <-ctx.Done():
	}
}

func buildResponseRuntime(cfg config.Config, registrar response.XSKRegistrar) (*response.Runtime, error) {
	if !cfg.Response.Enabled {
		return nil, nil
	}

	iface, err := net.InterfaceByName(cfg.Dataplane.Interface)
	if err != nil {
		return nil, fmt.Errorf("lookup response interface: %w", err)
	}

	var hardwareAddr net.HardwareAddr
	if cfg.Response.HardwareAddr != "" {
		hardwareAddr, err = net.ParseMAC(cfg.Response.HardwareAddr)
		if err != nil {
			return nil, fmt.Errorf("parse response hardware address: %w", err)
		}
	}

	return response.NewRuntime(response.RuntimeConfig{
		IfIndex:              iface.Index,
		Queues:               cfg.Response.WorkerQueues(),
		ResultBufferCapacity: cfg.Response.ResultBufferCapacity(),
		HardwareAddr:         hardwareAddr,
		TCPSeq:               cfg.Response.TCPSeq,
		Registrar:            registrar,
		BackendFactory:       response.UnsupportedBackendFactory{},
	})
}
