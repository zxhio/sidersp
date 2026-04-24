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
	applogging "sidersp/internal/logging"
	"sidersp/internal/response"
	"sidersp/internal/response/afxdp"
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

	logManager, err := applogging.NewManager(cfg.Logging)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to configure logging")
	}
	defer func() {
		if err := logManager.Close(); err != nil {
			logrus.WithError(err).Error("Fail to close logger")
		}
	}()

	tcpResetTX, err := buildTCPResetTXOptions(cfg.Egress)
	if err != nil {
		logrus.WithError(err).Fatal("Fail to configure tcp_reset TX")
	}

	dp, err := dataplane.Open(dataplane.Options{
		Interface:      cfg.Dataplane.Interface,
		AttachMode:     cfg.Dataplane.AttachMode,
		IngressVerdict: cfg.Dataplane.NormalizedIngressVerdict(),
		TCPResetTX:     tcpResetTX,
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
	consoleServer := console.NewServer(cfg.Console.ListenAddr, cp, logManager)
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

func buildTCPResetTXOptions(cfg config.EgressConfig) (dataplane.TCPResetTXOptions, error) {
	var egressIfIndex int
	if cfg.TXPath() == "egress-interface" {
		iface, err := net.InterfaceByName(cfg.Interface)
		if err != nil {
			return dataplane.TCPResetTXOptions{}, fmt.Errorf("lookup egress interface %s: %w", cfg.Interface, err)
		}
		egressIfIndex = iface.Index
	}

	return dataplane.TCPResetTXOptions{
		EgressIfIndex:  egressIfIndex,
		VLANMode:       cfg.NormalizedVLANMode(),
		FailureVerdict: cfg.NormalizedFailureVerdict(),
	}, nil
}

func buildResponseRuntime(cfg config.Config, registrar response.XSKRegistrar) (*response.Runtime, error) {
	if !cfg.Response.Runtime.Enabled {
		return nil, nil
	}

	iface, err := net.InterfaceByName(cfg.Dataplane.Interface)
	if err != nil {
		return nil, fmt.Errorf("lookup response interface: %w", err)
	}

	var hardwareAddr net.HardwareAddr
	if cfg.Response.Actions.ARPReply.HardwareAddr != "" {
		hardwareAddr, err = net.ParseMAC(cfg.Response.Actions.ARPReply.HardwareAddr)
		if err != nil {
			return nil, fmt.Errorf("parse response hardware address: %w", err)
		}
	}

	afxdpCfg := buildAFXDPConfig(cfg.Response.Runtime, iface.Index)

	newBackend := func(queueID int) (response.XSKBackend, error) {
		return afxdp.NewSocket(afxdpCfg, queueID)
	}

	return response.NewRuntime(response.RuntimeConfig{
		IfIndex:              iface.Index,
		Queues:               cfg.Response.Runtime.WorkerQueues(),
		ResultBufferCapacity: cfg.Response.Runtime.ResultBufferCapacity(),
		HardwareAddr:         hardwareAddr,
		TCPSeq:               cfg.Response.Actions.TCPSynAck.TCPSeq,
		EgressInterface:      cfg.Egress.Interface,
		Registrar:            registrar,
		NewXSKBackend:        newBackend,
	})
}

func buildAFXDPConfig(cfg config.ResponseRuntimeConfig, ifindex int) afxdp.SocketConfig {
	afxdpCfg := afxdp.DefaultSocketConfig()
	afxdpCfg.IfIndex = ifindex

	if v := cfg.AFXDP.FrameSize; v != 0 {
		afxdpCfg.FrameSize = v
	}
	if v := cfg.AFXDP.FrameCount; v != 0 {
		afxdpCfg.FrameCount = v
	}
	if v := cfg.AFXDP.FillRingSize; v != 0 {
		afxdpCfg.FillRingSize = v
	}
	if v := cfg.AFXDP.CompletionRingSize; v != 0 {
		afxdpCfg.CompletionRingSize = v
	}
	if v := cfg.AFXDP.RXRingSize; v != 0 {
		afxdpCfg.RXRingSize = v
	}
	if v := cfg.AFXDP.TXRingSize; v != 0 {
		afxdpCfg.TXRingSize = v
	}
	if v := cfg.AFXDP.TXFrameReserve; v != 0 {
		afxdpCfg.TXFrameReserve = v
	}

	return afxdpCfg
}
