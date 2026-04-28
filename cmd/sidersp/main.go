package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
	"sidersp/internal/console"
	"sidersp/internal/controlplane"
	"sidersp/internal/dataplane"
	"sidersp/internal/logs"
	"sidersp/internal/model"
	"sidersp/internal/response"
	"sidersp/internal/rule"
)

func main() {
	configPath := flag.String("config", "configs/config.example.yaml", "path to config file")
	flag.Parse()

	bootstrapLog := logs.App()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	cfg, err := config.Load(*configPath)
	if err != nil {
		bootstrapLog.WithError(err).WithField("config_path", *configPath).Fatal("Fail to load config")
	}

	logManager, err := logs.NewManager(cfg.Logging)
	if err != nil {
		bootstrapLog.WithError(err).Fatal("Fail to configure logging")
	}
	logs.SetDefaultManager(logManager)
	defer logs.ResetDefaultManager()
	defer func() {
		if err := logManager.Close(); err != nil {
			logs.App().WithError(err).Error("Fail to close logger")
		}
	}()

	go func() {
		sig := <-sigCh
		logs.App().WithField("signal", sig.String()).Info("Stopped service")
		cancel()
	}()

	dpOpts, err := dataplane.NewOptions(cfg.Dataplane, cfg.Egress)
	if err != nil {
		logs.App().WithError(err).Fatal("Fail to build dataplane options")
	}

	dp, err := dataplane.Open(dpOpts)
	if err != nil {
		logs.App().WithError(err).Fatal("Fail to open dataplane")
	}
	defer func() {
		if err := dp.Close(); err != nil {
			logs.App().WithError(err).WithField("interface", cfg.Dataplane.Interface).Error("Fail to close dataplane")
		}
	}()

	responseOpts, err := response.NewOptions(cfg.Dataplane, cfg.Egress, cfg.Response, dp)
	if err != nil {
		logs.App().WithError(err).Fatal("Fail to build response options")
	}

	var responseRuntime *response.Runtime
	if responseOpts.Enabled {
		responseRuntime, err = response.NewRuntime(responseOpts)
		if err != nil {
			logs.App().WithError(err).Fatal("Fail to build response runtime")
		}
	}
	// Apply dataplane first so a failed dataplane sync never leaves user-space
	// response params ahead of the active redirect rules.
	syncer := ruleSyncFanout{targets: []controlplane.RuleSyncer{dp}}
	if responseRuntime != nil {
		syncer.targets = append(syncer.targets, responseRuntime)
	}

	cpOpts, err := controlplane.NewOptions(cfg.ControlPlane, cfg.Console)
	if err != nil {
		logs.App().WithError(err).Fatal("Fail to build controlplane options")
	}

	cp, err := controlplane.NewRuntime(cpOpts, syncer, dp, runtimeStatsReader{
		dataplane: dp,
		response:  responseRuntime,
	})
	if err != nil {
		logs.App().WithError(err).Fatal("Fail to build controlplane runtime")
	}
	consoleServer := console.NewServer(cfg.Console.ListenAddr, newConsoleService(cp, cfg), logManager)
	logs.App().WithFields(logrus.Fields{
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
		logs.App().WithError(err).Fatal("Fail to run service")
	case <-ctx.Done():
	}
}

type dataplaneStatsReader interface {
	ReadStats() (model.DataplaneStats, error)
	ResetStats() error
}

type responseStatsReader interface {
	ReadStats() model.ResponseStats
	ResetStats() error
}

type runtimeStatsReader struct {
	dataplane dataplaneStatsReader
	response  responseStatsReader
}

type consoleService struct {
	*controlplane.Runtime
	status controlplane.Status
}

func newConsoleService(runtime *controlplane.Runtime, cfg config.Config) *consoleService {
	return &consoleService{
		Runtime: runtime,
		status: controlplane.Status{
			ListenAddr:     cfg.Console.ListenAddr,
			Interface:      strings.TrimSpace(cfg.Dataplane.Interface),
			TXInterface:    txInterface(cfg.Dataplane.Interface, cfg.Egress.Interface),
			TXHardwareAddr: txHardwareAddr(cfg.Dataplane.Interface, cfg.Egress.Interface),
		},
	}
}

func (s *consoleService) Status() controlplane.Status {
	current := s.Runtime.RuleStatus()
	status := s.status
	status.RulesPath = current.RulesPath
	status.TotalRules = current.TotalRules
	status.Enabled = current.Enabled
	return status
}

func (r runtimeStatsReader) ReadStats() (model.RuntimeStats, error) {
	dataplaneStats, err := r.dataplane.ReadStats()
	if err != nil {
		return model.RuntimeStats{}, err
	}

	var responseStats model.ResponseStats
	if r.response != nil {
		responseStats = r.response.ReadStats()
	}

	return model.RuntimeStats{
		Dataplane: dataplaneStats,
		Response:  responseStats,
	}, nil
}

func (r runtimeStatsReader) ResetStats() error {
	if err := r.dataplane.ResetStats(); err != nil {
		return err
	}

	if r.response != nil {
		if err := r.response.ResetStats(); err != nil {
			return err
		}
	}

	return nil
}

func txInterface(dataplaneInterface string, egressInterface string) string {
	if iface := strings.TrimSpace(egressInterface); iface != "" {
		return iface
	}
	return strings.TrimSpace(dataplaneInterface)
}

func txHardwareAddr(dataplaneInterface string, egressInterface string) string {
	ifaceName := txInterface(dataplaneInterface, egressInterface)
	if ifaceName == "" {
		return ""
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil || len(iface.HardwareAddr) != 6 {
		return ""
	}
	return iface.HardwareAddr.String()
}

type ruleSyncFanout struct {
	targets []controlplane.RuleSyncer
}

func (s ruleSyncFanout) ReplaceRules(set rule.RuleSet) error {
	for _, target := range s.targets {
		if err := target.ReplaceRules(set); err != nil {
			return err
		}
	}
	return nil
}
