package controlplane

import (
	"fmt"
	"strings"
	"time"

	"sidersp/internal/config"
)

const (
	defaultStatsCollectStep = 10 * time.Second
	defaultStatsKeepWindow  = 30 * 24 * time.Hour
)

type Options struct {
	RulesPath        string
	StatsCollectStep time.Duration
	StatsKeepWindow  time.Duration
	StatsKeepLimit   int
}

func NewOptions(controlCfg config.ControlPlaneConfig, consoleCfg config.ConsoleConfig) (Options, error) {
	if strings.TrimSpace(controlCfg.RulesPath) == "" {
		return Options{}, fmt.Errorf("controlplane.rules_path is required")
	}

	statsCfg, err := consoleCfg.ParsedStats()
	if err != nil {
		return Options{}, fmt.Errorf("console.stats: %w", err)
	}
	collectStep, keepWindow, keepLimit := buildStatsRetention(statsCfg)

	return normalizeOptions(Options{
		RulesPath:        controlCfg.RulesPath,
		StatsCollectStep: collectStep,
		StatsKeepWindow:  keepWindow,
		StatsKeepLimit:   keepLimit,
	}), nil
}

func normalizeOptions(opts Options) Options {
	if opts.StatsCollectStep <= 0 {
		opts.StatsCollectStep = defaultStatsCollectStep
	}
	if opts.StatsKeepWindow <= 0 {
		opts.StatsKeepWindow = defaultStatsKeepWindow
	}
	if opts.StatsKeepLimit <= 0 {
		opts.StatsKeepLimit = int(opts.StatsKeepWindow / opts.StatsCollectStep)
		if opts.StatsKeepWindow%opts.StatsCollectStep != 0 {
			opts.StatsKeepLimit++
		}
		if opts.StatsKeepLimit <= 0 {
			opts.StatsKeepLimit = 1
		}
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.StatsCollectStep <= 0 {
		return fmt.Errorf("controlplane.stats_collect_step must be > 0")
	}
	if opts.StatsKeepWindow <= 0 {
		return fmt.Errorf("controlplane.stats_keep_window must be > 0")
	}
	if opts.StatsKeepWindow < opts.StatsCollectStep {
		return fmt.Errorf("controlplane.stats_keep_window must be >= stats_collect_step")
	}
	if opts.StatsKeepLimit <= 0 {
		return fmt.Errorf("controlplane.stats_keep_limit must be > 0")
	}
	return nil
}
