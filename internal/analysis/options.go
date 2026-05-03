package analysis

import (
	"fmt"
	"strings"

	"sidersp/internal/config"
)

type Options struct {
	Enabled   bool
	Interface string
	QueueSize int
	sender    frameSender
}

func NewOptions(analysisCfg config.AnalysisConfig, xskCfg config.XSKConfig) (Options, error) {
	opts := Options{
		Enabled:   xskCfg.Enabled && strings.TrimSpace(analysisCfg.Interface) != "",
		Interface: strings.TrimSpace(analysisCfg.Interface),
	}
	return normalizeOptions(opts), nil
}

func normalizeOptions(opts Options) Options {
	opts.Interface = strings.TrimSpace(opts.Interface)
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	return opts
}

func validateOptions(opts Options) error {
	if opts.QueueSize <= 0 {
		return fmt.Errorf("create analysis runtime: queue size must be > 0")
	}
	if opts.sender == nil && opts.Interface == "" {
		return fmt.Errorf("create analysis runtime: interface is required")
	}
	return nil
}
