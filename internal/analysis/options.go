package analysis

import (
	"fmt"
	"strings"

	"sidersp/internal/config"
)

type Options struct {
	Enabled    bool
	Interface  string
	QueueSize  int
	WorkerCPUs map[int]int
	sender     frameSender
}

func NewOptions(analysisCfg config.AnalysisConfig, xskCfg config.XSKConfig) (Options, error) {
	opts := Options{
		Enabled:   xskCfg.Enabled && strings.TrimSpace(analysisCfg.Interface) != "",
		Interface: strings.TrimSpace(analysisCfg.Interface),
	}
	if len(analysisCfg.WorkerCPUs) != 0 {
		opts.WorkerCPUs = make(map[int]int, len(analysisCfg.WorkerCPUs))
		for queueID, cpuID := range analysisCfg.WorkerCPUs {
			opts.WorkerCPUs[queueID] = cpuID
		}
	}
	return normalizeOptions(opts), nil
}

func normalizeOptions(opts Options) Options {
	opts.Interface = strings.TrimSpace(opts.Interface)
	if opts.QueueSize <= 0 {
		opts.QueueSize = defaultQueueSize
	}
	if len(opts.WorkerCPUs) != 0 {
		cpus := make(map[int]int, len(opts.WorkerCPUs))
		for queueID, cpuID := range opts.WorkerCPUs {
			cpus[queueID] = cpuID
		}
		opts.WorkerCPUs = cpus
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
	for queueID, cpuID := range opts.WorkerCPUs {
		if queueID < 0 {
			return fmt.Errorf("create analysis runtime: worker_cpus queue %d out of range", queueID)
		}
		if cpuID < 0 {
			return fmt.Errorf("create analysis runtime: worker_cpus queue %d cpu %d out of range", queueID, cpuID)
		}
	}
	return nil
}
