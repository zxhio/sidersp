package controlplane

import (
	"context"
	"fmt"
	"log"

	"sidersp/internal/config"
)

type RuleSyncer interface {
	ReplaceRules(RuleSet) error
}

type EventStreamer interface {
	RunEventStream(context.Context, *log.Logger) error
}

type Runtime struct {
	cfg    config.Config
	syncer RuleSyncer
	logger *log.Logger
}

func NewRuntime(cfg config.Config, syncer RuleSyncer, logger *log.Logger) *Runtime {
	return &Runtime{
		cfg:    cfg,
		syncer: syncer,
		logger: logger,
	}
}

func (r *Runtime) bootstrap() (RuleSet, error) {
	rules, err := LoadRules(r.cfg.ControlPlane.RulesPath)
	if err != nil {
		return RuleSet{}, fmt.Errorf("load rules: %w", err)
	}

	if err := r.syncer.ReplaceRules(rules); err != nil {
		return RuleSet{}, fmt.Errorf("sync rules to dataplane: %w", err)
	}

	if r.logger != nil {
		r.logger.Printf("controlplane bootstrapped rules=%d rules_path=%s",
			len(rules.Rules), r.cfg.ControlPlane.RulesPath)
	}

	return rules, nil
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	rules, err := r.bootstrap()
	if err != nil {
		return err
	}

	if r.logger != nil {
		r.logger.Printf("controlplane runtime running rules=%d", len(rules.Rules))
	}

	if streamer, ok := r.syncer.(EventStreamer); ok {
		if err := streamer.RunEventStream(ctx, r.logger); err != nil {
			return fmt.Errorf("start event stream: %w", err)
		}
	}

	<-ctx.Done()
	return nil
}
