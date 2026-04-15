package controlplane

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
)

type RuleSyncer interface {
	ReplaceRules(RuleSet) error
}

type EventStreamer interface {
	RunEventStream(context.Context) error
}

type Runtime struct {
	cfg    config.Config
	syncer RuleSyncer
}

func NewRuntime(cfg config.Config, syncer RuleSyncer) *Runtime {
	return &Runtime{
		cfg:    cfg,
		syncer: syncer,
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

	logrus.WithFields(logrus.Fields{
		"rules":      len(rules.Rules),
		"rules_path": r.cfg.ControlPlane.RulesPath,
	}).Info("Bootstrapped controlplane")

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

	logrus.WithField("rules", len(rules.Rules)).Info("Started controlplane runtime")

	if streamer, ok := r.syncer.(EventStreamer); ok {
		if err := streamer.RunEventStream(ctx); err != nil {
			return fmt.Errorf("start event stream: %w", err)
		}
	}

	<-ctx.Done()
	return nil
}
