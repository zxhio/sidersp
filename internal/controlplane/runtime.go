package controlplane

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
	"sidersp/internal/rule"
)

type RuleSyncer interface {
	ReplaceRules(rule.RuleSet) error
}

type EventStreamer interface {
	RunEventStream(context.Context) error
}

type Runtime struct {
	cfg      config.Config
	syncer   RuleSyncer
	streamer EventStreamer
}

func NewRuntime(cfg config.Config, syncer RuleSyncer, streamer EventStreamer) *Runtime {
	if syncer == nil {
		panic("controlplane: syncer is required")
	}
	if streamer == nil {
		panic("controlplane: streamer is required")
	}
	return &Runtime{
		cfg:      cfg,
		syncer:   syncer,
		streamer: streamer,
	}
}

func (r *Runtime) bootstrap() (rule.RuleSet, error) {
	rules, err := LoadRules(r.cfg.ControlPlane.RulesPath)
	if err != nil {
		return rule.RuleSet{}, fmt.Errorf("load rules: %w", err)
	}

	if err := r.syncer.ReplaceRules(rules); err != nil {
		return rule.RuleSet{}, fmt.Errorf("sync rules to dataplane: %w", err)
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

	if err := r.streamer.RunEventStream(ctx); err != nil {
		return fmt.Errorf("start event stream: %w", err)
	}
	return nil
}
