package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
	"sidersp/internal/rule"
)

var ErrRuleNotFound = fmt.Errorf("rule not found")
var ErrRuleConflict = fmt.Errorf("rule conflict")

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
	mu       sync.RWMutex
	rules    rule.RuleSet
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

	if err := r.syncRules(rules); err != nil {
		return rule.RuleSet{}, fmt.Errorf("sync rules to dataplane: %w", err)
	}

	r.mu.Lock()
	r.rules = cloneRuleSet(rules)
	r.mu.Unlock()

	logrus.WithFields(logrus.Fields{
		"rules":      len(enabledRuleSet(rules).Rules),
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

	<-ctx.Done()
	return nil
}

func (r *Runtime) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return newStatus(r.cfg, r.rules)
}

func (r *Runtime) ListRules() []rule.Rule {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return cloneRules(r.rules.Rules)
}

func (r *Runtime) GetRule(id int) (rule.Rule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, item := range r.rules.Rules {
		if item.ID == id {
			return cloneRule(item), nil
		}
	}

	return rule.Rule{}, ErrRuleNotFound
}

func (r *Runtime) SetRuleEnabled(id int, enabled bool) (rule.Rule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := cloneRuleSet(r.rules)
	for idx := range next.Rules {
		if next.Rules[idx].ID != id {
			continue
		}

		next.Rules[idx].Enabled = enabled
		if err := r.syncRules(next); err != nil {
			return rule.Rule{}, err
		}

		r.rules = next
		return cloneRule(next.Rules[idx]), nil
	}

	return rule.Rule{}, ErrRuleNotFound
}

func (r *Runtime) CreateRule(item rule.Rule) (rule.Rule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := cloneRuleSet(r.rules)
	for _, existing := range next.Rules {
		if existing.ID == item.ID {
			return rule.Rule{}, ErrRuleConflict
		}
	}

	next.Rules = append(next.Rules, cloneRule(item))
	if err := normalizeRuleSet(&next); err != nil {
		return rule.Rule{}, err
	}
	if err := r.persistRules(next); err != nil {
		return rule.Rule{}, err
	}
	if err := r.syncRules(next); err != nil {
		return rule.Rule{}, err
	}

	r.rules = next
	return r.findRuleLocked(item.ID)
}

func (r *Runtime) UpdateRule(id int, item rule.Rule) (rule.Rule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := cloneRuleSet(r.rules)
	found := false
	for idx := range next.Rules {
		if next.Rules[idx].ID != id {
			continue
		}
		next.Rules[idx] = cloneRule(item)
		found = true
		break
	}
	if !found {
		return rule.Rule{}, ErrRuleNotFound
	}

	if item.ID != id {
		for _, existing := range next.Rules {
			if existing.ID == item.ID {
				return rule.Rule{}, ErrRuleConflict
			}
		}
	}

	if err := normalizeRuleSet(&next); err != nil {
		return rule.Rule{}, err
	}
	if err := r.persistRules(next); err != nil {
		return rule.Rule{}, err
	}
	if err := r.syncRules(next); err != nil {
		return rule.Rule{}, err
	}

	r.rules = next
	return r.findRuleLocked(item.ID)
}

func (r *Runtime) DeleteRule(id int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	next := cloneRuleSet(r.rules)
	for idx := range next.Rules {
		if next.Rules[idx].ID != id {
			continue
		}

		next.Rules = append(next.Rules[:idx], next.Rules[idx+1:]...)
		if err := r.persistRules(next); err != nil {
			return err
		}
		if err := r.syncRules(next); err != nil {
			return err
		}

		r.rules = next
		return nil
	}

	return ErrRuleNotFound
}

func (r *Runtime) syncRules(rules rule.RuleSet) error {
	return r.syncer.ReplaceRules(enabledRuleSet(rules))
}

func (r *Runtime) persistRules(rules rule.RuleSet) error {
	if r.cfg.ControlPlane.RulesPath == "" {
		return nil
	}
	if err := SaveRules(r.cfg.ControlPlane.RulesPath, rules); err != nil {
		if errors.Is(err, ErrRuleValidation) {
			return err
		}
		return fmt.Errorf("persist rules: %w", err)
	}
	return nil
}

func (r *Runtime) findRuleLocked(id int) (rule.Rule, error) {
	for _, item := range r.rules.Rules {
		if item.ID == id {
			return cloneRule(item), nil
		}
	}
	return rule.Rule{}, ErrRuleNotFound
}

type Status struct {
	RulesPath  string `json:"rules_path"`
	ListenAddr string `json:"listen_addr"`
	Interface  string `json:"interface"`
	TotalRules int    `json:"total_rules"`
	Enabled    int    `json:"enabled_rules"`
}

func newStatus(cfg config.Config, rules rule.RuleSet) Status {
	return Status{
		RulesPath:  cfg.ControlPlane.RulesPath,
		ListenAddr: cfg.Console.ListenAddr,
		Interface:  cfg.Dataplane.Interface,
		TotalRules: len(rules.Rules),
		Enabled:    len(enabledRuleSet(rules).Rules),
	}
}

func cloneRuleSet(set rule.RuleSet) rule.RuleSet {
	return rule.RuleSet{Rules: cloneRules(set.Rules)}
}

func cloneRules(items []rule.Rule) []rule.Rule {
	cloned := make([]rule.Rule, 0, len(items))
	for _, item := range items {
		cloned = append(cloned, cloneRule(item))
	}
	return cloned
}

func cloneRule(item rule.Rule) rule.Rule {
	item.Match.VLANs = append([]int(nil), item.Match.VLANs...)
	item.Match.SrcPrefixes = append([]string(nil), item.Match.SrcPrefixes...)
	item.Match.DstPrefixes = append([]string(nil), item.Match.DstPrefixes...)
	item.Match.SrcPorts = append([]int(nil), item.Match.SrcPorts...)
	item.Match.DstPorts = append([]int(nil), item.Match.DstPorts...)
	item.Match.Features = append([]string(nil), item.Match.Features...)
	return item
}
