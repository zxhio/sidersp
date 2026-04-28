package controlplane

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"sidersp/internal/logs"
	"sidersp/internal/model"
	"sidersp/internal/rule"
)

var ErrRuleNotFound = fmt.Errorf("rule not found")
var ErrRuleConflict = fmt.Errorf("rule conflict")
var ErrStatsRangeInvalid = fmt.Errorf("stats range invalid")

type RuleSyncer interface {
	ReplaceRules(rule.RuleSet) error
}

type EventStreamer interface {
	RunEventStream(context.Context) error
}

type StatsReader interface {
	ReadStats() (model.RuntimeStats, error)
	ResetStats() error
}

type Runtime struct {
	opts     Options
	syncer   RuleSyncer
	streamer EventStreamer
	stats    StatsReader
	mu       sync.RWMutex
	rules    rule.RuleSet
	history  []StatsPoint
}

func NewRuntime(opts Options, syncer RuleSyncer, streamer EventStreamer, statsReader StatsReader) (*Runtime, error) {
	if syncer == nil {
		return nil, fmt.Errorf("controlplane: syncer is required")
	}
	if streamer == nil {
		return nil, fmt.Errorf("controlplane: streamer is required")
	}
	if statsReader == nil {
		return nil, fmt.Errorf("controlplane: stats reader is required")
	}
	if err := validateOptions(opts); err != nil {
		return nil, fmt.Errorf("controlplane: invalid options: %w", err)
	}

	return &Runtime{
		opts:     opts,
		syncer:   syncer,
		streamer: streamer,
		stats:    statsReader,
	}, nil
}

func (r *Runtime) bootstrap() (rule.RuleSet, error) {
	rules, changed, err := loadRulesFile(r.opts.RulesPath)
	if err != nil {
		return rule.RuleSet{}, fmt.Errorf("load rules: %w", err)
	}
	if changed {
		if err := r.persistRules(rules); err != nil {
			return rule.RuleSet{}, err
		}
	}

	if err := r.syncRules(rules); err != nil {
		return rule.RuleSet{}, fmt.Errorf("sync rules to dataplane: %w", err)
	}

	r.mu.Lock()
	r.rules = cloneRuleSet(rules)
	r.mu.Unlock()

	logs.App().WithFields(logrus.Fields{
		"rules":      len(enabledRuleSet(rules).Rules),
		"rules_path": r.opts.RulesPath,
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

	logs.App().WithField("rules", len(rules.Rules)).Info("Started controlplane runtime")

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		r.runStatsCollector(runCtx)
	}()

	err = r.streamer.RunEventStream(runCtx)
	cancel()
	<-statsDone
	if err != nil {
		return fmt.Errorf("start event stream: %w", err)
	}
	return nil
}

func (r *Runtime) RuleStatus() RuleStatus {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return newRuleStatus(r.opts, r.rules)
}

func (r *Runtime) Stats(rangeSeconds int) (Stats, error) {
	runtimeStats, err := r.stats.ReadStats()
	if err != nil {
		return Stats{}, fmt.Errorf("read runtime stats: %w", err)
	}

	rangeDuration, err := normalizeStatsRange(rangeSeconds, r.opts.StatsCollectStep, r.opts.StatsKeepWindow)
	if err != nil {
		return Stats{}, err
	}
	query := buildStatsQuery(rangeDuration, r.opts.StatsCollectStep)

	r.mu.Lock()
	defer r.mu.Unlock()

	current := newStats(r.rules, runtimeStats)
	current.RangeSeconds = int(rangeDuration / time.Second)
	current.CollectIntervalSeconds = int(r.opts.StatsCollectStep / time.Second)
	current.RetentionSeconds = int(r.opts.StatsKeepWindow / time.Second)
	current.DisplayStepSeconds = int(query.Step / time.Second)

	history, err := r.buildStatsHistory(time.Now().UTC(), current, query)
	if err != nil {
		return Stats{}, err
	}
	stageHistory, err := r.buildDiagnosticHistory(time.Now().UTC(), current, query)
	if err != nil {
		return Stats{}, err
	}
	current.Histories = history
	current.StageHistories = stageHistory

	return current, nil
}

func (r *Runtime) ResetStats() error {
	if err := r.stats.ResetStats(); err != nil {
		return fmt.Errorf("reset runtime stats: %w", err)
	}

	r.mu.Lock()
	r.history = nil
	r.mu.Unlock()

	return nil
}

func (r *Runtime) RuleMatchCounts() (map[int]uint64, error) {
	runtimeStats, err := r.stats.ReadStats()
	if err != nil {
		return nil, fmt.Errorf("read runtime stats: %w", err)
	}

	counts := make(map[int]uint64, len(runtimeStats.Dataplane.RuleMatches))
	for ruleID, matchedCount := range runtimeStats.Dataplane.RuleMatches {
		counts[int(ruleID)] = matchedCount
	}
	return counts, nil
}

type RuleStatus struct {
	RulesPath  string `json:"rules_path"`
	TotalRules int    `json:"total_rules"`
	Enabled    int    `json:"enabled_rules"`
}

func newRuleStatus(opts Options, rules rule.RuleSet) RuleStatus {
	return RuleStatus{
		RulesPath:  opts.RulesPath,
		TotalRules: len(rules.Rules),
		Enabled:    len(enabledRuleSet(rules).Rules),
	}
}

type Status struct {
	RulesPath   string `json:"rules_path"`
	ListenAddr  string `json:"listen_addr"`
	Interface   string `json:"interface"`
	TXInterface string `json:"tx_interface"`
	TotalRules  int    `json:"total_rules"`
	Enabled     int    `json:"enabled_rules"`
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

		if next.Rules[idx].Enabled == enabled {
			return cloneRule(next.Rules[idx]), nil
		}

		next.Rules[idx].Enabled = enabled
		if err := r.persistRules(next); err != nil {
			return rule.Rule{}, err
		}
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
	existingIDs := make(map[int]struct{}, len(next.Rules))
	for _, existing := range next.Rules {
		existingIDs[existing.ID] = struct{}{}
		if existing.ID == item.ID {
			return rule.Rule{}, ErrRuleConflict
		}
	}

	next.Rules = append(next.Rules, cloneRule(item))
	if err := normalizeRuleSet(&next); err != nil {
		return rule.Rule{}, err
	}

	createdID := item.ID
	if createdID == 0 {
		for _, current := range next.Rules {
			if _, ok := existingIDs[current.ID]; ok {
				continue
			}
			createdID = current.ID
			break
		}
	}
	if err := r.persistRules(next); err != nil {
		return rule.Rule{}, err
	}
	if err := r.syncRules(next); err != nil {
		return rule.Rule{}, err
	}

	r.rules = next
	return r.findRuleLocked(createdID)
}

func (r *Runtime) UpdateRule(id int, item rule.Rule) (rule.Rule, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	item.ID = id
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
	return r.findRuleLocked(id)
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
	if r.opts.RulesPath == "" {
		return nil
	}
	if err := SaveRules(r.opts.RulesPath, rules); err != nil {
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
	if item.Match.ICMP != nil {
		icmp := *item.Match.ICMP
		item.Match.ICMP = &icmp
	}
	if item.Match.ARP != nil {
		arp := *item.Match.ARP
		item.Match.ARP = &arp
	}
	if len(item.Response.Params) > 0 {
		params := make(map[string]interface{}, len(item.Response.Params))
		for key, value := range item.Response.Params {
			params[key] = value
		}
		item.Response.Params = params
	}
	return item
}
