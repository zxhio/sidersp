package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sidersp/internal/config"
	"sidersp/internal/model"
	"sidersp/internal/rule"
)

type testSyncer struct {
	last rule.RuleSet
}

func (s *testSyncer) ReplaceRules(set rule.RuleSet) error {
	s.last = cloneRuleSet(set)
	return nil
}

type testStreamer struct{}

func (testStreamer) RunEventStream(context.Context) error { return nil }

type testStatsReader struct {
	stats model.DataplaneStats
}

func (s testStatsReader) ReadStats() (model.DataplaneStats, error) { return s.stats, nil }

func TestSetRuleEnabledSyncsEnabledRulesOnly(t *testing.T) {
	t.Parallel()

	syncer := &testSyncer{}
	r := NewRuntime(config.Config{}, syncer, testStreamer{}, testStatsReader{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	got, err := r.SetRuleEnabled(2, true)
	if err != nil {
		t.Fatalf("SetRuleEnabled() error = %v", err)
	}

	if !got.Enabled {
		t.Fatal("SetRuleEnabled() returned disabled rule, want enabled")
	}
	if len(syncer.last.Rules) != 2 {
		t.Fatalf("synced rules = %d, want %d", len(syncer.last.Rules), 2)
	}
}

func TestGetRuleReturnsNotFound(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})
	_, err := r.GetRule(99)
	if err != ErrRuleNotFound {
		t.Fatalf("GetRule() error = %v, want %v", err, ErrRuleNotFound)
	}
}

func TestCreateRulePersistsAndSyncs(t *testing.T) {
	t.Parallel()

	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	syncer := &testSyncer{}
	r := NewRuntime(config.Config{
		ControlPlane: config.ControlPlaneConfig{RulesPath: rulesPath},
	}, syncer, testStreamer{}, testStatsReader{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	item, err := r.CreateRule(rule.Rule{
		ID:       2,
		Name:     "two",
		Enabled:  true,
		Priority: 20,
		Match:    rule.RuleMatch{DstPorts: []int{443}},
		Response: rule.RuleResponse{Action: "tcp_reset"},
	})
	if err != nil {
		t.Fatalf("CreateRule() error = %v", err)
	}
	if item.ID != 2 {
		t.Fatalf("created rule id = %d, want 2", item.ID)
	}
	if len(syncer.last.Rules) != 2 {
		t.Fatalf("synced rules = %d, want 2", len(syncer.last.Rules))
	}
	if _, err := os.Stat(rulesPath); err != nil {
		t.Fatalf("stat rules file: %v", err)
	}
}

func TestUpdateRuleConflict(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: true, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	_, err := r.UpdateRule(2, rule.Rule{
		ID:       1,
		Name:     "dup",
		Enabled:  true,
		Priority: 20,
		Response: rule.RuleResponse{Action: "tcp_reset"},
	})
	if !errors.Is(err, ErrRuleConflict) {
		t.Fatalf("UpdateRule() error = %v, want %v", err, ErrRuleConflict)
	}
}

func TestUpdateRuleAllowsChangingOwnID(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: true, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	updated, err := r.UpdateRule(1, rule.Rule{
		ID:       3,
		Name:     "three",
		Enabled:  true,
		Priority: 10,
		Response: rule.RuleResponse{Action: "tcp_reset"},
	})
	if err != nil {
		t.Fatalf("UpdateRule() error = %v", err)
	}
	if updated.ID != 3 {
		t.Fatalf("updated rule id = %d, want 3", updated.ID)
	}
	if r.rules.Rules[0].ID != 3 {
		t.Fatalf("first rule id = %d, want 3", r.rules.Rules[0].ID)
	}
	if r.rules.Rules[1].ID != 2 {
		t.Fatalf("second rule id = %d, want 2", r.rules.Rules[1].ID)
	}
}

func TestDeleteRuleRemovesAndSyncs(t *testing.T) {
	t.Parallel()

	syncer := &testSyncer{}
	r := NewRuntime(config.Config{}, syncer, testStreamer{}, testStatsReader{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	if err := r.DeleteRule(1); err != nil {
		t.Fatalf("DeleteRule() error = %v", err)
	}
	if len(r.rules.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(r.rules.Rules))
	}
	if len(syncer.last.Rules) != 0 {
		t.Fatalf("enabled synced rules = %d, want 0", len(syncer.last.Rules))
	}
}

func TestSetRuleEnabledPersistsAndSyncs(t *testing.T) {
	t.Parallel()

	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	syncer := &testSyncer{}
	r := NewRuntime(config.Config{
		ControlPlane: config.ControlPlaneConfig{RulesPath: rulesPath},
	}, syncer, testStreamer{}, testStatsReader{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	got, err := r.SetRuleEnabled(1, false)
	if err != nil {
		t.Fatalf("SetRuleEnabled() error = %v", err)
	}
	if got.Enabled {
		t.Fatal("SetRuleEnabled() returned enabled rule, want disabled")
	}
	if len(syncer.last.Rules) != 0 {
		t.Fatalf("enabled synced rules = %d, want 0", len(syncer.last.Rules))
	}

	set, err := LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if len(set.Rules) != 1 || set.Rules[0].Enabled {
		t.Fatalf("persisted rules = %+v, want one disabled rule", set.Rules)
	}
}

func TestStatsReturnsRuntimeAndDataplaneCounters(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{
		stats: model.DataplaneStats{
			RXPackets:         100,
			ParseFailed:       2,
			RuleCandidates:    40,
			MatchedRules:      7,
			RuleMatches:       map[uint32]uint64{1: 11},
			RingbufDropped:    1,
			XDPTX:             3,
			XskTX:             4,
			TXFailed:          5,
			XskFailed:         6,
			XskMetaFailed:     10,
			XskRedirectFailed: 11,
			RedirectTX:        7,
			RedirectFailed:    8,
			FibLookupFailed:   9,
		},
	})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	got, err := r.Stats("1d")
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if got.TotalRules != 2 || got.EnabledRules != 1 {
		t.Fatalf("rule stats = %+v, want total=2 enabled=1", got)
	}
	if got.Overview.TotalRules != 2 || got.Overview.EnabledRules != 1 {
		t.Fatalf("overview = %+v, want total=2 enabled=1", got.Overview)
	}
	if got.RXPackets != 100 || got.MatchedRules != 7 {
		t.Fatalf("dataplane stats = %+v, want rx=100 matched=7", got)
	}
	if got.XskFailed != 6 {
		t.Fatalf("xsk_failed = %d, want 6", got.XskFailed)
	}
	if got.XskMetaFailed != 10 || got.XskRedirectFailed != 11 {
		t.Fatalf("xsk breakdown = %+v, want meta=10 redirect=11", got)
	}
	if got.RedirectTX != 7 || got.RedirectFailed != 8 || got.FibLookupFailed != 9 {
		t.Fatalf("redirect stats = %+v, want redirect_tx=7 redirect_failed=8 fib_lookup_failed=9", got)
	}
	if got.Overview.PrimaryIssueStage != model.StatsStageXSKRedirect {
		t.Fatalf("primary issue stage = %q, want %q", got.Overview.PrimaryIssueStage, model.StatsStageXSKRedirect)
	}
	if len(got.Stages) != 7 {
		t.Fatalf("stages len = %d, want 7", len(got.Stages))
	}
	if got.Stages[5].Key != model.StatsStageXSKRedirect {
		t.Fatalf("xsk stage = %+v, want xsk_redirect stage", got.Stages[5])
	}
	if len(got.Histories) != 1 {
		t.Fatalf("histories len = %d, want 1", len(got.Histories))
	}
	if got.Histories[0].Name != "1d" {
		t.Fatalf("first history = %+v, want name=1d", got.Histories[0])
	}
	if len(got.StageHistories) != 1 {
		t.Fatalf("stage histories len = %d, want 1", len(got.StageHistories))
	}
	if got.StageHistories[0].Stages[5].Metrics[2].Key != model.StatsMetricXskMetaFailed {
		t.Fatalf("stage history xsk metric = %+v, want xsk_meta_failed metric", got.StageHistories[0].Stages[5].Metrics[2])
	}
}

func TestRuleMatchCountsReturnsPerRuleCounters(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{
		stats: model.DataplaneStats{
			RuleMatches: map[uint32]uint64{
				1: 8,
				2: 3,
			},
		},
	})

	got, err := r.RuleMatchCounts()
	if err != nil {
		t.Fatalf("RuleMatchCounts() error = %v", err)
	}
	if got[1] != 8 || got[2] != 3 {
		t.Fatalf("RuleMatchCounts() = %+v, want rule 1=8 rule 2=3", got)
	}
}

func TestStatsRejectsUnknownWindow(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})

	_, err := r.Stats("bad")
	if !errors.Is(err, ErrStatsWindowNotFound) {
		t.Fatalf("Stats() error = %v, want %v", err, ErrStatsWindowNotFound)
	}
}

func TestStatsWindowsReturnsConfiguredWindows(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})

	got := r.StatsWindows()
	if len(got) != 3 {
		t.Fatalf("StatsWindows len = %d, want 3", len(got))
	}
	if got[0] != "10min" || got[1] != "1d" || got[2] != "30d" {
		t.Fatalf("StatsWindows = %+v, want default windows", got)
	}
}

func TestTrimRawStatsHistoryDropsExpiredPoints(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})
	r.history = []StatsPoint{
		{Timestamp: now.Add(-(10 * time.Minute) - (20 * time.Second)), RXPackets: 1},
		{Timestamp: now.Add(-time.Minute).Truncate(10 * time.Second), RXPackets: 2},
		{Timestamp: now, RXPackets: 3},
	}
	r.statsKeepWindow = 10 * time.Minute
	r.statsKeepLimit = 60

	r.trimRawStatsHistory(now)

	if len(r.history) != 2 {
		t.Fatalf("history len = %d, want 2", len(r.history))
	}
	if r.history[0].RXPackets != 2 || r.history[1].RXPackets != 3 {
		t.Fatalf("history = %+v, want rx_packets [2,3]", r.history)
	}
}

func TestTrimRawStatsHistoryKeepsMaxCount(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})
	r.statsKeepWindow = time.Hour
	r.statsKeepLimit = 3
	r.history = make([]StatsPoint, 0, 5)
	for i := 0; i < 5; i++ {
		r.appendRawStatsPoint(StatsPoint{
			Timestamp: now.Add(time.Duration(i) * 10 * time.Second),
			RXPackets: uint64(i),
		})
	}
	r.trimRawStatsHistory(now.Add(40 * time.Second))

	if len(r.history) != 3 {
		t.Fatalf("history len = %d, want 3", len(r.history))
	}
	if r.history[0].RXPackets != 2 {
		t.Fatalf("first point = %+v, want rx_packets=2", r.history[0])
	}
}

func TestAppendRawStatsPointMergesSameBucket(t *testing.T) {
	t.Parallel()

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{}, testStatsReader{})
	base := time.Date(2026, 4, 16, 12, 34, 56, 0, time.UTC)

	r.appendRawStatsPoint(StatsPoint{Timestamp: base, RXPackets: 1})
	r.appendRawStatsPoint(StatsPoint{Timestamp: base, RXPackets: 2})

	if len(r.history) != 1 {
		t.Fatalf("history len = %d, want 1", len(r.history))
	}
	if r.history[0].RXPackets != 2 {
		t.Fatalf("point[0] = %+v, want rx_packets=2", r.history[0])
	}
}

func TestAggregateStatsPointsUsesWindowStepAndLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)
	history := []StatsPoint{
		{Timestamp: now.Add(-20 * time.Minute), RXPackets: 1},
		{Timestamp: now.Add(-9 * time.Minute), RXPackets: 2},
		{Timestamp: now.Add(-8 * time.Minute), RXPackets: 3},
		{Timestamp: now.Add(-2 * time.Minute), RXPackets: 4},
	}
	plan := config.ParsedStatsHistoryWindow{Name: "recent", Window: 10 * time.Minute, Step: 5 * time.Minute, Limit: 2}
	current := Stats{RXPackets: 5}

	points := aggregateStatsPoints(history, now, plan, current)

	if len(points) != 2 {
		t.Fatalf("points len = %d, want 2", len(points))
	}
	if points[0].RXPackets != 4 || points[1].RXPackets != 5 {
		t.Fatalf("points = %+v, want rx_packets [4,5]", points)
	}
}
