package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sidersp/internal/model"
	"sidersp/internal/rule"
)

type testSyncer struct {
	last  rule.RuleSet
	err   error
	calls int
}

func (s *testSyncer) ReplaceRules(set rule.RuleSet) error {
	s.calls++
	if s.err != nil {
		return s.err
	}
	s.last = cloneRuleSet(set)
	return nil
}

type testStreamer struct{}

func (testStreamer) RunEventStream(context.Context) error { return nil }

type testStatsReader struct {
	stats      model.RuntimeStats
	resetErr   error
	resetCalls *int
}

func (s testStatsReader) ReadStats() (model.RuntimeStats, error) { return s.stats, nil }
func (s testStatsReader) ResetStats() error {
	if s.resetCalls != nil {
		*s.resetCalls = *s.resetCalls + 1
	}
	return s.resetErr
}

func newTestRuntime(t testing.TB, opts Options, syncer RuleSyncer, streamer EventStreamer, statsReader StatsReader) *Runtime {
	t.Helper()

	opts = normalizeOptions(opts)
	runtime, err := NewRuntime(opts, syncer, streamer, statsReader, nil)
	if err != nil {
		t.Fatalf("NewRuntime() error = %v", err)
	}
	return runtime
}

func testRuntimeRuleSet() rule.RuleSet {
	return rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}
}

func TestSetRuleEnabledSyncsEnabledRulesOnly(t *testing.T) {
	t.Parallel()

	syncer := &testSyncer{}
	r := newTestRuntime(t, Options{}, syncer, testStreamer{}, testStatsReader{})
	r.rules = testRuntimeRuleSet()

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

func TestSetRuleEnabledKeepsCurrentRulesOnPersistFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("block"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	rulesPath := filepath.Join(blocker, "rules.yaml")
	syncer := &testSyncer{}
	r := newTestRuntime(t, Options{RulesPath: rulesPath}, syncer, testStreamer{}, testStatsReader{})
	r.rules = testRuntimeRuleSet()

	_, err := r.SetRuleEnabled(2, true)
	if err == nil {
		t.Fatal("SetRuleEnabled() error = nil, want persist error")
	}
	if r.rules.Rules[1].Enabled {
		t.Fatalf("rules = %+v, want current rules unchanged after persist failure", r.rules.Rules)
	}
	if syncer.calls != 0 {
		t.Fatalf("sync calls = %d, want 0 after persist failure", syncer.calls)
	}
}

func TestSetRuleEnabledKeepsCurrentRulesOnSyncFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("sync failed")
	syncer := &testSyncer{err: wantErr}
	r := newTestRuntime(t, Options{}, syncer, testStreamer{}, testStatsReader{})
	r.rules = testRuntimeRuleSet()

	_, err := r.SetRuleEnabled(2, true)
	if !errors.Is(err, wantErr) {
		t.Fatalf("SetRuleEnabled() error = %v, want %v", err, wantErr)
	}
	if r.rules.Rules[1].Enabled {
		t.Fatalf("rules = %+v, want current rules unchanged after sync failure", r.rules.Rules)
	}
}

func TestBootstrapPersistsAssignedRuleIDs(t *testing.T) {
	t.Parallel()

	rulesPath := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(rulesPath, []byte(`rules:
  - name: one
    enabled: true
    priority: 10
    response:
      action: tcp_reset
`), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}

	syncer := &testSyncer{}
	r := newTestRuntime(t, Options{RulesPath: rulesPath}, syncer, testStreamer{}, testStatsReader{})

	set, err := r.bootstrap()
	if err != nil {
		t.Fatalf("bootstrap() error = %v", err)
	}
	if len(set.Rules) != 1 || set.Rules[0].ID != 1 {
		t.Fatalf("bootstrapped rules = %+v, want one rule id 1", set.Rules)
	}
	if len(syncer.last.Rules) != 1 || syncer.last.Rules[0].ID != 1 {
		t.Fatalf("synced rules = %+v, want one rule id 1", syncer.last.Rules)
	}

	persisted, err := LoadRules(rulesPath)
	if err != nil {
		t.Fatalf("LoadRules() error = %v", err)
	}
	if len(persisted.Rules) != 1 || persisted.Rules[0].ID != 1 {
		t.Fatalf("persisted rules = %+v, want one rule id 1", persisted.Rules)
	}
}

func TestStatsReturnsRuntimeAndDataplaneCounters(t *testing.T) {
	t.Parallel()

	r := newTestRuntime(t, Options{}, &testSyncer{}, testStreamer{}, testStatsReader{
		stats: model.RuntimeStats{
			Dataplane: model.DataplaneStats{
				RXPackets:            100,
				ParseFailed:          2,
				RuleCandidates:       40,
				MatchedRules:         7,
				RuleMatches:          map[uint32]uint64{1: 11},
				RingbufDropped:       1,
				XDPTX:                3,
				TXFailed:             5,
				XskRedirected:        4,
				XskRedirectFailed:    6,
				XskMetaFailed:        10,
				XskMapRedirectFailed: 11,
				RedirectTX:           7,
				RedirectFailed:       8,
				FibLookupFailed:      9,
			},
			Response: model.ResponseStats{
				ResponseSent:     12,
				ResponseFailed:   20,
				AFXDPTX:          12,
				AFXDPTXFailed:    20,
				AFPacketTX:       0,
				AFPacketTXFailed: 0,
			},
		},
	})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "tcp_reset"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}},
		},
	}

	got, err := r.Stats(600)
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if got.TotalRules != 2 || got.EnabledRules != 1 {
		t.Fatalf("rule stats = %+v, want total=2 enabled=1", got)
	}
	if got.Overview.TotalRules != 2 || got.Overview.EnabledRules != 1 {
		t.Fatalf("overview = %+v, want total=2 enabled=1", got.Overview)
	}
	if got.RangeSeconds != 600 || got.CollectIntervalSeconds != 10 || got.DisplayStepSeconds != 10 {
		t.Fatalf("stats timing = %+v, want range=600 collect=10 display=10", got)
	}
	if got.RXPackets != 100 || got.MatchedRules != 7 {
		t.Fatalf("dataplane stats = %+v, want rx=100 matched=7", got)
	}
	if got.XskRedirected != 4 {
		t.Fatalf("xsk_redirected = %d, want 4", got.XskRedirected)
	}
	if got.XskRedirectFailed != 6 || got.XskMetaFailed != 10 || got.XskMapRedirectFailed != 11 {
		t.Fatalf("response redirect breakdown = %+v, want failed=6 meta=10 map=11", got)
	}
	if got.RedirectTX != 7 || got.RedirectFailed != 8 || got.FibLookupFailed != 9 {
		t.Fatalf("redirect stats = %+v, want redirect_tx=7 redirect_failed=8 fib_lookup_failed=9", got)
	}
	if got.ResponseSent != 12 || got.ResponseFailed != 20 || got.AFXDPTX != 12 || got.AFXDPTXFailed != 20 {
		t.Fatalf("response stats = %+v, want response/afxdp counters copied", got)
	}
	if got.Overview.PrimaryIssueStage != model.StatsStageResponseTX {
		t.Fatalf("primary issue stage = %q, want %q", got.Overview.PrimaryIssueStage, model.StatsStageResponseTX)
	}
	if len(got.Stages) != 8 {
		t.Fatalf("stages len = %d, want 8", len(got.Stages))
	}
	if got.Stages[5].Key != model.StatsStageResponseRedirect {
		t.Fatalf("response redirect stage = %+v, want response_redirect stage", got.Stages[5])
	}
	if got.Stages[5].PrimaryMetricKey != model.StatsMetricXskRedirected {
		t.Fatalf("response redirect stage = %+v, want primary metric xsk_redirected", got.Stages[5])
	}
	if got.Stages[7].Key != model.StatsStageResponseTX || got.Stages[7].PrimaryMetricKey != model.StatsMetricResponseSent {
		t.Fatalf("response tx stage = %+v, want response_tx response_sent", got.Stages[7])
	}
	if len(got.Histories) != 1 {
		t.Fatalf("histories len = %d, want 1", len(got.Histories))
	}
	if got.Histories[0].Window != "10m0s" {
		t.Fatalf("first history = %+v, want window=10m0s", got.Histories[0])
	}
	if len(got.StageHistories) != 1 {
		t.Fatalf("stage histories len = %d, want 1", len(got.StageHistories))
	}
	if got.StageHistories[0].Stages[5].Metrics[2].Key != model.StatsMetricXskMetaFailed {
		t.Fatalf("stage history response redirect metric = %+v, want xsk_meta_failed metric", got.StageHistories[0].Stages[5].Metrics[2])
	}
	if got.StageHistories[0].Stages[7].Metrics[0].Key != model.StatsMetricResponseSent {
		t.Fatalf("stage history response tx metric = %+v, want response_sent metric", got.StageHistories[0].Stages[7].Metrics[0])
	}
}

func TestRuleMatchCountsReturnsPerRuleCounters(t *testing.T) {
	t.Parallel()

	r := newTestRuntime(t, Options{}, &testSyncer{}, testStreamer{}, testStatsReader{
		stats: model.RuntimeStats{
			Dataplane: model.DataplaneStats{
				RuleMatches: map[uint32]uint64{
					1: 8,
					2: 3,
				},
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

func TestStatsRejectsInvalidRange(t *testing.T) {
	t.Parallel()

	r := newTestRuntime(t, Options{}, &testSyncer{}, testStreamer{}, testStatsReader{})

	_, err := r.Stats(601)
	if !errors.Is(err, ErrStatsRangeInvalid) {
		t.Fatalf("Stats() error = %v, want %v", err, ErrStatsRangeInvalid)
	}
}

func TestResetStatsClearsHistoryAndCallsReader(t *testing.T) {
	t.Parallel()

	resetCalls := 0
	r := newTestRuntime(t, Options{}, &testSyncer{}, testStreamer{}, testStatsReader{
		resetCalls: &resetCalls,
	})
	r.history = []StatsPoint{{Timestamp: time.Now().UTC(), RXPackets: 9}}

	if err := r.ResetStats(); err != nil {
		t.Fatalf("ResetStats() error = %v", err)
	}
	if resetCalls != 1 {
		t.Fatalf("reset calls = %d, want 1", resetCalls)
	}
	if len(r.history) != 0 {
		t.Fatalf("history len = %d, want 0", len(r.history))
	}
}
