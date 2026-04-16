package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"sidersp/internal/config"
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

func TestSetRuleEnabledSyncsEnabledRulesOnly(t *testing.T) {
	t.Parallel()

	syncer := &testSyncer{}
	r := NewRuntime(config.Config{}, syncer, testStreamer{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "RST"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "RST"}},
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

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{})
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
	}, syncer, testStreamer{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "RST"}},
		},
	}

	item, err := r.CreateRule(rule.Rule{
		ID:       2,
		Name:     "two",
		Enabled:  true,
		Priority: 20,
		Match:    rule.RuleMatch{DstPorts: []int{443}},
		Response: rule.RuleResponse{Action: "RST"},
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

	r := NewRuntime(config.Config{}, &testSyncer{}, testStreamer{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "RST"}},
			{ID: 2, Name: "two", Enabled: true, Priority: 20, Response: rule.RuleResponse{Action: "RST"}},
		},
	}

	_, err := r.UpdateRule(2, rule.Rule{
		ID:       1,
		Name:     "dup",
		Enabled:  true,
		Priority: 20,
		Response: rule.RuleResponse{Action: "RST"},
	})
	if !errors.Is(err, ErrRuleConflict) {
		t.Fatalf("UpdateRule() error = %v, want %v", err, ErrRuleConflict)
	}
}

func TestDeleteRuleRemovesAndSyncs(t *testing.T) {
	t.Parallel()

	syncer := &testSyncer{}
	r := NewRuntime(config.Config{}, syncer, testStreamer{})
	r.rules = rule.RuleSet{
		Rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true, Priority: 10, Response: rule.RuleResponse{Action: "RST"}},
			{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "RST"}},
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
