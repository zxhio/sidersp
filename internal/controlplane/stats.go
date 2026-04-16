package controlplane

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"sidersp/internal/config"
	"sidersp/internal/model"
	"sidersp/internal/rule"
)

type Stats struct {
	TotalRules     int                  `json:"total_rules"`
	EnabledRules   int                  `json:"enabled_rules"`
	RXPackets      uint64               `json:"rx_packets"`
	ParseFailed    uint64               `json:"parse_failed"`
	RuleCandidates uint64               `json:"rule_candidates"`
	MatchedRules   uint64               `json:"matched_rules"`
	RingbufDropped uint64               `json:"ringbuf_dropped"`
	Histories      []StatsHistorySeries `json:"histories"`
}

type StatsHistorySeries struct {
	Name   string       `json:"name"`
	Window string       `json:"window"`
	Step   string       `json:"step"`
	Points []StatsPoint `json:"points"`
}

type StatsPoint struct {
	Timestamp      time.Time `json:"timestamp"`
	TotalRules     int       `json:"total_rules"`
	EnabledRules   int       `json:"enabled_rules"`
	RXPackets      uint64    `json:"rx_packets"`
	ParseFailed    uint64    `json:"parse_failed"`
	RuleCandidates uint64    `json:"rule_candidates"`
	MatchedRules   uint64    `json:"matched_rules"`
	RingbufDropped uint64    `json:"ringbuf_dropped"`
}

func buildStatsRetention(plan []config.ParsedStatsHistoryWindow) (time.Duration, time.Duration, int) {
	collectStep := plan[0].Step
	keepWindow := plan[0].Window
	for _, item := range plan[1:] {
		if item.Step < collectStep {
			collectStep = item.Step
		}
		if item.Window > keepWindow {
			keepWindow = item.Window
		}
	}

	keepLimit := int(keepWindow / collectStep)
	if keepLimit <= 0 {
		keepLimit = 1
	}
	return collectStep, keepWindow, keepLimit
}

func newStats(rules rule.RuleSet, dpStats model.DataplaneStats) Stats {
	return Stats{
		TotalRules:     len(rules.Rules),
		EnabledRules:   len(enabledRuleSet(rules).Rules),
		RXPackets:      dpStats.RXPackets,
		ParseFailed:    dpStats.ParseFailed,
		RuleCandidates: dpStats.RuleCandidates,
		MatchedRules:   dpStats.MatchedRules,
		RingbufDropped: dpStats.RingbufDropped,
	}
}

func newStatsPoint(ts time.Time, item Stats) StatsPoint {
	return StatsPoint{
		Timestamp:      ts,
		TotalRules:     item.TotalRules,
		EnabledRules:   item.EnabledRules,
		RXPackets:      item.RXPackets,
		ParseFailed:    item.ParseFailed,
		RuleCandidates: item.RuleCandidates,
		MatchedRules:   item.MatchedRules,
		RingbufDropped: item.RingbufDropped,
	}
}

func (r *Runtime) runStatsCollector(ctx context.Context) {
	step := r.statsCollectStep
	if step <= 0 {
		return
	}

	r.collectStats(time.Now().UTC())

	ticker := time.NewTicker(step)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.collectStats(now.UTC())
		}
	}
}

func (r *Runtime) collectStats(now time.Time) {
	dpStats, err := r.stats.ReadStats()
	if err != nil {
		logrus.WithError(err).Warn("Fail to collect stats")
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	current := newStats(r.rules, dpStats)
	point := newStatsPoint(now.Truncate(r.statsCollectStep), current)
	r.appendRawStatsPoint(point)
	r.trimRawStatsHistory(point.Timestamp)
}

func (r *Runtime) appendRawStatsPoint(point StatsPoint) {
	if len(r.history) > 0 && r.history[len(r.history)-1].Timestamp.Equal(point.Timestamp) {
		r.history[len(r.history)-1] = point
		return
	}

	r.history = append(r.history, point)
}

func (r *Runtime) trimRawStatsHistory(now time.Time) {
	cutoff := now.Add(-r.statsKeepWindow)
	trimmed := make([]StatsPoint, 0, len(r.history))
	for _, item := range r.history {
		if item.Timestamp.Before(cutoff) {
			continue
		}
		trimmed = append(trimmed, item)
	}
	if len(trimmed) > r.statsKeepLimit {
		trimmed = append([]StatsPoint(nil), trimmed[len(trimmed)-r.statsKeepLimit:]...)
	}
	r.history = trimmed
}

func (r *Runtime) buildStatsHistory(now time.Time, current Stats, window string) ([]StatsHistorySeries, error) {
	plan, err := r.selectStatsHistoryWindow(window)
	if err != nil {
		return nil, err
	}

	return []StatsHistorySeries{
		{
			Name:   plan.Name,
			Window: plan.Window.String(),
			Step:   plan.Step.String(),
			Points: aggregateStatsPoints(r.history, now, plan, current),
		},
	}, nil
}

func (r *Runtime) selectStatsHistoryWindow(name string) (config.ParsedStatsHistoryWindow, error) {
	if len(r.statsPlan) == 0 {
		return config.ParsedStatsHistoryWindow{}, ErrStatsWindowNotFound
	}
	if name == "" {
		return r.statsPlan[0], nil
	}
	for _, item := range r.statsPlan {
		if item.Name == name {
			return item, nil
		}
	}
	return config.ParsedStatsHistoryWindow{}, fmt.Errorf("%w: %s", ErrStatsWindowNotFound, name)
}

func aggregateStatsPoints(history []StatsPoint, now time.Time, plan config.ParsedStatsHistoryWindow, current Stats) []StatsPoint {
	if len(history) == 0 {
		return nil
	}

	cutoff := now.Add(-plan.Window)
	points := make([]StatsPoint, 0, plan.Limit)
	for _, item := range history {
		if item.Timestamp.Before(cutoff) {
			continue
		}
		bucket := item
		bucket.Timestamp = item.Timestamp.Truncate(plan.Step)
		if len(points) > 0 && points[len(points)-1].Timestamp.Equal(bucket.Timestamp) {
			points[len(points)-1] = bucket
		} else {
			points = append(points, bucket)
		}
	}

	currentBucket := newStatsPoint(now.Truncate(plan.Step), current)
	if len(points) == 0 || !points[len(points)-1].Timestamp.Equal(currentBucket.Timestamp) {
		points = append(points, currentBucket)
	} else {
		points[len(points)-1] = currentBucket
	}

	if len(points) > plan.Limit {
		points = append([]StatsPoint(nil), points[len(points)-plan.Limit:]...)
	}
	return points
}

func (r *Runtime) StatsWindows() []string {
	out := make([]string, 0, len(r.statsPlan))
	for _, item := range r.statsPlan {
		out = append(out, item.Name)
	}
	return out
}
