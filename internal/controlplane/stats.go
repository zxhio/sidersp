package controlplane

import (
	"context"
	"fmt"
	"time"

	"sidersp/internal/config"
	"sidersp/internal/logs"
	"sidersp/internal/model"
	"sidersp/internal/rule"
)

type Stats struct {
	Overview               StatsOverview             `json:"overview"`
	RangeSeconds           int                       `json:"range_seconds"`
	CollectIntervalSeconds int                       `json:"collect_interval_seconds"`
	RetentionSeconds       int                       `json:"retention_seconds"`
	DisplayStepSeconds     int                       `json:"display_step_seconds"`
	TotalRules             int                       `json:"total_rules"`
	EnabledRules           int                       `json:"enabled_rules"`
	RXPackets              uint64                    `json:"rx_packets"`
	ParseFailed            uint64                    `json:"parse_failed"`
	RuleCandidates         uint64                    `json:"rule_candidates"`
	MatchedRules           uint64                    `json:"matched_rules"`
	RingbufDropped         uint64                    `json:"ringbuf_dropped"`
	XDPTX                  uint64                    `json:"xdp_tx"`
	TXFailed               uint64                    `json:"tx_failed"`
	XskRedirected          uint64                    `json:"xsk_redirected"`
	XskRedirectFailed      uint64                    `json:"xsk_redirect_failed"`
	XskMetaFailed          uint64                    `json:"xsk_meta_failed"`
	XskMapRedirectFailed   uint64                    `json:"xsk_map_redirect_failed"`
	RedirectTX             uint64                    `json:"redirect_tx"`
	RedirectFailed         uint64                    `json:"redirect_failed"`
	FibLookupFailed        uint64                    `json:"fib_lookup_failed"`
	ResponseSent           uint64                    `json:"response_sent"`
	ResponseFailed         uint64                    `json:"response_failed"`
	AFXDPTX                uint64                    `json:"afxdp_tx"`
	AFXDPTXFailed          uint64                    `json:"afxdp_tx_failed"`
	AFPacketTX             uint64                    `json:"afpacket_tx"`
	AFPacketTXFailed       uint64                    `json:"afpacket_tx_failed"`
	Stages                 []DiagnosticStage         `json:"stages"`
	Histories              []StatsHistorySeries      `json:"histories"`
	StageHistories         []DiagnosticHistorySeries `json:"stage_histories"`
}

type StatsOverview struct {
	TotalRules        int    `json:"total_rules"`
	EnabledRules      int    `json:"enabled_rules"`
	RXPackets         uint64 `json:"rx_packets"`
	MatchedRules      uint64 `json:"matched_rules"`
	PrimaryIssueStage string `json:"primary_issue_stage,omitempty"`
}

type DiagnosticStage struct {
	Key              string             `json:"key"`
	Title            string             `json:"title"`
	Summary          string             `json:"summary"`
	PrimaryMetricKey string             `json:"primary_metric_key"`
	Metrics          []DiagnosticMetric `json:"metrics"`
}

type DiagnosticMetric struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Role        string `json:"role"`
	Value       uint64 `json:"value"`
}

type StatsHistorySeries struct {
	Name   string       `json:"name"`
	Window string       `json:"window"`
	Step   string       `json:"step"`
	Points []StatsPoint `json:"points"`
}

type DiagnosticHistorySeries struct {
	Name   string                   `json:"name"`
	Window string                   `json:"window"`
	Step   string                   `json:"step"`
	Stages []DiagnosticStageHistory `json:"stages"`
}

type DiagnosticStageHistory struct {
	Key              string                    `json:"key"`
	Title            string                    `json:"title"`
	Summary          string                    `json:"summary"`
	PrimaryMetricKey string                    `json:"primary_metric_key"`
	Metrics          []DiagnosticMetricHistory `json:"metrics"`
}

type DiagnosticMetricHistory struct {
	Key         string        `json:"key"`
	Label       string        `json:"label"`
	Description string        `json:"description"`
	Role        string        `json:"role"`
	Points      []MetricPoint `json:"points"`
}

type MetricPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     uint64    `json:"value"`
}

type StatsPoint struct {
	Timestamp            time.Time `json:"timestamp"`
	TotalRules           int       `json:"total_rules"`
	EnabledRules         int       `json:"enabled_rules"`
	RXPackets            uint64    `json:"rx_packets"`
	ParseFailed          uint64    `json:"parse_failed"`
	RuleCandidates       uint64    `json:"rule_candidates"`
	MatchedRules         uint64    `json:"matched_rules"`
	RingbufDropped       uint64    `json:"ringbuf_dropped"`
	XDPTX                uint64    `json:"xdp_tx"`
	TXFailed             uint64    `json:"tx_failed"`
	XskRedirected        uint64    `json:"xsk_redirected"`
	XskRedirectFailed    uint64    `json:"xsk_redirect_failed"`
	XskMetaFailed        uint64    `json:"xsk_meta_failed"`
	XskMapRedirectFailed uint64    `json:"xsk_map_redirect_failed"`
	RedirectTX           uint64    `json:"redirect_tx"`
	RedirectFailed       uint64    `json:"redirect_failed"`
	FibLookupFailed      uint64    `json:"fib_lookup_failed"`
	ResponseSent         uint64    `json:"response_sent"`
	ResponseFailed       uint64    `json:"response_failed"`
	AFXDPTX              uint64    `json:"afxdp_tx"`
	AFXDPTXFailed        uint64    `json:"afxdp_tx_failed"`
	AFPacketTX           uint64    `json:"afpacket_tx"`
	AFPacketTXFailed     uint64    `json:"afpacket_tx_failed"`
}

type StatsQuery struct {
	Range time.Duration
	Step  time.Duration
	Limit int
}

const (
	minStatsRangeSeconds  = 600
	maxStatsDisplayPoints = 96
)

type stageDescriptor struct {
	Key              string
	Title            string
	Summary          string
	PrimaryMetricKey string
	Metrics          []metricDescriptor
}

type metricDescriptor struct {
	Key         string
	Label       string
	Description string
	Role        string
}

var diagnosticStageDescriptors = []stageDescriptor{
	{
		Key:              model.StatsStageIngress,
		Title:            "收包",
		Summary:          "入口收包基线，判断流量是否进入数据面。",
		PrimaryMetricKey: model.StatsMetricRXPackets,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricRXPackets, Label: "收包数", Description: "进入数据面的原始报文总数。", Role: model.MetricRoleTraffic},
		},
	},
	{
		Key:              model.StatsStageParse,
		Title:            "解析",
		Summary:          "解析头部和协议字段，判断报文是否能进入规则匹配。",
		PrimaryMetricKey: model.StatsMetricParseFailed,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricParseFailed, Label: "解析失败", Description: "报文格式不支持或头部不完整，无法进入匹配。", Role: model.MetricRoleFailure},
		},
	},
	{
		Key:              model.StatsStageMatch,
		Title:            "匹配",
		Summary:          "从候选规则到最终命中，判断规则筛选链路是否正常。",
		PrimaryMetricKey: model.StatsMetricMatchedRules,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricRuleCandidates, Label: "候选规则", Description: "通过索引预筛选进入逐条判断的候选规则数。", Role: model.MetricRoleTraffic},
			{Key: model.StatsMetricMatchedRules, Label: "规则命中", Description: "最终命中的规则次数。", Role: model.MetricRoleSuccess},
		},
	},
	{
		Key:              model.StatsStageObserve,
		Title:            "观测",
		Summary:          "输出观测事件，判断 ringbuf 是否成为诊断盲点。",
		PrimaryMetricKey: model.StatsMetricRingbufDropped,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricRingbufDropped, Label: "观测丢弃", Description: "ringbuf 满或保留失败导致的观测事件丢失。", Role: model.MetricRoleFailure},
		},
	},
	{
		Key:              model.StatsStageTXSameInterface,
		Title:            "同口发送",
		Summary:          "BPF 直接在入口网卡发送响应，主要对应 tcp_reset 和 icmp_port_unreachable。",
		PrimaryMetricKey: model.StatsMetricXDPTX,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricXDPTX, Label: "同口发送成功", Description: "BPF 通过 XDP_TX 提交发送的次数。", Role: model.MetricRoleSuccess},
			{Key: model.StatsMetricTXFailed, Label: "同口发送失败", Description: "BPF 构造或发送同口响应失败的次数。", Role: model.MetricRoleFailure},
		},
	},
	{
		Key:              model.StatsStageResponseRedirect,
		Title:            "响应重定向",
		Summary:          "BPF 把原始报文重定向到 XSK，由用户态响应模块继续处理。",
		PrimaryMetricKey: model.StatsMetricXskRedirected,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricXskRedirected, Label: "重定向到响应模块", Description: "BPF 成功把原始报文提交到 XSK 的次数。", Role: model.MetricRoleSuccess},
			{Key: model.StatsMetricXskRedirectFailed, Label: "响应重定向失败", Description: "XSK 重定向阶段总失败次数。", Role: model.MetricRoleFailure},
			{Key: model.StatsMetricXskMetaFailed, Label: "XSK 元数据失败", Description: "申请或写入 XDP metadata 失败的次数。", Role: model.MetricRoleFailure},
			{Key: model.StatsMetricXskMapRedirectFailed, Label: "XSK 映射重定向失败", Description: "调用 bpf_redirect_map() 提交到 XSK 失败的次数。", Role: model.MetricRoleFailure},
		},
	},
	{
		Key:              model.StatsStageRedirectEgress,
		Title:            "转发出口",
		Summary:          "把响应重定向到指定出口网卡，主要用于 egress redirect 路径。",
		PrimaryMetricKey: model.StatsMetricRedirectTX,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricRedirectTX, Label: "出口重定向成功", Description: "BPF 成功把响应提交到出口网卡的次数。", Role: model.MetricRoleSuccess},
			{Key: model.StatsMetricRedirectFailed, Label: "出口重定向失败", Description: "重定向准备阶段失败的次数。", Role: model.MetricRoleFailure},
			{Key: model.StatsMetricFibLookupFailed, Label: "FIB 查询失败", Description: "出口重定向所需的 FIB 查询失败次数。", Role: model.MetricRoleFailure},
		},
	},
	{
		Key:              model.StatsStageResponseTX,
		Title:            "响应发送",
		Summary:          "用户态响应模块构造并发送响应帧，区分 AF_XDP 和 AF_PACKET backend。",
		PrimaryMetricKey: model.StatsMetricResponseSent,
		Metrics: []metricDescriptor{
			{Key: model.StatsMetricResponseSent, Label: "响应发送成功", Description: "用户态响应模块成功发送响应帧的总次数。", Role: model.MetricRoleSuccess},
			{Key: model.StatsMetricResponseFailed, Label: "响应发送失败", Description: "用户态响应模块发送失败的总次数。", Role: model.MetricRoleFailure},
			{Key: model.StatsMetricAFXDPTX, Label: "AF_XDP 发送成功", Description: "通过 AF_XDP backend 成功发送响应帧的次数。", Role: model.MetricRoleSuccess},
			{Key: model.StatsMetricAFXDPTXFailed, Label: "AF_XDP 发送失败", Description: "AF_XDP backend 路径失败的次数。", Role: model.MetricRoleFailure},
			{Key: model.StatsMetricAFPacketTX, Label: "AF_PACKET 发送成功", Description: "通过 AF_PACKET backend 成功发送响应帧的次数。", Role: model.MetricRoleSuccess},
			{Key: model.StatsMetricAFPacketTXFailed, Label: "AF_PACKET 发送失败", Description: "AF_PACKET backend 路径失败的次数。", Role: model.MetricRoleFailure},
		},
	},
}

func buildStatsRetention(cfg config.ParsedConsoleStatsConfig) (time.Duration, time.Duration, int) {
	keepLimit := int(cfg.Retention / cfg.CollectInterval)
	if cfg.Retention%cfg.CollectInterval != 0 {
		keepLimit++
	}
	if keepLimit <= 0 {
		keepLimit = 1
	}
	return cfg.CollectInterval, cfg.Retention, keepLimit
}

func newStats(rules rule.RuleSet, runtimeStats model.RuntimeStats) Stats {
	counters := runtimeStats.Counters()
	stages := buildDiagnosticStages(counters)
	totalRules := len(rules.Rules)
	enabledRules := len(enabledRuleSet(rules).Rules)

	return Stats{
		Overview:             buildStatsOverview(totalRules, enabledRules, counters, stages),
		TotalRules:           totalRules,
		EnabledRules:         enabledRules,
		RXPackets:            counters.Dataplane.RXPackets,
		ParseFailed:          counters.Dataplane.ParseFailed,
		RuleCandidates:       counters.Dataplane.RuleCandidates,
		MatchedRules:         counters.Dataplane.MatchedRules,
		RingbufDropped:       counters.Dataplane.RingbufDropped,
		XDPTX:                counters.Dataplane.XDPTX,
		TXFailed:             counters.Dataplane.TXFailed,
		XskRedirected:        counters.Dataplane.XskRedirected,
		XskRedirectFailed:    counters.Dataplane.XskRedirectFailed,
		XskMetaFailed:        counters.Dataplane.XskMetaFailed,
		XskMapRedirectFailed: counters.Dataplane.XskMapRedirectFailed,
		RedirectTX:           counters.Dataplane.RedirectTX,
		RedirectFailed:       counters.Dataplane.RedirectFailed,
		FibLookupFailed:      counters.Dataplane.FibLookupFailed,
		ResponseSent:         counters.Response.ResponseSent,
		ResponseFailed:       counters.Response.ResponseFailed,
		AFXDPTX:              counters.Response.AFXDPTX,
		AFXDPTXFailed:        counters.Response.AFXDPTXFailed,
		AFPacketTX:           counters.Response.AFPacketTX,
		AFPacketTXFailed:     counters.Response.AFPacketTXFailed,
		Stages:               stages,
	}
}

func newStatsPoint(ts time.Time, item Stats) StatsPoint {
	return StatsPoint{
		Timestamp:            ts,
		TotalRules:           item.TotalRules,
		EnabledRules:         item.EnabledRules,
		RXPackets:            item.RXPackets,
		ParseFailed:          item.ParseFailed,
		RuleCandidates:       item.RuleCandidates,
		MatchedRules:         item.MatchedRules,
		RingbufDropped:       item.RingbufDropped,
		XDPTX:                item.XDPTX,
		TXFailed:             item.TXFailed,
		XskRedirected:        item.XskRedirected,
		XskRedirectFailed:    item.XskRedirectFailed,
		XskMetaFailed:        item.XskMetaFailed,
		XskMapRedirectFailed: item.XskMapRedirectFailed,
		RedirectTX:           item.RedirectTX,
		RedirectFailed:       item.RedirectFailed,
		FibLookupFailed:      item.FibLookupFailed,
		ResponseSent:         item.ResponseSent,
		ResponseFailed:       item.ResponseFailed,
		AFXDPTX:              item.AFXDPTX,
		AFXDPTXFailed:        item.AFXDPTXFailed,
		AFPacketTX:           item.AFPacketTX,
		AFPacketTXFailed:     item.AFPacketTXFailed,
	}
}

func buildStatsOverview(totalRules int, enabledRules int, counters model.RuntimeCounters, stages []DiagnosticStage) StatsOverview {
	return StatsOverview{
		TotalRules:        totalRules,
		EnabledRules:      enabledRules,
		RXPackets:         counters.Dataplane.RXPackets,
		MatchedRules:      counters.Dataplane.MatchedRules,
		PrimaryIssueStage: selectPrimaryIssueStage(stages),
	}
}

func buildDiagnosticStages(counters model.RuntimeCounters) []DiagnosticStage {
	stages := make([]DiagnosticStage, 0, len(diagnosticStageDescriptors))
	for _, desc := range diagnosticStageDescriptors {
		metrics := make([]DiagnosticMetric, 0, len(desc.Metrics))
		for _, metric := range desc.Metrics {
			metrics = append(metrics, DiagnosticMetric{
				Key:         metric.Key,
				Label:       metric.Label,
				Description: metric.Description,
				Role:        metric.Role,
				Value:       counterValueByKey(counters, metric.Key),
			})
		}
		stages = append(stages, DiagnosticStage{
			Key:              desc.Key,
			Title:            desc.Title,
			Summary:          desc.Summary,
			PrimaryMetricKey: desc.PrimaryMetricKey,
			Metrics:          metrics,
		})
	}
	return stages
}

func selectPrimaryIssueStage(stages []DiagnosticStage) string {
	var (
		selected string
		maxValue uint64
	)
	for _, stage := range stages {
		var stageFailure uint64
		for _, metric := range stage.Metrics {
			if metric.Role == model.MetricRoleFailure {
				stageFailure += metric.Value
			}
		}
		if stageFailure == 0 {
			continue
		}
		if selected == "" || stageFailure > maxValue {
			selected = stage.Key
			maxValue = stageFailure
		}
	}
	return selected
}

func counterValueByKey(counters model.RuntimeCounters, key string) uint64 {
	switch key {
	case model.StatsMetricRXPackets:
		return counters.Dataplane.RXPackets
	case model.StatsMetricParseFailed:
		return counters.Dataplane.ParseFailed
	case model.StatsMetricRuleCandidates:
		return counters.Dataplane.RuleCandidates
	case model.StatsMetricMatchedRules:
		return counters.Dataplane.MatchedRules
	case model.StatsMetricRingbufDropped:
		return counters.Dataplane.RingbufDropped
	case model.StatsMetricXDPTX:
		return counters.Dataplane.XDPTX
	case model.StatsMetricTXFailed:
		return counters.Dataplane.TXFailed
	case model.StatsMetricXskRedirected:
		return counters.Dataplane.XskRedirected
	case model.StatsMetricXskRedirectFailed:
		return counters.Dataplane.XskRedirectFailed
	case model.StatsMetricXskMetaFailed:
		return counters.Dataplane.XskMetaFailed
	case model.StatsMetricXskMapRedirectFailed:
		return counters.Dataplane.XskMapRedirectFailed
	case model.StatsMetricRedirectTX:
		return counters.Dataplane.RedirectTX
	case model.StatsMetricRedirectFailed:
		return counters.Dataplane.RedirectFailed
	case model.StatsMetricFibLookupFailed:
		return counters.Dataplane.FibLookupFailed
	case model.StatsMetricResponseSent:
		return counters.Response.ResponseSent
	case model.StatsMetricResponseFailed:
		return counters.Response.ResponseFailed
	case model.StatsMetricAFXDPTX:
		return counters.Response.AFXDPTX
	case model.StatsMetricAFXDPTXFailed:
		return counters.Response.AFXDPTXFailed
	case model.StatsMetricAFPacketTX:
		return counters.Response.AFPacketTX
	case model.StatsMetricAFPacketTXFailed:
		return counters.Response.AFPacketTXFailed
	default:
		return 0
	}
}

func (r *Runtime) runStatsCollector(ctx context.Context) {
	step := r.opts.StatsCollectStep
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
	runtimeStats, err := r.stats.ReadStats()
	if err != nil {
		logs.App().WithError(err).Warn("Fail to collect stats")
		return
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	current := newStats(r.rules, runtimeStats)
	point := newStatsPoint(now.Truncate(r.opts.StatsCollectStep), current)
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
	cutoff := now.Add(-r.opts.StatsKeepWindow)
	trimmed := make([]StatsPoint, 0, len(r.history))
	for _, item := range r.history {
		if item.Timestamp.Before(cutoff) {
			continue
		}
		trimmed = append(trimmed, item)
	}
	if len(trimmed) > r.opts.StatsKeepLimit {
		trimmed = append([]StatsPoint(nil), trimmed[len(trimmed)-r.opts.StatsKeepLimit:]...)
	}
	r.history = trimmed
}

func normalizeStatsRange(rangeSeconds int, collectInterval time.Duration, retention time.Duration) (time.Duration, error) {
	if rangeSeconds == 0 {
		rangeSeconds = minStatsRangeSeconds
	}
	if rangeSeconds < minStatsRangeSeconds {
		return 0, fmt.Errorf("%w: range_seconds must be >= %d", ErrStatsRangeInvalid, minStatsRangeSeconds)
	}
	if rangeSeconds%minStatsRangeSeconds != 0 {
		return 0, fmt.Errorf("%w: range_seconds must be a multiple of %d", ErrStatsRangeInvalid, minStatsRangeSeconds)
	}

	rangeDuration := time.Duration(rangeSeconds) * time.Second
	if rangeDuration < collectInterval {
		return 0, fmt.Errorf("%w: range_seconds must be >= collect_interval", ErrStatsRangeInvalid)
	}
	if rangeDuration > retention {
		return 0, fmt.Errorf("%w: range_seconds must be <= retention", ErrStatsRangeInvalid)
	}

	return rangeDuration, nil
}

func buildStatsQuery(rangeDuration time.Duration, collectInterval time.Duration) StatsQuery {
	step := rangeDuration / maxStatsDisplayPoints
	if rangeDuration%maxStatsDisplayPoints != 0 {
		step++
	}
	if step < collectInterval {
		step = collectInterval
	}
	if rem := step % collectInterval; rem != 0 {
		step += collectInterval - rem
	}
	return StatsQuery{
		Range: rangeDuration,
		Step:  step,
		Limit: maxStatsDisplayPoints,
	}
}

func (r *Runtime) buildStatsHistory(now time.Time, current Stats, query StatsQuery) ([]StatsHistorySeries, error) {
	points := aggregateStatsPoints(r.history, now, query, current)

	return []StatsHistorySeries{
		{
			Name:   query.Range.String(),
			Window: query.Range.String(),
			Step:   query.Step.String(),
			Points: points,
		},
	}, nil
}

func (r *Runtime) buildDiagnosticHistory(now time.Time, current Stats, query StatsQuery) ([]DiagnosticHistorySeries, error) {
	points := aggregateStatsPoints(r.history, now, query, current)
	return []DiagnosticHistorySeries{
		{
			Name:   query.Range.String(),
			Window: query.Range.String(),
			Step:   query.Step.String(),
			Stages: aggregateDiagnosticStages(points),
		},
	}, nil
}

func aggregateStatsPoints(history []StatsPoint, now time.Time, query StatsQuery, current Stats) []StatsPoint {
	cutoff := now.Add(-query.Range)
	points := make([]StatsPoint, 0, query.Limit)
	for _, item := range history {
		if item.Timestamp.Before(cutoff) {
			continue
		}
		bucket := item
		bucket.Timestamp = item.Timestamp.Truncate(query.Step)
		if len(points) > 0 && points[len(points)-1].Timestamp.Equal(bucket.Timestamp) {
			points[len(points)-1] = bucket
		} else {
			points = append(points, bucket)
		}
	}

	currentBucket := newStatsPoint(now.Truncate(query.Step), current)
	if len(points) == 0 || !points[len(points)-1].Timestamp.Equal(currentBucket.Timestamp) {
		points = append(points, currentBucket)
	} else {
		points[len(points)-1] = currentBucket
	}

	if len(points) > query.Limit {
		points = append([]StatsPoint(nil), points[len(points)-query.Limit:]...)
	}
	return points
}

func aggregateDiagnosticStages(points []StatsPoint) []DiagnosticStageHistory {
	stages := make([]DiagnosticStageHistory, 0, len(diagnosticStageDescriptors))
	for _, desc := range diagnosticStageDescriptors {
		metrics := make([]DiagnosticMetricHistory, 0, len(desc.Metrics))
		for _, metric := range desc.Metrics {
			historyPoints := make([]MetricPoint, 0, len(points))
			for _, point := range points {
				historyPoints = append(historyPoints, MetricPoint{
					Timestamp: point.Timestamp,
					Value:     counterValueByKey(statsPointCounters(point), metric.Key),
				})
			}
			metrics = append(metrics, DiagnosticMetricHistory{
				Key:         metric.Key,
				Label:       metric.Label,
				Description: metric.Description,
				Role:        metric.Role,
				Points:      historyPoints,
			})
		}
		stages = append(stages, DiagnosticStageHistory{
			Key:              desc.Key,
			Title:            desc.Title,
			Summary:          desc.Summary,
			PrimaryMetricKey: desc.PrimaryMetricKey,
			Metrics:          metrics,
		})
	}
	return stages
}

func statsPointCounters(point StatsPoint) model.RuntimeCounters {
	return model.RuntimeCounters{
		Dataplane: model.DataplaneCounters{
			RXPackets:            point.RXPackets,
			ParseFailed:          point.ParseFailed,
			RuleCandidates:       point.RuleCandidates,
			MatchedRules:         point.MatchedRules,
			RingbufDropped:       point.RingbufDropped,
			XDPTX:                point.XDPTX,
			TXFailed:             point.TXFailed,
			XskRedirected:        point.XskRedirected,
			XskRedirectFailed:    point.XskRedirectFailed,
			XskMetaFailed:        point.XskMetaFailed,
			XskMapRedirectFailed: point.XskMapRedirectFailed,
			RedirectTX:           point.RedirectTX,
			RedirectFailed:       point.RedirectFailed,
			FibLookupFailed:      point.FibLookupFailed,
		},
		Response: model.ResponseCounters{
			ResponseSent:     point.ResponseSent,
			ResponseFailed:   point.ResponseFailed,
			AFXDPTX:          point.AFXDPTX,
			AFXDPTXFailed:    point.AFXDPTXFailed,
			AFPacketTX:       point.AFPacketTX,
			AFPacketTXFailed: point.AFPacketTXFailed,
		},
	}
}
