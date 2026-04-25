package console

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sidersp/internal/controlplane"
	"sidersp/internal/rule"
)

type stubService struct {
	status     controlplane.Status
	stats      controlplane.Stats
	statsByKey map[int]controlplane.Stats
	ruleCounts map[int]uint64
	lastRange  int
	rules      []rule.Rule
}

func (s *stubService) Status() controlplane.Status { return s.status }
func (s *stubService) Stats(rangeSeconds int) (controlplane.Stats, error) {
	s.lastRange = rangeSeconds
	if s.statsByKey != nil {
		item, ok := s.statsByKey[rangeSeconds]
		if !ok {
			return controlplane.Stats{}, controlplane.ErrStatsRangeInvalid
		}
		return item, nil
	}
	return s.stats, nil
}
func (s *stubService) RuleMatchCounts() (map[int]uint64, error) {
	return mapsClone(s.ruleCounts), nil
}
func (s *stubService) ListRules() []rule.Rule { return append([]rule.Rule(nil), s.rules...) }
func (s *stubService) GetRule(id int) (rule.Rule, error) {
	for _, item := range s.rules {
		if item.ID == id {
			return item, nil
		}
	}
	return rule.Rule{}, controlplane.ErrRuleNotFound
}
func (s *stubService) CreateRule(item rule.Rule) (rule.Rule, error) {
	if err := validateStubRule(item); err != nil {
		return rule.Rule{}, err
	}
	for _, existing := range s.rules {
		if existing.ID == item.ID {
			return rule.Rule{}, controlplane.ErrRuleConflict
		}
	}
	s.rules = append(s.rules, item)
	return item, nil
}
func (s *stubService) UpdateRule(id int, item rule.Rule) (rule.Rule, error) {
	if err := validateStubRule(item); err != nil {
		return rule.Rule{}, err
	}
	for idx := range s.rules {
		if s.rules[idx].ID == id {
			s.rules[idx] = item
			return item, nil
		}
	}
	return rule.Rule{}, controlplane.ErrRuleNotFound
}
func (s *stubService) DeleteRule(id int) error {
	for idx := range s.rules {
		if s.rules[idx].ID == id {
			s.rules = append(s.rules[:idx], s.rules[idx+1:]...)
			return nil
		}
	}
	return controlplane.ErrRuleNotFound
}
func (s *stubService) SetRuleEnabled(id int, enabled bool) (rule.Rule, error) {
	for idx := range s.rules {
		if s.rules[idx].ID == id {
			s.rules[idx].Enabled = enabled
			return s.rules[idx], nil
		}
	}
	return rule.Rule{}, controlplane.ErrRuleNotFound
}

func validateStubRule(item rule.Rule) error {
	switch {
	case item.ID <= 0:
		return controlplane.ErrRuleValidation
	case strings.TrimSpace(item.Name) == "":
		return controlplane.ErrRuleValidation
	case strings.TrimSpace(item.Response.Action) == "":
		return controlplane.ErrRuleValidation
	default:
		return nil
	}
}

func mapsClone(src map[int]uint64) map[int]uint64 {
	if len(src) == 0 {
		return nil
	}
	out := make(map[int]uint64, len(src))
	for key, value := range src {
		out[key] = value
	}
	return out
}

func TestGetStatus(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		status: controlplane.Status{
			ListenAddr:  "127.0.0.1:8080",
			Interface:   "enp1s0",
			TXInterface: "eth1",
			TotalRules:  13,
			Enabled:     1,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data StatusResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body.Data.Interface != "enp1s0" || body.Data.TXInterface != "eth1" {
		t.Fatalf("status body = %+v, want interface and tx interface", body.Data)
	}
	if body.Data.Enabled != 1 || body.Data.TotalRules != 13 {
		t.Fatalf("status body = %+v, want rule counts", body.Data)
	}
}

func TestServeWebIndex(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "SideRSP") {
		t.Fatalf("body = %q, want embedded index html", rec.Body.String())
	}
}

func TestServeWebFallback(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})

	req := httptest.NewRequest(http.MethodGet, "/rules", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "SideRSP") {
		t.Fatalf("body = %q, want embedded index html", rec.Body.String())
	}
}

func TestAPINotFoundDoesNotFallbackToWeb(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/not-found", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if strings.Contains(rec.Body.String(), "SideRSP") {
		t.Fatalf("body = %q, want api 404 instead of web fallback", rec.Body.String())
	}
}

func TestAssetNotFoundDoesNotFallbackToWeb(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})

	req := httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	if strings.Contains(rec.Body.String(), "SideRSP") {
		t.Fatalf("body = %q, want asset 404 instead of web fallback", rec.Body.String())
	}
}

func TestListRules(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		ruleCounts: map[int]uint64{1: 12, 2: 3},
		rules: []rule.Rule{
			{ID: 1, Name: "one", Enabled: true},
			{ID: 2, Name: "two", Enabled: false},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules?page=1&page_size=1", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data     []RuleBody `json:"data"`
		Total    int        `json:"total"`
		Page     int        `json:"page"`
		PageSize int        `json:"page_size"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}

	if body.Total != 2 || body.Page != 1 || body.PageSize != 1 {
		t.Fatalf("pagination = %+v, want total=2 page=1 page_size=1", body)
	}
	if len(body.Data) != 1 || body.Data[0].ID != 1 {
		t.Fatalf("data = %+v, want first rule only", body.Data)
	}
	if body.Data[0].MatchedCount != 12 {
		t.Fatalf("matched_count = %d, want 12", body.Data[0].MatchedCount)
	}
}

func TestGetStats(t *testing.T) {
	t.Parallel()

	service := &stubService{
		statsByKey: map[int]controlplane.Stats{
			86400: {
				Overview: controlplane.StatsOverview{
					TotalRules:        2,
					EnabledRules:      1,
					RXPackets:         100,
					MatchedRules:      8,
					PrimaryIssueStage: "parse",
				},
				RangeSeconds:           86400,
				CollectIntervalSeconds: 10,
				RetentionSeconds:       30 * 24 * 60 * 60,
				DisplayStepSeconds:     900,
				TotalRules:             2,
				EnabledRules:           1,
				RXPackets:              100,
				ParseFailed:            3,
				RuleCandidates:         20,
				MatchedRules:           8,
				RingbufDropped:         1,
				Stages: []controlplane.DiagnosticStage{
					{
						Key:              "parse",
						Title:            "解析",
						Summary:          "解析头部和协议字段。",
						PrimaryMetricKey: "parse_failed",
						Metrics: []controlplane.DiagnosticMetric{
							{Key: "parse_failed", Label: "解析失败", Description: "报文格式不支持或头部不完整。", Role: "failure", Value: 3},
						},
					},
				},
				Histories: []controlplane.StatsHistorySeries{
					{
						Name:   "10min",
						Window: "10m",
						Step:   "10s",
						Points: []controlplane.StatsPoint{
							{
								TotalRules:     2,
								EnabledRules:   1,
								RXPackets:      90,
								ParseFailed:    2,
								RuleCandidates: 18,
								MatchedRules:   7,
								RingbufDropped: 1,
							},
						},
					},
				},
				StageHistories: []controlplane.DiagnosticHistorySeries{
					{
						Name:   "10min",
						Window: "10m",
						Step:   "10s",
						Stages: []controlplane.DiagnosticStageHistory{
							{
								Key:              "parse",
								Title:            "解析",
								Summary:          "解析头部和协议字段。",
								PrimaryMetricKey: "parse_failed",
								Metrics: []controlplane.DiagnosticMetricHistory{
									{
										Key:         "parse_failed",
										Label:       "解析失败",
										Description: "报文格式不支持或头部不完整。",
										Role:        "failure",
										Points: []controlplane.MetricPoint{
											{Value: 2},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	server := NewServer("127.0.0.1:0", service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?range_seconds=86400", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data StatsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body.Data.RXPackets != 100 {
		t.Fatalf("stats = %+v, want rx_packets=100", body.Data)
	}
	if body.Data.Overview.TotalRules != 2 || body.Data.Overview.PrimaryIssueStage != "parse" {
		t.Fatalf("overview = %+v, want total_rules=2 primary_issue_stage=parse", body.Data.Overview)
	}
	if body.Data.RangeSeconds != 86400 || body.Data.DisplayStepSeconds != 900 {
		t.Fatalf("stats metadata = %+v, want range_seconds=86400 display_step_seconds=900", body.Data)
	}
	if len(body.Data.Stages) != 1 || body.Data.Stages[0].Key != "parse" {
		t.Fatalf("stages = %+v, want parse stage", body.Data.Stages)
	}
	if body.Data.EnabledRules == nil || *body.Data.EnabledRules != 1 || body.Data.RingbufDropped == nil || *body.Data.RingbufDropped != 1 {
		t.Fatalf("stats = %+v, want legacy fields populated", body.Data)
	}
	if service.lastRange != 86400 {
		t.Fatalf("range_seconds = %d, want 86400", service.lastRange)
	}
	if len(body.Data.Histories) != 1 {
		t.Fatalf("histories len = %d, want 1", len(body.Data.Histories))
	}
	if len(body.Data.StageHistories) != 1 || len(body.Data.StageHistories[0].Stages) != 1 {
		t.Fatalf("stage histories = %+v, want one parse stage history", body.Data.StageHistories)
	}
	if body.Data.Histories[0].Points[0].TotalRules == nil || *body.Data.Histories[0].Points[0].TotalRules != 2 {
		t.Fatalf("point = %+v, want legacy totals in history response", body.Data.Histories[0].Points[0])
	}
}

func TestGetStatsVerbose(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		statsByKey: map[int]controlplane.Stats{
			86400: {
				Overview: controlplane.StatsOverview{
					TotalRules:        2,
					EnabledRules:      1,
					RXPackets:         100,
					MatchedRules:      8,
					PrimaryIssueStage: "xsk_redirect",
				},
				RangeSeconds:           86400,
				CollectIntervalSeconds: 10,
				RetentionSeconds:       30 * 24 * 60 * 60,
				DisplayStepSeconds:     900,
				TotalRules:             2,
				EnabledRules:           1,
				RXPackets:              100,
				ParseFailed:            3,
				RuleCandidates:         20,
				MatchedRules:           8,
				RingbufDropped:         1,
				XDPTX:                  2,
				XskTX:                  3,
				TXFailed:               4,
				XskFailed:              5,
				XskMetaFailed:          9,
				XskRedirectFailed:      10,
				RedirectTX:             6,
				RedirectFailed:         7,
				FibLookupFailed:        8,
				Stages: []controlplane.DiagnosticStage{
					{
						Key:              "xsk_redirect",
						Title:            "响应重定向",
						Summary:          "把原始报文重定向到 XSK。",
						PrimaryMetricKey: "xsk_tx",
						Metrics: []controlplane.DiagnosticMetric{
							{Key: "xsk_tx", Label: "重定向到响应模块", Description: "BPF 成功把报文提交到 XSK 的次数。", Role: "success", Value: 3},
							{Key: "xsk_failed", Label: "响应重定向失败", Description: "XSK 重定向总失败次数。", Role: "failure", Value: 5},
							{Key: "xsk_meta_failed", Label: "XSK 元数据失败", Description: "写入 XDP metadata 失败。", Role: "failure", Value: 9},
							{Key: "xsk_redirect_failed", Label: "XSK 提交失败", Description: "调用 redirect_map 提交到 XSK 失败。", Role: "failure", Value: 10},
						},
					},
				},
				Histories: []controlplane.StatsHistorySeries{
					{
						Name:   "10min",
						Window: "10m",
						Step:   "10s",
						Points: []controlplane.StatsPoint{
							{
								TotalRules:        2,
								EnabledRules:      1,
								RXPackets:         90,
								ParseFailed:       2,
								RuleCandidates:    18,
								MatchedRules:      7,
								RingbufDropped:    1,
								XDPTX:             2,
								XskTX:             3,
								TXFailed:          4,
								XskFailed:         5,
								XskMetaFailed:     9,
								XskRedirectFailed: 10,
								RedirectTX:        6,
								RedirectFailed:    7,
								FibLookupFailed:   8,
							},
						},
					},
				},
				StageHistories: []controlplane.DiagnosticHistorySeries{
					{
						Name:   "10min",
						Window: "10m",
						Step:   "10s",
						Stages: []controlplane.DiagnosticStageHistory{
							{
								Key:              "xsk_redirect",
								Title:            "响应重定向",
								Summary:          "把原始报文重定向到 XSK。",
								PrimaryMetricKey: "xsk_tx",
								Metrics: []controlplane.DiagnosticMetricHistory{
									{
										Key:         "xsk_meta_failed",
										Label:       "XSK 元数据失败",
										Description: "写入 XDP metadata 失败。",
										Role:        "failure",
										Points: []controlplane.MetricPoint{
											{Value: 9},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?range_seconds=86400", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data StatsResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body.Data.EnabledRules == nil || *body.Data.EnabledRules != 1 {
		t.Fatalf("stats = %+v, want enabled_rules=1", body.Data)
	}
	if body.Data.RingbufDropped == nil || *body.Data.RingbufDropped != 1 {
		t.Fatalf("stats = %+v, want ringbuf_dropped=1", body.Data)
	}
	if body.Data.Overview.PrimaryIssueStage != "xsk_redirect" {
		t.Fatalf("overview = %+v, want primary_issue_stage=xsk_redirect", body.Data.Overview)
	}
	if body.Data.RangeSeconds != 86400 || body.Data.DisplayStepSeconds != 900 {
		t.Fatalf("stats metadata = %+v, want range_seconds=86400 display_step_seconds=900", body.Data)
	}
	if len(body.Data.Stages) != 1 || body.Data.Stages[0].Metrics[2].Key != "xsk_meta_failed" {
		t.Fatalf("stages = %+v, want xsk_meta_failed metric in xsk stage", body.Data.Stages)
	}
	if body.Data.XskMetaFailed == nil || *body.Data.XskMetaFailed != 9 {
		t.Fatalf("stats = %+v, want xsk_meta_failed=9", body.Data)
	}
	if body.Data.Histories[0].Points[0].TotalRules == nil || *body.Data.Histories[0].Points[0].TotalRules != 2 {
		t.Fatalf("point = %+v, want total_rules=2", body.Data.Histories[0].Points[0])
	}
	if len(body.Data.StageHistories) != 1 || body.Data.StageHistories[0].Stages[0].Metrics[0].Points[0].Value != 9 {
		t.Fatalf("stage history = %+v, want xsk_meta_failed history point 9", body.Data.StageHistories)
	}
}

func TestGetStatsInvalidRange(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		statsByKey: map[int]controlplane.Stats{
			600: {},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?range_seconds=601", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestEnableRule(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		rules: []rule.Rule{{ID: 2, Name: "two", Enabled: false}},
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules/2/enable", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data rule.Rule `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !body.Data.Enabled {
		t.Fatalf("enabled = %v, want true", body.Data.Enabled)
	}
}

func TestGetRuleNotFound(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/99", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestCreateRule(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})
	body := []byte(`{"id":3,"name":"three","enabled":true,"priority":30,"match":{"dst_ports":[443]},"response":{"action":"tcp_reset"}}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusCreated)
	}
}

func TestUpdateRule(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		rules: []rule.Rule{{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "tcp_reset"}}},
	})
	body := []byte(`{"id":2,"name":"two-updated","enabled":true,"priority":10,"match":{"dst_ports":[80]},"response":{"action":"tcp_reset"}}`)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/rules/2", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestDeleteRule(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		rules: []rule.Rule{{ID: 2, Name: "two", Enabled: false}},
	})

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/rules/2", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
}

func TestCreateRuleValidationError(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{})
	body := []byte(`{"id":0,"name":"","enabled":true,"priority":30,"match":{"dst_ports":[443]},"response":{"action":"tcp_reset"}}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
