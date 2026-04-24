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
	windows    []string
	statsByKey map[string]controlplane.Stats
	lastWindow string
	rules      []rule.Rule
}

func (s *stubService) Status() controlplane.Status { return s.status }
func (s *stubService) Stats(window string) (controlplane.Stats, error) {
	s.lastWindow = window
	if s.statsByKey != nil {
		item, ok := s.statsByKey[window]
		if !ok {
			return controlplane.Stats{}, controlplane.ErrStatsWindowNotFound
		}
		return item, nil
	}
	return s.stats, nil
}
func (s *stubService) StatsWindows() []string {
	return append([]string(nil), s.windows...)
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

func TestListRules(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
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
		Data     []rule.Rule `json:"data"`
		Total    int         `json:"total"`
		Page     int         `json:"page"`
		PageSize int         `json:"page_size"`
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
}

func TestGetStats(t *testing.T) {
	t.Parallel()

	service := &stubService{
		statsByKey: map[string]controlplane.Stats{
			"1d": {
				TotalRules:     2,
				EnabledRules:   1,
				RXPackets:      100,
				ParseFailed:    3,
				RuleCandidates: 20,
				MatchedRules:   8,
				RingbufDropped: 1,
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
			},
		},
	}
	server := NewServer("127.0.0.1:0", service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?window=1d", nil)
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
	if body.Data.EnabledRules != nil || body.Data.RingbufDropped != nil {
		t.Fatalf("stats = %+v, want compact response without more-only fields", body.Data)
	}
	if service.lastWindow != "1d" {
		t.Fatalf("window = %q, want 1d", service.lastWindow)
	}
	if len(body.Data.Histories) != 1 {
		t.Fatalf("histories len = %d, want 1", len(body.Data.Histories))
	}
	if body.Data.Histories[0].Points[0].TotalRules != nil || body.Data.Histories[0].Points[0].RingbufDropped != nil {
		t.Fatalf("point = %+v, want compact history response", body.Data.Histories[0].Points[0])
	}
}

func TestGetStatsVerbose(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		statsByKey: map[string]controlplane.Stats{
			"1d": {
				TotalRules:      2,
				EnabledRules:    1,
				RXPackets:       100,
				ParseFailed:     3,
				RuleCandidates:  20,
				MatchedRules:    8,
				RingbufDropped:  1,
				XDPTX:           2,
				XskTX:           3,
				TXFailed:        4,
				XskFailed:       5,
				RedirectTX:      6,
				RedirectFailed:  7,
				FibLookupFailed: 8,
				Histories: []controlplane.StatsHistorySeries{
					{
						Name:   "10min",
						Window: "10m",
						Step:   "10s",
						Points: []controlplane.StatsPoint{
							{
								TotalRules:      2,
								EnabledRules:    1,
								RXPackets:       90,
								ParseFailed:     2,
								RuleCandidates:  18,
								MatchedRules:    7,
								RingbufDropped:  1,
								XDPTX:           2,
								XskTX:           3,
								TXFailed:        4,
								XskFailed:       5,
								RedirectTX:      6,
								RedirectFailed:  7,
								FibLookupFailed: 8,
							},
						},
					},
				},
			},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?window=1d&more=1", nil)
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
	if body.Data.Histories[0].Points[0].TotalRules == nil || *body.Data.Histories[0].Points[0].TotalRules != 2 {
		t.Fatalf("point = %+v, want total_rules=2", body.Data.Histories[0].Points[0])
	}
}

func TestGetStatsInvalidWindow(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		statsByKey: map[string]controlplane.Stats{
			"10min": {},
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats?window=bad", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

func TestListStatsWindows(t *testing.T) {
	t.Parallel()

	server := NewServer("127.0.0.1:0", &stubService{
		windows: []string{"10min", "1d"},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stats/windows", nil)
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body struct {
		Data []string `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if len(body.Data) != 2 {
		t.Fatalf("windows len = %d, want 2", len(body.Data))
	}
	if body.Data[0] != "10min" || body.Data[1] != "1d" {
		t.Fatalf("windows = %+v, want [10min 1d]", body.Data)
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
