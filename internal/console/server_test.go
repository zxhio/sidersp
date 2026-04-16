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
	status controlplane.Status
	rules  []rule.Rule
}

func (s *stubService) Status() controlplane.Status { return s.status }
func (s *stubService) ListRules() []Rule           { return append([]Rule(nil), s.rules...) }
func (s *stubService) GetRule(id int) (Rule, error) {
	for _, item := range s.rules {
		if item.ID == id {
			return item, nil
		}
	}
	return rule.Rule{}, controlplane.ErrRuleNotFound
}
func (s *stubService) CreateRule(item Rule) (Rule, error) {
	if err := validateStubRule(item); err != nil {
		return Rule{}, err
	}
	for _, existing := range s.rules {
		if existing.ID == item.ID {
			return Rule{}, controlplane.ErrRuleConflict
		}
	}
	s.rules = append(s.rules, item)
	return item, nil
}
func (s *stubService) UpdateRule(id int, item Rule) (Rule, error) {
	if err := validateStubRule(item); err != nil {
		return Rule{}, err
	}
	for idx := range s.rules {
		if s.rules[idx].ID == id {
			s.rules[idx] = item
			return item, nil
		}
	}
	return Rule{}, controlplane.ErrRuleNotFound
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
func (s *stubService) SetRuleEnabled(id int, enabled bool) (Rule, error) {
	for idx := range s.rules {
		if s.rules[idx].ID == id {
			s.rules[idx].Enabled = enabled
			return s.rules[idx], nil
		}
	}
	return rule.Rule{}, controlplane.ErrRuleNotFound
}

func validateStubRule(item Rule) error {
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
	body := []byte(`{"id":3,"name":"three","enabled":true,"priority":30,"match":{"dst_ports":[443]},"response":{"action":"RST"}}`)

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
		rules: []rule.Rule{{ID: 2, Name: "two", Enabled: false, Priority: 20, Response: rule.RuleResponse{Action: "RST"}}},
	})
	body := []byte(`{"id":2,"name":"two-updated","enabled":true,"priority":10,"match":{"dst_ports":[80]},"response":{"action":"RST"}}`)

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
	body := []byte(`{"id":0,"name":"","enabled":true,"priority":30,"match":{"dst_ports":[443]},"response":{"action":"RST"}}`)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.newRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
