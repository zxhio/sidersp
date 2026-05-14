package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
)

func TestGetHealth(t *testing.T) {
	router := newTestRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, map[string]any{"status": "ok"}, body)
	require.NotContains(t, body, "data")
}

func TestGetStatus(t *testing.T) {
	router := newTestRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "running", body["status"])
	require.Equal(t, float64(0), body["attachments"])
	require.Equal(t, float64(0), body["ruleset_version"])
	require.Equal(t, false, body["response_configured"])
	require.Equal(t, false, body["dispatch_enabled"])
	require.NotContains(t, body, "data")
}

func TestReplaceRulesetDryRunDoesNotModifyCurrentRuleset(t *testing.T) {
	ruleset := newStaticRulesetService()
	router := NewRouter(staticStatusService{}, ruleset, staticResponseService{}, staticDispatchService{})

	reqBody := []byte(`{"version":3,"rules":[{"rule_id":1001,"priority":10,"match":{"protocol":"tcp","dst_ports":[80]},"response":{"action":"tcp_reset"}}]}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/ruleset?dry_run=true", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, uint64(0), ruleset.current.Version)

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, float64(3), body["version"])
	require.NotContains(t, body, "data")
}

func TestReplaceRulesetUpdatesCurrentRuleset(t *testing.T) {
	ruleset := newStaticRulesetService()
	router := NewRouter(staticStatusService{}, ruleset, staticResponseService{}, staticDispatchService{})

	reqBody := []byte(`{"version":4,"rules":[{"rule_id":1002,"response":{"action":"alert"}}]}`)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/ruleset", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, uint64(4), ruleset.current.Version)
	require.Len(t, ruleset.current.Rules, 1)
}

func TestClearRulesetClearsCurrentRuleset(t *testing.T) {
	ruleset := newStaticRulesetService()
	ruleset.current = types.Ruleset{
		Version: 5,
		Rules: []types.Rule{
			{RuleID: 1003, Response: types.RuleResponse{Action: "alert"}},
		},
	}
	router := NewRouter(staticStatusService{}, ruleset, staticResponseService{}, staticDispatchService{})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/ruleset", nil)

	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusNoContent, rec.Code)
	require.Empty(t, rec.Body.String())
	require.Zero(t, ruleset.current.Version)
	require.Nil(t, ruleset.current.Rules)
}

func newTestRouter() *gin.Engine {
	return NewRouter(staticStatusService{}, newStaticRulesetService(), staticResponseService{}, staticDispatchService{})
}

type staticStatusService struct{}

func (staticStatusService) Health(ctx context.Context) (types.Health, error) {
	return types.Health{Status: types.HealthStatusOK}, nil
}

func (staticStatusService) Status(ctx context.Context) (types.Status, error) {
	return types.Status{Status: types.StatusRunning}, nil
}

type staticRulesetService struct {
	current types.Ruleset
}

func newStaticRulesetService() *staticRulesetService {
	return &staticRulesetService{}
}

func (s *staticRulesetService) GetRuleset(ctx context.Context) (types.Ruleset, error) {
	return s.current, nil
}

func (s *staticRulesetService) ReplaceRuleset(ctx context.Context, ruleset types.Ruleset, dryRun bool) (types.Ruleset, error) {
	if dryRun {
		return ruleset, nil
	}
	s.current = ruleset
	return s.current, nil
}

func (s *staticRulesetService) ClearRuleset(ctx context.Context) error {
	s.current = types.Ruleset{}
	return nil
}

type staticResponseService struct{}

func (staticResponseService) GetResponse(ctx context.Context) (types.ResponseConfig, error) {
	return types.ResponseConfig{VLANMode: types.VLANModePreserve}, nil
}

func (staticResponseService) ReplaceResponse(ctx context.Context, config types.ResponseConfig) (types.ResponseConfig, error) {
	return config, nil
}

func (staticResponseService) ClearResponse(ctx context.Context) error {
	return nil
}

type staticDispatchService struct{}

func (staticDispatchService) GetDispatch(ctx context.Context) (types.DispatchConfig, error) {
	return types.DispatchConfig{
		Backend:   types.DispatchBackendAFPacket,
		VLANMode:  types.VLANModePreserve,
		QueueSize: 4096,
	}, nil
}

func (staticDispatchService) ReplaceDispatch(ctx context.Context, config types.DispatchConfig) (types.DispatchConfig, error) {
	return config, nil
}

func (staticDispatchService) ClearDispatch(ctx context.Context) error {
	return nil
}
