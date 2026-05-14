package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"sidersp/internal/agent/types"
)

func TestGetHealth(t *testing.T) {
	router := NewRouter(staticStatusService{})
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
	router := NewRouter(staticStatusService{})
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

type staticStatusService struct{}

func (staticStatusService) Health(ctx context.Context) (types.Health, error) {
	return types.Health{Status: types.HealthStatusOK}, nil
}

func (staticStatusService) Status(ctx context.Context) (types.Status, error) {
	return types.Status{Status: types.StatusRunning}, nil
}
