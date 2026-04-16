package console

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"sidersp/internal/controlplane"
	"sidersp/internal/rule"
)

type Handler struct {
	service RuleService
}

func (h Handler) getStatus(c *gin.Context) {
	c.JSON(http.StatusOK, dataEnvelope{Data: newStatusResponse(h.service.Status())})
}

func (h Handler) getStats(c *gin.Context) {
	window := strings.TrimSpace(c.Query("window"))
	item, err := h.service.Stats(window)
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newStatsResponse(item)})
}

func (h Handler) listStatsWindows(c *gin.Context) {
	c.JSON(http.StatusOK, dataEnvelope{Data: h.service.StatsWindows()})
}

func (h Handler) listRules(c *gin.Context) {
	page, pageSize, err := parsePage(c)
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	all := h.service.ListRules()
	start := (page - 1) * pageSize
	if start > len(all) {
		start = len(all)
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}

	c.JSON(http.StatusOK, listEnvelope{
		Data:     newRuleBodies(all[start:end]),
		Total:    len(all),
		Page:     page,
		PageSize: pageSize,
	})
}

func (h Handler) getRule(c *gin.Context) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.GetRule(id)
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleBody(item)})
}

func (h Handler) createRule(c *gin.Context) {
	var req RuleBody
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.CreateRule(newRuleModel(req))
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, dataEnvelope{Data: newRuleBody(item)})
}

func (h Handler) updateRule(c *gin.Context) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	var req RuleBody
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.UpdateRule(id, newRuleModel(req))
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleBody(item)})
}

func (h Handler) deleteRule(c *gin.Context) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	if err := h.service.DeleteRule(id); err != nil {
		writeServiceError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h Handler) enableRule(c *gin.Context) {
	h.setRuleEnabled(c, true)
}

func (h Handler) disableRule(c *gin.Context) {
	h.setRuleEnabled(c, false)
}

func (h Handler) setRuleEnabled(c *gin.Context, enabled bool) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.SetRuleEnabled(id, enabled)
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleBody(item)})
}

func writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, controlplane.ErrRuleNotFound):
		writeError(c, http.StatusNotFound, "NOT_FOUND", "rule not found")
	case errors.Is(err, controlplane.ErrRuleConflict):
		writeError(c, http.StatusConflict, "CONFLICT", "rule already exists")
	case errors.Is(err, controlplane.ErrRuleValidation):
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	case errors.Is(err, controlplane.ErrStatsWindowNotFound):
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", "invalid stats window")
	default:
		logrus.WithError(err).Error("Console request failed")
		writeError(c, http.StatusInternalServerError, "INTERNAL_ERROR", "internal error")
	}
}

func writeError(c *gin.Context, status int, code string, message string) {
	c.JSON(status, errorEnvelope{
		Error: apiError{
			Code:    code,
			Message: message,
		},
	})
}

func parseID(raw string) (int, error) {
	id, err := strconv.Atoi(raw)
	if err != nil || id <= 0 {
		return 0, fmt.Errorf("id must be a positive integer")
	}
	return id, nil
}

func parsePage(c *gin.Context) (int, int, error) {
	page := 1
	pageSize := 100
	var err error

	if raw := c.Query("page"); raw != "" {
		page, err = strconv.Atoi(raw)
		if err != nil || page <= 0 {
			return 0, 0, fmt.Errorf("page must be a positive integer")
		}
	}

	if raw := c.Query("page_size"); raw != "" {
		pageSize, err = strconv.Atoi(raw)
		if err != nil || pageSize <= 0 {
			return 0, 0, fmt.Errorf("page_size must be a positive integer")
		}
	}

	return page, pageSize, nil
}

func newStatusResponse(item controlplane.Status) StatusResponse {
	return StatusResponse{
		RulesPath:  item.RulesPath,
		ListenAddr: item.ListenAddr,
		Interface:  item.Interface,
		TotalRules: item.TotalRules,
		Enabled:    item.Enabled,
	}
}

func newStatsResponse(item controlplane.Stats) StatsResponse {
	histories := make([]StatsHistoryResponse, 0, len(item.Histories))
	for _, series := range item.Histories {
		points := make([]StatsPointResponse, 0, len(series.Points))
		for _, point := range series.Points {
			points = append(points, StatsPointResponse{
				Timestamp:      point.Timestamp.Format(time.RFC3339),
				TotalRules:     point.TotalRules,
				EnabledRules:   point.EnabledRules,
				RXPackets:      point.RXPackets,
				ParseFailed:    point.ParseFailed,
				RuleCandidates: point.RuleCandidates,
				MatchedRules:   point.MatchedRules,
				RingbufDropped: point.RingbufDropped,
			})
		}
		histories = append(histories, StatsHistoryResponse{
			Name:   series.Name,
			Window: series.Window,
			Step:   series.Step,
			Points: points,
		})
	}

	return StatsResponse{
		TotalRules:     item.TotalRules,
		EnabledRules:   item.EnabledRules,
		RXPackets:      item.RXPackets,
		ParseFailed:    item.ParseFailed,
		RuleCandidates: item.RuleCandidates,
		MatchedRules:   item.MatchedRules,
		RingbufDropped: item.RingbufDropped,
		Histories:      histories,
	}
}

func newRuleBodies(items []rule.Rule) []RuleBody {
	out := make([]RuleBody, 0, len(items))
	for _, item := range items {
		out = append(out, newRuleBody(item))
	}
	return out
}

func newRuleBody(item rule.Rule) RuleBody {
	return RuleBody{
		ID:       item.ID,
		Name:     item.Name,
		Enabled:  item.Enabled,
		Priority: item.Priority,
		Match: RuleMatch{
			VLANs:       append([]int(nil), item.Match.VLANs...),
			SrcPrefixes: append([]string(nil), item.Match.SrcPrefixes...),
			DstPrefixes: append([]string(nil), item.Match.DstPrefixes...),
			SrcPorts:    append([]int(nil), item.Match.SrcPorts...),
			DstPorts:    append([]int(nil), item.Match.DstPorts...),
			Features:    append([]string(nil), item.Match.Features...),
		},
		Response: RuleAction{Action: item.Response.Action},
	}
}

func newRuleModel(item RuleBody) rule.Rule {
	return rule.Rule{
		ID:       item.ID,
		Name:     item.Name,
		Enabled:  item.Enabled,
		Priority: item.Priority,
		Match: rule.RuleMatch{
			VLANs:       append([]int(nil), item.Match.VLANs...),
			SrcPrefixes: append([]string(nil), item.Match.SrcPrefixes...),
			DstPrefixes: append([]string(nil), item.Match.DstPrefixes...),
			SrcPorts:    append([]int(nil), item.Match.SrcPorts...),
			DstPorts:    append([]int(nil), item.Match.DstPorts...),
			Features:    append([]string(nil), item.Match.Features...),
		},
		Response: rule.RuleResponse{Action: item.Response.Action},
	}
}
