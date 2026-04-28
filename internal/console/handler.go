package console

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"sidersp/internal/controlplane"
	"sidersp/internal/logs"
	"sidersp/internal/rule"
)

type Handler struct {
	service    RuleService
	logService LogService
}

func (h Handler) getStatus(c *gin.Context) {
	c.JSON(http.StatusOK, dataEnvelope{Data: newStatusResponse(h.service.Status())})
}

func (h Handler) getLogLevel(c *gin.Context) {
	if h.logService == nil {
		writeError(c, http.StatusNotFound, "NOT_FOUND", "logging service not configured")
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: LogLevelResponse{Level: h.logService.Level()}})
}

func (h Handler) getLogLevels(c *gin.Context) {
	if h.logService == nil {
		writeError(c, http.StatusNotFound, "NOT_FOUND", "logging service not configured")
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newLogLevelsResponse(h.logService.Levels())})
}

func (h Handler) setLogLevel(c *gin.Context) {
	if h.logService == nil {
		writeError(c, http.StatusNotFound, "NOT_FOUND", "logging service not configured")
		return
	}

	var req LogLevelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	level, err := h.logService.SetLevel(req.Level)
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: LogLevelResponse{Level: level}})
}

func (h Handler) setLogLevels(c *gin.Context) {
	if h.logService == nil {
		writeError(c, http.StatusNotFound, "NOT_FOUND", "logging service not configured")
		return
	}

	var req LogLevelsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	levels, err := h.logService.SetLevels(newLogLevelsModel(req))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newLogLevelsResponse(levels)})
}

func (h Handler) getStats(c *gin.Context) {
	rangeSeconds, err := parseRangeSecondsQuery(c.Query("range_seconds"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.Stats(rangeSeconds)
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newStatsResponse(item)})
}

func (h Handler) resetStats(c *gin.Context) {
	if err := h.service.ResetStats(); err != nil {
		h.writeServiceError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

func (h Handler) listRules(c *gin.Context) {
	page, pageSize, err := parsePage(c)
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	all := h.service.ListRules()
	counts, err := h.service.RuleMatchCounts()
	if err != nil {
		h.writeServiceError(c, err)
		return
	}
	start := (page - 1) * pageSize
	if start > len(all) {
		start = len(all)
	}
	end := start + pageSize
	if end > len(all) {
		end = len(all)
	}

	c.JSON(http.StatusOK, listEnvelope{
		Data:     newRuleBodies(all[start:end], counts),
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
		h.writeServiceError(c, err)
		return
	}

	counts, err := h.service.RuleMatchCounts()
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleBody(item, counts[item.ID])})
}

func (h Handler) createRule(c *gin.Context) {
	var req RuleBody
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.CreateRule(newRuleModel(req))
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	counts, err := h.service.RuleMatchCounts()
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, dataEnvelope{Data: newRuleBody(item, counts[item.ID])})
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

	model := newRuleModel(req)
	model.ID = id

	item, err := h.service.UpdateRule(id, model)
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	counts, err := h.service.RuleMatchCounts()
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleBody(item, counts[item.ID])})
}

func (h Handler) deleteRule(c *gin.Context) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	if err := h.service.DeleteRule(id); err != nil {
		h.writeServiceError(c, err)
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
		h.writeServiceError(c, err)
		return
	}

	counts, err := h.service.RuleMatchCounts()
	if err != nil {
		h.writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleBody(item, counts[item.ID])})
}

func (h Handler) writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, controlplane.ErrRuleNotFound):
		writeError(c, http.StatusNotFound, "NOT_FOUND", "rule not found")
	case errors.Is(err, controlplane.ErrRuleConflict):
		writeError(c, http.StatusConflict, "CONFLICT", "rule already exists")
	case errors.Is(err, controlplane.ErrRuleValidation):
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	case errors.Is(err, controlplane.ErrStatsRangeInvalid):
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	default:
		logs.App().WithError(err).Error("Fail to handle console request")
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

func parseRangeSecondsQuery(raw string) (int, error) {
	if strings.TrimSpace(raw) == "" {
		return 600, nil
	}

	rangeSeconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || rangeSeconds <= 0 {
		return 0, fmt.Errorf("range_seconds must be a positive integer")
	}
	return rangeSeconds, nil
}

func newStatusResponse(item controlplane.Status) StatusResponse {
	return StatusResponse{
		RulesPath:      item.RulesPath,
		ListenAddr:     item.ListenAddr,
		Interface:      item.Interface,
		TXInterface:    item.TXInterface,
		TXHardwareAddr: item.TXHardwareAddr,
		TotalRules:     item.TotalRules,
		Enabled:        item.Enabled,
	}
}

func newStatsResponse(item controlplane.Stats) StatsResponse {
	histories := make([]StatsHistoryResponse, 0, len(item.Histories))
	for _, series := range item.Histories {
		points := make([]StatsPointResponse, 0, len(series.Points))
		for _, point := range series.Points {
			out := StatsPointResponse{
				Timestamp:      point.Timestamp.Format(time.RFC3339),
				RXPackets:      point.RXPackets,
				ParseFailed:    point.ParseFailed,
				RuleCandidates: point.RuleCandidates,
				MatchedRules:   point.MatchedRules,
			}
			out.TotalRules = intPtr(point.TotalRules)
			out.EnabledRules = intPtr(point.EnabledRules)
			out.RingbufDropped = uint64Ptr(point.RingbufDropped)
			out.XDPTX = uint64Ptr(point.XDPTX)
			out.TXFailed = uint64Ptr(point.TXFailed)
			out.XskRedirected = uint64Ptr(point.XskRedirected)
			out.XskRedirectFailed = uint64Ptr(point.XskRedirectFailed)
			out.XskMetaFailed = uint64Ptr(point.XskMetaFailed)
			out.XskMapRedirectFailed = uint64Ptr(point.XskMapRedirectFailed)
			out.RedirectTX = uint64Ptr(point.RedirectTX)
			out.RedirectFailed = uint64Ptr(point.RedirectFailed)
			out.FibLookupFailed = uint64Ptr(point.FibLookupFailed)
			out.ResponseSent = uint64Ptr(point.ResponseSent)
			out.ResponseFailed = uint64Ptr(point.ResponseFailed)
			out.AFXDPTX = uint64Ptr(point.AFXDPTX)
			out.AFXDPTXFailed = uint64Ptr(point.AFXDPTXFailed)
			out.AFPacketTX = uint64Ptr(point.AFPacketTX)
			out.AFPacketTXFailed = uint64Ptr(point.AFPacketTXFailed)
			points = append(points, out)
		}
		histories = append(histories, StatsHistoryResponse{
			Name:   series.Name,
			Window: series.Window,
			Step:   series.Step,
			Points: points,
		})
	}

	stageHistories := make([]DiagnosticHistorySeriesResponse, 0, len(item.StageHistories))
	for _, series := range item.StageHistories {
		stages := make([]DiagnosticStageHistoryResponse, 0, len(series.Stages))
		for _, stage := range series.Stages {
			metrics := make([]DiagnosticMetricHistoryResponse, 0, len(stage.Metrics))
			for _, metric := range stage.Metrics {
				points := make([]MetricPointResponse, 0, len(metric.Points))
				for _, point := range metric.Points {
					points = append(points, MetricPointResponse{
						Timestamp: point.Timestamp.Format(time.RFC3339),
						Value:     point.Value,
					})
				}
				metrics = append(metrics, DiagnosticMetricHistoryResponse{
					Key:         metric.Key,
					Label:       metric.Label,
					Description: metric.Description,
					Role:        metric.Role,
					Points:      points,
				})
			}
			stages = append(stages, DiagnosticStageHistoryResponse{
				Key:              stage.Key,
				Title:            stage.Title,
				Summary:          stage.Summary,
				PrimaryMetricKey: stage.PrimaryMetricKey,
				Metrics:          metrics,
			})
		}
		stageHistories = append(stageHistories, DiagnosticHistorySeriesResponse{
			Name:   series.Name,
			Window: series.Window,
			Step:   series.Step,
			Stages: stages,
		})
	}

	stages := make([]DiagnosticStageResponse, 0, len(item.Stages))
	for _, stage := range item.Stages {
		metrics := make([]DiagnosticMetricResponse, 0, len(stage.Metrics))
		for _, metric := range stage.Metrics {
			metrics = append(metrics, DiagnosticMetricResponse{
				Key:         metric.Key,
				Label:       metric.Label,
				Description: metric.Description,
				Role:        metric.Role,
				Value:       metric.Value,
			})
		}
		stages = append(stages, DiagnosticStageResponse{
			Key:              stage.Key,
			Title:            stage.Title,
			Summary:          stage.Summary,
			PrimaryMetricKey: stage.PrimaryMetricKey,
			Metrics:          metrics,
		})
	}

	out := StatsResponse{
		Overview: StatsOverviewResponse{
			TotalRules:        item.Overview.TotalRules,
			EnabledRules:      item.Overview.EnabledRules,
			RXPackets:         item.Overview.RXPackets,
			MatchedRules:      item.Overview.MatchedRules,
			PrimaryIssueStage: item.Overview.PrimaryIssueStage,
		},
		Stages:                 stages,
		RangeSeconds:           item.RangeSeconds,
		CollectIntervalSeconds: item.CollectIntervalSeconds,
		RetentionSeconds:       item.RetentionSeconds,
		DisplayStepSeconds:     item.DisplayStepSeconds,
		RXPackets:              item.RXPackets,
		ParseFailed:            item.ParseFailed,
		RuleCandidates:         item.RuleCandidates,
		MatchedRules:           item.MatchedRules,
		Histories:              histories,
		StageHistories:         stageHistories,
	}
	out.TotalRules = intPtr(item.TotalRules)
	out.EnabledRules = intPtr(item.EnabledRules)
	out.RingbufDropped = uint64Ptr(item.RingbufDropped)
	out.XDPTX = uint64Ptr(item.XDPTX)
	out.TXFailed = uint64Ptr(item.TXFailed)
	out.XskRedirected = uint64Ptr(item.XskRedirected)
	out.XskRedirectFailed = uint64Ptr(item.XskRedirectFailed)
	out.XskMetaFailed = uint64Ptr(item.XskMetaFailed)
	out.XskMapRedirectFailed = uint64Ptr(item.XskMapRedirectFailed)
	out.RedirectTX = uint64Ptr(item.RedirectTX)
	out.RedirectFailed = uint64Ptr(item.RedirectFailed)
	out.FibLookupFailed = uint64Ptr(item.FibLookupFailed)
	out.ResponseSent = uint64Ptr(item.ResponseSent)
	out.ResponseFailed = uint64Ptr(item.ResponseFailed)
	out.AFXDPTX = uint64Ptr(item.AFXDPTX)
	out.AFXDPTXFailed = uint64Ptr(item.AFXDPTXFailed)
	out.AFPacketTX = uint64Ptr(item.AFPacketTX)
	out.AFPacketTXFailed = uint64Ptr(item.AFPacketTXFailed)
	return out
}

func intPtr(v int) *int {
	return &v
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

func newLogLevelsModel(req LogLevelsRequest) logs.Levels {
	return logs.Levels{
		App:   req.App,
		Stats: req.Stats,
		Event: req.Event,
	}
}

func newLogLevelsResponse(levels logs.Levels) LogLevelsResponse {
	return LogLevelsResponse{
		App:   levels.App,
		Stats: levels.Stats,
		Event: levels.Event,
	}
}

func newRuleBodies(items []rule.Rule, counts map[int]uint64) []RuleBody {
	out := make([]RuleBody, 0, len(items))
	for _, item := range items {
		out = append(out, newRuleBody(item, counts[item.ID]))
	}
	return out
}

func newRuleBody(item rule.Rule, matchedCount uint64) RuleBody {
	return RuleBody{
		ID:           item.ID,
		Name:         item.Name,
		Enabled:      item.Enabled,
		Priority:     item.Priority,
		MatchedCount: matchedCount,
		Match: RuleMatch{
			Protocol:    item.Match.Protocol,
			VLANs:       append([]int(nil), item.Match.VLANs...),
			SrcPrefixes: append([]string(nil), item.Match.SrcPrefixes...),
			DstPrefixes: append([]string(nil), item.Match.DstPrefixes...),
			SrcPorts:    append([]int(nil), item.Match.SrcPorts...),
			DstPorts:    append([]int(nil), item.Match.DstPorts...),
			TCPFlags: ruleTCPFlags{
				SYN: item.Match.TCPFlags.SYN,
				ACK: item.Match.TCPFlags.ACK,
				RST: item.Match.TCPFlags.RST,
				FIN: item.Match.TCPFlags.FIN,
				PSH: item.Match.TCPFlags.PSH,
			},
			ICMP: newConsoleICMPMatch(item.Match.ICMP),
			ARP:  newConsoleARPMatch(item.Match.ARP),
		},
		Response: RuleAction{Action: item.Response.Action, Params: cloneParams(item.Response.Params)},
	}
}

func newRuleModel(item RuleBody) rule.Rule {
	return rule.Rule{
		ID:       item.ID,
		Name:     item.Name,
		Enabled:  item.Enabled,
		Priority: item.Priority,
		Match: rule.RuleMatch{
			Protocol:    item.Match.Protocol,
			VLANs:       append([]int(nil), item.Match.VLANs...),
			SrcPrefixes: append([]string(nil), item.Match.SrcPrefixes...),
			DstPrefixes: append([]string(nil), item.Match.DstPrefixes...),
			SrcPorts:    append([]int(nil), item.Match.SrcPorts...),
			DstPorts:    append([]int(nil), item.Match.DstPorts...),
			TCPFlags: rule.TCPFlags{
				SYN: item.Match.TCPFlags.SYN,
				ACK: item.Match.TCPFlags.ACK,
				RST: item.Match.TCPFlags.RST,
				FIN: item.Match.TCPFlags.FIN,
				PSH: item.Match.TCPFlags.PSH,
			},
			ICMP: newRuleICMPMatch(item.Match.ICMP),
			ARP:  newRuleARPMatch(item.Match.ARP),
		},
		Response: rule.RuleResponse{Action: item.Response.Action, Params: cloneParams(item.Response.Params)},
	}
}

func newConsoleICMPMatch(item *rule.ICMPMatch) *ruleICMPMatch {
	if item == nil {
		return nil
	}
	return &ruleICMPMatch{Type: item.Type}
}

func newConsoleARPMatch(item *rule.ARPMatch) *ruleARPMatch {
	if item == nil {
		return nil
	}
	return &ruleARPMatch{Operation: item.Operation}
}

func newRuleICMPMatch(item *ruleICMPMatch) *rule.ICMPMatch {
	if item == nil {
		return nil
	}
	return &rule.ICMPMatch{Type: item.Type}
}

func newRuleARPMatch(item *ruleARPMatch) *rule.ARPMatch {
	if item == nil {
		return nil
	}
	return &rule.ARPMatch{Operation: item.Operation}
}

func cloneParams(params map[string]interface{}) map[string]interface{} {
	if len(params) == 0 {
		return nil
	}
	cloned := make(map[string]interface{}, len(params))
	for key, value := range params {
		cloned[key] = value
	}
	return cloned
}
