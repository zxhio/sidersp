package console

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"sidersp/internal/controlplane"
)

type Handler struct {
	service RuleService
}

func (h Handler) getStatus(c *gin.Context) {
	c.JSON(http.StatusOK, dataEnvelope{Data: newStatusResponse(h.service.Status())})
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
		Data:     newRulesResponse(all[start:end]),
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

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleResponse(item)})
}

func (h Handler) createRule(c *gin.Context) {
	var req CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.CreateRule(req.toRule())
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, dataEnvelope{Data: newRuleResponse(item)})
}

func (h Handler) updateRule(c *gin.Context) {
	id, err := parseID(c.Param("id"))
	if err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	var req UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
		return
	}

	item, err := h.service.UpdateRule(id, req.toRule())
	if err != nil {
		writeServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleResponse(item)})
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

	c.JSON(http.StatusOK, dataEnvelope{Data: newRuleResponse(item)})
}

func writeServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, controlplane.ErrRuleNotFound):
		writeError(c, http.StatusNotFound, "NOT_FOUND", "rule not found")
	case errors.Is(err, controlplane.ErrRuleConflict):
		writeError(c, http.StatusConflict, "CONFLICT", "rule already exists")
	case errors.Is(err, controlplane.ErrRuleValidation):
		writeError(c, http.StatusBadRequest, "VALIDATION_FAILED", err.Error())
	default:
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
