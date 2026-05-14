package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) GetRuleset(c *gin.Context) {
	item, err := h.ruleset.GetRuleset(c.Request.Context())
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newRulesetResponse(item))
}

func (h Handler) ReplaceRuleset(c *gin.Context) {
	var req RulesetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, http.StatusBadRequest, ErrorCodeBadRequest, "Bad request", err.Error())
		return
	}

	item, err := newRuleset(req)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	item, err = h.ruleset.ReplaceRuleset(c.Request.Context(), item, c.Query("dry_run") == "true")
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newRulesetResponse(item))
}

func (h Handler) ClearRuleset(c *gin.Context) {
	if err := h.ruleset.ClearRuleset(c.Request.Context()); err != nil {
		writeAPIError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
