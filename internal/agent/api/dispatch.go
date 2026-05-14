package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) GetDispatch(c *gin.Context) {
	item, err := h.dispatch.GetDispatch(c.Request.Context())
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newDispatchConfigResponse(item))
}

func (h Handler) ReplaceDispatch(c *gin.Context) {
	var req DispatchConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, http.StatusBadRequest, ErrorCodeBadRequest, "Bad request", err.Error())
		return
	}

	item, err := h.dispatch.ReplaceDispatch(c.Request.Context(), newDispatchConfig(req))
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newDispatchConfigResponse(item))
}

func (h Handler) ClearDispatch(c *gin.Context) {
	if err := h.dispatch.ClearDispatch(c.Request.Context()); err != nil {
		writeAPIError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
