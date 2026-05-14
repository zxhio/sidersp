package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) GetResponse(c *gin.Context) {
	item, err := h.response.GetResponse(c.Request.Context())
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newResponseConfigResponse(item))
}

func (h Handler) ReplaceResponse(c *gin.Context) {
	var req ResponseConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, http.StatusBadRequest, ErrorCodeBadRequest, "Bad request", err.Error())
		return
	}

	item, err := newResponseConfig(req)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	item, err = h.response.ReplaceResponse(c.Request.Context(), item)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newResponseConfigResponse(item))
}

func (h Handler) ClearResponse(c *gin.Context) {
	if err := h.response.ClearResponse(c.Request.Context()); err != nil {
		writeAPIError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}
