package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) GetHealth(c *gin.Context) {
	item, err := h.status.Health(c.Request.Context())
	if err != nil {
		writeInternalError(c, err.Error())
		return
	}

	c.JSON(http.StatusOK, newHealthResponse(item))
}
