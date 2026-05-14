package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) GetStats(c *gin.Context) {
	item, err := h.stats.Stats(c.Request.Context())
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newStatsResponse(item))
}
