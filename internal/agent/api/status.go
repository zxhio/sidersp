package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) GetStatus(c *gin.Context) {
	item, err := h.status.Status(c.Request.Context())
	if err != nil {
		writeInternalError(c, err.Error())
		return
	}

	c.JSON(http.StatusOK, newStatusResponse(item))
}
