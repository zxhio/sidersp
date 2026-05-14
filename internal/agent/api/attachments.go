package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"sidersp/internal/agent/types"
)

func (h Handler) ListAttachments(c *gin.Context) {
	items, err := h.attachments.ListAttachments(c.Request.Context())
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newAttachmentResponses(items))
}

func (h Handler) GetAttachment(c *gin.Context) {
	ifindex, ok := parseIfIndex(c)
	if !ok {
		return
	}

	item, err := h.attachments.GetAttachment(c.Request.Context(), ifindex)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newAttachmentResponse(item))
}

func (h Handler) CreateAttachment(c *gin.Context) {
	var req AttachmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, http.StatusBadRequest, ErrorCodeBadRequest, "Bad request", err.Error())
		return
	}

	item, err := newAttachment(req)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	dryRun := c.Query("dry_run") == "true"
	item, err = h.attachments.CreateAttachment(c.Request.Context(), item, dryRun)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	status := http.StatusCreated
	if dryRun {
		status = http.StatusOK
	}
	c.JSON(status, newAttachmentResponse(item))
}

func (h Handler) SetAttachmentEnabled(c *gin.Context) {
	ifindex, ok := parseIfIndex(c)
	if !ok {
		return
	}

	var req PatchAttachmentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeProblem(c, http.StatusBadRequest, ErrorCodeBadRequest, "Bad request", err.Error())
		return
	}
	if req.Enabled == nil {
		writeAPIError(c, types.NewValidationError("enabled is required"))
		return
	}

	item, err := h.attachments.SetAttachmentEnabled(c.Request.Context(), ifindex, *req.Enabled)
	if err != nil {
		writeAPIError(c, err)
		return
	}

	c.JSON(http.StatusOK, newAttachmentResponse(item))
}

func (h Handler) DeleteAttachment(c *gin.Context) {
	ifindex, ok := parseIfIndex(c)
	if !ok {
		return
	}

	if err := h.attachments.DeleteAttachment(c.Request.Context(), ifindex); err != nil {
		writeAPIError(c, err)
		return
	}

	c.Status(http.StatusNoContent)
}

func parseIfIndex(c *gin.Context) (int, bool) {
	ifindex, err := strconv.Atoi(c.Param("ifindex"))
	if err != nil {
		writeProblem(c, http.StatusBadRequest, ErrorCodeBadRequest, "Bad request", "ifindex must be an integer")
		return 0, false
	}
	return ifindex, true
}
