package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"sidersp/internal/agent/types"
)

const (
	ErrorCodeBadRequest       = "bad_request"
	ErrorCodeValidationFailed = "validation_failed"
	ErrorCodeNotFound         = "not_found"
	ErrorCodeConflict         = "conflict"
	ErrorCodeRuntimeFailed    = "runtime_failed"
	ErrorCodeInternal         = "internal_error"
)

type ProblemDetails struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   string `json:"code"`
}

func writeProblem(c *gin.Context, status int, code string, title string, detail string) {
	c.JSON(status, ProblemDetails{
		Type:   "about:blank",
		Title:  title,
		Status: status,
		Detail: detail,
		Code:   code,
	})
}

func writeInternalError(c *gin.Context, detail string) {
	writeProblem(c, http.StatusInternalServerError, ErrorCodeInternal, "Internal error", detail)
}

func writeAPIError(c *gin.Context, err error) {
	var validationErr types.ValidationError
	if errors.As(err, &validationErr) {
		writeProblem(c, http.StatusBadRequest, ErrorCodeValidationFailed, "Validation failed", validationErr.Detail)
		return
	}
	var notFoundErr types.NotFoundError
	if errors.As(err, &notFoundErr) {
		writeProblem(c, http.StatusNotFound, ErrorCodeNotFound, "Not found", notFoundErr.Detail)
		return
	}
	var conflictErr types.ConflictError
	if errors.As(err, &conflictErr) {
		writeProblem(c, http.StatusConflict, ErrorCodeConflict, "Conflict", conflictErr.Detail)
		return
	}
	writeInternalError(c, err.Error())
}
