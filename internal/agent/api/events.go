package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (h Handler) StreamEvents(c *gin.Context) {
	events, err := h.events.SubscribeEvents(c.Request.Context())
	if err != nil {
		writeAPIError(c, err)
		return
	}

	header := c.Writer.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	c.Status(http.StatusOK)
	c.Writer.Flush()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case item, ok := <-events:
			if !ok {
				return
			}
			if err := writeEvent(c, newEventResponse(item)); err != nil {
				return
			}
		}
	}
}

func writeEvent(c *gin.Context, item EventResponse) error {
	body, err := json.Marshal(item)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(c.Writer, "event: rule_event\ndata: %s\n\n", body); err != nil {
		return err
	}
	c.Writer.Flush()
	return nil
}
