package api

import "github.com/gin-gonic/gin"

func NewRouter(status StatusService, ruleset RulesetService, attachments AttachmentService, response ResponseService, dispatch DispatchService, stats StatsService, events EventService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())

	handler := NewHandler(status, ruleset, attachments, response, dispatch, stats, events)
	v1 := router.Group("/api/v1")
	v1.GET("/health", handler.GetHealth)
	v1.GET("/status", handler.GetStatus)
	v1.POST("/attachments", handler.CreateAttachment)
	v1.GET("/attachments", handler.ListAttachments)
	v1.GET("/attachments/:ifindex", handler.GetAttachment)
	v1.PATCH("/attachments/:ifindex", handler.SetAttachmentEnabled)
	v1.DELETE("/attachments/:ifindex", handler.DeleteAttachment)
	v1.GET("/ruleset", handler.GetRuleset)
	v1.PUT("/ruleset", handler.ReplaceRuleset)
	v1.DELETE("/ruleset", handler.ClearRuleset)
	v1.GET("/response", handler.GetResponse)
	v1.PUT("/response", handler.ReplaceResponse)
	v1.DELETE("/response", handler.ClearResponse)
	v1.GET("/dispatch", handler.GetDispatch)
	v1.PUT("/dispatch", handler.ReplaceDispatch)
	v1.DELETE("/dispatch", handler.ClearDispatch)
	v1.GET("/stats", handler.GetStats)
	v1.GET("/events/stream", handler.StreamEvents)

	return router
}
