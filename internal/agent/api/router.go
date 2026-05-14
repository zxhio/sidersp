package api

import "github.com/gin-gonic/gin"

func NewRouter(status StatusService, ruleset RulesetService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())

	handler := NewHandler(status, ruleset)
	v1 := router.Group("/api/v1")
	v1.GET("/health", handler.GetHealth)
	v1.GET("/status", handler.GetStatus)
	v1.GET("/ruleset", handler.GetRuleset)
	v1.PUT("/ruleset", handler.ReplaceRuleset)
	v1.DELETE("/ruleset", handler.ClearRuleset)

	return router
}
