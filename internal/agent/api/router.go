package api

import "github.com/gin-gonic/gin"

func NewRouter(status StatusService, ruleset RulesetService, response ResponseService, dispatch DispatchService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())

	handler := NewHandler(status, ruleset, response, dispatch)
	v1 := router.Group("/api/v1")
	v1.GET("/health", handler.GetHealth)
	v1.GET("/status", handler.GetStatus)
	v1.GET("/ruleset", handler.GetRuleset)
	v1.PUT("/ruleset", handler.ReplaceRuleset)
	v1.DELETE("/ruleset", handler.ClearRuleset)
	v1.GET("/response", handler.GetResponse)
	v1.PUT("/response", handler.ReplaceResponse)
	v1.DELETE("/response", handler.ClearResponse)
	v1.GET("/dispatch", handler.GetDispatch)
	v1.PUT("/dispatch", handler.ReplaceDispatch)
	v1.DELETE("/dispatch", handler.ClearDispatch)

	return router
}
