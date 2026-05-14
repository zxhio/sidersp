package api

import "github.com/gin-gonic/gin"

func NewRouter(status StatusService) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Recovery())

	handler := NewHandler(status)
	v1 := router.Group("/api/v1")
	v1.GET("/health", handler.GetHealth)
	v1.GET("/status", handler.GetStatus)

	return router
}
