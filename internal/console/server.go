package console

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"

	"sidersp/internal/controlplane"
	"sidersp/internal/rule"
)

type RuleService interface {
	Status() controlplane.Status
	Stats(window string) (controlplane.Stats, error)
	StatsWindows() []string
	ListRules() []rule.Rule
	GetRule(id int) (rule.Rule, error)
	CreateRule(item rule.Rule) (rule.Rule, error)
	UpdateRule(id int, item rule.Rule) (rule.Rule, error)
	DeleteRule(id int) error
	SetRuleEnabled(id int, enabled bool) (rule.Rule, error)
}

type LogService interface {
	Level() string
	SetLevel(level string) (string, error)
}

type Server struct {
	addr       string
	service    RuleService
	logService LogService
}

func NewServer(addr string, service RuleService, logServices ...LogService) *Server {
	if service == nil {
		panic("console: service is required")
	}
	var logService LogService
	if len(logServices) > 0 {
		logService = logServices[0]
	}
	return &Server{addr: addr, service: service, logService: logService}
}

func (s *Server) Run(ctx context.Context) error {
	router := s.newRouter()
	srv := &http.Server{
		Addr:    s.addr,
		Handler: router,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	logrus.WithField("listen_addr", s.addr).Info("Started console server")

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	case err := <-errCh:
		if err == nil {
			return nil
		}
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
}

func (s *Server) newRouter() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	handler := Handler{service: s.service, logService: s.logService}
	v1 := router.Group("/api/v1")
	v1.GET("/status", handler.getStatus)
	v1.GET("/logging/level", handler.getLogLevel)
	v1.PUT("/logging/level", handler.setLogLevel)
	v1.GET("/stats", handler.getStats)
	v1.GET("/stats/windows", handler.listStatsWindows)
	v1.GET("/rules", handler.listRules)
	v1.POST("/rules", handler.createRule)
	v1.GET("/rules/:id", handler.getRule)
	v1.PUT("/rules/:id", handler.updateRule)
	v1.DELETE("/rules/:id", handler.deleteRule)
	v1.POST("/rules/:id/enable", handler.enableRule)
	v1.POST("/rules/:id/disable", handler.disableRule)

	return router
}
