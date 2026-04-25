package console

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"sidersp/internal/controlplane"
	"sidersp/internal/logs"
	"sidersp/internal/rule"
)

type RuleService interface {
	Status() controlplane.Status
	Stats(rangeSeconds int) (controlplane.Stats, error)
	ListRules() []rule.Rule
	RuleMatchCounts() (map[int]uint64, error)
	GetRule(id int) (rule.Rule, error)
	CreateRule(item rule.Rule) (rule.Rule, error)
	UpdateRule(id int, item rule.Rule) (rule.Rule, error)
	DeleteRule(id int) error
	SetRuleEnabled(id int, enabled bool) (rule.Rule, error)
}

type LogService interface {
	Level() string
	Levels() logs.Levels
	SetLevel(level string) (string, error)
	SetLevels(levels logs.Levels) (logs.Levels, error)
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

	logs.App().WithField("listen_addr", s.addr).Info("Started console server")

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
	v1.GET("/logging/levels", handler.getLogLevels)
	v1.PUT("/logging/levels", handler.setLogLevels)
	v1.GET("/stats", handler.getStats)
	v1.GET("/rules", handler.listRules)
	v1.POST("/rules", handler.createRule)
	v1.GET("/rules/:id", handler.getRule)
	v1.PUT("/rules/:id", handler.updateRule)
	v1.DELETE("/rules/:id", handler.deleteRule)
	v1.POST("/rules/:id/enable", handler.enableRule)
	v1.POST("/rules/:id/disable", handler.disableRule)
	if assetsFS, ok := subFS(consoleStaticFiles, "static/assets"); ok {
		router.StaticFS("/assets", http.FS(assetsFS))
	} else {
		router.GET("/assets/*filepath", func(c *gin.Context) {
			c.Status(http.StatusNotFound)
		})
	}
	router.GET("/", func(c *gin.Context) {
		serveWebIndex(c)
	})
	router.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || strings.HasPrefix(c.Request.URL.Path, "/assets/") {
			c.Status(http.StatusNotFound)
			return
		}
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}
		serveWebIndex(c)
	})

	return router
}

func subFS(root fs.FS, dir string) (fs.FS, bool) {
	sub, err := fs.Sub(root, dir)
	if err != nil {
		return nil, false
	}
	return sub, true
}

func serveWebIndex(c *gin.Context) {
	data, err := fs.ReadFile(consoleStaticFiles, "static/index.html")
	if err != nil {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(defaultWebIndexHTML))
		return
	}
	c.Data(http.StatusOK, "text/html; charset=utf-8", data)
}

const defaultWebIndexHTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SideRSP Console</title>
  </head>
  <body>
    <div id="root">SideRSP web assets are not built yet. Run make build-web.</div>
  </body>
</html>
`
