package api

import (
	"context"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Server HTTP 服务器
type Server struct {
	echo      *echo.Echo
	addr      string
	ruleGroup *echo.Group
}

// NewServer 创建一个新的 HTTP 服务器
func NewServer(addr string) *Server {
	e := echo.New()

	// 添加中间件
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// 创建路由组
	ruleGroup := e.Group("/api/v1")

	return &Server{
		echo:      e,
		addr:      addr,
		ruleGroup: ruleGroup,
	}
}

// Start 启动 HTTP 服务器
func (s *Server) Start() error {
	return s.echo.Start(s.addr)
}

// Stop 停止 HTTP 服务器
func (s *Server) Stop(ctx context.Context) error {
	return s.echo.Shutdown(ctx)
}

// GetRuleGroup 获取规则引擎的路由组
func (s *Server) GetRuleGroup() *echo.Group {
	return s.ruleGroup
}

// RegisterRuleService 注册规则服务
func (s *Server) RegisterRuleService(rs *RuleService) {
	PREFIX := "ruleEngine"

	// 注册路由
	s.ruleGroup.GET(PREFIX+"/configs", rs.GetRuleConfigs)
	s.ruleGroup.GET(PREFIX+"/configs/:rule_id", rs.GetRuleConfig)
	s.ruleGroup.POST(PREFIX+"/configs/:rule_id", rs.CreateRule)
	s.ruleGroup.POST(PREFIX+"/configs/:rule_id/start", rs.StartRule)
	s.ruleGroup.POST(PREFIX+"/configs/:rule_id/stop", rs.StopRule)
	s.ruleGroup.PUT(PREFIX+"/configs/:rule_id", rs.UpdateRule)
	s.ruleGroup.POST(PREFIX+"/configs/:rule_id/delete", rs.DeleteRule)
}
