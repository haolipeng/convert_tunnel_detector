package api

import (
	"context"
	"fmt"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/labstack/echo/v4"
)

// Server HTTP 服务器
type Server struct {
	echo *echo.Echo
	addr string
}

// NewServer 创建一个新的 HTTP 服务器
func NewServer(cfg *config.Config) *Server {
	e := echo.New()

	// 构建地址
	addr := fmt.Sprintf("%s:%s", cfg.API.Host, cfg.API.Port)

	return &Server{
		echo: e,
		addr: addr,
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

// GetEcho 获取Echo实例
func (s *Server) GetEcho() *echo.Echo {
	return s.echo
}

// RegisterRuleService 注册规则服务
func (s *Server) RegisterRuleService(rs *RuleService) {
	// 注册路由
	s.echo.GET("/ruleEngine/configs", rs.GetRuleConfigs)              // 获取所有规则配置
	s.echo.GET("/ruleEngine/configs/:rule_id", rs.GetRuleConfig)      // 获取指定规则配置
	s.echo.POST("/ruleEngine/configs/:rule_id", rs.CreateRule)        // 创建规则
	s.echo.POST("/ruleEngine/configs/:rule_id/start", rs.StartRule)   // 启动规则
	s.echo.POST("/ruleEngine/configs/:rule_id/stop", rs.StopRule)     // 停止规则
	s.echo.PUT("/ruleEngine/configs/:rule_id", rs.UpdateRule)         // 更新规则
	s.echo.POST("/ruleEngine/configs/:rule_id/delete", rs.DeleteRule) // 删除规则
	s.echo.POST("/ruleEngine/validate", rs.ValidateRule)              // 验证规则有效性
}
