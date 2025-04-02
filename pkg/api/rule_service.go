package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/processor"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/labstack/echo/v4"
	"github.com/sirupsen/logrus"
)

// 响应结构体
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// RuleService 规则服务
type RuleService struct {
	ruleLoader    *ruleEngine.RuleLoader
	ruleProcessor *processor.RuleEngine
	ruleDir       string
	config        *config.Config
}

// NewRuleService 创建一个新的规则服务
func NewRuleService(cfg *config.Config, ruleProcessor *processor.RuleEngine) *RuleService {
	// 创建规则加载器
	loader := ruleEngine.NewRuleLoader()

	// 从本地规则目录加载规则
	ruleDir := cfg.RuleEngine.RuleDirectory
	err := loader.LoadRulesFromDirectory(ruleDir)
	if err != nil {
		logrus.Errorf("加载规则目录失败: %v", err)
	}

	// 创建规则服务
	return &RuleService{
		ruleLoader:    loader,
		ruleProcessor: ruleProcessor,
		ruleDir:       ruleDir,
		config:        cfg,
	}
}

// GetRuleConfigs 获取所有规则配置
func (rs *RuleService) GetRuleConfigs(c echo.Context) error {
	// 使用查询参数过滤规则
	protocol := c.QueryParam("protocol") //指定协议
	mode := c.QueryParam("mode")         //指定模式
	state := c.QueryParam("state")       //指定状态

	// 获取所有规则
	allRules := rs.ruleLoader.GetAllRules()

	// 如果没有过滤条件，直接返回所有规则
	if protocol == "" && mode == "" && state == "" {
		logrus.WithFields(logrus.Fields{
			"rule_count": len(allRules),
			"operation":  "get_all_rules",
		}).Debug("获取所有规则")

		// 直接返回所有规则
		return c.JSON(http.StatusOK, Response{
			Code:    http.StatusOK,
			Message: "获取规则配置成功",
			Data:    allRules,
		})
	}

	// 应用过滤
	filteredRules := make(map[string]*ruleEngine.Rule)
	for id, rule := range allRules {
		// 过滤协议
		if protocol != "" && rule.RuleProtocol != protocol {
			continue
		}

		// 过滤模式
		if mode != "" && rule.RuleMode != mode {
			continue
		}

		// 过滤状态
		if state != "" && rule.State != state {
			continue
		}

		// 通过所有过滤条件，添加到结果中
		filteredRules[id] = rule
	}

	logrus.WithFields(logrus.Fields{
		"total_rules":    len(allRules),
		"filtered_rules": len(filteredRules),
		"protocol":       protocol,
		"mode":           mode,
		"state":          state,
		"operation":      "filter_rules",
	}).Debug("过滤规则")

	return c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "获取规则配置成功",
		Data:    filteredRules,
	})
}

// GetRuleConfig 获取特定规则配置
func (rs *RuleService) GetRuleConfig(c echo.Context) error {
	// 优先从路径参数获取rule_id，如果没有则从查询参数获取
	ruleID := c.Param("rule_id")

	if ruleID == "" {
		return HandleError(c, NewRuleIDEmptyError(ruleID))
	}

	//检查规则是否存在
	rule, exists := rs.ruleLoader.GetRule(ruleID)
	if !exists {
		return HandleError(c, NewRuleNotFoundError(ruleID))
	}

	return c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "获取规则配置成功",
		Data:    rule,
	})
}

// CreateRule 创建规则
func (rs *RuleService) CreateRule(c echo.Context) error {
	ruleID := c.Param("rule_id")
	if ruleID == "" {
		return HandleError(c, NewRuleIDEmptyError(ruleID))
	}

	// 1. 检查规则是否已存在
	if _, exists := rs.ruleLoader.GetRule(ruleID); exists {
		return HandleError(c, NewRuleAlreadyExistsError(ruleID))
	}

	// 2. 解析请求体中的规则
	var rule ruleEngine.Rule
	if err := c.Bind(&rule); err != nil {
		return HandleError(c, NewInvalidRuleFormatError(err))
	}

	// 确保规则ID一致性
	if ruleID != rule.RuleID {
		return HandleError(c, NewInvalidRuleFormatError(fmt.Errorf("规则ID不匹配")))
	}

	// 3. 验证规则的有效性
	if err := validateRule(&rule); err != nil {
		return HandleError(c, NewRuleValidationError(err))
	}

	// 4. 更新 RuleLoader 中的规则
	if err := rs.ruleLoader.AddRule(ruleID, &rule); err != nil {
		return HandleError(c, NewInternalServerError(fmt.Errorf("更新规则加载器失败: %w", err)))
	}

	// 5. 更新 RuleEngine 中的规则
	if rs.ruleProcessor != nil {
		// 检查 规则引擎的CEL环境 是否已初始化
		if rs.ruleProcessor.Env == nil {
			return HandleError(c, NewInternalServerError(fmt.Errorf("规则引擎环境未初始化")))
		}

		// 使用 RuleEngine 已有的 CEL 环境处理规则
		if err := rs.ruleProcessor.ProcessRule(rs.ruleProcessor.Env, &rule, ruleID, true); err != nil {
			return HandleError(c, NewInternalServerError(fmt.Errorf("更新规则引擎失败: %w", err)))
		}
	}

	// 6. 将规则保存到本地文件
	data, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return HandleError(c, NewInternalServerError(fmt.Errorf("序列化规则失败: %w", err)))
	}

	filePath := filepath.Join(rs.ruleDir, ruleID+".json")
	if err := os.WriteFile(filePath, data, os.FileMode(rs.config.Permissions.FileMode)); err != nil {
		return HandleError(c, NewInternalServerError(fmt.Errorf("保存规则文件失败: %w", err)))
	}

	// 记录成功日志
	logrus.WithFields(logrus.Fields{
		"rule_id": ruleID,
		"mode":    rule.RuleMode,
		"state":   rule.State,
	}).Info("规则创建成功")

	return c.JSON(http.StatusCreated, Response{
		Code:    http.StatusCreated,
		Message: "创建规则成功",
		Data:    rule,
	})
}

// UpdateRule 更新规则
func (rs *RuleService) UpdateRule(c echo.Context) error {
	// 1. 检查规则是否已存在
	ruleID := c.Param("rule_id")
	if ruleID == "" {
		return HandleError(c, NewRuleIDEmptyError(ruleID))
	}

	// 2. 解析请求体中的规则
	var rule ruleEngine.Rule
	if err := c.Bind(&rule); err != nil {
		return HandleError(c, NewInvalidRuleFormatError(err))
	}

	// 保持规则ID一致
	rule.RuleID = ruleID

	// 3. 验证规则的有效性
	if err := validateRule(&rule); err != nil {
		return HandleError(c, NewRuleValidationError(err))
	}

	// 4. 更新 RuleLoader 中的规则
	if err := rs.ruleLoader.UpdateRule(ruleID, &rule); err != nil {
		return HandleError(c, NewInternalServerError(fmt.Errorf("更新规则加载器失败: %w", err)))
	}

	// 5. 更新 RuleEngine 中的规则
	if rs.ruleProcessor != nil {
		// 使用 RuleEngine 已有的 CEL 环境处理规则
		if err := rs.ruleProcessor.ProcessRule(rs.ruleProcessor.Env, &rule, ruleID, false); err != nil {
			return HandleError(c, NewInternalServerError(fmt.Errorf("更新规则引擎失败: %w", err)))
		}
	}

	// 6. 将规则修改更新到本地文件
	data, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return HandleError(c, NewInternalServerError(fmt.Errorf("序列化规则失败: %w", err)))
	}

	// 确定文件路径
	filePath := filepath.Join(rs.ruleDir, ruleID+".json")

	// 保存到文件，使用配置的文件权限
	if err := os.WriteFile(filePath, data, os.FileMode(rs.config.Permissions.FileMode)); err != nil {
		return HandleError(c, NewInternalServerError(fmt.Errorf("保存规则文件失败: %w", err)))
	}

	// 7. 记录相关日志
	logrus.WithFields(logrus.Fields{
		"rule_id":   ruleID,
		"operation": "update",
		"file":      filePath,
	}).Info("规则更新成功")

	return c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "更新规则成功",
		Data:    rule,
	})
}

// DeleteRule 删除规则
func (rs *RuleService) DeleteRule(c echo.Context) error {
	ruleID := c.Param("rule_id")

	// 检查规则是否存在
	if _, exists := rs.ruleLoader.GetRule(ruleID); !exists {
		return HandleError(c, NewRuleNotFoundError(ruleID))
	}

	// 尝试删除JSON和YAML格式的文件
	jsonFilePath := filepath.Join(rs.ruleDir, ruleID+".json")
	yamlFilePath := filepath.Join(rs.ruleDir, ruleID+".yaml")
	ymlFilePath := filepath.Join(rs.ruleDir, ruleID+".yml")

	jsonRemoved := false
	yamlRemoved := false
	ymlRemoved := false

	if _, err := os.Stat(jsonFilePath); err == nil {
		if err := os.Remove(jsonFilePath); err == nil {
			jsonRemoved = true
		} else {
			logrus.WithFields(logrus.Fields{
				"rule_id": ruleID,
				"path":    jsonFilePath,
				"error":   err.Error(),
			}).Error("删除JSON规则文件失败")
		}
	}

	if _, err := os.Stat(yamlFilePath); err == nil {
		if err := os.Remove(yamlFilePath); err == nil {
			yamlRemoved = true
		} else {
			logrus.WithFields(logrus.Fields{
				"rule_id": ruleID,
				"path":    yamlFilePath,
				"error":   err.Error(),
			}).Error("删除YAML规则文件失败")
		}
	}

	if _, err := os.Stat(ymlFilePath); err == nil {
		if err := os.Remove(ymlFilePath); err == nil {
			ymlRemoved = true
		} else {
			logrus.WithFields(logrus.Fields{
				"rule_id": ruleID,
				"path":    ymlFilePath,
				"error":   err.Error(),
			}).Error("删除YML规则文件失败")
		}
	}

	if !jsonRemoved && !yamlRemoved && !ymlRemoved {
		return HandleError(c, NewInternalServerError(fmt.Errorf("删除规则文件失败，未找到任何匹配的文件")))
	}

	// 通知规则处理器更新规则
	if rs.ruleProcessor != nil {
		if err := rs.ruleProcessor.ReloadRules(); err != nil {
			logrus.WithFields(logrus.Fields{
				"rule_id": ruleID,
				"error":   err.Error(),
			}).Warn("重新加载规则引擎失败")
		}
	}

	return c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "删除规则成功",
	})
}

// validateRule 验证规则的有效性
func validateRule(rule *ruleEngine.Rule) error {
	// 验证规则ID
	if rule.RuleID == "" {
		return fmt.Errorf("规则ID不能为空")
	}

	// 验证协议类型
	if rule.RuleProtocol == "" {
		return fmt.Errorf("规则协议类型不能为空")
	}

	// 验证规则模式
	if rule.RuleMode != "whitelist" && rule.RuleMode != "blacklist" {
		return fmt.Errorf("规则模式必须是 whitelist 或 blacklist")
	}

	// 验证规则状态
	if rule.State != "enable" && rule.State != "disable" {
		return fmt.Errorf("规则状态必须是 enable 或 disable")
	}

	// 验证协议规则
	if len(rule.ProtocolRules) == 0 {
		return fmt.Errorf("协议规则不能为空")
	}

	// 验证每个协议规则
	for tag, protocolRule := range rule.ProtocolRules {
		if protocolRule.Expression == "" {
			return fmt.Errorf("协议规则 %s 的表达式不能为空", tag)
		}

		// 这里可以添加更多的验证逻辑，例如验证表达式的语法等
	}

	return nil
}

// ValidateRule 验证规则有效性（不保存到文件系统，不加载到规则引擎）
func (rs *RuleService) ValidateRule(c echo.Context) error {
	// 解析请求体
	var rule ruleEngine.Rule
	if err := c.Bind(&rule); err != nil {
		return HandleError(c, NewInvalidRuleFormatError(err))
	}

	// 验证基本字段
	errors := make(map[string]string)
	if rule.RuleID == "" {
		errors["rule_id"] = "规则ID不能为空"
	}

	if rule.RuleProtocol == "" {
		errors["rule_protocol"] = "规则协议类型不能为空"
	}

	if rule.RuleName == "" {
		errors["rule_name"] = "规则名称不能为空"
	}

	if rule.RuleMode != "whitelist" && rule.RuleMode != "blacklist" {
		errors["rule_mode"] = "规则模式必须是 whitelist 或 blacklist"
	}

	if rule.State != "enable" && rule.State != "disable" && rule.State != "" {
		errors["state"] = "规则状态必须是 enable 或 disable"
	}

	// 验证各OSPF包类型的表达式
	details := make(map[string]map[string]interface{})
	isValid := len(errors) == 0

	// 验证是否有协议规则
	if len(rule.ProtocolRules) == 0 {
		errors["protocol_rules"] = "协议规则不能为空"
		isValid = false
	} else {
		// 验证每个协议规则
		for packetType, packetRule := range rule.ProtocolRules {
			packetInfo := map[string]interface{}{
				"valid":       true,
				"description": packetRule.Description,
			}

			// 验证表达式是否为空
			if packetRule.Expression == "" {
				packetInfo["valid"] = false
				packetInfo["error"] = "表达式不能为空"
				isValid = false
				details[packetType] = packetInfo
				continue
			}

			// 使用RuleEngine验证表达式
			if rs.ruleProcessor != nil {
				expressionErr := rs.ruleProcessor.ValidateOSPFExpression(packetType, packetRule.Expression)
				if expressionErr != nil {
					packetInfo["valid"] = false
					packetInfo["error"] = expressionErr.Error()
					isValid = false
				} else {
					packetInfo["valid"] = true
				}
			} else {
				// 如果没有规则处理器，标记为警告而不是失败
				packetInfo["valid"] = false
				packetInfo["error"] = "规则引擎不可用，无法验证表达式"
				packetInfo["warning"] = true
				logrus.Warn("规则引擎不可用，跳过表达式验证")
			}

			details[packetType] = packetInfo
		}
	}

	// 准备响应数据
	responseData := map[string]interface{}{
		"valid": isValid,
	}

	if len(errors) > 0 {
		responseData["errors"] = errors
	}

	if len(details) > 0 {
		responseData["details"] = details
	}

	return c.JSON(http.StatusOK, Response{
		Code:    http.StatusOK,
		Message: "规则验证完成",
		Data:    responseData,
	})
}
