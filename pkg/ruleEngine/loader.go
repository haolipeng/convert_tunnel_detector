package ruleEngine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleLoader 负责加载和管理规则
type RuleLoader struct {
	rules map[string]*Rule // 使用map存储规则,key为规则ID,value为规则详情
}

// NewRuleLoader 创建一个新的规则加载器
func NewRuleLoader() *RuleLoader {
	return &RuleLoader{
		rules: make(map[string]*Rule),
	}
}

// LoadRuleFromFile 从文件加载规则
func (rl *RuleLoader) LoadRuleFromFile(filePath string) error {
	// 读取文件内容
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("读取规则文件失败: %v", err)
	}

	var rule Rule

	// 根据文件扩展名选择解析方式
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".json":
		// 解析JSON
		if err := json.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("解析JSON失败: %v", err)
		}
	case ".yaml", ".yml":
		// 解析YAML
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("解析YAML失败: %v", err)
		}
	default:
		return fmt.Errorf("不支持的文件格式: %s", ext)
	}

	// 存储规则
	rl.rules[rule.RuleID] = &rule
	return nil
}

// LoadRulesFromDirectory 从目录加载所有规则
func (rl *RuleLoader) LoadRulesFromDirectory(dirPath string) error {
	files, err := os.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("读取目录失败: %v", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		ext := strings.ToLower(filepath.Ext(file.Name()))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" {
			fullPath := filepath.Join(dirPath, file.Name())
			if err := rl.LoadRuleFromFile(fullPath); err != nil {
				return fmt.Errorf("加载规则文件 %s 失败: %v", file.Name(), err)
			}
		}
	}
	return nil
}

// GetRule 根据规则ID获取规则
func (rl *RuleLoader) GetRule(ruleID string) (*Rule, bool) {
	rule, exists := rl.rules[ruleID]
	return rule, exists
}

// GetAllRules 获取所有规则
func (rl *RuleLoader) GetAllRules() map[string]*Rule {
	return rl.rules
}

// AddRule 添加新规则到 RuleLoader
func (rl *RuleLoader) AddRule(ruleID string, rule *Rule) error {
	// 检查规则是否已存在
	if _, exists := rl.rules[ruleID]; exists {
		return fmt.Errorf("规则 %s 已存在", ruleID)
	}

	// 添加规则
	rl.rules[ruleID] = rule

	return nil
}

// UpdateRule 更新规则
func (rl *RuleLoader) UpdateRule(ruleID string, rule *Rule) error {
	// 检查规则是否存在
	if _, exists := rl.rules[ruleID]; !exists {
		return fmt.Errorf("规则 %s 不存在", ruleID)
	}

	// 更新规则
	rl.rules[ruleID] = rule
	return nil
}
