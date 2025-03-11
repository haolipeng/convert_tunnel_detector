package ruleEngine

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// RuleLoader 负责加载和管理规则
type RuleLoader struct {
	rules map[string]*Rule // 使用map存储规则，key为规则ID
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

	// 解析YAML
	var rule Rule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return fmt.Errorf("解析YAML失败: %v", err)
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
		if filepath.Ext(file.Name()) == ".yaml" || filepath.Ext(file.Name()) == ".yml" {
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
