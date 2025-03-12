package ruleEngine

import (
	"testing"
)

func TestRuleLoader(t *testing.T) {
	// 创建规则加载器
	loader := NewRuleLoader()

	// 加载单个规则文件
	err := loader.LoadRuleFromFile("../../test/rules.yaml")
	if err != nil {
		t.Fatalf("加载规则文件失败: %v", err)
	}

	// 获取并验证规则
	rule, exists := loader.GetRule("ospf_1357924680")
	if !exists {
		t.Fatal("未找到预期的规则")
	}

	// 验证规则内容
	if rule.State != "enable" {
		t.Errorf("规则状态不匹配，期望 enable，实际 %s", rule.State)
	}

	if rule.RuleTag != "ospf" {
		t.Errorf("规则标签不匹配，期望 ospf，实际 %s", rule.RuleTag)
	}

	/*// 验证协议规则
	if len(rule.ProtocolRules["HELLO"]) == 0 {
		t.Error("HELLO协议规则为空")
	}*/
}
