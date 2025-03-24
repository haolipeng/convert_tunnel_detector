package ruleEngine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLoadRuleFromFile 测试从文件加载规则
func TestLoadRuleFromFile(t *testing.T) {
	// 测试用例
	testCases := []struct {
		name           string
		filePath       string
		wantErr        bool
		expectedRuleID string
		expectedMode   string
		expectedType   string
		expectedState  string
		// 期望的LSR规则表达式
		expectedLSRExpr string
	}{
		{
			name:            "加载YAML格式的黑名单规则",
			filePath:        "../../rules/ospf_rules_blacklist.yaml",
			wantErr:         false,
			expectedRuleID:  "ospf_55667788",
			expectedMode:    "blacklist",
			expectedType:    "or",
			expectedState:   "enable",
			expectedLSRExpr: "ospf.link_state_id == \"192.168.170.8\"",
		},
		{
			name:            "加载YAML格式的白名单规则",
			filePath:        "../../rules/ospf_rules_whitelist.yaml",
			wantErr:         false,
			expectedRuleID:  "ospf_11223344",
			expectedMode:    "whitelist",
			expectedType:    "and",
			expectedState:   "enable",
			expectedLSRExpr: "ospf.link_state_id == \"192.168.170.8\"",
		},
		{
			name:            "加载JSON格式的黑名单规则",
			filePath:        "../../rules/ospf_rules_blacklist.json",
			wantErr:         false,
			expectedRuleID:  "ospf_55667788",
			expectedMode:    "blacklist",
			expectedType:    "or",
			expectedState:   "enable",
			expectedLSRExpr: "ospf.link_state_id == \"192.168.170.8\"",
		},
		{
			name:            "加载JSON格式的白名单规则",
			filePath:        "../../rules/ospf_rules_whitelist.json",
			wantErr:         false,
			expectedRuleID:  "ospf_whitelist_001",
			expectedMode:    "whitelist",
			expectedType:    "or",
			expectedState:   "enable",
			expectedLSRExpr: "ospf.link_state_id.startsWith(\"192.168.\")",
		},
		{
			name:     "加载不存在的文件",
			filePath: "../../rules/not_exist_file.yaml",
			wantErr:  true,
		},
	}

	// 执行测试
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			loader := NewRuleLoader()
			err := loader.LoadRuleFromFile(tc.filePath)

			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// 获取规则并验证内容
				rules := loader.GetAllRules()
				assert.NotEmpty(t, rules)

				// 获取规则实例
				var rule *Rule
				for _, r := range rules {
					rule = r
					break
				}

				// 验证基本规则属性
				assert.Equal(t, tc.expectedRuleID, rule.RuleID, "规则ID不匹配")
				assert.Equal(t, tc.expectedMode, rule.RuleMode, "规则模式不匹配")
				assert.Equal(t, tc.expectedType, rule.RuleType, "规则类型不匹配")
				assert.Equal(t, tc.expectedState, rule.State, "规则状态不匹配")
				assert.Equal(t, "ospf", rule.RuleProtocol, "规则协议不匹配")

				// 验证规则标签包含 ospf
				assert.Contains(t, rule.RuleTag, "ospf", "规则标签不包含 ospf")

				// 验证规则名称不为空
				assert.NotEmpty(t, rule.RuleName, "规则名称为空")

				// 验证协议规则
				assert.Contains(t, rule.ProtocolRules, "HELLO", "缺少 HELLO 规则")
				assert.Contains(t, rule.ProtocolRules, "DD", "缺少 DD 规则")
				assert.Contains(t, rule.ProtocolRules, "LSR", "缺少 LSR 规则")
				assert.Contains(t, rule.ProtocolRules, "LSU", "缺少 LSU 规则")
				assert.Contains(t, rule.ProtocolRules, "LSAck", "缺少 LSAck 规则")

				// 验证 HELLO 规则
				assert.Equal(t, "enable", rule.ProtocolRules["HELLO"].State, "HELLO 规则状态不匹配")
				assert.Equal(t, "single", rule.ProtocolRules["HELLO"].Type, "HELLO 规则类型不匹配")
				assert.Contains(t, rule.ProtocolRules["HELLO"].Expression, "ospf.hello.hello_interval", "HELLO 规则表达式不包含 ospf.hello.hello_interval")
				assert.Contains(t, rule.ProtocolRules["HELLO"].Description, "检查Hello包", "HELLO 规则描述不匹配")

				// 验证 LSR 规则
				assert.Equal(t, "enable", rule.ProtocolRules["LSR"].State, "LSR 规则状态不匹配")
				assert.Equal(t, "single", rule.ProtocolRules["LSR"].Type, "LSR 规则类型不匹配")
				assert.Equal(t, tc.expectedLSRExpr, rule.ProtocolRules["LSR"].Expression, "LSR 规则表达式不匹配")
				assert.Contains(t, rule.ProtocolRules["LSR"].Description, "检查LSR", "LSR 规则描述不匹配")

				// 验证表达式中的字符串正确处理
				assert.Contains(t, rule.ProtocolRules["LSR"].Expression, "192.168.", "LSR 规则表达式不包含 IP 地址字符串前缀")

				// 验证 LSAck 规则的序列号表达式
				assert.Contains(t, rule.ProtocolRules["LSAck"].Expression, "ospf.lsa.seqnum", "LSAck 规则表达式不包含序列号字段")
				assert.Contains(t, rule.ProtocolRules["LSAck"].Expression, "0x80000001", "LSAck 规则表达式不包含十六进制值")
			}
		})
	}
}

// TestLoadRulesFromDirectory 测试从目录加载所有规则
func TestLoadRulesFromDirectory(t *testing.T) {
	// 创建规则加载器
	loader := NewRuleLoader()

	// 加载规则目录
	err := loader.LoadRulesFromDirectory("../../rules")
	assert.NoError(t, err)

	// 获取所有规则
	rules := loader.GetAllRules()

	// 验证是否加载了规则
	assert.NotEmpty(t, rules)

	// 验证是否加载了特定的规则
	blacklistRuleID := "ospf_55667788"
	blacklistRule, exists := loader.GetRule(blacklistRuleID)
	assert.True(t, exists)
	assert.Equal(t, "blacklist", blacklistRule.RuleMode)

	whitelistRuleID := "ospf_whitelist_001"
	whitelistRule, exists := loader.GetRule(whitelistRuleID)
	assert.True(t, exists)
	assert.Equal(t, "whitelist", whitelistRule.RuleMode)

	// 验证规则内容
	assert.Contains(t, blacklistRule.ProtocolRules, "LSR")
	assert.Contains(t, blacklistRule.ProtocolRules["LSR"].Expression, "192.168.170.8")

	assert.Contains(t, whitelistRule.ProtocolRules, "LSR")
	assert.Contains(t, whitelistRule.ProtocolRules["LSR"].Expression, "startsWith")
}
