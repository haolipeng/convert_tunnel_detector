package types

import "github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"

// RuleMatchResult 表示规则引擎的匹配结果
type RuleMatchResult struct {
	WhiteRuleMatched bool                     // 白名单规则是否匹配
	BlackRuleMatched bool                     // 黑名单规则是否匹配
	WhiteRule        *ruleEngine.ProtocolRule // 匹配的白名单规则
	BlackRule        *ruleEngine.ProtocolRule // 匹配的黑名单规则
	Action           RuleAction               // 数据包处理动作
}

// RuleAction 表示规则匹配后的动作
// 可能的动作：
// 1. ActionForward: 转发数据包
// 2. ActionAlert: 触发告警
type RuleAction uint8

const (
	ActionForward RuleAction = iota + 1 // 转发数据包到目标接口
	ActionAlert                         // 触发告警，记录可疑流量
)
