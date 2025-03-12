package types

import "github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"

// RuleMatchResult 表示规则引擎的匹配结果
type RuleMatchResult struct {
	WhiteRuleMatched bool                     // 白名单规则是否匹配
	BlackRuleMatched bool                     // 黑名单规则是否匹配
	WhiteRule        *ruleEngine.ProtocolRule // 匹配的白名单规则
	BlackRule        *ruleEngine.ProtocolRule // 匹配的黑名单规则
}

// RuleAction 表示规则匹配后的动作
type RuleAction uint8

const (
	ActionDeny  RuleAction = iota + 1 // 拒绝
	ActionAllow                       // 允许
)
