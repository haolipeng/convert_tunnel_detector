package types

import "github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"

// RuleMatchResult 表示规则引擎的匹配结果
type RuleMatchResult struct {
	Matched bool             // 是否匹配
	Rule    *ruleEngine.Rule // 匹配的规则
}

// RuleAction 表示规则匹配后的动作
type RuleAction uint8

const (
	ActionDeny  RuleAction = iota + 1 // 拒绝
	ActionAllow                       // 允许
)
