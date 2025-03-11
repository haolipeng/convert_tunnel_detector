package types

import "github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"

// RuleEngineResult 表示规则引擎的匹配结果
type RuleEngineResult struct {
	Matched bool             // 是否匹配
	Rule    *ruleEngine.Rule // 匹配的规则
}
