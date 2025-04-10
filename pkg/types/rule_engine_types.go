package types

import "github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"

// RuleMatchResult 表示规则引擎的匹配结果,每个数据包对应的白名单和黑名单规则只有一条
type RuleMatchResult struct {
	WhiteRuleMatched bool                     // 白名单规则是否匹配
	BlackRuleMatched bool                     // 黑名单规则是否匹配
	WhiteRule        *ruleEngine.ProtocolRule // 匹配的白名单规则
	BlackRule        *ruleEngine.ProtocolRule // 匹配的黑名单规则
	Action           RuleAction               // 数据包处理动作
	MatchType        MatchType                // 匹配类型（黑名单或白名单）
	DetectMethod     string                   // 检测方法
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

// MatchType 表示匹配的规则类型
// 可能的类型：
// 1. MatchTypeNone: 未匹配
// 2. MatchTypeWhitelist: 白名单匹配
// 3. MatchTypeBlacklist: 黑名单匹配
type MatchType uint8

const (
	MatchTypeNone      MatchType = iota // 未匹配
	MatchTypeWhitelist                  // 白名单匹配
	MatchTypeBlacklist                  // 黑名单匹配
)
