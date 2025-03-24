package ruleEngine

// Rule 表示一个规则配置
type Rule struct {
	State         string                   `yaml:"state" json:"state"`                   // 规则状态 enable/disable
	RuleID        string                   `yaml:"rule_id" json:"rule_id"`               // 规则ID
	RuleProtocol  string                   `yaml:"rule_protocol" json:"rule_protocol"`   // 规则协议
	RuleTag       string                   `yaml:"rule_tag" json:"rule_tag"`             // 规则标签
	RuleName      string                   `yaml:"rule_name" json:"rule_name"`           // 规则名称
	RuleType      string                   `yaml:"rule_type" json:"rule_type"`           // 规则类型 (or/and)
	RuleMode      string                   `yaml:"rule_mode" json:"rule_mode"`           // 规则模式 (whitelist/blacklist)
	ProtocolRules map[string]*ProtocolRule `yaml:"protocol_rules" json:"protocol_rules"` // 协议规则
}

// ProtocolRule 表示具体的协议规则
type ProtocolRule struct {
	State       string `yaml:"state" json:"state"`             // 规则状态 enable/disable
	Expression  string `yaml:"expression" json:"expression"`   // 规则表达式
	Description string `yaml:"description" json:"description"` // 规则描述
	Type        string `yaml:"type" json:"type"`               // 规则类型 (single/multi)
}
