package processor

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
)

// OSPF报文类型常量
const (
	OSPFTypeHello = 1
	OSPFTypeDD    = 2
	OSPFTypeLSR   = 3
	OSPFTypeLSU   = 4
	OSPFTypeLSAck = 5
)

type RuleEngine struct {
	env           *cel.Env
	rules         map[int]*ruleEngine.Rule
	compiledRules map[int]cel.Program // 预编译的规则程序
}

func NewRuleEngine(rules map[string]*ruleEngine.Rule) (*RuleEngine, error) {
	// 创建CEL环境，声明所有可能用到的变量
	env, err := cel.NewEnv(
		cel.Declarations(
			// OSPF通用头部字段
			decls.NewVar("ospf.version", decls.Int),
			decls.NewVar("ospf.msg", decls.Int),
			decls.NewVar("ospf.packet_length", decls.Int),
			decls.NewVar("ospf.srcrouter", decls.String),
			decls.NewVar("ospf.area_id", decls.String),
			decls.NewVar("ospf.checksum", decls.Int),

			// Hello包字段
			decls.NewVar("ospf.hello.network_mask", decls.String),
			decls.NewVar("ospf.hello.hello_interval", decls.Int),
			decls.NewVar("ospf.hello.router_priority", decls.Int),
			decls.NewVar("ospf.hello.router_dead_interval", decls.Int),
			decls.NewVar("ospf.hello.designated_router", decls.String),
			decls.NewVar("ospf.hello.backup_designated_router", decls.String),
			decls.NewVar("ospf.v2.options", decls.Int),

			// DD包字段
			decls.NewVar("ospf.db.interface_mtu", decls.Int),
			decls.NewVar("ospf.v2.options", decls.Int),
			decls.NewVar("ospf.db.dd_sequence", decls.Int),
			decls.NewVar("ospf.db.dd_age", decls.Int),

			// LSR包字段
			decls.NewVar("ospf.link_state_id", decls.String),

			// LSU包字段
			decls.NewVar("ospf.advrouter", decls.String),

			// LSAck包字段
			decls.NewVar("ospf.lsa.seqnum", decls.Int),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create cel env failed: %v", err)
	}

	ruleMap := make(map[int]*ruleEngine.Rule)
	compiledRules := make(map[int]cel.Program)

	// 遍历所有规则
	for ruleID, rule := range rules {
		// 遍历每个规则的 ProtocolRules,ruleTag为规则标签，比如HELLO、DD、LSR、LSU、LSAck
		for ruleTag := range rule.ProtocolRules {
			var ruleType int
			switch ruleTag {
			case "HELLO":
				ruleType = OSPFTypeHello
			case "DD":
				ruleType = OSPFTypeDD
			case "LSR":
				ruleType = OSPFTypeLSR
			case "LSU":
				ruleType = OSPFTypeLSU
			case "LSAck":
				ruleType = OSPFTypeLSAck
			default:
				continue
			}

			// 预编译规则
			program, err := compileRule(env, rule, ruleTag)
			if err != nil {
				return nil, fmt.Errorf("compile rule failed for rule %s, type %d: %v", ruleID, ruleType, err)
			}

			ruleMap[ruleType] = rule
			compiledRules[ruleType] = program
		}
	}

	return &RuleEngine{
		env:           env,
		rules:         ruleMap,
		compiledRules: compiledRules,
	}, nil
}

func (r *RuleEngine) Process(ctx context.Context, in <-chan *types.Packet, wg *sync.WaitGroup) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(out)

		for packet := range in {
			// 根据packet类型获取对应的规则和预编译程序
			if matchRule, exists := r.rules[int(packet.Type)]; exists {
				if program, ok := r.compiledRules[int(packet.Type)]; ok {
					// 构建评估变量
					vars := buildEvalVars(packet)

					// 执行规则匹配
					result, err := r.evaluateRule(program, vars)
					if err != nil {
						// 记录错误但继续处理
						packet.Error = fmt.Errorf("rule evaluation failed: %v", err)
						continue
					}

					// 设置匹配结果
					packet.RuleResult = &types.RuleMatchResult{
						Matched: result,
						Rule:    matchRule,
					}
				}
			}
			out <- packet
		}
	}()

	return out, nil
}

// buildEvalVars 根据数据包构建评估变量
func buildEvalVars(packet *types.Packet) map[string]interface{} {
	// 从packet中提取OSPF字段
	ospfPacket, ok := packet.ParserResult.(*types.OSPFPacket)
	if !ok {
		return nil
	}

	vars := map[string]interface{}{
		// OSPF通用头部字段
		"ospf.version":       int64(ospfPacket.Version),
		"ospf.msg":           int64(packet.Type),
		"ospf.packet_length": int64(ospfPacket.PacketLen),
		"ospf.srcrouter":     ospfPacket.SrcRouter,
		"ospf.area_id":       ospfPacket.AreaID,
		"ospf.checksum":      int64(ospfPacket.Checksum),
		"ospf.auth.type":     int64(ospfPacket.AuType),
		"ospf.auth":          string(ospfPacket.Auth),
	}

	// 根据包类型添加特定字段
	switch packet.Type {
	case OSPFTypeHello:
		//添加Hello包特有字段
		if hello, ok := ospfPacket.Data.(*types.OSPFPacketV2); ok {
			vars["ospf.hello.network_mask"] = hello.NetworkMask
			vars["ospf.hello.hello_interval"] = int64(hello.HelloInterval)
			vars["ospf.hello.router_priority"] = int64(hello.Priority)
			vars["ospf.hello.router_dead_interval"] = int64(hello.DeadInterval)
			vars["ospf.hello.designated_router"] = hello.DR
			vars["ospf.hello.backup_designated_router"] = hello.BDR
			vars["ospf.v2.options"] = int64(hello.Options)
		}

	case OSPFTypeDD:
		// 添加DD包特有字段
		if dd, ok := ospfPacket.Data.(*types.OSPFDDPacket); ok {
			vars["ospf.db.interface_mtu"] = int64(dd.InterfaceMTU)
			vars["ospf.v2.options"] = int64(dd.Options)
			vars["ospf.db.dd_sequence"] = int64(dd.SeqNum)
			vars["ospf.dbd"] = int8(dd.Flags)
		}

	case OSPFTypeLSR:
		// 添加LSR包特有字段
		if lsr, ok := ospfPacket.Data.(*types.OSPFLSRPacket); ok {
			vars["ospf.link_state_id"] = lsr.LinkStateID
			vars["ospf.lsa"] = int32(lsr.LSType)
			vars["ospf.advrouter"] = lsr.AdvRouter
		}

	case OSPFTypeLSU:
		// 添加LSU包特有字段
		if lsu, ok := ospfPacket.Data.(*types.OSPFLSUPacket); ok {
			vars["ospf.advrouter"] = lsu.AdvRouter
		}

	case OSPFTypeLSAck:
		// 添加LSAck包特有字段
		if lsack, ok := ospfPacket.Data.(*types.OSPFLSAckPacket); ok {
			vars["ospf.lsa.seqnum"] = lsack.LSASequenceNumber
		}
	}

	return vars
}

// compileRule 编译CEL规则
func compileRule(env *cel.Env, rule *ruleEngine.Rule, ruleTag string) (cel.Program, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is nil")
	}

	// 获取规则类型对应的所有表达式
	expressions := make([]string, 0)
	if rules, ok := rule.ProtocolRules[ruleTag]; ok {
		for _, r := range rules {
			expressions = append(expressions, r.Expression)
		}
	}

	if len(expressions) == 0 {
		return nil, fmt.Errorf("no expressions found for rule tag: %s", ruleTag)
	}

	// 根据规则类型组合表达式
	var finalExpression string
	if rule.RuleType == "or" {
		// 对于or类型，任一表达式为true即可
		finalExpression = strings.Join(expressions, " || ")
	} else {
		// 对于and类型，所有表达式都必须为true
		finalExpression = strings.Join(expressions, " && ")
	}

	// 编译表达式
	ast, iss := env.Compile(finalExpression)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile expression failed: %v", iss.Err())
	}

	// 检查表达式
	checked, iss := env.Check(ast)
	if iss.Err() != nil {
		return nil, fmt.Errorf("check expression failed: %v", iss.Err())
	}

	// 创建程序
	program, err := env.Program(checked)
	if err != nil {
		return nil, fmt.Errorf("create program failed: %v", err)
	}

	return program, nil
}

// evaluateRule 评估规则
func (r *RuleEngine) evaluateRule(program cel.Program, vars map[string]interface{}) (bool, error) {
	if program == nil {
		return false, fmt.Errorf("program is nil")
	}

	// 执行规则程序
	result, _, err := program.Eval(vars)
	if err != nil {
		return false, fmt.Errorf("evaluate rule failed: %v", err)
	}

	// 获取结果
	matched, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("rule result is not boolean: %v", result.Value())
	}

	return matched, nil
}

func (r *RuleEngine) Stage() types.Stage {
	return types.StageRuleEngineDetection
}

func (r *RuleEngine) Name() string {
	return "RuleEngine"
}

func (r *RuleEngine) CheckReady() error {
	if r.env == nil {
		return types.ErrProcessorNotReady
	}
	return nil
}

// NewRuleEngineProcessor 创建新的规则引擎处理器
func NewRuleEngineProcessor(workerCount int, cfg interface{}) (*RuleEngine, error) {
	// 创建规则加载器
	loader := ruleEngine.NewRuleLoader()

	// 加载规则文件
	err := loader.LoadRuleFromFile("rules/ospf_rules.yaml")
	if err != nil {
		return nil, fmt.Errorf("load rules failed: %v", err)
	}

	// 创建规则引擎
	return NewRuleEngine(loader.GetAllRules())
}
