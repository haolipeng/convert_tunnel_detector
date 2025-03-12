package processor

import (
	"context"
	"fmt"
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
	env                    *cel.Env
	originWhitelistRules   map[string]map[int]*ruleEngine.ProtocolRule // 原始的白名单规则,第一层key为协议名,第二层key为协议子类型
	compiledWhitelistRules map[string]map[int]cel.Program              // 编译后的白名单规则程序,第一层key为协议名,第二层key为协议子类型
	originBlacklistRules   map[string]map[int]*ruleEngine.ProtocolRule // 原始的黑名单规则,第一层key为协议名,第二层key为协议子类型
	compiledBlacklistRules map[string]map[int]cel.Program              // 编译后的黑名单规则程序,第一层key为协议名,第二层key为协议子类型
}

// convertRuleTagToType 将规则标签转换为对应的类型
func convertRuleTagToType(ruleTag string) (int, bool) {
	switch ruleTag {
	case "HELLO":
		return OSPFTypeHello, true
	case "DD":
		return OSPFTypeDD, true
	case "LSR":
		return OSPFTypeLSR, true
	case "LSU":
		return OSPFTypeLSU, true
	case "LSAck":
		return OSPFTypeLSAck, true
	default:
		return 0, false
	}
}

// processRules 处理规则集合
func processRules(env *cel.Env, rule *ruleEngine.Rule, ruleID string) (map[string]map[int]*ruleEngine.ProtocolRule, map[string]map[int]cel.Program, error) {
	ruleMap := make(map[string]map[int]*ruleEngine.ProtocolRule)
	compiledRules := make(map[string]map[int]cel.Program)

	// 确保协议类型的map已初始化
	if _, exists := ruleMap[rule.RuleProtocol]; !exists {
		ruleMap[rule.RuleProtocol] = make(map[int]*ruleEngine.ProtocolRule)
	}
	if _, exists := compiledRules[rule.RuleProtocol]; !exists {
		compiledRules[rule.RuleProtocol] = make(map[int]cel.Program)
	}

	// 遍历每个规则的 ProtocolRules
	for ruleTag, ruleInfo := range rule.ProtocolRules {
		ruleType, ok := convertRuleTagToType(ruleTag)
		if !ok {
			continue
		}

		// 预编译规则
		program, err := compileRule(env, rule, ruleTag)
		if err != nil {
			return nil, nil, fmt.Errorf("compile rule failed for rule %s, type %d: %v", ruleID, ruleType, err)
		}

		// 添加规则
		ruleMap[rule.RuleProtocol][ruleType] = &ruleEngine.ProtocolRule{
			Expression:  ruleInfo.Expression,
			Description: ruleInfo.Description,
			Type:        ruleInfo.Type,
		}
		compiledRules[rule.RuleProtocol][ruleType] = program
	}

	return ruleMap, compiledRules, nil
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

	var whiteRuleMap, blackRuleMap map[string]map[int]*ruleEngine.ProtocolRule
	var compiledWhiteRules, compiledBlackRules map[string]map[int]cel.Program

	// 遍历所有规则
	for ruleID, rule := range rules {
		var err error
		switch rule.RuleMode {
		case "blacklist":
			blackRuleMap, compiledBlackRules, err = processRules(env, rule, ruleID)
		case "whitelist":
			whiteRuleMap, compiledWhiteRules, err = processRules(env, rule, ruleID)
		}
		if err != nil {
			return nil, err
		}
	}

	return &RuleEngine{
		env:                    env,
		originWhitelistRules:   whiteRuleMap,
		compiledWhitelistRules: compiledWhiteRules,
		originBlacklistRules:   blackRuleMap,
		compiledBlacklistRules: compiledBlackRules,
	}, nil
}

func (r *RuleEngine) Process(ctx context.Context, in <-chan *types.Packet, wg *sync.WaitGroup) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(out)

		for packet := range in {
			//1. 白名单处理逻辑，根据packet类型获取对应的规则和预编译程序
			if protocolRules, exists := r.originWhitelistRules[packet.Protocol]; exists {
				if programs, ok := r.compiledWhitelistRules[packet.Protocol]; ok {
					if program, ok := programs[int(packet.SubType)]; ok {
						// 构建评估变量
						vars := buildEvalVars(packet)

						// 执行规则匹配
						result, err := r.evaluateRule(program, vars)
						if err != nil {
							// 记录错误但继续处理
							packet.Error = fmt.Errorf("whitelist rule evaluation failed: %v", err)
							continue
						}

						// 获取原始规则信息，并进行有效性检查
						originalRule, exists := protocolRules[int(packet.SubType)]
						if !exists || originalRule == nil {
							packet.Error = fmt.Errorf("whitelist rule not found for protocol %s, type %d", packet.Protocol, packet.SubType)
							continue
						}

						// 设置白名单匹配结果
						packet.RuleResult = &types.RuleMatchResult{
							WhiteRuleMatched: result,
							WhiteRule:        originalRule,
						}
					}
				}
			}

			//2. 黑名单处理逻辑，根据packet类型获取对应的规则和预编译程序
			if protocolRules, exists := r.originBlacklistRules[packet.Protocol]; exists {
				if programs, ok := r.compiledBlacklistRules[packet.Protocol]; ok {
					if program, ok := programs[int(packet.SubType)]; ok {
						// 构建评估变量
						vars := buildEvalVars(packet)

						// 执行规则匹配
						result, err := r.evaluateRule(program, vars)
						if err != nil {
							// 记录错误但继续处理
							packet.Error = fmt.Errorf("blacklist rule evaluation failed: %v", err)
							continue
						}

						// 获取原始规则信息，并进行有效性检查
						originalRule, exists := protocolRules[int(packet.SubType)]
						if !exists || originalRule == nil {
							packet.Error = fmt.Errorf("blacklist rule not found for protocol %s, type %d", packet.Protocol, packet.SubType)
							continue
						}

						// 设置黑名单匹配结果，白名单处可能申请过packet.RuleResult变量
						if packet.RuleResult == nil {
							packet.RuleResult = &types.RuleMatchResult{}
						}
						packet.RuleResult.BlackRuleMatched = result
						packet.RuleResult.BlackRule = originalRule
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
	ospfPacket, ok := packet.ParserResult.(*OSPFPacket)
	if !ok {
		return nil
	}

	vars := map[string]interface{}{
		// OSPF通用头部字段
		"ospf.version":       int8(ospfPacket.Version),
		"ospf.msg":           int8(packet.SubType),
		"ospf.packet_length": uint16(ospfPacket.PacketLength),
		"ospf.srcrouter":     ospfPacket.RouterID.String(),
		"ospf.area_id":       ospfPacket.AreaID.String(),
		"ospf.checksum":      int64(ospfPacket.Checksum),
		"ospf.auth.type":     int64(ospfPacket.AuType),
		"ospf.auth.none":     ospfPacket.Authentication,
	}

	// 根据包类型添加特定字段
	switch packet.SubType {
	case OSPFTypeHello:
		// 添加Hello包特有字段
		if ospfPacket.HelloFields != nil {
			vars["ospf.hello.network_mask"] = ospfPacket.HelloFields.NetworkMask.String()
			vars["ospf.hello.hello_interval"] = uint16(ospfPacket.HelloFields.HelloInterval)
			vars["ospf.hello.router_priority"] = uint8(ospfPacket.HelloFields.Priority)
			vars["ospf.hello.router_dead_interval"] = uint32(ospfPacket.HelloFields.DeadInterval)
			vars["ospf.hello.designated_router"] = ospfPacket.HelloFields.DesignatedRouter.String()
			vars["ospf.hello.backup_designated_router"] = ospfPacket.HelloFields.BackupDesignatedRouter.String()
			vars["ospf.v2.options"] = int64(ospfPacket.HelloFields.Options)
		}

	case OSPFTypeDD:
		// 添加DD包特有字段
		if ospfPacket.DDFields != nil {
			vars["ospf.db.interface_mtu"] = int64(ospfPacket.DDFields.InterfaceMTU)
			vars["ospf.v2.options"] = int64(ospfPacket.DDFields.Options)
			vars["ospf.db.dd_sequence"] = int64(ospfPacket.DDFields.DDSequence)
			vars["ospf.dbd"] = int8(ospfPacket.DDFields.Flags)
		}

	case OSPFTypeLSR:
		// 添加LSR包特有字段
		if ospfPacket.LSRFields != nil && len(ospfPacket.LSRFields.LSARequests) > 0 {
			// TODO:这里我们取第一个LSR请求的信息
			lsr := ospfPacket.LSRFields.LSARequests[0]
			vars["ospf.link_state_id"] = lsr.LSID.String()
			vars["ospf.lsa"] = int32(lsr.LSType)
			vars["ospf.advrouter"] = lsr.AdvRouter.String()
		}

	case OSPFTypeLSU:
		// 添加LSU包特有字段
		if ospfPacket.LSUFields != nil {
			vars["ospf.ls.number_of_lsas"] = int64(ospfPacket.LSUFields.NumOfLSAs)
			if len(ospfPacket.LSUFields.LSAs) > 0 {
				//TODO: 这里我们取第一个LSU的信息
				lsa := ospfPacket.LSUFields.LSAs[0]
				vars["ospf.lsa.age"] = uint16(lsa.Header.LSAge)
				vars["ospf.v2.options"] = uint8(lsa.Header.LSOptions)
				vars["ospf.lsa"] = uint16(lsa.Header.LSType)
				vars["ospf.lsa.id"] = lsa.Header.LinkStateID.String()
				vars["ospf.advrouter"] = lsa.Header.AdvRouter.String()
				vars["ospf.lsa.seqnum"] = uint32(lsa.Header.LSSeqNumber)
				vars["ospf.lsa.chksum"] = uint16(lsa.Header.LSChecksum)
				vars["ospf.lsa.length"] = uint16(lsa.Header.Length)
			}
		}

	case OSPFTypeLSAck:
		// 添加LSAck包特有字段
		if ospfPacket.LSAckFields != nil && len(ospfPacket.LSAckFields.LSAHeaders) > 0 {
			//TODO: 这里我们取LSAck包的第一个LSA头部的序列号
			lsa := ospfPacket.LSAckFields.LSAHeaders[0]
			vars["ospf.lsa.age"] = int64(lsa.LSAge)
			vars["ospf.v2.options"] = int64(lsa.LSOptions)
			vars["ospf.lsa"] = int64(lsa.LSType)
			vars["ospf.lsa.id"] = lsa.LinkStateID.String()
			vars["ospf.advrouter"] = lsa.AdvRouter.String()
			vars["ospf.lsa.seqnum"] = int64(lsa.LSSeqNumber)
			vars["ospf.lsa.chksum"] = int64(lsa.LSChecksum)
			vars["ospf.lsa.length"] = int64(lsa.Length)
		}
	}

	return vars
}

// compileRule 编译CEL规则
func compileRule(env *cel.Env, rule *ruleEngine.Rule, ruleProtocol string) (cel.Program, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is nil")
	}

	protocolRule, ok := rule.ProtocolRules[ruleProtocol]
	if !ok {
		return nil, fmt.Errorf("no expressions found for rule protocol: %s", ruleProtocol)
	}

	finalExpression := protocolRule.Expression

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

	// 从文件夹加载所有协议的黑名单和白名单的规则
	err := loader.LoadRulesFromDirectory("rules/")
	if err != nil {
		return nil, fmt.Errorf("load rules failed: %v", err)
	}

	// 获取所有规则
	rules := loader.GetAllRules()

	// 创建规则引擎
	return NewRuleEngine(rules)
}
