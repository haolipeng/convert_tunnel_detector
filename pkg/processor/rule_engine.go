package processor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
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
	mu                     sync.RWMutex // 互斥锁，保护共享资源
	Env                    *cel.Env
	originWhitelistRules   map[string]map[int]*ruleEngine.ProtocolRule // 原始的白名单规则,第一层key为协议名,第二层key为协议子类型
	compiledWhitelistRules map[string]map[int]cel.Program              // 编译后的白名单规则程序,第一层key为协议名,第二层key为协议子类型
	originBlacklistRules   map[string]map[int]*ruleEngine.ProtocolRule // 原始的黑名单规则,第一层key为协议名,第二层key为协议子类型
	compiledBlacklistRules map[string]map[int]cel.Program              // 编译后的黑名单规则程序,第一层key为协议名,第二层key为协议子类型
	// 规则表达式哈希表，用于跟踪规则变化，格式为：map[ruleID]map[ruleTag]string
	ruleExpressionHashes map[string]map[string]string // 第一层key为规则ID，第二层key为规则标签，值为表达式哈希值
	config               *config.Config               // 配置对象
}

// convertRuleTagToType 将规则标签转换为对应的枚举类型
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
	for protoSubType, ruleInfo := range rule.ProtocolRules {
		// 将协议子类型转换为对应的枚举类型
		subType, ok := convertRuleTagToType(protoSubType)
		if !ok {
			continue
		}

		// 预编译规则
		program, err := compileRuleToProgram(env, rule, protoSubType)
		if err != nil {
			return nil, nil, fmt.Errorf("compile rule failed for rule %s, type %d: %v", ruleID, subType, err)
		}

		// 添加规则，并保存到规则map中
		ruleMap[rule.RuleProtocol][subType] = &ruleEngine.ProtocolRule{
			State:       ruleInfo.State,
			Expression:  ruleInfo.Expression,
			Description: ruleInfo.Description,
			Type:        ruleInfo.Type,
		}

		// 添加编译后的规则，并保存到规则map中
		compiledRules[rule.RuleProtocol][subType] = program
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

	// 创建表达式哈希表
	expressionHashes := make(map[string]map[string]string)

	// 遍历所有规则
	for ruleID, rule := range rules {
		// 为每个规则创建哈希表
		expressionHashes[ruleID] = make(map[string]string)

		// 计算并存储每个规则表达式的哈希值
		for ruleTag, protocolRule := range rule.ProtocolRules {
			expressionHashes[ruleID][ruleTag] = calculateExpressionHash(protocolRule.Expression)
		}

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
		Env:                    env,
		originWhitelistRules:   whiteRuleMap,
		compiledWhitelistRules: compiledWhiteRules,
		originBlacklistRules:   blackRuleMap,
		compiledBlacklistRules: compiledBlackRules,
		ruleExpressionHashes:   expressionHashes,
		config:                 nil,
	}, nil
}

// Process 是规则引擎的主要处理函数
// 输入：数据包通道
// 输出：处理后的数据包通道
// 处理流程：
// 1. 首先检查黑名单规则
// 2. 如果黑名单未匹配，则检查白名单规则
// 3. 根据规则匹配结果决定数据包的处理动作（转发或告警）
func (r *RuleEngine) Process(ctx context.Context, in <-chan *types.Packet, wg *sync.WaitGroup) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet)

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(out)

		for packet := range in {
			// 第一步：处理黑名单规则
			// 使用读锁保护规则访问，因为规则可能被动态更新
			r.mu.RLock()
			blacklistMatched, err := r.processBlacklistRule(packet)
			r.mu.RUnlock()

			if err != nil {
				packet.LastError = err
				out <- packet
				continue
			}

			// 第二步：如果黑名单未匹配，检查白名单规则
			// 黑名单规则优先级高于白名单，用于拦截可疑流量
			if !blacklistMatched {
				r.mu.RLock()
				_, err := r.processWhitelistRule(packet)
				r.mu.RUnlock()

				if err != nil {
					packet.LastError = err
				}
			}

			// 第三步：根据规则匹配结果决定数据包处理动作
			if packet.RuleResult != nil {
				if packet.RuleResult.BlackRuleMatched {
					// 黑名单匹配成功：发现可疑流量，触发告警
					packet.RuleResult.Action = types.ActionAlert
				} else if packet.RuleResult.WhiteRuleMatched {
					// 白名单匹配成功：数据包可信，转发到目标接口
					packet.RuleResult.Action = types.ActionForward
				} else {
					// 白名单匹配失败：未在允许列表中，触发告警
					packet.RuleResult.Action = types.ActionAlert
				}
			} else {
				// 没有规则匹配：默认转发，因为可能存在未配置规则的情况，防止误拦截关键数据包
				packet.RuleResult = &types.RuleMatchResult{
					Action: types.ActionForward,
				}
			}

			// 将处理后的数据包发送到输出通道
			out <- packet
		}
	}()

	return out, nil
}

// processWhitelistRule 处理白名单规则匹配
// 处理流程：
// 1. 查找对应协议和类型的规则
// 2. 检查规则状态（是否启用）
// 3. 构建评估变量
// 4. 执行规则匹配
// 5. 设置匹配结果
func (r *RuleEngine) processWhitelistRule(packet *types.Packet) (bool, error) {
	if protocolRules, exists := r.originWhitelistRules[packet.Protocol]; exists {
		if programs, ok := r.compiledWhitelistRules[packet.Protocol]; ok {
			if program, ok := programs[int(packet.SubType)]; ok {
				// 获取原始规则信息，并进行有效性检查
				originalRule, exists := protocolRules[int(packet.SubType)]
				if !exists || originalRule == nil {
					return false, fmt.Errorf("whitelist rule not found for protocol %s, type %d", packet.Protocol, packet.SubType)
				}

				// 检查规则状态，只有启用状态的规则才会被匹配
				if originalRule.State != "enable" {
					// 规则未启用，跳过匹配
					return false, nil
				}

				// 构建评估变量
				vars := buildEvalVars(packet)

				// 执行规则匹配
				result, err := r.evaluateRule(program, vars)
				if err != nil {
					return false, fmt.Errorf("whitelist rule evaluation failed: %v", err)
				}

				// 设置白名单匹配结果
				packet.RuleResult = &types.RuleMatchResult{
					WhiteRuleMatched: result,
					WhiteRule:        originalRule,
				}

				return true, nil
			}
		}
	}

	return false, nil
}

// processBlacklistRule 处理黑名单规则匹配
// 处理流程：
// 1. 查找对应协议和类型的规则
// 2. 检查规则状态（是否启用）
// 3. 构建评估变量
// 4. 执行规则匹配
// 5. 设置匹配结果
func (r *RuleEngine) processBlacklistRule(packet *types.Packet) (bool, error) {
	if protocolRules, exists := r.originBlacklistRules[packet.Protocol]; exists {
		if programs, ok := r.compiledBlacklistRules[packet.Protocol]; ok {
			if program, ok := programs[int(packet.SubType)]; ok {
				// 获取原始规则信息，并进行有效性检查
				originalRule, exists := protocolRules[int(packet.SubType)]
				if !exists || originalRule == nil {
					return false, fmt.Errorf("blacklist rule not found for protocol %s, type %d", packet.Protocol, packet.SubType)
				}

				// 检查规则状态，只有启用状态的规则才会被匹配
				if originalRule.State != "enable" {
					// 规则未启用，跳过匹配
					return false, nil
				}

				// 构建评估变量
				vars := buildEvalVars(packet)

				// 执行规则匹配
				result, err := r.evaluateRule(program, vars)
				if err != nil {
					return false, fmt.Errorf("blacklist rule evaluation failed: %v", err)
				}

				// 设置黑名单匹配结果，白名单处可能申请过packet.RuleResult变量
				if packet.RuleResult == nil {
					packet.RuleResult = &types.RuleMatchResult{}
				}
				packet.RuleResult.BlackRuleMatched = result
				packet.RuleResult.BlackRule = originalRule

				return true, nil
			}
		}
	}

	return false, nil
}

// buildEvalVars 根据数据包构建评估变量
// 处理流程：
// 1. 提取OSPF通用头部字段
// 2. 根据包类型（Hello/DD/LSR/LSU/LSAck）提取特定字段
// 3. 构建用于规则评估的变量映射
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
			// 将NetworkMask转换为字符串格式
			networkMask := fmt.Sprintf("%d.%d.%d.%d",
				ospfPacket.HelloFields.NetworkMask[0], ospfPacket.HelloFields.NetworkMask[1],
				ospfPacket.HelloFields.NetworkMask[2], ospfPacket.HelloFields.NetworkMask[3])
			vars["ospf.hello.network_mask"] = networkMask

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

// compileRuleToProgram 编译CEL规则
func compileRuleToProgram(env *cel.Env, rule *ruleEngine.Rule, ruleProtocol string) (cel.Program, error) {
	if rule == nil {
		return nil, fmt.Errorf("rule is nil")
	}

	// 1.检查规则是否存在
	protocolRule, ok := rule.ProtocolRules[ruleProtocol]
	if !ok {
		return nil, fmt.Errorf("no expressions found for rule protocol: %s", ruleProtocol)
	}

	// 2.获取规则的表达式
	finalExpression := protocolRule.Expression

	// 3.编译表达式，生成AST
	ast, iss := env.Compile(finalExpression)
	if iss.Err() != nil {
		return nil, fmt.Errorf("compile expression failed: %v", iss.Err())
	}

	// 4.检查表达式是否正确
	checked, iss := env.Check(ast)
	if iss.Err() != nil {
		return nil, fmt.Errorf("check expression failed: %v", iss.Err())
	}

	// 5.将AST转换为程序Program
	program, err := env.Program(checked)
	if err != nil {
		return nil, fmt.Errorf("create program failed: %v", err)
	}

	return program, nil
}

// evaluateRule 评估规则
// 处理流程：
// 1. 检查规则程序是否有效
// 2. 使用构建的变量执行规则程序
// 3. 验证并返回匹配结果
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
	if r.Env == nil {
		return types.ErrProcessorNotReady
	}
	return nil
}

// NewRuleEngineProcessor 创建新的规则引擎处理器
func NewRuleEngineProcessor(ruleFilePath string, workerCount int, cfg interface{}) (*RuleEngine, error) {
	// 创建规则加载器
	loader := ruleEngine.NewRuleLoader()

	// 从文件夹加载所有协议的黑名单和白名单的规则
	err := loader.LoadRulesFromDirectory(ruleFilePath)
	if err != nil {
		return nil, fmt.Errorf("load rules failed: %v", err)
	}

	// 获取所有规则
	rules := loader.GetAllRules()

	// 创建规则引擎
	ruleEngine, err := NewRuleEngine(rules)
	if err != nil {
		return nil, err
	}

	return ruleEngine, nil
}

// ReloadRules 重新加载规则引擎的规则
func (r *RuleEngine) ReloadRules() error {
	// 获取当前路径下的所有规则
	loader := ruleEngine.NewRuleLoader()

	// 使用配置的规则目录
	ruleDirectory := "rules/" // 默认值
	if r.config != nil && r.config.RuleEngine.RuleDirectory != "" {
		ruleDirectory = r.config.RuleEngine.RuleDirectory
	}

	err := loader.LoadRulesFromDirectory(ruleDirectory)
	if err != nil {
		return fmt.Errorf("加载规则目录失败: %v", err)
	}

	// 获取所有规则
	rules := loader.GetAllRules()

	// 2. 创建新的环境（这部分也不需要锁，因为只是创建对象）
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
		return fmt.Errorf("创建CEL环境失败: %v", err)
	}

	// 3. 在修改共享资源前，获取写锁
	r.mu.Lock()
	defer r.mu.Unlock()

	// 更新环境
	r.Env = env

	// 跟踪已处理的规则ID集合
	processedRuleIDs := make(map[string]bool)

	// 4. 处理所有规则（已持有写锁，安全地修改共享资源）
	for ruleID, rule := range rules {
		processedRuleIDs[ruleID] = true

		// 检查规则是否在哈希表中
		if _, exists := r.ruleExpressionHashes[ruleID]; !exists {
			// 新规则，需要处理
			r.ruleExpressionHashes[ruleID] = make(map[string]string)
			// 处理新规则
			if err := r.ProcessRule(env, rule, ruleID, true); err != nil {
				return fmt.Errorf("处理新规则失败: %w", err)
			}
			continue
		}

		// 检查规则的表达式是否有变化
		hasChanged := false
		for ruleTag, protocolRule := range rule.ProtocolRules {
			// 计算新哈希值
			newHash := calculateExpressionHash(protocolRule.Expression)

			// 检查表达式是否已存在且哈希值是否相同
			oldHash, exists := r.ruleExpressionHashes[ruleID][ruleTag]
			if !exists || oldHash != newHash {
				// 表达式已更改或新增，需要更新
				hasChanged = true
				// 更新哈希值
				r.ruleExpressionHashes[ruleID][ruleTag] = newHash
			}
		}

		// 检查是否有被删除的规则表达式
		for ruleTag := range r.ruleExpressionHashes[ruleID] {
			if _, exists := rule.ProtocolRules[ruleTag]; !exists {
				// 有规则表达式被删除，需要更新
				hasChanged = true
				// 从哈希表中删除
				delete(r.ruleExpressionHashes[ruleID], ruleTag)
			}
		}

		// 如果规则有变化，处理规则
		if hasChanged {
			if err := r.ProcessRule(env, rule, ruleID, false); err != nil {
				return fmt.Errorf("处理规则变化失败: %w", err)
			}
		}
	}

	// 5. 查找删除的规则（已持有写锁，安全地修改共享资源）
	for ruleID := range r.ruleExpressionHashes {
		if _, exists := processedRuleIDs[ruleID]; !exists {
			// 规则已被删除，从哈希表中删除
			delete(r.ruleExpressionHashes, ruleID)

			// 从规则集合中删除相应规则
			r.removeRule(ruleID)
		}
	}

	return nil
}

// ProcessRule 处理单个规则，将其添加到规则引擎中
// 注意：此方法假设调用者已经持有写锁(r.mu.Lock())，不会自行加锁
func (r *RuleEngine) ProcessRule(env *cel.Env, rule *ruleEngine.Rule, ruleID string, isNew bool) error {
	switch rule.RuleMode {
	case "blacklist":
		originRules, compiledRules, err := processRules(env, rule, ruleID)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"rule_id": ruleID,
				"error":   err.Error(),
			}).Error("处理黑名单规则失败")
			return fmt.Errorf("处理黑名单规则失败: %w", err)
		}

		// 合并规则
		for protocol, rules := range originRules {
			if _, exists := r.originBlacklistRules[protocol]; !exists {
				r.originBlacklistRules[protocol] = make(map[int]*ruleEngine.ProtocolRule)
			}
			for ruleType, rule := range rules {
				r.originBlacklistRules[protocol][ruleType] = rule
			}
		}
		for protocol, rules := range compiledRules {
			if _, exists := r.compiledBlacklistRules[protocol]; !exists {
				r.compiledBlacklistRules[protocol] = make(map[int]cel.Program)
			}
			for ruleType, program := range rules {
				r.compiledBlacklistRules[protocol][ruleType] = program
			}
		}
	case "whitelist":
		originRules, compiledRules, err := processRules(env, rule, ruleID)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"rule_id": ruleID,
				"error":   err.Error(),
			}).Error("处理白名单规则失败")
			return fmt.Errorf("处理白名单规则失败: %w", err)
		}

		// 合并规则
		for protocol, rules := range originRules {
			if _, exists := r.originWhitelistRules[protocol]; !exists {
				r.originWhitelistRules[protocol] = make(map[int]*ruleEngine.ProtocolRule)
			}
			for ruleType, rule := range rules {
				r.originWhitelistRules[protocol][ruleType] = rule
			}
		}
		for protocol, rules := range compiledRules {
			if _, exists := r.compiledWhitelistRules[protocol]; !exists {
				r.compiledWhitelistRules[protocol] = make(map[int]cel.Program)
			}
			for ruleType, program := range rules {
				r.compiledWhitelistRules[protocol][ruleType] = program
			}
		}
	default:
		return fmt.Errorf("不支持的规则模式: %s", rule.RuleMode)
	}

	return nil
}

// removeRule 从规则引擎中移除规则
// 注意：此方法假设调用者已经持有写锁(r.mu.Lock())，不会自行加锁
func (r *RuleEngine) removeRule(ruleID string) {
	logrus.WithFields(logrus.Fields{
		"rule_id":   ruleID,
		"operation": "remove",
	}).Info("从规则引擎中移除规则")

	// 目前的实现不支持在不知道具体协议和规则类型的情况下直接删除规则
	// 因为我们的规则映射表是按协议和类型组织的，而不是按规则ID
	// 这里需要在实际场景中根据需求完善
	// 一种可能的解决方案是维护一个ruleID到protocol和type的映射表
}

// calculateExpressionHash 计算表达式的哈希值
func calculateExpressionHash(expression string) string {
	h := sha256.New()
	h.Write([]byte(expression))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ValidateOSPFExpression 验证OSPF表达式是否有效，返回详细错误信息
func (r *RuleEngine) ValidateOSPFExpression(packetType string, expression string) error {
	if expression == "" {
		return fmt.Errorf("表达式不能为空")
	}

	// 创建临时环境用于验证
	var opts []cel.EnvOption

	// 添加通用OSPF字段
	opts = append(opts, cel.Declarations(
		decls.NewVar("ospf.version", decls.Int),
		decls.NewVar("ospf.msg", decls.Int),
		decls.NewVar("ospf.packet_length", decls.Int),
		decls.NewVar("ospf.srcrouter", decls.String),
		decls.NewVar("ospf.area_id", decls.String),
		decls.NewVar("ospf.checksum", decls.Int),
	))

	// 根据包类型添加特定字段
	switch packetType {
	case "HELLO":
		opts = append(opts, cel.Declarations(
			decls.NewVar("ospf.hello.network_mask", decls.String),
			decls.NewVar("ospf.hello.hello_interval", decls.Int),
			decls.NewVar("ospf.hello.router_priority", decls.Int),
			decls.NewVar("ospf.hello.router_dead_interval", decls.Int),
			decls.NewVar("ospf.hello.designated_router", decls.String),
			decls.NewVar("ospf.hello.backup_designated_router", decls.String),
			decls.NewVar("ospf.v2.options", decls.Int),
		))
	case "DD":
		opts = append(opts, cel.Declarations(
			decls.NewVar("ospf.db.interface_mtu", decls.Int),
			decls.NewVar("ospf.v2.options", decls.Int),
			decls.NewVar("ospf.db.dd_sequence", decls.Int),
			decls.NewVar("ospf.db.dd_age", decls.Int),
		))
	case "LSR":
		opts = append(opts, cel.Declarations(
			decls.NewVar("ospf.link_state_id", decls.String),
		))
	case "LSU":
		opts = append(opts, cel.Declarations(
			decls.NewVar("ospf.advrouter", decls.String),
			decls.NewVar("ospf.lsa", decls.Int),
			decls.NewVar("ospf.lsa.age", decls.Int),
			decls.NewVar("ospf.lsa.id", decls.String),
			decls.NewVar("ospf.lsa.seqnum", decls.Int),
		))
	case "LSAck":
		opts = append(opts, cel.Declarations(
			decls.NewVar("ospf.lsa", decls.Int),
			decls.NewVar("ospf.lsa.seqnum", decls.Int),
		))
	default:
		return fmt.Errorf("未知的包类型: %s", packetType)
	}

	// 创建临时CEL环境
	env, err := cel.NewEnv(opts...)
	if err != nil {
		return fmt.Errorf("创建CEL环境失败: %v", err)
	}

	// 编译表达式
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		return fmt.Errorf("表达式编译错误: %v", iss.Err())
	}

	// 检查表达式
	checked, iss := env.Check(ast)
	if iss.Err() != nil {
		return fmt.Errorf("表达式类型检查错误: %v", iss.Err())
	}

	// 验证表达式返回值类型必须是布尔型
	if !checked.OutputType().IsAssignableType(cel.BoolType) {
		return fmt.Errorf("表达式必须返回布尔值，当前返回: %s", checked.OutputType().String())
	}

	return nil
}
