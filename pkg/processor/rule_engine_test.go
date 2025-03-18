package processor

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/stretchr/testify/assert"
)

// 测试规则编译功能
func TestRuleCompilation(t *testing.T) {
	// 创建CEL环境
	env, err := cel.NewEnv(
		cel.Variable("ospf.hello.hello_interval", cel.IntType),
	)
	assert.NoError(t, err)

	// 创建一个测试规则
	rule := &ruleEngine.Rule{
		RuleID:       "test_rule",
		RuleProtocol: "ospf",
		RuleMode:     "whitelist",
		ProtocolRules: map[string]*ruleEngine.ProtocolRule{
			"HELLO": {
				State:       "enable",
				Expression:  "ospf.hello.hello_interval == 10",
				Description: "测试Hello包间隔",
				Type:        "single",
			},
		},
	}

	// 直接调用compileRule函数
	program, err := compileRule(env, rule, "HELLO")
	assert.NoError(t, err)
	assert.NotNil(t, program)

	// 测试禁用状态的规则
	disabledRule := &ruleEngine.Rule{
		RuleID:       "test_disabled_rule",
		RuleProtocol: "ospf",
		RuleMode:     "whitelist",
		ProtocolRules: map[string]*ruleEngine.ProtocolRule{
			"HELLO": {
				State:       "disable",
				Expression:  "ospf.hello.hello_interval == 10",
				Description: "测试禁用的规则",
				Type:        "single",
			},
		},
	}

	// 规则编译应该成功，即使规则被禁用
	program, err = compileRule(env, disabledRule, "HELLO")
	assert.NoError(t, err)
	assert.NotNil(t, program)
}

// 测试规则评估功能
func TestEvaluateRule(t *testing.T) {
	// 创建规则引擎
	engine, err := CreateTestRuleEngine()
	assert.NoError(t, err)

	// 创建测试程序
	env, err := cel.NewEnv(
		cel.Variable("ospf.hello.hello_interval", cel.IntType),
	)
	assert.NoError(t, err)

	ast, iss := env.Compile("ospf.hello.hello_interval == 10")
	assert.NoError(t, iss.Err())

	program, err := env.Program(ast)
	assert.NoError(t, err)

	// 测试匹配的情况
	vars := map[string]interface{}{
		"ospf.hello.hello_interval": int64(10),
	}
	result, err := engine.evaluateRule(program, vars)
	assert.NoError(t, err)
	assert.True(t, result)

	// 测试不匹配的情况
	vars = map[string]interface{}{
		"ospf.hello.hello_interval": int64(20),
	}
	result, err = engine.evaluateRule(program, vars)
	assert.NoError(t, err)
	assert.False(t, result)
}

// 测试构建评估变量功能
func TestEvalVarsBuilding(t *testing.T) {
	// 创建一个测试OSPF数据包
	ospfPacket := &OSPFPacket{
		Version:      2,
		PacketLength: 48,
		RouterID:     net.ParseIP("192.168.1.1").To4(),
		AreaID:       net.ParseIP("0.0.0.0").To4(),
		Checksum:     0x1234,
		HelloFields: &HelloFields{
			NetworkMask:            net.IPv4Mask(255, 255, 255, 0),
			HelloInterval:          10,
			Options:                0x02,
			Priority:               1,
			DeadInterval:           40,
			DesignatedRouter:       net.ParseIP("192.168.1.1").To4(),
			BackupDesignatedRouter: net.ParseIP("0.0.0.0").To4(),
		},
	}

	// 创建一个包含OSPF数据包的Packet
	packet := &types.Packet{
		Protocol:     "ospf",
		SubType:      OSPFTypeHello,
		ParserResult: ospfPacket,
	}

	// 直接调用buildEvalVars函数
	vars := buildEvalVars(packet)

	// 验证变量是否正确构建
	assert.Equal(t, int8(2), vars["ospf.version"])
	assert.Equal(t, int8(OSPFTypeHello), vars["ospf.msg"])
	assert.Equal(t, uint16(48), vars["ospf.packet_length"])
	assert.Equal(t, "192.168.1.1", vars["ospf.srcrouter"])
	assert.Equal(t, "0.0.0.0", vars["ospf.area_id"])
	assert.Equal(t, int64(0x1234), vars["ospf.checksum"])

	// 验证Hello包特有字段
	assert.Equal(t, "255.255.255.0", vars["ospf.hello.network_mask"])
	assert.Equal(t, uint16(10), vars["ospf.hello.hello_interval"])
	assert.Equal(t, uint8(1), vars["ospf.hello.router_priority"])
	assert.Equal(t, uint32(40), vars["ospf.hello.router_dead_interval"])
	assert.Equal(t, "192.168.1.1", vars["ospf.hello.designated_router"])
	assert.Equal(t, "0.0.0.0", vars["ospf.hello.backup_designated_router"])
	assert.Equal(t, int64(0x02), vars["ospf.v2.options"])
}

// 集成测试：测试规则引擎处理流程
func TestRuleEngineProcess(t *testing.T) {
	// 创建规则引擎
	rules := map[string]*ruleEngine.Rule{
		// 白名单规则
		"test_whitelist": {
			State:        "enable",
			RuleID:       "test_whitelist",
			RuleProtocol: "ospf",
			RuleMode:     "whitelist",
			ProtocolRules: map[string]*ruleEngine.ProtocolRule{
				"HELLO": {
					State:       "enable",
					Expression:  "ospf.hello.hello_interval == 10",
					Description: "测试Hello包间隔",
					Type:        "single",
				},
				"DD": {
					State:       "disable", // 禁用的规则
					Expression:  "ospf.db.interface_mtu == 1500",
					Description: "测试DD包MTU",
					Type:        "single",
				},
			},
		},
		// 黑名单规则
		"test_blacklist": {
			State:        "enable",
			RuleID:       "test_blacklist",
			RuleProtocol: "ospf",
			RuleMode:     "blacklist",
			ProtocolRules: map[string]*ruleEngine.ProtocolRule{
				"HELLO": {
					State:       "enable",
					Expression:  "ospf.hello.hello_interval < 5",
					Description: "测试异常Hello包间隔",
					Type:        "single",
				},
			},
		},
	}

	// 创建规则引擎
	engine, err := NewRuleEngine(rules)
	assert.NoError(t, err)

	// 创建测试数据包
	packets := []*types.Packet{
		{
			// 符合白名单规则的包
			Protocol: "ospf",
			SubType:  OSPFTypeHello,
			ParserResult: &OSPFPacket{
				Version:      2,
				PacketLength: 48,
				RouterID:     net.ParseIP("192.168.1.1").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				HelloFields: &HelloFields{
					NetworkMask:   net.IPv4Mask(255, 255, 255, 0),
					HelloInterval: 10,
				},
			},
		},
		{
			// 不符合白名单规则的包
			Protocol: "ospf",
			SubType:  OSPFTypeHello,
			ParserResult: &OSPFPacket{
				Version:      2,
				PacketLength: 48,
				RouterID:     net.ParseIP("192.168.1.2").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				HelloFields: &HelloFields{
					NetworkMask:   net.IPv4Mask(255, 255, 255, 0),
					HelloInterval: 20,
				},
			},
		},
		{
			// 符合黑名单规则的包
			Protocol: "ospf",
			SubType:  OSPFTypeHello,
			ParserResult: &OSPFPacket{
				Version:      2,
				PacketLength: 48,
				RouterID:     net.ParseIP("192.168.1.3").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				HelloFields: &HelloFields{
					NetworkMask:   net.IPv4Mask(255, 255, 255, 0),
					HelloInterval: 3,
				},
			},
		},
		{
			// DD包，但规则被禁用
			Protocol: "ospf",
			SubType:  OSPFTypeDD,
			ParserResult: &OSPFPacket{
				Version:      2,
				PacketLength: 32,
				RouterID:     net.ParseIP("192.168.1.1").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				DDFields: &DDFields{
					InterfaceMTU: 1500,
				},
			},
		},
	}

	// 创建输入通道，将数据包放入通道
	in := make(chan *types.Packet, len(packets))
	for _, p := range packets {
		in <- p
	}
	close(in)

	// 处理数据包
	ctx := context.Background()
	var wg sync.WaitGroup
	out, err := engine.Process(ctx, in, &wg)
	assert.NoError(t, err)

	// 收集结果
	var results []*types.Packet
	for p := range out {
		results = append(results, p)
	}
	wg.Wait()

	// 验证结果
	assert.Len(t, results, 3)

	// 验证第一个包（符合白名单规则）
	assert.NotNil(t, results[0].RuleResult, "第一个数据包应该匹配规则")
	assert.True(t, results[0].RuleResult.WhiteRuleMatched, "第一个数据包应该匹配白名单规则")
	assert.Equal(t, "测试Hello包间隔", results[0].RuleResult.WhiteRule.Description, "应该匹配正确的规则描述")

	// 验证第二个包（不符合白名单规则）
	assert.NotNil(t, results[1].RuleResult) // 不匹配，所以没有结果

	// 验证第三个包（符合黑名单规则）
	assert.NotNil(t, results[2].RuleResult, "第三个数据包应该匹配规则")
	assert.True(t, results[2].RuleResult.BlackRuleMatched, "第三个数据包应该匹配黑名单规则")
	assert.Equal(t, "测试异常Hello包间隔", results[2].RuleResult.BlackRule.Description, "应该匹配正确的规则描述")
}
