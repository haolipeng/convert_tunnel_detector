package main

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/haolipeng/convert_tunnel_detector/pkg/processor"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/stretchr/testify/assert"
)

// 测试规则状态功能
func TestRuleState(t *testing.T) {
	// 创建测试规则，包含启用和禁用的规则
	rules := map[string]*ruleEngine.Rule{
		"test_rule": {
			State:        "enable",
			RuleID:       "test_rule",
			RuleProtocol: "ospf",
			RuleMode:     "whitelist",
			ProtocolRules: map[string]*ruleEngine.ProtocolRule{
				"HELLO": {
					State:       "enable", // 启用的规则
					Expression:  "ospf.hello.hello_interval == 10",
					Description: "启用的Hello规则",
					Type:        "single",
				},
				"DD": {
					State:       "disable", // 禁用的规则
					Expression:  "ospf.db.interface_mtu == 1500",
					Description: "禁用的DD规则",
					Type:        "single",
				},
				"LSR": {
					State:       "enable", // 启用的规则
					Expression:  "ospf.link_state_id == \"192.168.1.1\"",
					Description: "启用的LSR规则",
					Type:        "single",
				},
			},
		},
	}

	// 创建规则引擎
	ruleEngine, err := processor.NewRuleEngine(rules)
	assert.NoError(t, err)

	// 创建测试数据包
	packets := []*types.Packet{
		// 符合启用的Hello规则
		{
			Protocol: "ospf",
			SubType:  processor.OSPFTypeHello,
			ParserResult: &processor.OSPFPacket{
				Version:      2,
				PacketLength: 48,
				RouterID:     net.ParseIP("192.168.1.1").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				HelloFields: &processor.HelloFields{
					HelloInterval: 10,
				},
			},
		},
		// 符合禁用的DD规则,被禁用的规则，是不会有匹配结果的
		{
			Protocol: "ospf",
			SubType:  processor.OSPFTypeDD,
			ParserResult: &processor.OSPFPacket{
				Version:      2,
				PacketLength: 32,
				RouterID:     net.ParseIP("192.168.1.1").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				DDFields: &processor.DDFields{
					InterfaceMTU: 1500,
				},
			},
		},
		// 符合启用的LSR规则
		{
			Protocol: "ospf",
			SubType:  processor.OSPFTypeLSR,
			ParserResult: &processor.OSPFPacket{
				Version:      2,
				PacketLength: 36,
				RouterID:     net.ParseIP("192.168.1.1").To4(),
				AreaID:       net.ParseIP("0.0.0.0").To4(),
				LSRFields: &processor.LSRFields{
					LSARequests: []processor.LSARequest{
						{
							LSID: net.ParseIP("192.168.1.1").To4(),
						},
					},
				},
			},
		},
	}

	// 创建输入通道
	in := make(chan *types.Packet, len(packets))
	for _, p := range packets {
		in <- p
	}
	close(in)

	// 处理数据包
	ctx := context.Background()
	var wg sync.WaitGroup
	out, err := ruleEngine.Process(ctx, in, &wg)
	assert.NoError(t, err)

	// 收集结果
	var results []*types.Packet
	for p := range out {
		results = append(results, p)
	}
	wg.Wait()

	// 验证结果
	assert.Len(t, results, 3-1)

	// 验证第一个包（符合启用的Hello规则）
	assert.NotNil(t, results[0].RuleResult)
	assert.True(t, results[0].RuleResult.WhiteRuleMatched)
	assert.Equal(t, "启用的Hello规则", results[0].RuleResult.WhiteRule.Description)

	// 验证第二个包（符合禁用的DD规则）规则被禁用，所以没有结果

	// 验证第三个包（符合启用的LSR规则）
	assert.NotNil(t, results[1].RuleResult)
	assert.True(t, results[1].RuleResult.WhiteRuleMatched)
	assert.Equal(t, "启用的LSR规则", results[1].RuleResult.WhiteRule.Description)
}
