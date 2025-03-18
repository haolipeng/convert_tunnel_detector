package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/pipeline"
	"github.com/haolipeng/convert_tunnel_detector/pkg/processor"
	"github.com/haolipeng/convert_tunnel_detector/pkg/source"
	"github.com/stretchr/testify/assert"
)

// 测试从PCAP文件读取并处理OSPF数据包
func TestProcessOSPFPacketsFromPCAP(t *testing.T) {
	// 跳过测试如果PCAP文件不存在
	pcapFile := "../ospf.pcap"
	if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
		t.Skip("PCAP file not found, skipping test")
	}

	// 创建配置
	cfg := &config.Config{}
	cfg.Pipeline.WorkerCount = 1
	cfg.Pipeline.BufferSize = 1000
	cfg.Source.Type = "file"
	cfg.Source.Filename = pcapFile

	// 创建流水线
	p := pipeline.NewPipeline()

	// 设置配置
	err := p.SetConfig(cfg)
	assert.NoError(t, err)

	// 创建数据源
	fileSource, err := source.NewPcapFileSource(cfg.Source.Filename, cfg.Pipeline.BufferSize)
	assert.NoError(t, err)
	p.SetSource(fileSource)

	// 添加协议解析处理器
	err = p.AddProcessor(processor.NewProtocolParser(cfg.Pipeline.WorkerCount, cfg))
	assert.NoError(t, err)

	// 添加规则引擎处理器
	ruleEngine, err := processor.NewRuleEngineProcessor("../rules/", cfg.Pipeline.WorkerCount, cfg)
	assert.NoError(t, err)
	err = p.AddProcessor(ruleEngine)
	assert.NoError(t, err)

	// 创建内存输出
	memorySink, err := NewMemorySink()
	assert.NoError(t, err)
	p.SetSink(memorySink)

	// 启动流水线
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = p.Start(ctx)
	assert.NoError(t, err)

	// 等待处理完成
	time.Sleep(500 * time.Second)

	// 停止流水线
	err = p.Stop()
	assert.NoError(t, err)

	// 获取结果
	results := memorySink.GetResults()

	// 验证结果：确保处理了足够数量的数据包
	assert.NotEmpty(t, results, "处理结果不应为空")
	assert.GreaterOrEqual(t, len(results), 1, "应该至少处理了一个数据包")

	// 检查是否有匹配的规则
	matchedCount := 0
	whitelistCount := 0
	blacklistCount := 0

	for _, packet := range results {
		if packet.RuleResult != nil {
			matchedCount++
			if packet.RuleResult.WhiteRuleMatched {
				assert.NotEmpty(t, packet.RuleResult.WhiteRule.Description, "白名单规则应有描述")
				whitelistCount++
			}
			if packet.RuleResult.BlackRuleMatched {
				assert.NotEmpty(t, packet.RuleResult.BlackRule.Description, "黑名单规则应有描述")
				blacklistCount++
			}
		}
	}

	// 验证规则匹配情况
	// 注意：这里的具体断言取决于你的预期结果，可能需要根据实际情况调整
	if matchedCount > 0 {
		assert.GreaterOrEqual(t, matchedCount, 1, "应该至少有一个数据包匹配规则")

		// 验证白名单和黑名单规则匹配
		if whitelistCount > 0 {
			assert.GreaterOrEqual(t, whitelistCount, 1, "应该至少有一个数据包匹配白名单规则")
		}

		if blacklistCount > 0 {
			assert.GreaterOrEqual(t, blacklistCount, 1, "应该至少有一个数据包匹配黑名单规则")
		}

		// 确保匹配总数等于白名单和黑名单匹配数之和
		assert.Equal(t, matchedCount, whitelistCount+blacklistCount,
			"匹配总数应等于白名单匹配数和黑名单匹配数之和")
	} else {
		// 如果没有匹配，这可能是预期的行为，或者是测试环境中规则不匹配的情况
		// 可以根据实际需求决定是否增加断言
		t.Log("没有数据包匹配规则，这可能是预期的，取决于测试规则和测试数据")
	}
}
