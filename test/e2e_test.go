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
	ruleEngine, err := processor.NewRuleEngineProcessor(cfg.Pipeline.WorkerCount, cfg)
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
	time.Sleep(5 * time.Second)

	// 停止流水线
	err = p.Stop()
	assert.NoError(t, err)

	// 获取结果
	results := memorySink.GetResults()

	// 验证结果
	t.Logf("Processed packets, got %d results", len(results))

	// 检查是否有匹配的规则
	matchedCount := 0
	for _, packet := range results {
		if packet.RuleResult != nil {
			matchedCount++
			if packet.RuleResult.WhiteRuleMatched {
				t.Logf("Packet matched whitelist rule: %s", packet.RuleResult.WhiteRule.Description)
			}
			if packet.RuleResult.BlackRuleMatched {
				t.Logf("Packet matched blacklist rule: %s", packet.RuleResult.BlackRule.Description)
			}
		}
	}
	t.Logf("Matched %d packets", matchedCount)
}
