package metrics

import (
	"sync/atomic"
	"time"
)

type ProcessorMetrics struct {
	ProcessedPackets uint64
	DroppedPackets   uint64
	ProcessingTime   uint64 // 纳秒
	WhitelistMatched uint64 // 白名单规则匹配计数
	BlacklistMatched uint64 // 黑名单规则匹配计数
}

func (m *ProcessorMetrics) IncrementProcessed() {
	atomic.AddUint64(&m.ProcessedPackets, 1)
}

func (m *ProcessorMetrics) IncrementDropped() {
	atomic.AddUint64(&m.DroppedPackets, 1)
}

func (m *ProcessorMetrics) IncrementWhitelistMatched() {
	atomic.AddUint64(&m.WhitelistMatched, 1)
}

func (m *ProcessorMetrics) IncrementBlacklistMatched() {
	atomic.AddUint64(&m.BlacklistMatched, 1)
}

func (m *ProcessorMetrics) AddProcessingTime(duration time.Duration) {
	atomic.AddUint64(&m.ProcessingTime, uint64(duration.Nanoseconds()))
}

type SourceMetrics struct {
	PacketsCaptured uint64
	PacketsDropped  uint64
	BytesProcessed  uint64
	ErrorCount      uint64
}

func (m *SourceMetrics) IncrementErrorCount() {
	atomic.AddUint64(&m.ErrorCount, 1)
}

type SinkMetrics struct {
	PacketsWritten uint64
	WriteErrors    uint64
	BytesWritten   uint64
}

// 添加性能指标收集方法
func (m *ProcessorMetrics) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"processed_packets": atomic.LoadUint64(&m.ProcessedPackets),
		"dropped_packets":   atomic.LoadUint64(&m.DroppedPackets),
		"processing_time":   atomic.LoadUint64(&m.ProcessingTime),
		"whitelist_matched": atomic.LoadUint64(&m.WhitelistMatched),
		"blacklist_matched": atomic.LoadUint64(&m.BlacklistMatched),
		"avg_process_time": float64(atomic.LoadUint64(&m.ProcessingTime)) /
			float64(atomic.LoadUint64(&m.ProcessedPackets)+1),
	}
}

// IncrementPacketsCaptured 增加捕获的数据包计数
func (m *SourceMetrics) IncrementPacketsCaptured() {
	atomic.AddUint64(&m.PacketsCaptured, 1)
}

// AddBytesProcessed 增加处理的字节数
func (m *SourceMetrics) AddBytesProcessed(bytes uint64) {
	atomic.AddUint64(&m.BytesProcessed, bytes)
}
