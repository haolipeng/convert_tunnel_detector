package metrics

import (
	"sync/atomic"
	"time"
)

type ProcessorMetrics struct {
	ProcessedPackets uint64
	DroppedPackets   uint64
	ProcessingTime   uint64 // 纳秒
}

func (m *ProcessorMetrics) IncrementProcessed() {
	atomic.AddUint64(&m.ProcessedPackets, 1)
}

func (m *ProcessorMetrics) IncrementDropped() {
	atomic.AddUint64(&m.DroppedPackets, 1)
}

func (m *ProcessorMetrics) AddProcessingTime(duration time.Duration) {
	atomic.AddUint64(&m.ProcessingTime, uint64(duration.Nanoseconds()))
}

type SourceMetrics struct {
	PacketsCaptured uint64
	PacketsDropped  uint64
	BytesProcessed  uint64
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
		"avg_process_time": float64(atomic.LoadUint64(&m.ProcessingTime)) /
			float64(atomic.LoadUint64(&m.ProcessedPackets)+1),
	}
}
