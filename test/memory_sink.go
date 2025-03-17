package main

import (
	"context"
	"sync"

	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
)

// MemorySink 是一个用于测试的内存Sink
type MemorySink struct {
	results []*types.Packet
	ready   chan struct{}
	mu      sync.Mutex
}

// NewMemorySink 创建一个新的内存Sink
func NewMemorySink() (*MemorySink, error) {
	sink := &MemorySink{
		results: make([]*types.Packet, 0),
		ready:   make(chan struct{}),
	}
	close(sink.ready) // 立即标记为就绪
	return sink, nil
}

// Consume 消费数据包并存储在内存中
func (s *MemorySink) Consume(ctx context.Context, in <-chan *types.Packet) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		case packet, ok := <-in:
			if !ok {
				return nil
			}
			s.mu.Lock()
			s.results = append(s.results, packet)
			s.mu.Unlock()
		}
	}
}

// Ready 返回就绪信号
func (s *MemorySink) Ready() <-chan struct{} {
	return s.ready
}

// GetResults 获取收集的结果
func (s *MemorySink) GetResults() []*types.Packet {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.results
}
