package pipeline

import (
	"context"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
)

// Source 定义数据源接口
type Source interface {
	// Start 启动数据源捕获
	Start(ctx context.Context) error
	// Output 返回数据输出channel
	Output() <-chan *types.Packet
	// SetFilter 设置数据包过滤器
	SetFilter(filter string) error
}

// Processor 定义数据处理器接口
type Processor interface {
	// Process 处理数据包
	Process(ctx context.Context, in <-chan *types.Packet) (<-chan *types.Packet, error)
	// Stage 返回处理器所属阶段
	Stage() types.Stage
	// Name 返回处理器的名称
	Name() string
}

// Sink 定义数据输出接口
type Sink interface {
	// Consume 消费处理后的数据包
	Consume(ctx context.Context, in <-chan *types.Packet) error
}

// Pipeline 定义处理流水线接口
type Pipeline interface {
	// AddProcessor 添加处理器
	AddProcessor(processor Processor) error
	// SetSource 设置数据源
	SetSource(source Source)
	// SetSink 设置数据输出
	SetSink(sink Sink)
	// Start 启动流水线
	Start(ctx context.Context) error
	// Stop 停止流水线
	Stop() error
} 