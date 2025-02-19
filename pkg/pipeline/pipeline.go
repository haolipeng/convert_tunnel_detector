package pipeline

import (
	"context"
	"fmt"
	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"sort"
	"sync"
	"time"
)

type pipeline struct {
	source     Source
	processors []Processor
	sink       Sink
	running    bool
	mu         sync.Mutex
	errChan    chan error
	status     string
	metrics    map[string]*metrics.ProcessorMetrics
	config     *config.Config
	startTime  time.Time
	wg         sync.WaitGroup // 用于跟踪所有goroutine
}

func NewPipeline() Pipeline {
	return &pipeline{
		processors: make([]Processor, 0),
		errChan:    make(chan error, 1),
		metrics:    make(map[string]*metrics.ProcessorMetrics),
		status:     "initialized",
	}
}

func (p *pipeline) AddProcessor(processor Processor) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("cannot add processor while pipeline is running")
	}

	p.processors = append(p.processors, processor)
	// 按Stage排序处理器
	sort.Slice(p.processors, func(i, j int) bool {
		return p.processors[i].Stage() < p.processors[j].Stage()
	})

	return nil
}

func (p *pipeline) SetSource(source Source) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.source = source
}

func (p *pipeline) SetSink(sink Sink) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sink = sink
}

func (p *pipeline) Start(ctx context.Context) error {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return types.NewPipelineError("start", fmt.Errorf("pipeline already running"))
	}

	// 重置 WaitGroup
	p.wg = sync.WaitGroup{}

	// 设置状态为正在启动
	p.running = true
	p.startTime = time.Now()
	p.status = "starting"
	p.metrics = make(map[string]*metrics.ProcessorMetrics)
	p.errChan = make(chan error, 100)
	p.mu.Unlock()

	// 为每个处理器初始化指标对象
	for _, proc := range p.processors {
		p.metrics[proc.Name()] = &metrics.ProcessorMetrics{}
	}

	logrus.Info("Starting pipeline")

	// 启动错误处理goroutine
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.handleErrors(ctx)
	}()

	var input <-chan *types.Packet = p.source.Output()
	var err error
	// 为每个处理器启动时增加 WaitGroup 计数

	processorCnt := len(p.processors)
	p.wg.Add(processorCnt)
	for _, proc := range p.processors {
		logrus.Debugf("Starting processor at stage: %v", proc.Stage())
		// 前一个stage阶段处理器的处理结果直接传递给下一个stage阶段的处理器
		input, err = proc.Process(ctx, input, &p.wg)
		if err != nil {
			logrus.Errorf("Failed to start processor at stage %v: %v", proc.Stage(), err)
			p.errChan <- fmt.Errorf("failed to start processor: %w", err)
		}
	}

	// 1. 首先检查所有处理器是否就绪
	processorReady := make(chan struct{})
	go func() {
		for _, processor := range p.processors {
			// 检查处理器的内部状态
			if err := processor.CheckReady(); err != nil {
				logrus.Errorf("Processor %s not ready: %v", processor.Name(), err)
				p.errChan <- fmt.Errorf("processor not ready: %w", err)
				return
			}
		}
		close(processorReady) // 所有处理器就绪后关闭channel
	}()

	// 2. 等待处理器就绪，设置超时
	select {
	case <-processorReady:
		logrus.Debug("All processors are ready")
	case <-time.After(10 * time.Second):
		return types.NewPipelineError("start", fmt.Errorf("timeout waiting for processors to be ready"))
	}

	//添加日志表示处理器启动成功
	logrus.Info("All processors have started successfully")

	// 3. 处理器就绪后，再启动sink
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		if err := p.sink.Consume(ctx, input); err != nil {
			logrus.Errorf("Sink error: %v", err)
			p.errChan <- fmt.Errorf("sink error: %w", err)
		}
	}()

	// 4. 等待sink就绪
	select {
	case <-p.sink.Ready():
		logrus.Debug("Sink is ready")
	case <-time.After(5 * time.Second):
		return types.NewPipelineError("start", fmt.Errorf("timeout waiting for sink to be ready"))
	}

	//添加日志表示sink启动成功
	logrus.Info("Sink have started successfully")

	// 5. 最后启动数据源，开始数据流转
	p.wg.Add(1)
	if err := p.source.Start(ctx, &p.wg); err != nil {
		logrus.Errorf("Failed to start source: %v", err)
		return fmt.Errorf("failed to start source: %w", err)
	}

	//添加日志表示数据源启动成功
	logrus.Info("Data Source have started successfully")

	p.status = "running"
	logrus.Info("Pipeline is now running")
	return nil
}

func (p *pipeline) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	p.status = "stopping"
	logrus.Info("Pipeline stopping...")

	// 1. 先设置状态，防止新的goroutine启动
	p.running = false

	// 2. 关闭错误通道，停止错误处理 goroutine
	if p.errChan != nil {
		close(p.errChan)
		p.errChan = nil
	}

	// 3. 等待所有处理器完成
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()

	// 设置超时时间
	select {
	case <-done:
		logrus.Info("All processors completed gracefully")
	case <-time.After(30 * time.Second):
		logrus.Warn("Timeout waiting for processors to complete")
	}

	// 4. 清理处理器资源
	for _, processor := range p.processors {
		if cleaner, ok := processor.(interface{ Cleanup() error }); ok {
			if err := cleaner.Cleanup(); err != nil {
				logrus.Errorf("Error cleaning up processor %s: %v", processor.Name(), err)
			}
		}
	}

	p.status = "stopped"
	p.processors = nil
	p.metrics = make(map[string]*metrics.ProcessorMetrics)
	p.startTime = time.Time{}

	logrus.Info("Pipeline stopped and cleaned up")
	return nil
}

func (p *pipeline) handleErrors(ctx context.Context) {
	logrus.Debug("Starting error handler")
	for {
		select {
		case err, ok := <-p.errChan:
			if !ok {
				logrus.Debug("Error channel closed, stopping error handler")
				return
			}
			logrus.Errorf("Pipeline error: %v", err)
		case <-ctx.Done():
			logrus.Debug("Context cancelled, stopping error handler")
			return
		}
	}
}

// 添加资源统计方法
func (p *pipeline) GetStats() map[string]interface{} {
	p.mu.Lock()
	defer p.mu.Unlock()

	return map[string]interface{}{
		"status":     p.status,
		"uptime":     time.Since(p.startTime).String(),
		"processors": len(p.processors),
		"metrics":    p.metrics,
	}
}

// GetMetrics 实现Pipeline接口的GetMetrics方法
func (p *pipeline) GetMetrics() map[string]*metrics.ProcessorMetrics {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.metrics
}

// SetConfig 实现Pipeline接口的SetConfig方法
func (p *pipeline) SetConfig(cfg *config.Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return types.NewPipelineError("config", fmt.Errorf("cannot set config while pipeline is running"))
	}

	if err := cfg.Validate(); err != nil {
		return types.NewPipelineError("config", err)
	}

	p.config = cfg
	return nil
}

// Status 实现Pipeline接口的Status方法
func (p *pipeline) Status() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}
