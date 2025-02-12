package pipeline

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
)

type pipeline struct {
	source     Source
	processors []Processor
	sink       Sink
	running    bool
	mu         sync.Mutex
	errChan    chan error
}

func NewPipeline() Pipeline {
	return &pipeline{
		processors: make([]Processor, 0),
		errChan:   make(chan error, 1),
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
		logrus.Warn("Attempted to start already running pipeline")
		return fmt.Errorf("pipeline is already running")
	}
	
	if p.source == nil || p.sink == nil {
		p.mu.Unlock()
		logrus.Error("Attempted to start pipeline without source or sink")
		return fmt.Errorf("source and sink must be set before starting pipeline")
	}
	
	p.running = true
	p.mu.Unlock()

	logrus.Info("Starting pipeline")
	
	// 启动错误处理goroutine
	go p.handleErrors(ctx)

	// 启动数据源
	if err := p.source.Start(ctx); err != nil {
		logrus.Errorf("Failed to start source: %v", err)
		return fmt.Errorf("failed to start source: %w", err)
	}

	// 构建处理链
	var input <-chan *types.Packet = p.source.Output()
	var err error

	for _, proc := range p.processors {
		logrus.Debugf("Starting processor at stage: %v", proc.Stage())
		input, err = proc.Process(ctx, input)
		if err != nil {
			logrus.Errorf("Failed to start processor at stage %v: %v", proc.Stage(), err)
			return fmt.Errorf("failed to start processor: %w", err)
		}
	}

	// 启动数据输出
	go func() {
		if err := p.sink.Consume(ctx, input); err != nil {
			logrus.Errorf("Sink error: %v", err)
			p.errChan <- fmt.Errorf("sink error: %w", err)
		}
	}()

	logrus.Info("Pipeline started successfully")
	return nil
}

func (p *pipeline) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	
	if !p.running {
		return nil
	}
	
	p.running = false
	close(p.errChan)
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