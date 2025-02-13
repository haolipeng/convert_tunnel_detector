package processor

import (
	"context"
	"fmt"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"time"
)

type BasicFeatureExtractor struct {
	workers int
}

func NewBasicFeatureExtractor(workers int) *BasicFeatureExtractor {
	return &BasicFeatureExtractor{
		workers: workers,
	}
}

func (p *BasicFeatureExtractor) Stage() types.Stage {
	return types.StageBasicFeatureExtraction
}

func (p *BasicFeatureExtractor) Process(ctx context.Context, in <-chan *types.Packet) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet, 1000)

	logrus.Debugf("Starting BasicFeatureExtractor with %d workers", p.workers)

	for i := 0; i < p.workers; i++ {
		go func(workerID int) {
			logrus.Debugf("Worker %d started", workerID)
			for {
				select {
				case <-ctx.Done():
					logrus.Debugf("Worker %d received context cancellation", workerID)
					return
				case packet, ok := <-in:
					if !ok {
						logrus.Debugf("Worker %d: input channel closed", workerID)
						return
					}

					if packet == nil {
						logrus.Warnf("Worker %d received nil packet", workerID)
						continue
					}

					// 提取基础特征
					packet.Features["packet_size"] = len(packet.RawData)
					packet.Features["process_time"] = time.Now().UnixNano()

					logrus.Debugf("Worker %d processed packet: size=%d, time=%d",
						workerID, packet.Features["packet_size"], packet.Features["process_time"])

					select {
					case out <- packet:
					case <-ctx.Done():
						logrus.Warnf("Worker %d: context cancelled while sending packet", workerID)
						return
					}
				}
			}
		}(i)
	}

	return out, nil
}

func (p *BasicFeatureExtractor) Name() string {
	return "BasicFeatureExtractor"
}

func (p *BasicFeatureExtractor) CheckReady() error {
	if p.workers <= 0 {
		return fmt.Errorf("invalid worker count: %d", p.workers)
	}
	return nil
}
