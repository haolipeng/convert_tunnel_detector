package processor

import (
	"context"
	"fmt"
	"sync"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
)

type BasicFeatureExtractor struct {
	workers int
	config  *config.Config
}

func NewBasicFeatureExtractor(workers int, config *config.Config) *BasicFeatureExtractor {
	return &BasicFeatureExtractor{
		workers: workers,
		config:  config,
	}
}

func (p *BasicFeatureExtractor) Stage() types.Stage {
	return types.StageBasicFeatureExtraction
}

func (p *BasicFeatureExtractor) Process(ctx context.Context, in <-chan *types.Packet, wg *sync.WaitGroup) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet, p.config.Pipeline.BufferSize)
	logrus.Debugf("Starting BasicFeatureExtractor with %d workers", p.workers)

	go func() {
		defer wg.Done()
		defer logrus.Debugf("Feature extractor worker stopped")

		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping feature extractor: context cancellation")
				close(out)
				return
			case packet, ok := <-in:
				if !ok {
					logrus.Info("Stopping feature extractor: dataCh channel closed")
					close(out)
					return
				}

				if packet == nil {
					logrus.Warnf("feature extractor received nil packet")
					continue
				}

				// TODO:提取基础特征,没做任何事情，单纯将数据包转发给下一个处理器

				select {
				case out <- packet:
					//logrus.Infof("Feature Extractor Worker: sent packet to out channel")
				default: //非阻塞发送
					logrus.Warnf("Feature Extractor Worker: out channel is full, dropping packet - %s", packet.ID)
				case <-ctx.Done():
					logrus.Warnf("Feature Extractor Worker: context cancelled while sending packet")
					close(out)
					return
				}
			}
		}
		//不要忘记关闭channel通道
		close(out)
	}()

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
