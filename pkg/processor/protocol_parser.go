package processor

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

type ProtocolParser struct {
	workers int
	metrics *metrics.ProcessorMetrics
	config  *config.Config
}

// NewProtocolParser 创建协议解析器
func NewProtocolParser(workers int, config *config.Config) *ProtocolParser {
	return &ProtocolParser{
		workers: workers,
		config:  config,
		metrics: &metrics.ProcessorMetrics{},
	}
}

// Stage 返回处理器所属阶段
func (p *ProtocolParser) Stage() types.Stage {
	return types.StageProtocolParsing
}

// Process 处理数据包
func (p *ProtocolParser) Process(ctx context.Context, dataCh <-chan *types.Packet, wg *sync.WaitGroup) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet, p.config.Pipeline.BufferSize)

	go func() {
		defer wg.Done()
		defer logrus.Debugf("ProtocolParser stopped")

		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping protocol parser: context cancellation")
				close(out)
				return
			case packet, ok := <-dataCh:
				if !ok {
					logrus.Info("Stopping protocol parser: dataCh channel closed")
					close(out)
					return
				}

				if packet == nil {
					logrus.Warnf("protocol parser received nil packet")
					continue
				}

				start := time.Now()
				//开始解析数据包
				result, err := p.parsePacket(packet)
				duration := time.Since(start)
				p.metrics.AddProcessingTime(duration)

				if err != nil {
					logrus.Errorf("Worker: parsing error: %v", err)
					p.metrics.IncrementDropped()
					// 可以选择将错误信息添加到packet中而不是直接丢弃
					if result != nil {
						result.Error = err
					}
					continue
				}

				if result == nil {
					logrus.Warnf("Worker: nil result from parsePacket")
					p.metrics.IncrementDropped()
					continue
				}

				select {
				case out <- result:
					p.metrics.IncrementProcessed()
					logrus.Debugf("Worker processed packet %s in %v", packet.ID, duration)
				case <-ctx.Done():
					logrus.Infof("Worker: context cancelled while sending result")
					close(out)
					return
				default:
					logrus.Warnf("Worker: output channel full, dropping packet %s", packet.ID)
					p.metrics.IncrementDropped()
				}
			}
		}

		//不要忘记关闭channel通道
		close(out)
	}()

	return out, nil
}

// Name 返回处理器名称
func (p *ProtocolParser) Name() string {
	return "ProtocolParser"
}

// parsePacket 解析数据包
func (p *ProtocolParser) parsePacket(packetData *types.Packet) (*types.Packet, error) {
	if packetData == nil {
		logrus.Warnf("Protocol parser received nil packet")
		return nil, nil
	}

	packet := gopacket.NewPacket(packetData.RawData, layers.LayerTypeEthernet, gopacket.Default)

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		switch ip.Protocol {
		case layers.IPProtocolOSPF: // OSPF协议 (89)
			logrus.Info("detect protocol OSPF!")
			// 检查OSPF层
			ospfLayer := packet.Layer(layers.LayerTypeOSPF)
			if ospfLayer == nil {
				logrus.Errorf("convert layer to ospf type failed!\n")
				return nil, nil
			}

			if ospfV2, ok := ospfLayer.(*layers.OSPFv2); ok {
				ospfParser := NewOSPFParser()
				ospfParser.parsePacketV2(ip, ospfV2)
			} else if ospfV3, ok := ospfLayer.(*layers.OSPFv3); ok {
				ospfParser := NewOSPFParser()
				ospfParser.parsePacketV3(ip, ospfV3)
			}

		case layers.IPProtocolIGMP:
			logrus.Info("detect protocol IGMP!")
		case layers.IPProtocolICMPv4:
			logrus.Info("detect protocol ICMP!")
		case layers.IPProtocolTCP:
			logrus.Info("detect protocol TCP!")
		case layers.IPProtocolUDP:
			logrus.Info("detect protocol UDP!")
		}
	} else if ipLayerV6 := packet.Layer(layers.LayerTypeIPv6); ipLayerV6 != nil {
		//TODO:ipv6 not finished
	} else {
		logrus.Warnf("packet type is not ipv4 or ipv6!\n")
	}

	//TODO:这里返回值是有问题的
	return packetData, nil
}

func (p *ProtocolParser) CheckReady() error {
	if p.workers <= 0 {
		return fmt.Errorf("invalid worker count: %d", p.workers)
	}
	if p.metrics == nil {
		return fmt.Errorf("metrics not initialized")
	}
	return nil
}
