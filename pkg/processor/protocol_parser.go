package processor

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"net"
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
func (p *ProtocolParser) parsePacket(packet *types.Packet) (*types.Packet, error) {
	if packet == nil {
		logrus.Warnf("Protocol parser received nil packet")
		return nil, nil
	}

	parsed := gopacket.NewPacket(packet.RawData, layers.LayerTypeEthernet, gopacket.Default)

	// 识别并解析数据包
	if ipLayer := parsed.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		packet.Protocol = "IPv4"
		ip, _ := ipLayer.(*layers.IPv4)
		packet.Features["src_ip"] = ip.SrcIP.String()
		packet.Features["dst_ip"] = ip.DstIP.String()
		logrus.Debugf("Worker: Parsed IPv4 packet from %s to %s", ip.SrcIP, ip.DstIP)

		// 根据IP协议号识别上层协议
		switch ip.Protocol {
		case layers.IPProtocolOSPF: // OSPF协议 (89)
			packet.Protocol = "OSPF"
			if ospfLayer := parsed.Layer(layers.LayerTypeOSPF); ospfLayer != nil {
				if ospfV2, ok := ospfLayer.(*layers.OSPFv2); ok {
					packet.Features["ospf_type"] = ospfV2.Type.String()
					// 将 RouterID (uint32) 转换为 IP 地址格式
					routerIP := make(net.IP, 4)
					binary.BigEndian.PutUint32(routerIP, ospfV2.RouterID)
					packet.Features["ospf_router_id"] = routerIP.String()
					logrus.Debugf("Worker: Parsed OSPFv2 packet, type: %s, router_id: %s",
						ospfV2.Type.String(), routerIP.String())
				} else if ospfV3, ok := ospfLayer.(*layers.OSPFv3); ok {
					packet.Features["ospf_type"] = ospfV3.Type.String()
					// 处理 OSPFv3 的 RouterID
					routerIP := ospfV3.RouterID // 假设 OSPFv3 也有 RouterID 字段
					packet.Features["ospf_router_id"] = routerIP
					logrus.Debugf("Worker: Parsed OSPFv3 packet, type: %s, router_id: %s",
						ospfV3.Type.String(), routerIP)
				} else {
					logrus.Warnf("Unsupported OSPF layer type")
				}
			}

		case layers.IPProtocolICMPv4: // ICMP协议 (1)
			packet.Protocol = "ICMP"
			if icmpLayer := parsed.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				packet.Features["icmp_type"] = icmp.TypeCode.Type()
				packet.Features["icmp_code"] = icmp.TypeCode.Code()
				packet.Features["icmp_seq"] = icmp.Seq
				logrus.Debugf("Worker: Parsed ICMP packet, type: %d, code: %d, seq: %d",
					icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Seq)
			}

		case layers.IPProtocolTCP:
			if tcpLayer := parsed.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				packet.Protocol = "TCP"
				tcp, _ := tcpLayer.(*layers.TCP)
				packet.Features["src_port"] = tcp.SrcPort
				packet.Features["dst_port"] = tcp.DstPort
				logrus.Debugf("Worker %d: Parsed TCP packet from port %d to %d",
					tcp.SrcPort, tcp.DstPort)
			}
		default:
			logrus.Warnf("This Protocol is not supported!")
		}
	}

	return packet, nil
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
