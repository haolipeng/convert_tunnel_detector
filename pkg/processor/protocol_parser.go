package processor

import (
	"context"
	"encoding/binary"
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
	wg      sync.WaitGroup
}

func NewProtocolParser(workers int, config *config.Config) *ProtocolParser {
	return &ProtocolParser{
		workers: workers,
		config:  config,
		metrics: &metrics.ProcessorMetrics{},
	}
}

func (p *ProtocolParser) Stage() types.Stage {
	return types.StageProtocolParsing
}

func (p *ProtocolParser) Process(ctx context.Context, in <-chan *types.Packet) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet, p.config.Pipeline.BufferSize)

	p.wg.Add(p.workers)
	for i := 0; i < p.workers; i++ {
		go func(workerID int) {
			defer p.wg.Done()
			p.processWorker(ctx, workerID, in, out)
		}(i)
	}

	// 启动清理goroutine
	go func() {
		p.wg.Wait()
		close(out)
	}()

	return out, nil
}

// 将worker逻辑抽取为单独的方法
func (p *ProtocolParser) processWorker(ctx context.Context, workerID int,
	in <-chan *types.Packet, out chan<- *types.Packet) {

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-in:
			if !ok {
				return
			}

			start := time.Now()
			result, err := p.parsePacket(packet, workerID)
			p.metrics.AddProcessingTime(time.Since(start))

			if err != nil {
				logrus.Errorf("Worker %d: parsing error: %v", workerID, err)
				p.metrics.IncrementDropped()
				continue
			}

			select {
			case out <- result:
				p.metrics.IncrementProcessed()
			case <-ctx.Done():
				return
			}
		}
	}
}

// Name 返回处理器名称
func (p *ProtocolParser) Name() string {
	return "ProtocolParser"
}

func (p *ProtocolParser) parsePacket(packet *types.Packet, workerID int) (*types.Packet, error) {
	if packet == nil {
		logrus.Warnf("Protocol parser received nil packet")
		return nil, nil
	}

	// 解析数据包
	parsed := gopacket.NewPacket(packet.RawData, layers.LayerTypeEthernet, gopacket.Default)

	// 识别协议
	if ipLayer := parsed.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		packet.Protocol = "IPv4"
		ip, _ := ipLayer.(*layers.IPv4)
		packet.Features["src_ip"] = ip.SrcIP.String()
		packet.Features["dst_ip"] = ip.DstIP.String()
		logrus.Debugf("Worker %d: Parsed IPv4 packet from %s to %s",
			workerID, ip.SrcIP, ip.DstIP)

		// 根据IP协议号识别上层协议
		switch ip.Protocol {
		case layers.IPProtocolOSPF: // OSPF协议 (89)
			packet.Protocol = "OSPF"
			if ospfLayer := parsed.Layer(layers.LayerTypeOSPF); ospfLayer != nil {
				ospf, _ := ospfLayer.(*layers.OSPFv2)
				packet.Features["ospf_type"] = ospf.Type.String()
				// 将 RouterID (uint32) 转换为 IP 地址格式
				routerIP := make(net.IP, 4)
				binary.BigEndian.PutUint32(routerIP, ospf.RouterID)
				packet.Features["ospf_router_id"] = routerIP.String()
				logrus.Debugf("Worker %d: Parsed OSPF packet, type: %s, router_id: %s",
					workerID, ospf.Type.String(), routerIP.String())
			}

		case layers.IPProtocolICMPv4: // ICMP协议 (1)
			packet.Protocol = "ICMP"
			if icmpLayer := parsed.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
				icmp, _ := icmpLayer.(*layers.ICMPv4)
				packet.Features["icmp_type"] = icmp.TypeCode.Type()
				packet.Features["icmp_code"] = icmp.TypeCode.Code()
				packet.Features["icmp_seq"] = icmp.Seq
				logrus.Debugf("Worker %d: Parsed ICMP packet, type: %d, code: %d, seq: %d",
					workerID, icmp.TypeCode.Type(), icmp.TypeCode.Code(), icmp.Seq)
			}
		}
	}

	if tcpLayer := parsed.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		packet.Protocol = "TCP"
		tcp, _ := tcpLayer.(*layers.TCP)
		packet.Features["src_port"] = tcp.SrcPort
		packet.Features["dst_port"] = tcp.DstPort
		logrus.Debugf("Worker %d: Parsed TCP packet from port %d to %d",
			workerID, tcp.SrcPort, tcp.DstPort)
	}

	return packet, nil
}
