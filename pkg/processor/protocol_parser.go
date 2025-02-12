package processor

import (
	"context"
	"encoding/binary"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"net"
)

type ProtocolParser struct {
	workers int
}

func NewProtocolParser(workers int) *ProtocolParser {
	return &ProtocolParser{
		workers: workers,
	}
}

func (p *ProtocolParser) Stage() types.Stage {
	return types.StageProtocolParsing
}

func (p *ProtocolParser) Process(ctx context.Context, in <-chan *types.Packet) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet, 1000)
	logrus.Debugf("Starting ProtocolParser with %d workers", p.workers)

	for i := 0; i < p.workers; i++ {
		go func(workerID int) {
			logrus.Debugf("Protocol parser worker %d started", workerID)
			for {
				select {
				case <-ctx.Done():
					logrus.Debugf("Protocol parser worker %d stopping due to context cancellation", workerID)
					return
				case packet, ok := <-in:
					if !ok {
						logrus.Debugf("Protocol parser worker %d: input channel closed", workerID)
						return
					}

					if packet == nil {
						logrus.Warnf("Protocol parser worker %d received nil packet", workerID)
						continue
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

// Name 返回处理器名称
func (p *ProtocolParser) Name() string {
	return "ProtocolParser"
}
