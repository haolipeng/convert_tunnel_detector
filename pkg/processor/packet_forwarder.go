package processor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/haolipeng/gopacket"
	"github.com/haolipeng/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// PacketForwarder 实现数据包转发处理器
type PacketForwarder struct {
	config    *config.Config
	metrics   *metrics.ProcessorMetrics
	ifaceName string
	socket    int
	isReady   bool
}

// NewPacketForwarder 创建新的数据包转发处理器
func NewPacketForwarder(workers int, config *config.Config) *PacketForwarder {
	return &PacketForwarder{
		config:    config,
		metrics:   &metrics.ProcessorMetrics{},
		ifaceName: "eth2", // 默认转发到eth2网口
		isReady:   false,
	}
}

// Stage 返回处理器所属阶段
func (p *PacketForwarder) Stage() types.Stage {
	return types.StagePacketForwarding
}

// Process 处理数据包
// 处理流程：
// 1. 接收数据包
// 2. 检查规则匹配结果
// 3. 根据规则动作处理数据包（转发或告警）
// 4. 更新指标统计
func (p *PacketForwarder) Process(ctx context.Context, in <-chan *types.Packet, wg *sync.WaitGroup) (<-chan *types.Packet, error) {
	out := make(chan *types.Packet, p.config.Pipeline.BufferSize)

	go func() {
		defer wg.Done()
		defer close(out)
		defer p.cleanup()

		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping packet forwarder: context cancellation")
				return
			case packet, ok := <-in:
				if !ok {
					logrus.Info("Stopping packet forwarder: input channel closed")
					return
				}

				if packet == nil {
					logrus.Warnf("packet forwarder received nil packet")
					continue
				}

				// 检查规则匹配结果
				// 如果没有规则匹配结果，说明该数据包不需要特殊处理，直接转发
				if packet.RuleResult == nil {
					select {
					case out <- packet:
						p.metrics.IncrementProcessed()
					case <-ctx.Done():
						return
					default:
						logrus.Warnf("Packet forwarder: output channel full, dropping packet %s", packet.ID)
						p.metrics.IncrementDropped()
					}
					continue
				}

				// 根据规则动作处理数据包
				// 规则动作由规则引擎根据规则匹配结果设置
				switch packet.RuleResult.Action {
				case types.ActionForward:
					// 需要转发的数据包
					logrus.Infof("Packet %s action is forward, forwarding to %s", packet.ID, p.ifaceName)
					if err := p.forwardPacket(packet); err != nil {
						logrus.Errorf("Failed to forward packet %s: %v", packet.ID, err)
						p.metrics.IncrementDropped()
						continue
					}
					p.metrics.IncrementProcessed()
					p.metrics.IncrementWhitelistMatched()
					logrus.Debugf("Successfully forwarded packet %s", packet.ID)

				case types.ActionAlert:
					// 黑名单规则匹配或白名单规则未匹配，触发告警
					// 记录告警信息并更新黑名单匹配计数器
					var ruleInfo *ruleEngine.ProtocolRule
					t := packet.RuleResult.MatchType
					if t == types.MatchTypeBlacklist {
						ruleInfo = packet.RuleResult.BlackRule
					} else if t == types.MatchTypeWhitelist {
						ruleInfo = packet.RuleResult.WhiteRule
					}

					var alertType string
					if packet.Protocol == "OSPF" || packet.Protocol == "ospf" {
						alertType = "OSPF Tunnel Detection"
					} else if packet.Protocol == "PIM" || packet.Protocol == "pim" {
						alertType = "PIM Tunnel Detection"
					} else if packet.Protocol == "IGMP" || packet.Protocol == "igmp" {
						alertType = "IGMP Tunnel Detection"
					}

					alertInfo := map[string]interface{}{
						"alert_time":    time.Now().Format("2006-01-02 15:04:05"),
						"src_ip":        packet.SrcIP.String(),
						"src_port":      packet.SrcPort,
						"dst_ip":        packet.DstIP.String(),
						"dst_port":      packet.DstPort,
						"protocol":      packet.Protocol,
						"sub_protocol":  packet.SubProtocol,
						"detect_method": packet.RuleResult.DetectMethod,
						"rule_id":       ruleInfo.RuleID,
						"alert_type":    alertType,
						"description":   ruleInfo.Description,
						"action":        "alert",
						"packet_id":     packet.ID,
						"feature":       "{}", // TODO:暂时不编写
					}
					logrus.WithFields(logrus.Fields(alertInfo)).Warn("告警信息")

					if packet.RuleResult.BlackRuleMatched {
						p.metrics.IncrementBlacklistMatched()
					}

				default:
					// 未知的动作类型，记录警告日志
					logrus.Warnf("Packet %s has unknown action: %v", packet.ID, packet.RuleResult.Action)
				}

				// 继续传递给下一个处理器
				// 数据包转发后，就不需要下一个处理器进行处理了
				select {
				case out <- packet:
					p.metrics.IncrementProcessed()
				case <-ctx.Done():
					return
				default:
					logrus.Warnf("Packet forwarder: output channel full, dropping packet %s", packet.ID)
					p.metrics.IncrementDropped()
				}
			}
		}
	}()

	return out, nil
}

// Name 返回处理器名称
func (p *PacketForwarder) Name() string {
	return "PacketForwarder"
}

// CheckReady 检查处理器是否就绪
func (p *PacketForwarder) CheckReady() error {
	if p.isReady {
		return nil
	}

	// 创建AF_PACKET socket
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		return fmt.Errorf("failed to create AF_PACKET socket: %v", err)
	}

	// 获取网口索引
	iface, err := net.InterfaceByName(p.ifaceName)
	if err != nil {
		syscall.Close(socket)
		return fmt.Errorf("failed to get interface %s: %v", p.ifaceName, err)
	}

	// 绑定网口
	ll := syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ALL,
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(socket, &ll); err != nil {
		syscall.Close(socket)
		return fmt.Errorf("failed to bind to interface %s: %v", p.ifaceName, err)
	}

	p.socket = socket
	p.isReady = true
	return nil
}

// forwardPacket 转发数据包
func (p *PacketForwarder) forwardPacket(packet *types.Packet) error {
	if !p.isReady {
		return fmt.Errorf("packet forwarder not ready")
	}

	// 构建以太网帧
	eth := &layers.Ethernet{
		SrcMAC:       packet.SrcMAC,
		DstMAC:       packet.DstMAC,
		EthernetType: layers.EthernetType(packet.EthernetType),
	}

	// 序列化数据包
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buffer, opts,
		eth,
		gopacket.Payload(packet.RawData),
	); err != nil {
		return fmt.Errorf("failed to serialize packet: %v", err)
	}

	// 发送数据包
	if err := syscall.Sendto(p.socket, buffer.Bytes(), 0, &syscall.SockaddrLinklayer{
		Protocol: syscall.ETH_P_ALL,
		Ifindex:  packet.Interface.Index,
	}); err != nil {
		return fmt.Errorf("failed to send packet: %v", err)
	}

	return nil
}

// cleanup 清理资源
func (p *PacketForwarder) cleanup() {
	if p.socket != 0 {
		syscall.Close(p.socket)
		p.socket = 0
	}
	p.isReady = false
}
