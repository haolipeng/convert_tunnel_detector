package source

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/haolipeng/gopacket"
	"github.com/haolipeng/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

type PcapLiveSource struct {
	handle    *pcap.Handle
	output    chan *types.Packet
	bpfFilter string
	done      chan struct{}
	stats     *metrics.SourceMetrics
	bufSize   int
	device    string
	mu        sync.Mutex
}

func NewPcapLiveSource(config *config.Config) (*PcapLiveSource, error) {
	if config.Source.Interface.Name == "" {
		return nil, fmt.Errorf("interface name is required")
	}

	// 打开捕获的网口
	handle, err := pcap.OpenLive(
		config.Source.Interface.Name,
		config.Source.Interface.Snaplen,
		config.Source.Interface.Promiscuous,
		config.Source.Interface.Timeout,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open interface %s: %w",
			config.Source.Interface.Name, err)
	}

	// 设置BPF过滤器
	if config.Source.Interface.BPFFilter != "" {
		if err := handle.SetBPFFilter(config.Source.Interface.BPFFilter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	return &PcapLiveSource{
		handle:  handle,
		output:  make(chan *types.Packet, config.Pipeline.BufferSize),
		device:  config.Source.Interface.Name,
		stats:   &metrics.SourceMetrics{},
		bufSize: config.Pipeline.BufferSize,
	}, nil
}

func (s *PcapLiveSource) Start(ctx context.Context, wg *sync.WaitGroup) error {
	s.done = make(chan struct{})

	if s.bpfFilter != "" {
		logrus.Debugf("Setting BPF filter: %s", s.bpfFilter)
		if err := s.handle.SetBPFFilter(s.bpfFilter); err != nil {
			logrus.Errorf("Failed to set BPF filter: %v", err)
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	logrus.Infof("Started packet capture on interface with link type: %v", s.handle.LinkType())

	go func() {
		defer func() {
			wg.Done()
			s.cleanup()
			close(s.done)
			logrus.Info("Packet capture goroutine cleaned up")
		}()

		var packetCount int64 = 0
		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping packet capture: context cancellation")
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					logrus.Warnf("Error capturing packet: %v", err)
					continue
				}

				p := &types.Packet{
					ID:          fmt.Sprintf("pkt-%d", packetCount),
					Timestamp:   time.Now().UnixNano(),
					RawData:     packet.Data(),
					CaptureInfo: packet.Metadata().CaptureInfo,
					Protocol:    "Unknown", // 需要进一步解析, 暂时设置为Unknown
				}

				select {
				case s.output <- p:
					packetCount++
					s.stats.PacketsCaptured++
					s.stats.BytesProcessed += uint64(len(packet.Data()))
					logrus.Debugf("capture Source: sent packet to out channel - %s", p.ID)
				default:
					logrus.Warnf("Source: out channel is full, dropping packet - %s", p.ID)
				case <-ctx.Done(): //取消操作
					logrus.Warnf("Source: context cancelled while sending packet - %s", p.ID)
					return
				}
			}
		}
	}()

	return nil
}

func (s *PcapLiveSource) Output() <-chan *types.Packet {
	return s.output
}

func (s *PcapLiveSource) SetFilter(filter string) error {
	s.bpfFilter = filter
	return nil
}

func (s *PcapLiveSource) Stop() error {
	logrus.Info("Stopping PcapSource...")
	s.cleanup()
	return nil
}

func (s *PcapLiveSource) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 关闭捕获的网口
	if s.handle != nil {
		logrus.Debug("Closing pcap handle")
		s.handle.Close()
		s.handle = nil
	}

	// 关闭输出通道
	if s.output != nil {
		logrus.Debug("Closing output channel")
		close(s.output)
		s.output = nil
	}
}
