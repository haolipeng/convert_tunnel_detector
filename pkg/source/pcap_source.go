package source

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"time"
)

type PcapSource struct {
	handle    *pcap.Handle
	output    chan *types.Packet
	bpfFilter string
	done      chan struct{}
	stats     *metrics.SourceMetrics
	bufSize   int
	device    string
}

func NewPcapSource(config *config.Config) (*PcapSource, error) {
	if config.Source.Interface.Name == "" {
		return nil, fmt.Errorf("interface name is required")
	}

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

	return &PcapSource{
		handle:  handle,
		output:  make(chan *types.Packet, config.Pipeline.BufferSize),
		device:  config.Source.Interface.Name,
		stats:   &metrics.SourceMetrics{},
		bufSize: config.Pipeline.BufferSize,
	}, nil
}

func (s *PcapSource) Start(ctx context.Context) error {
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
		defer close(s.output)
		defer s.handle.Close()
		logrus.Debug("Starting packet capture goroutine")

		var packetCount int64 = 0
		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping packet capture due to context cancellation")
				close(s.done)
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					logrus.Warnf("Error capturing packet: %v", err)
					continue
				}

				packetCount++
				s.output <- &types.Packet{
					ID:        fmt.Sprintf("pkt-%d", packetCount),
					Timestamp: time.Now().UnixNano(),
					RawData:   packet.Data(),
					Protocol:  "Unknown", // 需要进一步解析
					Features:  make(map[string]interface{}),
				}
			}
		}
	}()

	return nil
}

func (s *PcapSource) Output() <-chan *types.Packet {
	return s.output
}

func (s *PcapSource) SetFilter(filter string) error {
	s.bpfFilter = filter
	return nil
}

// 添加资源清理方法
func (s *PcapSource) cleanup() {
	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}
	if s.output != nil {
		close(s.output)
		s.output = nil
	}
}
