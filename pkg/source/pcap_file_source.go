package source

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
)

type PcapFileSource struct {
	handle    *pcap.Handle
	output    chan *types.Packet
	bpfFilter string
	done      chan struct{}
	stats     *metrics.SourceMetrics
	filename  string
}

func NewPcapFileSource(filename string, bufferSize int) (*PcapFileSource, error) {
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap file %s: %w", filename, err)
	}

	return &PcapFileSource{
		handle:   handle,
		output:   make(chan *types.Packet, bufferSize),
		filename: filename,
		stats:    &metrics.SourceMetrics{},
	}, nil
}

func (s *PcapFileSource) Start(ctx context.Context) error {
	s.done = make(chan struct{})

	if s.bpfFilter != "" {
		logrus.Debugf("Setting BPF filter: %s", s.bpfFilter)
		if err := s.handle.SetBPFFilter(s.bpfFilter); err != nil {
			logrus.Errorf("Failed to set BPF filter: %v", err)
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	logrus.Infof("Started reading packets from file: %s", s.filename)

	go func() {
		defer close(s.output)
		defer s.handle.Close()
		defer close(s.done)

		var packetCount int64 = 0
		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping packet reading due to context cancellation")
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					if err == pcap.NextErrorNoMorePackets {
						logrus.Info("Reached end of pcap file")
						return
					}
					logrus.Warnf("Error reading packet: %v", err)
					continue
				}

				packetCount++
				s.output <- &types.Packet{
					ID:        fmt.Sprintf("pkt-%d", packetCount),
					Timestamp: packet.Metadata().Timestamp.UnixNano(),
					RawData:   packet.Data(),
					Protocol:  "Unknown", // ��Ҫ��һ������
					Features:  make(map[string]interface{}),
				}

				// ����ͳ����Ϣ
				s.stats.PacketsCaptured++
				s.stats.BytesProcessed += uint64(len(packet.Data()))
			}
		}
	}()

	return nil
}

func (s *PcapFileSource) Output() <-chan *types.Packet {
	return s.output
}

func (s *PcapFileSource) SetFilter(filter string) error {
	s.bpfFilter = filter
	return nil
}

// ���һЩ��������
func (s *PcapFileSource) GetStats() *metrics.SourceMetrics {
	return s.stats
}

func (s *PcapFileSource) WaitForCompletion() <-chan struct{} {
	return s.done
}
