package source

import (
	"context"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"time"
	"github.com/sirupsen/logrus"
)

type pcapSource struct {
	handle    *pcap.Handle
	output    chan *types.Packet
	bpfFilter string
}

func NewPcapSource(device string) (*pcapSource, error) {
	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	return &pcapSource{
		handle: handle,
		output: make(chan *types.Packet, 1000),
	}, nil
}

func (s *pcapSource) Start(ctx context.Context) error {
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

func (s *pcapSource) Output() <-chan *types.Packet {
	return s.output
}

func (s *pcapSource) SetFilter(filter string) error {
	s.bpfFilter = filter
	return nil
} 