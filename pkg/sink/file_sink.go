package sink

import (
	"context"
	"os"
	"sync"

	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/haolipeng/gopacket/layers"
	"github.com/haolipeng/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

type PcapSink struct {
	filename   string
	pcapWriter *pcapgo.Writer
	file       *os.File
	mu         sync.Mutex
	ready      chan struct{}
}

func NewPcapSink(filename string) (*PcapSink, error) {
	logrus.Infof("Creating new pcap sink: %s", filename)

	f, err := os.Create(filename)
	if err != nil {
		logrus.Errorf("Failed to create pcap file: %v", err)
		return nil, err
	}

	// 创建 pcap writer，使用以太网链路类型
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		logrus.Errorf("Failed to write pcap header: %v", err)
		return nil, err
	}

	return &PcapSink{
		filename:   filename,
		pcapWriter: w,
		file:       f,
		ready:      make(chan struct{}),
	}, nil
}

func (s *PcapSink) writePacketToPcap(packet *types.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 从 Packet 中获取原始数据和捕获信息
	if packet.RawData == nil {
		logrus.Error("No raw packet data available")
		return nil
	}

	// 写入数据包
	err := s.pcapWriter.WritePacket(packet.CaptureInfo, packet.RawData)
	if err != nil {
		logrus.Errorf("Failed to write packet to pcap: %v", err)
		return err
	}

	return nil
}

func (s *PcapSink) Consume(ctx context.Context, in <-chan *types.Packet) error {
	logrus.Info("Starting pcap sink consumer")
	defer logrus.Info("Pcap sink consumer stopped")

	close(s.ready)

	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Pcap sink received context cancellation")
			if err := s.file.Close(); err != nil {
				logrus.Errorf("Failed to close pcap file: %v", err)
			}
			return nil
		case packet, ok := <-in:
			if !ok {
				logrus.Debug("Pcap sink input channel closed")
				if err := s.file.Close(); err != nil {
					logrus.Errorf("Failed to close pcap file: %v", err)
				}
				return nil
			}

			if err := s.writePacketToPcap(packet); err != nil {
				logrus.Errorf("Failed to write packet: %v", err)
				continue
			}
		}
	}
}

func (s *PcapSink) Ready() <-chan struct{} {
	return s.ready
}
