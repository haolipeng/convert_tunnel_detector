package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/haolipeng/convert_tunnel_detector/pkg/metrics"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/haolipeng/gopacket"
	"github.com/haolipeng/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

type PcapFileSource struct {
	handle    *pcap.Handle
	output    chan *types.Packet
	bpfFilter string
	done      chan struct{}
	stats     *metrics.SourceMetrics // 统计信息
	filename  string
	mu        sync.Mutex
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

func (s *PcapFileSource) Start(ctx context.Context, wg *sync.WaitGroup) error {
	//使用channel来通知完成操作
	s.done = make(chan struct{})

	if s.bpfFilter != "" {
		logrus.Debugf("Setting BPF filter: %s", s.bpfFilter)
		if err := s.handle.SetBPFFilter(s.bpfFilter); err != nil {
			logrus.Errorf("Failed to set BPF filter: %v", err)
			s.cleanup()
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(s.handle, s.handle.LinkType())
	logrus.Infof("Started reading packets from file: %s", s.filename)

	go func() {
		defer func() {
			wg.Done()
			s.cleanup()
			close(s.done)
			logrus.Info("Packet reading goroutine cleaned up")
		}()

		var packetCount int64 = 0
		for {
			select {
			case <-ctx.Done():
				logrus.Info("Stopping packet reading: context cancellation")
				return
			default:
				packet, err := packetSource.NextPacket()
				if err != nil {
					if errors.Is(err, pcap.NextErrorNoMorePackets) || err == io.EOF {
						logrus.Infof("Reached end of pcap file, total packets: %d\n", packetCount)
						return
					}
					logrus.Warnf("Error reading packet: %v", err)
					s.stats.IncrementErrorCount()
					continue
				}

				p := &types.Packet{
					ID:        fmt.Sprintf("pkt-%d", packetCount),
					Timestamp: time.Now().UnixNano(),
					RawData:   packet.Data(),
					Protocol:  "Unknown",
				}

				select {
				case s.output <- p:
					packetCount++
					s.stats.PacketsCaptured++
					s.stats.BytesProcessed += uint64(len(packet.Data()))
					logrus.Debugf("pcapfile Source: sent packet to out channel - %s", p.ID)
				default:
					logrus.Warnf("Source: out channel is full, dropping packet - %s", p.ID)
				case <-ctx.Done():
					logrus.Warnf("Source: context cancelled while sending packet - %s", p.ID)
					return
				}
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

// 获取状态信息的实例
func (s *PcapFileSource) GetStats() *metrics.SourceMetrics {
	return s.stats
}

func (s *PcapFileSource) WaitForCompletion() <-chan struct{} {
	return s.done
}

func (s *PcapFileSource) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}

	//关闭数据源的输出channel通道
	if s.output != nil {
		select {
		case _, ok := <-s.output:
			if ok {
				close(s.output)
			}
		default:
			close(s.output)
		}
		s.output = nil
	}
}

func (s *PcapFileSource) Stop() error {
	logrus.Info("Stopping PcapFileSource...")
	s.cleanup()
	return nil
}
