package sink

import (
	"context"
	"encoding/json"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/sirupsen/logrus"
	"os"
	"sync"
)

type FileSink struct {
	filename string
	file     *os.File
	mu       sync.Mutex
	ready    chan struct{}
}

func NewFileSink(filename string) (*FileSink, error) {
	logrus.Infof("Creating new file sink: %s", filename)
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		logrus.Errorf("Failed to open file sink: %v", err)
		return nil, err
	}

	return &FileSink{
		filename: filename,
		file:     file,
		ready:    make(chan struct{}),
	}, nil
}

func (s *FileSink) writePacketToFile(packet *types.Packet) error {
	// 将数据包转换为JSON格式
	data := map[string]interface{}{
		"id":        packet.ID,
		"timestamp": packet.Timestamp,
		"protocol":  packet.Protocol,
		"features":  packet.Features,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		logrus.Errorf("Failed to marshal packet to JSON: %v", err)
		return err
	}

	// 写入文件
	s.mu.Lock()
	defer s.mu.Unlock() // 确保在函数结束时解锁

	if _, err := s.file.Write(jsonData); err != nil {
		logrus.Errorf("Failed to write packet to file: %v", err)
		return err
	}
	if _, err := s.file.Write([]byte("\n")); err != nil {
		logrus.Errorf("Failed to write newline to file: %v", err)
		return err
	}
	return nil
}

func (s *FileSink) Consume(ctx context.Context, in <-chan *types.Packet) error {
	logrus.Info("Starting file sink consumer")
	defer logrus.Info("File sink consumer stopped")

	close(s.ready)

	for {
		select {
		case <-ctx.Done():
			logrus.Debug("File sink received context cancellation")
			return s.file.Close()
		case packet, ok := <-in:
			if !ok {
				logrus.Debug("File sink input channel closed")
				return s.file.Close()
			}

			if err := s.writePacketToFile(packet); err != nil {
				continue
			}
		}
	}
}

func (s *FileSink) Ready() <-chan struct{} {
	return s.ready
}
