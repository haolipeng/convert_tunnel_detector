package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/haolipeng/convert_tunnel_detector/pkg/config"
	"github.com/haolipeng/convert_tunnel_detector/pkg/ruleEngine"
	"github.com/haolipeng/convert_tunnel_detector/pkg/types"
	"github.com/haolipeng/gopacket/layers"
	"github.com/haolipeng/gopacket/pcapgo"
	"github.com/sirupsen/logrus"
)

// AlertEndpoint 告警上报的HTTP地址
var AlertEndpoint = "http://192.168.1.191:8080/event"

type PcapSink struct {
	baseFilename string // 基础文件名（如 "qt"）
	maxFileSize  int64  // 文件大小限制（50MB）
	currentSize  int64  // 当前文件大小
	fileIndex    int    // 当前文件索引
	pcapWriter   *pcapgo.Writer
	curFileName  string // 当前文件名
	file         *os.File
	mu           sync.Mutex
	ready        chan struct{}
}

func NewPcapSink(config *config.Config) (*PcapSink, error) {
	// 从配置文件中读取 max_file_size，如果没有设置则使用默认值 50MB
	maxFileSize := int64(50 * 1024 * 1024) // 默认 50MB
	if config.Output.MaxFileSize > 0 {
		maxFileSize = config.Output.MaxFileSize
	}

	sink := &PcapSink{
		baseFilename: config.Output.BaseFilename,
		maxFileSize:  maxFileSize,
		fileIndex:    1,
		ready:        make(chan struct{}),
	}

	// 创建第一个文件
	if err := sink.createNewPcapFile(); err != nil {
		return nil, err
	}

	return sink, nil
}

func (s *PcapSink) createNewPcapFile() error {
	// 生成文件名：qt_20240318_153000_1.pcap
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("%s_%s_%d.pcap", s.baseFilename, timestamp, s.fileIndex)

	// 创建新文件
	f, err := os.Create(filename)
	if err != nil {
		logrus.Errorf("Failed to create pcap file: %v", err)
		return err
	}

	// 如果已有打开的文件，先关闭
	if s.file != nil {
		if err := s.file.Close(); err != nil {
			logrus.Errorf("Failed to close previous pcap file: %v", err)
		}
	}

	// 创建新的 pcap writer
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		f.Close()
		logrus.Errorf("Failed to write pcap header: %v", err)
		return err
	}

	s.curFileName = filename
	s.file = f
	s.pcapWriter = w
	s.currentSize = 0
	s.fileIndex++

	logrus.Infof("Created new pcap file: %s", filename)
	return nil
}

func (s *PcapSink) writePacketToPcap(packet *types.Packet) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if packet.RawData == nil {
		logrus.Error("No raw packet data available")
		return nil
	}

	// 检查文件大小是否超过限制
	if s.currentSize >= s.maxFileSize {
		if err := s.createNewPcapFile(); err != nil {
			return err
		}
	}

	// 写入数据包
	err := s.pcapWriter.WritePacket(packet.CaptureInfo, packet.RawData)
	if err != nil {
		logrus.Errorf("Failed to write packet to pcap: %v", err)
		return err
	}

	// 更新文件大小
	s.currentSize += int64(len(packet.RawData))

	// 如果数据包是告警包，则调用告警函数
	if packet.RuleResult.Action == types.ActionAlert {
		generateAlert(packet, s.curFileName)
	}
	return nil
}

func (s *PcapSink) Consume(ctx context.Context, in <-chan *types.Packet) error {
	logrus.Info("Starting pcap sink consumer")
	//在程序结束时统一关闭文件
	defer func() {
		if s.file != nil {
			if err := s.file.Close(); err != nil {
				logrus.Errorf("Failed to close pcap file: %v", err)
			}
		}
		logrus.Info("Pcap sink consumer stopped")
	}()

	close(s.ready)

	for {
		select {
		case <-ctx.Done():
			logrus.Debug("Pcap sink received context cancellation")
			return nil
		case packet, ok := <-in:
			if !ok {
				logrus.Debug("Pcap sink input channel closed")
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

func generateAlert(packet *types.Packet, curFileName string) {
	var ruleInfo *ruleEngine.ProtocolRule
	t := packet.RuleResult.MatchType
	if t == types.MatchTypeBlacklist {
		ruleInfo = packet.RuleResult.BlackRule
	} else if t == types.MatchTypeWhitelist {
		ruleInfo = packet.RuleResult.WhiteRule
	}

	// 生成告警ID：协议名称_规则ID_数据包ID_时间戳
	alertID := fmt.Sprintf("%s_%s_%s_%d",
		strings.ToLower(packet.Protocol),
		ruleInfo.RuleID,
		packet.ID,
		time.Now().UnixNano(),
	)

	var alertType string
	if packet.Protocol == "OSPF" || packet.Protocol == "ospf" {
		alertType = "OSPF Tunnel Detection"
	} else if packet.Protocol == "PIM" || packet.Protocol == "pim" {
		alertType = "PIM Tunnel Detection"
	} else if packet.Protocol == "IGMP" || packet.Protocol == "igmp" {
		alertType = "IGMP Tunnel Detection"
	}

	alertInfo := map[string]interface{}{
		"alert_id":       alertID, // 新的告警ID格式
		"alert_time":     time.Now(),
		"src_ip":         packet.SrcIP.String(),
		"src_port":       packet.SrcPort,
		"dst_ip":         packet.DstIP.String(),
		"dst_port":       packet.DstPort,
		"protocol":       packet.Protocol,
		"sub_protocol":   packet.SubProtocol,
		"detect_method":  packet.RuleResult.DetectMethod,
		"rule_id":        ruleInfo.RuleID,
		"alert_type":     alertType,
		"description":    ruleInfo.Description,
		"action":         "alert",
		"packet_id":      packet.ID,
		"pcap_file_path": curFileName,
		"feature":        "{}", // TODO:暂时不编写
	}

	// 记录本地日志
	logrus.WithFields(logrus.Fields(alertInfo)).Warn("告警信息")

	// 将告警信息转换为JSON
	jsonData, err := json.Marshal(alertInfo)
	if err != nil {
		logrus.Errorf("Failed to marshal alert info: %v", err)
		return
	}

	// 创建HTTP请求
	req, err := http.NewRequest("POST", AlertEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		logrus.Errorf("Failed to create HTTP request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// 创建HTTP客户端
	client := &http.Client{
		Timeout: time.Second * 5, // 设置5秒超时
	}

	// 发送HTTP请求
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("Failed to send alert: %v", err)
		return
	}
	defer resp.Body.Close()

	// 检查响应状态
	if resp.StatusCode != http.StatusOK {
		logrus.Errorf("Alert server returned non-200 status code: %d", resp.StatusCode)
		return
	}

	logrus.Debugf("Alert successfully sent to %s", AlertEndpoint)
}
