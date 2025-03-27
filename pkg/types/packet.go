package types

import (
	"net"
)

// Packet 表示处理流水线中传递的数据包
type Packet struct {
	ID        string // 包ID
	Timestamp int64  // 时间戳
	RawData   []byte // 原始数据
	Protocol  string // 协议类型
	LastError error  // 错误信息

	ParserResult PacketResult // 协议解析结果

	RuleResult *RuleMatchResult // 规则匹配结果

	SubType uint8 // OSPF报文类型：1=Hello, 2=DD, 3=LSR, 4=LSU, 5=LSAck

	// 数据包转发相关字段
	SrcMAC       net.HardwareAddr // 源MAC地址
	DstMAC       net.HardwareAddr // 目标MAC地址
	EthernetType uint16           // 以太网类型
	Interface    *net.Interface   // 网络接口信息
}

// PacketType 表示数据包类型
type PacketType uint8

const (
	OSPF PacketType = 1 //OSPF报文
	PIM  PacketType = 2 //PIM报文
	IGMP PacketType = 3 //IGMP报文
	ICMP PacketType = 4 //ICMP报文
)

// Stage 表示处理阶段的状态
type Stage int

const (
	StageProtocolParsing           Stage = iota + 1 //协议解析阶段
	StageBasicFeatureExtraction                     //基础特征提取阶段
	StageProtocolFeatureExtraction                  //协议相关特征提取阶段
	StageRuleEngineDetection                        //规则引擎检测阶段
	StageFSMEngineDetection                         //状态机引擎检测阶段
	StateBaselineDetection                          //基线引擎检测阶段
	StagePacketForwarding                           //数据包转发阶段
)

type PacketResult interface {
	GetType() PacketType
}
