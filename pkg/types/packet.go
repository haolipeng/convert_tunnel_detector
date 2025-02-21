package types

// Packet 表示处理流水线中传递的数据包
type Packet struct {
	ID           string
	Timestamp    int64
	RawData      []byte
	Protocol     string
	Error        error
	ParserResult PacketResult // 协议解析结果

	RuleResult RuleEngineResult //添加规则匹配结果
}

type PacketType uint8

const (
	OSPF PacketType = 1
	PIM  PacketType = 2
	IGMP PacketType = 3
	ICMP PacketType = 4
)

type RuleEngineResult uint8

const (
	Deny  RuleEngineResult = 1
	Pass  RuleEngineResult = 2
	Alert RuleEngineResult = 3
)

type PacketResult interface {
	GetType() PacketType
}

// Stage 表示处理阶段的状态
type Stage int

const (
	StageProtocolParsing           Stage = iota + 1 //协议解析
	StageBasicFeatureExtraction                     //基础特征提取
	StageProtocolFeatureExtraction                  //协议相关特征提取
	StageRuleEngineDetection                        //规则引擎检测
	StageFSMEngineDetection                         //状态机引擎检测
	StateBaselineDetection                          //基线引擎检测
)
